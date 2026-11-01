import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  PutCommand,
  GetCommand,
  QueryCommand,
  DeleteCommand,
  TransactWriteCommand,
} from '@aws-sdk/lib-dynamodb';
import { createHash } from 'node:crypto';
import type {
  SecurityEvent,
  Incident,
  Detection,
  DetectionQueryOptions,
  IncidentStatus,
  Severity,
  DetectionRule,
  ThreatIndicator,
  ResponseExecution,
  AuditLog,
  AuditState,
  WebsiteAsset,
  Integration,
} from '@veltrix/shared';
import type { StorageInterface, EventQueryOptions } from './storage-interface.js';
import { signCursor, verifyCursor, computeFilterHash } from '../utils/cursor.js';
import { extractDateFromUuidV7 } from '../utils/uuid.js';

export class DynamoDBStore implements StorageInterface {
  private docClient: DynamoDBDocumentClient;
  private readonly eventsTable: string;
  private readonly incidentsTable: string;
  private readonly rulesTable: string;
  private readonly indicatorsTable: string;
  private readonly responsesTable: string;
  private readonly auditTable: string;
  private readonly auditStateTable: string;
  private readonly websitesTable: string;
  private readonly integrationsTable: string;

  private static readonly GENESIS_HASH = '0'.repeat(64);

  constructor(client?: DynamoDBClient) {
    const region = process.env.AWS_REGION || 'us-east-1';
    const rawClient = client || new DynamoDBClient({ region });

    this.docClient = DynamoDBDocumentClient.from(rawClient, {
      marshallOptions: {
        removeUndefinedValues: true,
      },
    });

    const env = process.env.ENVIRONMENT || 'dev';
    this.eventsTable = process.env.DYNAMODB_EVENTS_TABLE || `Veltrix-SecurityEvents-${env}`;
    this.incidentsTable = process.env.DYNAMODB_INCIDENTS_TABLE || `Veltrix-Incidents-${env}`;
    this.rulesTable = process.env.DYNAMODB_RULES_TABLE || `Veltrix-DetectionRules-${env}`;
    this.indicatorsTable = process.env.DYNAMODB_INDICATORS_TABLE || `Veltrix-ThreatIndicators-${env}`;
    this.responsesTable = process.env.DYNAMODB_RESPONSES_TABLE || `Veltrix-ResponseExecutions-${env}`;
    this.auditTable = process.env.DYNAMODB_AUDIT_TABLE || `Veltrix-AuditLogs-${env}`;
    this.auditStateTable = process.env.DYNAMODB_AUDIT_STATE_TABLE || `Veltrix-AuditState-${env}`;
    this.websitesTable = process.env.DYNAMODB_WEBSITES_TABLE || `Veltrix-WebsiteAssets-${env}`;
    this.integrationsTable = process.env.DYNAMODB_INTEGRATIONS_TABLE || `Veltrix-Integrations-${env}`;
  }

  // --- Exponential Backoff Retry Helper ---
  private async executeWithRetry<T>(operation: () => Promise<T>, maxRetries = 3): Promise<T> {
    let attempt = 0;
    while (true) {
      try {
        return await operation();
      } catch (err: unknown) {
        attempt++;
        const errName = (err as { name?: string })?.name || '';
        const isRetryable =
          errName === 'ProvisionedThroughputExceededException' ||
          errName === 'InternalServerError' ||
          errName === 'TransactionConflictException' ||
          errName === 'TimeoutError';

        if (!isRetryable || attempt >= maxRetries) {
          throw err;
        }

        const delayMs = Math.pow(2, attempt) * 50 + Math.random() * 50;
        await new Promise((resolve) => setTimeout(resolve, delayMs));
      }
    }
  }

  // --- Security Events Telemetry (Time-Sharded & Idempotent) ---

  async saveEvent(
    event: SecurityEvent,
    payloadHash?: string
  ): Promise<{ saved: boolean; isDuplicate: boolean; eventId?: string }> {
    const orgId = event.orgId;
    const dateStr = event.timestamp.slice(0, 10); // YYYY-MM-DD
    const pk = `ORG#${orgId}#DATE#${dateStr}`;
    const sk = `EVENT#${event.timestamp}#${event.eventId}`;
    const idempotencyKey = event.idempotencyKey || event.eventId;

    const ttlEpoch = Math.floor(new Date(event.timestamp).getTime() / 1000) + 30 * 86400;

    const item: Record<string, unknown> = {
      PK: pk,
      SK: sk,
      GSI1_PK: `ORG#${orgId}#TYPE#${event.eventType}`,
      GSI1_SK: event.timestamp,
      GSI2_PK: `ORG#${orgId}#IP#${event.sourceIp}`,
      GSI2_SK: event.timestamp,
      eventId: event.eventId,
      orgId: event.orgId,
      timestamp: event.timestamp,
      eventType: event.eventType,
      severity: event.severity,
      category: event.category,
      sourceIp: event.sourceIp,
      username: event.username,
      sourceSystem: event.sourceSystem,
      metadata: event.metadata,
      isSimulated: event.isSimulated || false,
      idempotencyKey,
      payloadHash: payloadHash || '',
      ttl: ttlEpoch,
    };

    if (event.trustedEvidenceContext) {
      item.trustedEvidenceContext = event.trustedEvidenceContext;
    }

    const { PK: _p, SK: _s, ...itemPayload } = item;

    // Atomically create Main Event, ID Pointer, and Idempotency Record in a single TransactWriteCommand
    const transactItems: Array<{
      Put: {
        TableName: string;
        Item: Record<string, unknown>;
        ConditionExpression: string;
      };
    }> = [
      {
        Put: {
          TableName: this.eventsTable,
          Item: item,
          ConditionExpression: 'attribute_not_exists(PK) AND attribute_not_exists(SK)',
        },
      },
      {
        Put: {
          TableName: this.eventsTable,
          Item: {
            PK: `ORG#${orgId}#EVENTID#${event.eventId}`,
            SK: 'METADATA',
            ...itemPayload,
          },
          ConditionExpression: 'attribute_not_exists(PK)',
        },
      },
    ];

    if (idempotencyKey !== event.eventId) {
      transactItems.push({
        Put: {
          TableName: this.eventsTable,
          Item: {
            PK: `ORG#${orgId}#IDEMPOTENCY#${idempotencyKey}`,
            SK: 'RECORD',
            orgId,
            idempotencyKey,
            eventId: event.eventId,
            payloadHash: payloadHash || '',
            ttl: ttlEpoch,
          },
          ConditionExpression: 'attribute_not_exists(PK)',
        },
      });
    }

    try {
      await this.executeWithRetry(() =>
        this.docClient.send(
          new TransactWriteCommand({
            TransactItems: transactItems,
          })
        )
      );
      return { saved: true, isDuplicate: false, eventId: event.eventId };
    } catch (err: unknown) {
      const errName = (err as { name?: string })?.name;
      if (
        errName === 'ConditionalCheckFailedException' ||
        errName === 'TransactionCanceledException'
      ) {
        // Atomic duplicate caught; verify payload consistency
        return await this.handleDuplicatePayloadConsistency(
          orgId,
          idempotencyKey,
          event.eventId,
          payloadHash
        );
      }
      throw err;
    }
  }

  private async handleDuplicatePayloadConsistency(
    orgId: string,
    idempotencyKey: string,
    eventId: string,
    payloadHash?: string
  ): Promise<{ saved: boolean; isDuplicate: boolean; eventId?: string }> {
    try {
      let existingRecord: { payloadHash?: string; eventId?: string } | undefined;

      // 1. Check existing event ID pointer
      const pointerResult = await this.executeWithRetry(() =>
        this.docClient.send(
          new GetCommand({
            TableName: this.eventsTable,
            Key: {
              PK: `ORG#${orgId}#EVENTID#${eventId}`,
              SK: 'METADATA',
            },
          })
        )
      );

      if (pointerResult.Item) {
        existingRecord = pointerResult.Item as { payloadHash?: string; eventId?: string };
      } else if (idempotencyKey !== eventId) {
        // 2. Check existing idempotency record
        const idempResult = await this.executeWithRetry(() =>
          this.docClient.send(
            new GetCommand({
              TableName: this.eventsTable,
              Key: {
                PK: `ORG#${orgId}#IDEMPOTENCY#${idempotencyKey}`,
                SK: 'RECORD',
              },
            })
          )
        );
        if (idempResult.Item) {
          existingRecord = idempResult.Item as { payloadHash?: string; eventId?: string };
        }
      }

      if (
        existingRecord &&
        payloadHash &&
        existingRecord.payloadHash &&
        existingRecord.payloadHash !== payloadHash
      ) {
        const mismatchErr = new Error(
          `Idempotency key or Event ID was previously used with a different request payload.`
        );
        (mismatchErr as unknown as { code: string }).code = 'IDEMPOTENCY_PAYLOAD_MISMATCH';
        throw mismatchErr;
      }

      return {
        saved: false,
        isDuplicate: true,
        eventId: existingRecord?.eventId || eventId,
      };
    } catch (err: unknown) {
      if ((err as { code?: string })?.code === 'IDEMPOTENCY_PAYLOAD_MISMATCH') {
        throw err;
      }
      return { saved: false, isDuplicate: true, eventId };
    }
  }

  async getEvents(
    orgId: string,
    options?: EventQueryOptions
  ): Promise<{ items: SecurityEvent[]; nextCursor?: string; total?: number }> {
    const targetDate = options?.startTime
      ? options.startTime.slice(0, 10)
      : options?.endTime
        ? options.endTime.slice(0, 10)
        : new Date().toISOString().slice(0, 10);

    const pk = `ORG#${orgId}#DATE#${targetDate}`;

    let indexName: string | undefined;
    let keyCondition = 'PK = :pk';
    const exprValues: Record<string, unknown> = { ':pk': pk };
    const exprNames: Record<string, string> = {};
    const filterConditions: string[] = [];

    if (options?.eventType) {
      indexName = 'GSI1-EventTypeIndex';
      keyCondition = 'GSI1_PK = :gsi1pk';
      exprValues[':gsi1pk'] = `ORG#${orgId}#TYPE#${options.eventType}`;
      delete exprValues[':pk'];

      if (options.startTime && options.endTime) {
        keyCondition += ' AND GSI1_SK BETWEEN :startTime AND :endTime';
        exprValues[':startTime'] = options.startTime;
        exprValues[':endTime'] = options.endTime;
      } else if (options.startTime) {
        keyCondition += ' AND GSI1_SK >= :startTime';
        exprValues[':startTime'] = options.startTime;
      } else if (options.endTime) {
        keyCondition += ' AND GSI1_SK <= :endTime';
        exprValues[':endTime'] = options.endTime;
      }
    } else if (options?.sourceIp) {
      indexName = 'GSI2-SourceIpIndex';
      keyCondition = 'GSI2_PK = :gsi2pk';
      exprValues[':gsi2pk'] = `ORG#${orgId}#IP#${options.sourceIp}`;
      delete exprValues[':pk'];

      if (options.startTime && options.endTime) {
        keyCondition += ' AND GSI2_SK BETWEEN :startTime AND :endTime';
        exprValues[':startTime'] = options.startTime;
        exprValues[':endTime'] = options.endTime;
      } else if (options.startTime) {
        keyCondition += ' AND GSI2_SK >= :startTime';
        exprValues[':startTime'] = options.startTime;
      } else if (options.endTime) {
        keyCondition += ' AND GSI2_SK <= :endTime';
        exprValues[':endTime'] = options.endTime;
      }
    } else {
      if (options?.startTime && options?.endTime) {
        keyCondition += ' AND SK BETWEEN :startSk AND :endSk';
        exprValues[':startSk'] = `EVENT#${options.startTime}`;
        exprValues[':endSk'] = `EVENT#${options.endTime}#\uffff`;
      } else if (options?.startTime) {
        keyCondition += ' AND SK >= :startSk';
        exprValues[':startSk'] = `EVENT#${options.startTime}`;
      } else if (options?.endTime) {
        keyCondition += ' AND SK <= :endSk';
        exprValues[':endSk'] = `EVENT#${options.endTime}#\uffff`;
      }
    }

    if (options?.severity) {
      filterConditions.push('#sev = :sev');
      exprNames['#sev'] = 'severity';
      exprValues[':sev'] = options.severity;
    }
    if (options?.username) {
      filterConditions.push('#usr = :usr');
      exprNames['#usr'] = 'username';
      exprValues[':usr'] = options.username;
    }
    if (options?.sourceSystem) {
      filterConditions.push('#srcSys = :srcSys');
      exprNames['#srcSys'] = 'sourceSystem';
      exprValues[':srcSys'] = options.sourceSystem;
    }

    let exclusiveStartKey: Record<string, unknown> | undefined;
    if (options?.cursor) {
      try {
        const verified = verifyCursor(options.cursor, orgId, options);
        exclusiveStartKey = verified.exclusiveStartKey;
      } catch (err: unknown) {
        throw new Error('INVALID_CURSOR');
      }
    }

    const command = new QueryCommand({
      TableName: this.eventsTable,
      IndexName: indexName,
      KeyConditionExpression: keyCondition,
      ExpressionAttributeValues: exprValues,
      ExpressionAttributeNames: Object.keys(exprNames).length > 0 ? exprNames : undefined,
      FilterExpression: filterConditions.length > 0 ? filterConditions.join(' AND ') : undefined,
      ScanIndexForward: false,
      Limit: options?.limit || 50,
      ExclusiveStartKey: exclusiveStartKey,
    });

    const response = await this.executeWithRetry(() => this.docClient.send(command));
    const items = (response.Items || []).map((item) => {
      const { PK: _pk, SK: _sk, GSI1_PK: _g1p, GSI1_SK: _g1s, GSI2_PK: _g2p, GSI2_SK: _g2s, ...event } = item as Record<string, unknown>;
      return event as unknown as SecurityEvent;
    });
    const filterHash = computeFilterHash(options);
    const nextCursor = response.LastEvaluatedKey
      ? signCursor({
          orgId,
          filterHash,
          exclusiveStartKey: response.LastEvaluatedKey as Record<string, unknown>,
        })
      : undefined;

    return { items, nextCursor, total: items.length };
  }

  async getEventById(orgId: string, eventId: string): Promise<SecurityEvent | null> {
    try {
      // 1. Direct O(1) lookup via ID pointer (works instantly for UUIDv4, UUIDv7, delayed events)
      try {
        const pointerResult = await this.executeWithRetry(() =>
          this.docClient.send(
            new GetCommand({
              TableName: this.eventsTable,
              Key: {
                PK: `ORG#${orgId}#EVENTID#${eventId}`,
                SK: 'METADATA',
              },
            })
          )
        );
        if (pointerResult.Item) {
          const item = pointerResult.Item as SecurityEvent & Record<string, unknown>;
          const { PK, SK, GSI1_PK, GSI1_SK, GSI2_PK, GSI2_SK, ...event } = item;
          return event as unknown as SecurityEvent;
        }
      } catch {
        // Fallback to targeted partition query
      }

      // 2. Targeted single-partition Query via UUIDv7 date extraction
      const extractedDate = extractDateFromUuidV7(eventId);
      const candidateDates: string[] = [];

      if (extractedDate) {
        candidateDates.push(extractedDate);
        // Cover UTC midnight boundary and clock skew (+/- 1 day)
        const dateObj = new Date(extractedDate + 'T00:00:00.000Z');
        const prevDay = new Date(dateObj.getTime() - 86400000).toISOString().slice(0, 10);
        const nextDay = new Date(dateObj.getTime() + 86400000).toISOString().slice(0, 10);
        candidateDates.push(prevDay, nextDay);
      } else {
        // UUIDv4 or untimed identifier: check today and yesterday partitions (no full table scans)
        const today = new Date().toISOString().slice(0, 10);
        const yesterday = new Date(Date.now() - 86400000).toISOString().slice(0, 10);
        candidateDates.push(today, yesterday);
      }

      for (const targetDate of candidateDates) {
        const pk = `ORG#${orgId}#DATE#${targetDate}`;
        const queryRes = await this.executeWithRetry(() =>
          this.docClient.send(
            new QueryCommand({
              TableName: this.eventsTable,
              KeyConditionExpression: 'PK = :pk',
              FilterExpression: 'eventId = :eventId',
              ExpressionAttributeValues: {
                ':pk': pk,
                ':eventId': eventId,
              },
              Limit: 1,
            })
          )
        );
        const items = (queryRes.Items || []).map((it) => {
          const { PK, SK, GSI1_PK, GSI1_SK, GSI2_PK, GSI2_SK, ...event } = it as Record<string, unknown>;
          return event as unknown as SecurityEvent;
        });
        if (items.length > 0 && items[0]) {
          return items[0];
        }
      }

      return null;
    } catch {
      return null;
    }
  }

  // --- Threat Detections ---

  async saveDetection(
    detection: Detection
  ): Promise<{ saved: boolean; isDuplicate: boolean }> {
    const orgId = detection.orgId;
    const pk = `ORG#${orgId}`;
    const sk = `DETECTION#${detection.detectedAt}#${detection.detectionId}`;
    const dedupKey = detection.dedupKey || detection.detectionId;
    const ttlEpoch = detection.ttl || Math.floor(new Date(detection.detectedAt).getTime() / 1000) + 90 * 86400;

    const item = {
      PK: pk,
      SK: sk,
      GSI1_PK: `ORG#${orgId}#RULE#${detection.ruleId}`,
      GSI1_SK: detection.detectedAt,
      GSI2_PK: `ORG#${orgId}#SEVERITY#${detection.severity}`,
      GSI2_SK: detection.detectedAt,
      detectionId: detection.detectionId,
      ruleId: detection.ruleId,
      ruleName: detection.ruleName,
      orgId: detection.orgId,
      severity: detection.severity,
      confidence: detection.confidence,
      category: detection.category,
      title: detection.title,
      description: detection.description,
      detectedAt: detection.detectedAt,
      relatedEventIds: detection.relatedEventIds,
      evidence: detection.evidence,
      mitreAttack: detection.mitreAttack,
      status: detection.status || 'ACTIVE',
      siteId: (detection.evidence?.details as { siteId?: string } | undefined)?.siteId,
      dedupKey,
      ttl: ttlEpoch,
    };

    const transactItems: Array<{
      Put: {
        TableName: string;
        Item: Record<string, unknown>;
        ConditionExpression: string;
      };
    }> = [
      // 1. Primary detection record
      {
        Put: {
          TableName: this.incidentsTable,
          Item: item,
          ConditionExpression: 'attribute_not_exists(PK) AND attribute_not_exists(SK)',
        },
      },
      // 2. Direct O(1) detectionId pointer
      {
        Put: {
          TableName: this.incidentsTable,
          Item: {
            ...item,
            PK: `ORG#${orgId}#DETECTIONID#${detection.detectionId}`,
            SK: 'METADATA',
          },
          ConditionExpression: 'attribute_not_exists(PK)',
        },
      },
      // 3. Deduplication key record
      {
        Put: {
          TableName: this.incidentsTable,
          Item: {
            PK: `ORG#${orgId}#DEDUP#${dedupKey}`,
            SK: 'DETECTION',
            detectionId: detection.detectionId,
            orgId,
            ttl: ttlEpoch,
          },
          ConditionExpression: 'attribute_not_exists(PK)',
        },
      },
    ];

    try {
      await this.executeWithRetry(() =>
        this.docClient.send(
          new TransactWriteCommand({
            TransactItems: transactItems,
          })
        )
      );
      return { saved: true, isDuplicate: false };
    } catch (err: unknown) {
      const errName = (err as { name?: string })?.name;
      if (
        errName === 'ConditionalCheckFailedException' ||
        errName === 'TransactionCanceledException'
      ) {
        return { saved: false, isDuplicate: true };
      }
      throw err;
    }
  }

  async getDetections(
    orgId: string,
    options?: DetectionQueryOptions
  ): Promise<{ items: Detection[]; nextCursor?: string; total?: number }> {
    let indexName: string | undefined;
    let keyCondition = 'PK = :pk AND begins_with(SK, :skPrefix)';
    const exprValues: Record<string, unknown> = {
      ':pk': `ORG#${orgId}`,
      ':skPrefix': 'DETECTION#',
    };
    const exprNames: Record<string, string> = {};
    const filterConditions: string[] = [];

    if (options?.severity) {
      indexName = 'GSI2-SeverityIndex';
      keyCondition = 'GSI2_PK = :gsi2pk';
      exprValues[':gsi2pk'] = `ORG#${orgId}#SEVERITY#${options.severity}`;
      delete exprValues[':pk'];
      delete exprValues[':skPrefix'];

      if (options.startTime && options.endTime) {
        keyCondition += ' AND GSI2_SK BETWEEN :startTime AND :endTime';
        exprValues[':startTime'] = options.startTime;
        exprValues[':endTime'] = options.endTime;
      } else if (options.startTime) {
        keyCondition += ' AND GSI2_SK >= :startTime';
        exprValues[':startTime'] = options.startTime;
      } else if (options.endTime) {
        keyCondition += ' AND GSI2_SK <= :endTime';
        exprValues[':endTime'] = options.endTime;
      }
    } else {
      if (options?.startTime && options?.endTime) {
        keyCondition = 'PK = :pk AND SK BETWEEN :startSk AND :endSk';
        exprValues[':startSk'] = `DETECTION#${options.startTime}`;
        exprValues[':endSk'] = `DETECTION#${options.endTime}#\uffff`;
        delete exprValues[':skPrefix'];
      } else if (options?.startTime) {
        keyCondition = 'PK = :pk AND SK >= :startSk';
        exprValues[':startSk'] = `DETECTION#${options.startTime}`;
        delete exprValues[':skPrefix'];
      }
    }

    if (options?.ruleId) {
      filterConditions.push('#rId = :rId');
      exprNames['#rId'] = 'ruleId';
      exprValues[':rId'] = options.ruleId;
    }
    if (options?.status) {
      filterConditions.push('#st = :st');
      exprNames['#st'] = 'status';
      if (options?.siteId) {
        filterConditions.push('(#sId = :sId OR #ev.#det.#sId = :sId)');
        exprNames['#sId'] = 'siteId';
        exprNames['#ev'] = 'evidence';
        exprNames['#det'] = 'details';
        exprValues[':sId'] = options.siteId;
      }
      exprValues[':st'] = options.status;
    }

    let exclusiveStartKey: Record<string, unknown> | undefined;
    if (options?.cursor) {
      try {
        const verified = verifyCursor(options.cursor, orgId, options as any);
        exclusiveStartKey = verified.exclusiveStartKey;
      } catch {
        throw new Error('INVALID_CURSOR');
      }
    }

    const command = new QueryCommand({
      TableName: this.incidentsTable,
      IndexName: indexName,
      KeyConditionExpression: keyCondition,
      ExpressionAttributeValues: exprValues,
      ExpressionAttributeNames: Object.keys(exprNames).length > 0 ? exprNames : undefined,
      FilterExpression: filterConditions.length > 0 ? filterConditions.join(' AND ') : undefined,
      ScanIndexForward: false,
      Limit: options?.limit || 50,
      ExclusiveStartKey: exclusiveStartKey,
    });

    const response = await this.executeWithRetry(() => this.docClient.send(command));
    const items = (response.Items || []) as Detection[];
    const filterHash = computeFilterHash(options as any);
    const nextCursor = response.LastEvaluatedKey
      ? signCursor({
          orgId,
          filterHash,
          exclusiveStartKey: response.LastEvaluatedKey as Record<string, unknown>,
        })
      : undefined;

    return { items, nextCursor, total: items.length };
  }

  async getDetectionById(orgId: string, detectionId: string): Promise<Detection | null> {
    try {
      const result = await this.executeWithRetry(() =>
        this.docClient.send(
          new GetCommand({
            TableName: this.incidentsTable,
            Key: {
              PK: `ORG#${orgId}#DETECTIONID#${detectionId}`,
              SK: 'METADATA',
            },
          })
        )
      );

      if (!result.Item) {
        return null;
      }

      const { PK, SK, GSI1_PK, GSI1_SK, GSI2_PK, GSI2_SK, ...detection } = result.Item as Record<string, unknown>;
      return detection as unknown as Detection;
    } catch {
      return null;
    }
  }

  // --- Incidents Management ---

  async saveIncident(incident: Incident): Promise<void> {
    const orgId = incident.orgId;
    const pk = `ORG#${orgId}`;
    const sk = `INCIDENT#${incident.createdAt}#${incident.incidentId}`;
    const ttlEpoch = Math.floor(new Date(incident.createdAt).getTime() / 1000) + 90 * 86400;

    const item = {
      PK: pk,
      SK: sk,
      GSI1_PK: `ORG#${orgId}#STATUS#${incident.status}`,
      GSI1_SK: incident.riskScore,
      GSI2_PK: `ORG#${orgId}#SEVERITY#${incident.severity}`,
      GSI2_SK: incident.createdAt,
      incidentId: incident.incidentId,
      orgId: incident.orgId,
      title: incident.title,
      description: incident.description,
      severity: incident.severity,
      riskScore: incident.riskScore,
      riskFactors: incident.riskFactors,
      status: incident.status,
      assignedTo: incident.assignedTo,
      associatedEventIds: incident.associatedEventIds,
      timeline: incident.timeline,
      suggestedResponses: incident.suggestedResponses,
      notes: incident.notes,
      createdAt: incident.createdAt,
      updatedAt: incident.updatedAt,
      siteId: incident.siteId,
      domain: incident.domain,
      sourceIp: incident.sourceIp,
      attackTypes: incident.attackTypes,
      highestConfidence: incident.highestConfidence,
      webRiskFactors: incident.webRiskFactors,
      ttl: ttlEpoch,
    };

    await this.executeWithRetry(() =>
      this.docClient.send(
        new PutCommand({
          TableName: this.incidentsTable,
          Item: item,
        })
      )
    );

    try {
      await this.executeWithRetry(() =>
        this.docClient.send(
          new PutCommand({
            TableName: this.incidentsTable,
            Item: {
              ...item,
              PK: `ORG#${orgId}#INCIDENTID#${incident.incidentId}`,
              SK: 'METADATA',
            },
          })
        )
      );
    } catch {
      // Best-effort pointer write
    }
  }

  async getIncidents(
    orgId: string,
    options?: {
      status?: IncidentStatus;
      severity?: Severity;
      siteId?: string;
      limit?: number;
      cursor?: string;
    }
  ): Promise<{ items: Incident[]; nextCursor?: string }> {
    let indexName: string | undefined;
    let keyCondition = 'PK = :pk';
    const exprValues: Record<string, unknown> = { ':pk': `ORG#${orgId}` };
    const filterConditions: string[] = [];
    const exprNames: Record<string, string> = {};

    if (options?.siteId) {
      filterConditions.push('#sId = :sId');
      exprNames['#sId'] = 'siteId';
      exprValues[':sId'] = options.siteId;
    }

    if (options?.status) {
      indexName = 'GSI1-StatusRiskIndex';
      keyCondition = 'GSI1_PK = :gsi1pk';
      exprValues[':gsi1pk'] = `ORG#${orgId}#STATUS#${options.status}`;
      delete exprValues[':pk'];
    } else if (options?.severity) {
      indexName = 'GSI2-SeverityIndex';
      keyCondition = 'GSI2_PK = :gsi2pk';
      exprValues[':gsi2pk'] = `ORG#${orgId}#SEVERITY#${options.severity}`;
      delete exprValues[':pk'];
    }

    const exclusiveStartKey = options?.cursor
      ? JSON.parse(Buffer.from(options.cursor, 'base64').toString('utf8'))
      : undefined;

    const command = new QueryCommand({
      TableName: this.incidentsTable,
      IndexName: indexName,
      KeyConditionExpression: keyCondition,
      ExpressionAttributeValues: exprValues,
      ExpressionAttributeNames: Object.keys(exprNames).length > 0 ? exprNames : undefined,
      FilterExpression: filterConditions.length > 0 ? filterConditions.join(' AND ') : undefined,
      ScanIndexForward: false,
      Limit: options?.limit || 20,
      ExclusiveStartKey: exclusiveStartKey,
    });

    const response = await this.executeWithRetry(() => this.docClient.send(command));
    const items = (response.Items || []) as Incident[];
    const nextCursor = response.LastEvaluatedKey
      ? Buffer.from(JSON.stringify(response.LastEvaluatedKey)).toString('base64')
      : undefined;

    return { items, nextCursor };
  }

  async getIncidentById(orgId: string, incidentId: string): Promise<Incident | null> {
    try {
      const result = await this.executeWithRetry(() =>
        this.docClient.send(
          new GetCommand({
            TableName: this.incidentsTable,
            Key: {
              PK: `ORG#${orgId}#INCIDENTID#${incidentId}`,
              SK: 'METADATA',
            },
          })
        )
      );
      if (result.Item) {
        const { PK, SK, GSI1_PK, GSI1_SK, GSI2_PK, GSI2_SK, ...incident } = result.Item as Record<string, unknown>;
        return incident as unknown as Incident;
      }
    } catch {
      // Fallback to query
    }
    const response = await this.getIncidents(orgId, { limit: 100 });
    const match = response.items.find((i) => i.incidentId === incidentId);
    return match || null;
  }

  async updateIncident(
    orgId: string,
    incidentId: string,
    updates: Partial<Incident>
  ): Promise<Incident | null> {
    const existing = await this.getIncidentById(orgId, incidentId);
    if (!existing) return null;

    const updated: Incident = {
      ...existing,
      ...updates,
      updatedAt: new Date().toISOString(),
    };
    await this.saveIncident(updated);
    return updated;
  }

  // --- Detection Rules ---

  async saveRule(rule: DetectionRule): Promise<void> {
    const pk = `ORG#${rule.orgId}`;
    const sk = `RULE#${rule.ruleId}`;

    const item = {
      PK: pk,
      SK: sk,
      GSI1_PK: rule.category,
      GSI1_SK: rule.severity,
      ruleId: rule.ruleId,
      orgId: rule.orgId,
      name: rule.name,
      description: rule.description,
      category: rule.category,
      severity: rule.severity,
      mitreAttack: rule.mitreAttack,
      condition: rule.condition,
      slidingWindowSeconds: rule.slidingWindowSeconds,
      threshold: rule.threshold,
      isEnabled: rule.isEnabled,
      createdAt: rule.createdAt,
      updatedAt: rule.updatedAt,
    };

    await this.executeWithRetry(() =>
      this.docClient.send(
        new PutCommand({
          TableName: this.rulesTable,
          Item: item,
        })
      )
    );
  }

  async getRules(orgId: string): Promise<DetectionRule[]> {
    const command = new QueryCommand({
      TableName: this.rulesTable,
      KeyConditionExpression: 'PK = :pk AND begins_with(SK, :skPrefix)',
      ExpressionAttributeValues: {
        ':pk': `ORG#${orgId}`,
        ':skPrefix': 'RULE#',
      },
    });

    const response = await this.executeWithRetry(() => this.docClient.send(command));
    return (response.Items || []) as DetectionRule[];
  }

  async getRuleById(orgId: string, ruleId: string): Promise<DetectionRule | null> {
    const command = new GetCommand({
      TableName: this.rulesTable,
      Key: {
        PK: `ORG#${orgId}`,
        SK: `RULE#${ruleId}`,
      },
    });

    const response = await this.executeWithRetry(() => this.docClient.send(command));
    return (response.Item as DetectionRule) || null;
  }

  async updateRule(
    orgId: string,
    ruleId: string,
    updates: Partial<DetectionRule>
  ): Promise<DetectionRule | null> {
    const existing = await this.getRuleById(orgId, ruleId);
    if (!existing) return null;

    const updated: DetectionRule = {
      ...existing,
      ...updates,
      updatedAt: new Date().toISOString(),
    };
    await this.saveRule(updated);
    return updated;
  }

  // --- Detection Rules Aliases for StorageInterface ---
  async saveDetectionRule(rule: DetectionRule): Promise<void> {
    return this.saveRule(rule);
  }

  async getDetectionRules(orgId: string): Promise<DetectionRule[]> {
    return this.getRules(orgId);
  }

  async getDetectionRuleById(orgId: string, ruleId: string): Promise<DetectionRule | null> {
    return this.getRuleById(orgId, ruleId);
  }

  async updateDetectionRule(
    orgId: string,
    ruleId: string,
    updates: Partial<DetectionRule>
  ): Promise<DetectionRule | null> {
    return this.updateRule(orgId, ruleId, updates);
  }


  // --- Threat Indicators ---

  async saveIndicator(indicator: ThreatIndicator): Promise<void> {
    const orgScope = indicator.orgId || 'global';
    const item = {
      PK: `INDICATOR#${indicator.type}#${orgScope}`,
      SK: `VALUE#${indicator.value}`,
      GSI1_PK: `INDICATORID#${indicator.indicatorId}`,
      GSI1_SK: indicator.severity,
      ...indicator,
    };

    await this.executeWithRetry(() =>
      this.docClient.send(
        new PutCommand({
          TableName: this.indicatorsTable,
          Item: item,
        })
      )
    );
  }

  async getIndicatorById(indicatorId: string, orgId?: string): Promise<ThreatIndicator | null> {
    const command = new QueryCommand({
      TableName: this.indicatorsTable,
      IndexName: 'GSI1-SeverityIndex',
      KeyConditionExpression: 'GSI1_PK = :pk',
      ExpressionAttributeValues: {
        ':pk': `INDICATORID#${indicatorId}`,
      },
      Limit: 1,
    });
    const response = await this.executeWithRetry(() => this.docClient.send(command));
    const item = (response.Items?.[0] as ThreatIndicator) || null;
    if (item && orgId && item.orgId && item.orgId !== 'global' && item.orgId !== orgId) {
      return null;
    }
    return item;
  }

  async getIndicatorByValue(
    type: ThreatIndicator['type'],
    value: string,
    orgId?: string
  ): Promise<ThreatIndicator | null> {
    const orgScope = orgId || 'global';
    let command = new GetCommand({
      TableName: this.indicatorsTable,
      Key: {
        PK: `INDICATOR#${type}#${orgScope}`,
        SK: `VALUE#${value}`,
      },
    });

    let response = await this.executeWithRetry(() => this.docClient.send(command));
    if (response.Item) {
      return response.Item as ThreatIndicator;
    }

    if (orgScope !== 'global') {
      command = new GetCommand({
        TableName: this.indicatorsTable,
        Key: {
          PK: `INDICATOR#${type}#global`,
          SK: `VALUE#${value}`,
        },
      });
      response = await this.executeWithRetry(() => this.docClient.send(command));
      return (response.Item as ThreatIndicator) || null;
    }

    return null;
  }

  async listIndicators(orgId?: string, limit = 100): Promise<ThreatIndicator[]> {
    const orgScope = orgId || 'global';
    const command = new QueryCommand({
      TableName: this.indicatorsTable,
      KeyConditionExpression: 'PK = :pk',
      ExpressionAttributeValues: {
        ':pk': `INDICATOR#IP#${orgScope}`,
      },
      Limit: limit,
    });

    const response = await this.executeWithRetry(() => this.docClient.send(command));
    return (response.Items || []) as ThreatIndicator[];
  }

  async updateIndicator(
    indicatorId: string,
    updates: Partial<ThreatIndicator>,
    orgId?: string
  ): Promise<ThreatIndicator | null> {
    const existing = await this.getIndicatorById(indicatorId, orgId);
    if (!existing) return null;
    const updated = { ...existing, ...updates, indicatorId };
    await this.saveIndicator(updated);
    return updated;
  }

  async deleteIndicator(indicatorId: string, orgId?: string): Promise<boolean> {
    const existing = await this.getIndicatorById(indicatorId, orgId);
    if (!existing) return false;
    const orgScope = existing.orgId || 'global';
    await this.executeWithRetry(() =>
      this.docClient.send(
        new DeleteCommand({
          TableName: this.indicatorsTable,
          Key: {
            PK: `INDICATOR#${existing.type}#${orgScope}`,
            SK: `VALUE#${existing.value}`,
          },
        })
      )
    );
    return true;
  }

  // --- Defensive Response Executions ---

  async saveExecution(execution: ResponseExecution): Promise<void> {
    const pk = `ORG#${execution.orgId}`;
    const sk = `RESP#${execution.executedAt || new Date().toISOString()}#${execution.executionId}`;
    const ttlEpoch = Math.floor(Date.now() / 1000) + 60 * 86400;

    const item = {
      PK: pk,
      SK: sk,
      GSI1_PK: `INCIDENT#${execution.incidentId}`,
      GSI1_SK: execution.executedAt || new Date().toISOString(),
      ...execution,
      ttl: ttlEpoch,
    };

    await this.executeWithRetry(() =>
      this.docClient.send(
        new PutCommand({
          TableName: this.responsesTable,
          Item: item,
        })
      )
    );
  }

  async getExecutionById(orgId: string, executionId: string): Promise<ResponseExecution | null> {
    const executions = await this.listExecutions(orgId);
    return executions.find((e) => e.executionId === executionId) || null;
  }

  async listExecutions(orgId: string, incidentId?: string): Promise<ResponseExecution[]> {
    let indexName: string | undefined;
    let keyCondition = 'PK = :pk AND begins_with(SK, :skPrefix)';
    const exprValues: Record<string, unknown> = {
      ':pk': `ORG#${orgId}`,
      ':skPrefix': 'RESP#',
    };

    if (incidentId) {
      indexName = 'GSI1-IncidentResponseIndex';
      keyCondition = 'GSI1_PK = :gsi1pk';
      exprValues[':gsi1pk'] = `INCIDENT#${incidentId}`;
      delete exprValues[':pk'];
      delete exprValues[':skPrefix'];
    }

    const command = new QueryCommand({
      TableName: this.responsesTable,
      IndexName: indexName,
      KeyConditionExpression: keyCondition,
      ExpressionAttributeValues: exprValues,
      ScanIndexForward: false,
    });

    const response = await this.executeWithRetry(() => this.docClient.send(command));
    return (response.Items || []) as ResponseExecution[];
  }

  async updateExecution(
    orgId: string,
    executionId: string,
    updates: Partial<ResponseExecution>
  ): Promise<ResponseExecution | null> {
    const existing = await this.getExecutionById(orgId, executionId);
    if (!existing) return null;

    const updated: ResponseExecution = {
      ...existing,
      ...updates,
    };
    await this.saveExecution(updated);
    return updated;
  }

  // --- Cryptographic Audit Ledger (Two-Table Atomic TransactWriteItems) ---

  async appendAuditLog(
    logData: Omit<AuditLog, 'prevHash' | 'currentHash'>,
    maxRetries = 5
  ): Promise<AuditLog> {
    const orgId = logData.orgId;
    let attempt = 0;

    while (true) {
      attempt++;
      const currentState = await this.getAuditState(orgId);
      const prevHash = currentState ? currentState.lastVerifiedHash : DynamoDBStore.GENESIS_HASH;
      const currentHash = this.computeAuditHash(prevHash, logData);

      const fullLog: AuditLog = {
        ...logData,
        prevHash,
        currentHash,
      };

      const pk = `ORG#${orgId}`;
      const sk = `AUDIT#${logData.timestamp}#${logData.logId}`;

      const transactItems = [
        {
          Put: {
            TableName: this.auditTable,
            Item: {
              PK: pk,
              SK: sk,
              GSI1_PK: `ORG#${orgId}#ACTOR#${logData.actor.userId}`,
              GSI1_SK: logData.timestamp,
              ...fullLog,
            },
            ConditionExpression: 'attribute_not_exists(PK) AND attribute_not_exists(SK)',
          },
        },
        {
          Update: {
            TableName: this.auditStateTable,
            Key: {
              PK: `ORG#${orgId}`,
              SK: 'STATE',
            },
            UpdateExpression: 'SET lastVerifiedHash = :curr, updatedAt = :now',
            ConditionExpression: currentState
              ? 'lastVerifiedHash = :prev'
              : 'attribute_not_exists(PK) OR lastVerifiedHash = :prev',
            ExpressionAttributeValues: {
              ':curr': currentHash,
              ':prev': prevHash,
              ':now': new Date().toISOString(),
            },
          },
        },
      ];

      try {
        await this.docClient.send(new TransactWriteCommand({ TransactItems: transactItems }));
        return fullLog;
      } catch (err: unknown) {
        const errName = (err as { name?: string })?.name || '';
        const isConflict =
          errName === 'TransactionCanceledException' ||
          errName === 'TransactionConflictException';

        if (isConflict && attempt < maxRetries) {
          // Jittered backoff before re-reading state and re-hashing
          const delayMs = Math.pow(2, attempt) * 40 + Math.random() * 30;
          await new Promise((r) => setTimeout(r, delayMs));
          continue;
        }

        throw err;
      }
    }
  }

  async getAuditLogs(orgId: string, limit = 100): Promise<AuditLog[]> {
    const command = new QueryCommand({
      TableName: this.auditTable,
      KeyConditionExpression: 'PK = :pk AND begins_with(SK, :skPrefix)',
      ExpressionAttributeValues: {
        ':pk': `ORG#${orgId}`,
        ':skPrefix': 'AUDIT#',
      },
      ScanIndexForward: false,
      Limit: limit,
    });

    const response = await this.executeWithRetry(() => this.docClient.send(command));
    const items = (response.Items || []) as AuditLog[];
    return items.reverse(); // Return in chronological order
  }

  async getAuditState(orgId: string): Promise<AuditState | null> {
    const command = new GetCommand({
      TableName: this.auditStateTable,
      Key: {
        PK: `ORG#${orgId}`,
        SK: 'STATE',
      },
    });

    const response = await this.executeWithRetry(() => this.docClient.send(command));
    return (response.Item as AuditState) || null;
  }

  async verifyAuditChain(
    orgId: string
  ): Promise<{ verified: boolean; length: number; brokenRecordId?: string }> {
    const logs = await this.getAuditLogs(orgId, 500);
    if (logs.length === 0) {
      return { verified: true, length: 0 };
    }

    let expectedPrevHash = DynamoDBStore.GENESIS_HASH;

    for (const log of logs) {
      if (log.prevHash !== expectedPrevHash) {
        return { verified: false, length: logs.length, brokenRecordId: log.logId };
      }

      const recomputedHash = this.computeAuditHash(expectedPrevHash, log);
      if (recomputedHash !== log.currentHash) {
        return { verified: false, length: logs.length, brokenRecordId: log.logId };
      }

      expectedPrevHash = log.currentHash;
    }

    return { verified: true, length: logs.length };
  }

  private computeAuditHash(
    prevHash: string,
    data: Omit<AuditLog, 'prevHash' | 'currentHash'>
  ): string {
    const payload = `${prevHash}|${data.logId}|${data.orgId}|${data.timestamp}|${data.action}|${data.actor.userId}|${this.canonicalStringify(data.details)}`;
    return createHash('sha256').update(payload, 'utf8').digest('hex');
  }

  private canonicalStringify(obj: unknown): string {
    if (obj === null || typeof obj !== 'object') {
      return JSON.stringify(obj);
    }
    if (Array.isArray(obj)) {
      return '[' + obj.map((item) => this.canonicalStringify(item)).join(',') + ']';
    }
    const record = obj as Record<string, unknown>;
    const sortedKeys = Object.keys(record).sort();
    const parts = sortedKeys.map(
      (key) => `${JSON.stringify(key)}:${this.canonicalStringify(record[key])}`
    );
    return '{' + parts.join(',') + '}';
  }

  // --- Website Asset Inventory (TASK-601, TASK-602) ---

  async saveWebsite(site: WebsiteAsset): Promise<WebsiteAsset> {
    const normalizedDomain = site.primaryDomain.toLowerCase().trim();

    // Strongly consistent atomic domain ownership registry lock using TransactWriteItems
    const transactItems = [
      // 1. Primary website asset item
      {
        Put: {
          TableName: this.websitesTable,
          Item: {
            PK: `ORG#${site.orgId}`,
            SK: `SITE#${site.siteId}`,
            GSI1_PK: `ORG#${site.orgId}#STATUS#${site.status}`,
            GSI1_SK: normalizedDomain,
            GSI2_PK: `DOMAIN#${normalizedDomain}`,
            GSI2_SK: `ORG#${site.orgId}`,
            ...site,
            primaryDomain: normalizedDomain,
          },
        },
      },
      // 2. Strongly consistent atomic domain ownership lock item
      {
        Put: {
          TableName: this.websitesTable,
          Item: {
            PK: `DOMAIN#${normalizedDomain}`,
            SK: 'OWNERSHIP',
            orgId: site.orgId,
            siteId: site.siteId,
            claimedAt: site.createdAt,
          },
          ConditionExpression: 'attribute_not_exists(PK) OR orgId = :orgId',
          ExpressionAttributeValues: {
            ':orgId': site.orgId,
          },
        },
      },
    ];

    try {
      await this.executeWithRetry(() =>
        this.docClient.send(
          new TransactWriteCommand({
            TransactItems: transactItems,
          })
        )
      );
      return { ...site, primaryDomain: normalizedDomain };
    } catch (err: unknown) {
      const errName = (err as { name?: string })?.name;
      if (
        errName === 'ConditionalCheckFailedException' ||
        errName === 'TransactionCanceledException'
      ) {
        const conflictErr = new Error(`DOMAIN_ALREADY_CLAIMED: Domain '${normalizedDomain}' is already claimed by another organization.`);
        (conflictErr as any).name = 'ConditionalCheckFailedException';
        throw conflictErr;
      }
      throw err;
    }
  }

  async getWebsites(
    orgId: string,
    options?: { status?: string; limit?: number; cursor?: string }
  ): Promise<{ items: WebsiteAsset[]; nextCursor?: string; total?: number }> {
    const limit = options?.limit || 50;
    const isStatusFiltered = !!options?.status;

    let exclusiveStartKey: Record<string, unknown> | undefined = undefined;
    if (options?.cursor) {
      try {
        exclusiveStartKey = JSON.parse(Buffer.from(options.cursor, 'base64').toString('utf8'));
      } catch {
        // ignore invalid cursor
      }
    }

    let command: QueryCommand;
    if (isStatusFiltered) {
      command = new QueryCommand({
        TableName: this.websitesTable,
        IndexName: 'GSI1-StatusDomain',
        KeyConditionExpression: 'GSI1_PK = :pk',
        ExpressionAttributeValues: {
          ':pk': `ORG#${orgId}#STATUS#${options.status}`,
        },
        Limit: limit,
        ExclusiveStartKey: exclusiveStartKey,
      });
    } else {
      command = new QueryCommand({
        TableName: this.websitesTable,
        KeyConditionExpression: 'PK = :pk AND begins_with(SK, :skPrefix)',
        ExpressionAttributeValues: {
          ':pk': `ORG#${orgId}`,
          ':skPrefix': 'SITE#',
        },
        Limit: limit,
        ExclusiveStartKey: exclusiveStartKey,
      });
    }

    const response = await this.executeWithRetry(() => this.docClient.send(command));
    const items = (response.Items || []).map((raw) => {
      const { PK, SK, GSI1_PK, GSI1_SK, GSI2_PK, GSI2_SK, ...site } = raw;
      return site as WebsiteAsset;
    });

    let nextCursor: string | undefined = undefined;
    if (response.LastEvaluatedKey) {
      nextCursor = Buffer.from(JSON.stringify(response.LastEvaluatedKey)).toString('base64');
    }

    return {
      items,
      total: response.Count || items.length,
      nextCursor,
    };
  }

  async getWebsiteById(orgId: string, siteId: string): Promise<WebsiteAsset | null> {
    const response = await this.executeWithRetry(() =>
      this.docClient.send(
        new GetCommand({
          TableName: this.websitesTable,
          Key: {
            PK: `ORG#${orgId}`,
            SK: `SITE#${siteId}`,
          },
        })
      )
    );

    if (!response.Item) return null;
    const { PK, SK, GSI1_PK, GSI1_SK, GSI2_PK, GSI2_SK, ...site } = response.Item;
    return site as WebsiteAsset;
  }

  async getWebsiteByDomain(domain: string): Promise<WebsiteAsset | null> {
    const normalizedDomain = domain.toLowerCase().trim();
    const command = new QueryCommand({
      TableName: this.websitesTable,
      IndexName: 'GSI2-DomainLookup',
      KeyConditionExpression: 'GSI2_PK = :pk',
      ExpressionAttributeValues: {
        ':pk': `DOMAIN#${normalizedDomain}`,
      },
      Limit: 1,
    });

    const response = await this.executeWithRetry(() => this.docClient.send(command));
    if (!response.Items || response.Items.length === 0 || !response.Items[0]) return null;
    const raw = response.Items[0];
    const { PK, SK, GSI1_PK, GSI1_SK, GSI2_PK, GSI2_SK, ...site } = raw;
    return site as WebsiteAsset;
  }

  async updateWebsite(
    orgId: string,
    siteId: string,
    updates: Partial<WebsiteAsset>
  ): Promise<WebsiteAsset | null> {
    const existing = await this.getWebsiteById(orgId, siteId);
    if (!existing) return null;

    const merged: WebsiteAsset = {
      ...existing,
      ...updates,
      siteId: existing.siteId,
      orgId: existing.orgId,
      updatedAt: new Date().toISOString(),
    };

    return this.saveWebsite(merged);
  }

  async deleteWebsite(orgId: string, siteId: string): Promise<boolean> {
    const site = await this.getWebsiteById(orgId, siteId);
    if (!site) return false;

    const normalizedDomain = site.primaryDomain.toLowerCase().trim();
    await this.executeWithRetry(() =>
      this.docClient.send(
        new TransactWriteCommand({
          TransactItems: [
            {
              Delete: {
                TableName: this.websitesTable,
                Key: {
                  PK: `ORG#${orgId}`,
                  SK: `SITE#${siteId}`,
                },
              },
            },
            {
              Delete: {
                TableName: this.websitesTable,
                Key: {
                  PK: `DOMAIN#${normalizedDomain}`,
                  SK: 'OWNERSHIP',
                },
                ConditionExpression: 'orgId = :orgId',
                ExpressionAttributeValues: {
                  ':orgId': orgId,
                },
              },
            },
          ],
        })
      )
    );
    return true;
  }

  // --- Integration Management (TASK-603, TASK-606) ---

  async saveIntegration(integration: Integration): Promise<Integration> {
    const item = {
      PK: `ORG#${integration.orgId}`,
      SK: `INT#${integration.integrationId}`,
      GSI1_PK: `APIKEY#${integration.apiKeyHash}`,
      GSI1_SK: `ORG#${integration.orgId}`,
      ...integration,
    };

    await this.executeWithRetry(() =>
      this.docClient.send(
        new PutCommand({
          TableName: this.integrationsTable,
          Item: item,
        })
      )
    );

    return { ...integration };
  }

  async getIntegrations(orgId: string, siteId?: string): Promise<Integration[]> {
    const command = new QueryCommand({
      TableName: this.integrationsTable,
      KeyConditionExpression: 'PK = :pk AND begins_with(SK, :skPrefix)',
      ExpressionAttributeValues: {
        ':pk': `ORG#${orgId}`,
        ':skPrefix': 'INT#',
      },
    });

    const response = await this.executeWithRetry(() => this.docClient.send(command));
    let items = (response.Items || []).map((raw) => {
      const { PK, SK, GSI1_PK, GSI1_SK, ...i } = raw;
      return i as Integration;
    });

    if (siteId) {
      items = items.filter((i) => i.siteId === siteId);
    }
    items.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
    return items;
  }

  async getIntegrationById(orgId: string, integrationId: string): Promise<Integration | null> {
    const response = await this.executeWithRetry(() =>
      this.docClient.send(
        new GetCommand({
          TableName: this.integrationsTable,
          Key: {
            PK: `ORG#${orgId}`,
            SK: `INT#${integrationId}`,
          },
        })
      )
    );

    if (!response.Item) return null;
    const { PK, SK, GSI1_PK, GSI1_SK, ...item } = response.Item;
    return item as Integration;
  }

  async getIntegrationByApiKeyHash(apiKeyHash: string): Promise<Integration | null> {
    const command = new QueryCommand({
      TableName: this.integrationsTable,
      IndexName: 'GSI1-ApiKeyLookup',
      KeyConditionExpression: 'GSI1_PK = :pk',
      ExpressionAttributeValues: {
        ':pk': `APIKEY#${apiKeyHash}`,
      },
      Limit: 1,
    });

    const response = await this.executeWithRetry(() => this.docClient.send(command));
    if (!response.Items || response.Items.length === 0 || !response.Items[0]) return null;
    const raw = response.Items[0];
    const { PK, SK, GSI1_PK, GSI1_SK, ...item } = raw;
    return item as Integration;
  }

  async updateIntegration(
    orgId: string,
    integrationId: string,
    updates: Partial<Integration>
  ): Promise<Integration | null> {
    const existing = await this.getIntegrationById(orgId, integrationId);
    if (!existing) return null;

    const merged: Integration = {
      ...existing,
      ...updates,
      integrationId: existing.integrationId,
      orgId: existing.orgId,
      updatedAt: new Date().toISOString(),
    };

    return this.saveIntegration(merged);
  }

  async deleteIntegration(orgId: string, integrationId: string): Promise<boolean> {
    await this.executeWithRetry(() =>
      this.docClient.send(
        new DeleteCommand({
          TableName: this.integrationsTable,
          Key: {
            PK: `ORG#${orgId}`,
            SK: `INT#${integrationId}`,
          },
        })
      )
    );
    return true;
  }

}
