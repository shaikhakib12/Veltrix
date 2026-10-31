import {
  DynamoDBClient,
} from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  PutCommand,
  GetCommand,
  QueryCommand,
  TransactWriteCommand,
} from '@aws-sdk/lib-dynamodb';
import { createHash } from 'node:crypto';
import type {
  SecurityEvent,
  Incident,
  IncidentStatus,
  Severity,
  DetectionRule,
  ThreatIndicator,
  ResponseExecution,
  AuditLog,
  AuditState,
} from '@veltrix/shared';
import type { StorageInterface } from './storage-interface.js';

export class DynamoDBStore implements StorageInterface {
  private docClient: DynamoDBDocumentClient;
  private readonly eventsTable: string;
  private readonly incidentsTable: string;
  private readonly rulesTable: string;
  private readonly indicatorsTable: string;
  private readonly responsesTable: string;
  private readonly auditTable: string;
  private readonly auditStateTable: string;

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
    event: SecurityEvent
  ): Promise<{ saved: boolean; isDuplicate: boolean }> {
    const orgId = event.orgId;
    const dateStr = event.timestamp.slice(0, 10); // YYYY-MM-DD
    const pk = `ORG#${orgId}#DATE#${dateStr}`;
    const sk = `EVENT#${event.timestamp}#${event.eventId}`;

    const ttlEpoch = Math.floor(new Date(event.timestamp).getTime() / 1000) + 30 * 86400;

    const item = {
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
      idempotencyKey: event.idempotencyKey || event.eventId,
      ttl: ttlEpoch,
    };

    try {
      await this.executeWithRetry(() =>
        this.docClient.send(
          new PutCommand({
            TableName: this.eventsTable,
            Item: item,
            ConditionExpression: 'attribute_not_exists(PK) AND attribute_not_exists(SK)',
          })
        )
      );
      return { saved: true, isDuplicate: false };
    } catch (err: unknown) {
      if ((err as { name?: string })?.name === 'ConditionalCheckFailedException') {
        // Atomic duplicate caught; suppress downstream processing
        return { saved: false, isDuplicate: true };
      }
      throw err;
    }
  }

  async getEvents(
    orgId: string,
    options?: {
      limit?: number;
      cursor?: string;
      eventType?: string;
      sourceIp?: string;
    }
  ): Promise<{ items: SecurityEvent[]; nextCursor?: string }> {
    const today = new Date().toISOString().slice(0, 10);
    const pk = `ORG#${orgId}#DATE#${today}`;

    let indexName: string | undefined;
    let keyCondition = 'PK = :pk';
    const exprValues: Record<string, unknown> = { ':pk': pk };

    if (options?.eventType) {
      indexName = 'GSI1-EventTypeIndex';
      keyCondition = 'GSI1_PK = :gsi1pk';
      exprValues[':gsi1pk'] = `ORG#${orgId}#TYPE#${options.eventType}`;
      delete exprValues[':pk'];
    } else if (options?.sourceIp) {
      indexName = 'GSI2-SourceIpIndex';
      keyCondition = 'GSI2_PK = :gsi2pk';
      exprValues[':gsi2pk'] = `ORG#${orgId}#IP#${options.sourceIp}`;
      delete exprValues[':pk'];
    }

    const exclusiveStartKey = options?.cursor
      ? JSON.parse(Buffer.from(options.cursor, 'base64').toString('utf8'))
      : undefined;

    const command = new QueryCommand({
      TableName: this.eventsTable,
      IndexName: indexName,
      KeyConditionExpression: keyCondition,
      ExpressionAttributeValues: exprValues,
      ScanIndexForward: false, // Descending chronological
      Limit: options?.limit || 50,
      ExclusiveStartKey: exclusiveStartKey,
    });

    const response = await this.executeWithRetry(() => this.docClient.send(command));
    const items = (response.Items || []) as SecurityEvent[];
    const nextCursor = response.LastEvaluatedKey
      ? Buffer.from(JSON.stringify(response.LastEvaluatedKey)).toString('base64')
      : undefined;

    return { items, nextCursor };
  }

  async getEventById(_orgId: string, _eventId: string): Promise<SecurityEvent | null> {
    // In DynamoDB, full event fetch by ID without date is typically served via GSI or scan
    // Left as extensible stub for Phase 4 ingestion queries
    return null;
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
  }

  async getIncidents(
    orgId: string,
    options?: {
      status?: IncidentStatus;
      severity?: Severity;
      limit?: number;
      cursor?: string;
    }
  ): Promise<{ items: Incident[]; nextCursor?: string }> {
    let indexName: string | undefined;
    let keyCondition = 'PK = :pk';
    const exprValues: Record<string, unknown> = { ':pk': `ORG#${orgId}` };

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

  // --- Threat Indicators ---

  async saveIndicator(indicator: ThreatIndicator): Promise<void> {
    const item = {
      PK: `INDICATOR#${indicator.type}`,
      SK: `VALUE#${indicator.value}`,
      GSI1_PK: indicator.severity,
      GSI1_SK: indicator.confidence,
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

  async getIndicatorByValue(
    type: ThreatIndicator['type'],
    value: string
  ): Promise<ThreatIndicator | null> {
    const command = new GetCommand({
      TableName: this.indicatorsTable,
      Key: {
        PK: `INDICATOR#${type}`,
        SK: `VALUE#${value}`,
      },
    });

    const response = await this.executeWithRetry(() => this.docClient.send(command));
    return (response.Item as ThreatIndicator) || null;
  }

  async listIndicators(limit = 100): Promise<ThreatIndicator[]> {
    const command = new QueryCommand({
      TableName: this.indicatorsTable,
      KeyConditionExpression: 'PK = :pk',
      ExpressionAttributeValues: {
        ':pk': 'INDICATOR#IP',
      },
      Limit: limit,
    });

    const response = await this.executeWithRetry(() => this.docClient.send(command));
    return (response.Items || []) as ThreatIndicator[];
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
}
