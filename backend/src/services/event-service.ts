import { z } from 'zod';
import type {
  SecurityEvent,
  IngestionItemResult,
  IngestionResponseData,
  InternalTrustedEvidenceContext,
} from '@veltrix/shared';
import { getDefaultInternalEvidenceAuthority } from '../detection/evidence-authority.js';
import {
  SingleEventIngestSchema,
  EventQueryRequestSchema,
} from '@veltrix/shared';
import type { StorageInterface, EventQueryOptions } from '../storage/storage-interface.js';
import { getStorage } from '../storage/index.js';
import { generateUuidV7, isValidUuid } from '../utils/uuid.js';
import { computePayloadHash } from '../utils/idempotency.js';
import { type DetectionPipeline, getDetectionPipeline } from '../detection/pipeline.js';

export interface SingleIngestionResult {
  status: 'ACCEPTED' | 'DUPLICATE_SUPPRESSED';
  eventId: string;
  event?: SecurityEvent;
}

export class EventService {
  private storage: StorageInterface;
  private detectionPipeline: DetectionPipeline;

  constructor(storage?: StorageInterface, detectionPipeline?: DetectionPipeline) {
    this.storage = storage || getStorage();
    this.detectionPipeline = detectionPipeline || getDetectionPipeline();
  }

  /**
   * Ingests a single security event with Zod validation, UUIDv7 generation,
   * UTC timestamp canonicalization, and idempotency deduplication.
   */
  async ingestSingleEvent(
    rawPayload: unknown,
    tenantOrgId: string,
    isSuperAdmin: boolean = false,
    headerIdempotencyKey?: string,
    internalTrustedContext?: InternalTrustedEvidenceContext
  ): Promise<SingleIngestionResult> {
    // 1. Zod schema validation
    const parseResult = SingleEventIngestSchema.safeParse(rawPayload);
    if (!parseResult.success) {
      const errorDetails = parseResult.error.errors.map((e) => ({
        field: e.path.join('.'),
        message: e.message,
      }));
      const err = new Error('VALIDATION_FAILED');
      (err as unknown as { details: typeof errorDetails }).details = errorDetails;
      throw err;
    }

    const data = parseResult.data;

    // 2. Tenant isolation check: reject conflicting orgId
    if (data.orgId && data.orgId !== tenantOrgId && !isSuperAdmin) {
      const err = new Error('FORBIDDEN_CROSS_TENANT_ACCESS');
      (err as unknown as { code: string }).code = 'FORBIDDEN_CROSS_TENANT_ACCESS';
      throw err;
    }

    // 3. Normalization
    const normalizedEvent = this.normalizeEvent(data, tenantOrgId, headerIdempotencyKey);
    const payloadHash = computePayloadHash(rawPayload);

    // If an authorized internal caller passed a trusted context, cryptographically verify and attach it
    if (internalTrustedContext) {
      const authority = getDefaultInternalEvidenceAuthority();
      const meta = (normalizedEvent.metadata || {}) as Record<string, unknown>;
      const siteId = typeof meta.siteId === 'string' ? meta.siteId : '';

      const isValid = authority.verifyContext(internalTrustedContext, {
        eventId: normalizedEvent.eventId,
        orgId: tenantOrgId,
        siteId,
      });

      if (isValid) {
        normalizedEvent.trustedEvidenceContext = internalTrustedContext;
      } else {
        console.warn(
          `[VELTRIX-SECURITY] Rejected invalid or unverified internalTrustedContext during event ingestion for event ${normalizedEvent.eventId}`
        );
      }
    }

    // 4. Persistence with atomic conditional deduplication & payload consistency check
    const persistResult = await this.storage.saveEvent(normalizedEvent, payloadHash);

    if (persistResult.isDuplicate) {
      return {
        status: 'DUPLICATE_SUPPRESSED',
        eventId: persistResult.eventId || normalizedEvent.eventId,
      };
    }

    // Automatically dispatch to asynchronous detection pipeline without blocking HTTP write path
    try {
      this.detectionPipeline.dispatch(normalizedEvent);
    } catch (pipelineErr) {
      console.warn('[VELTRIX] Failed to dispatch event to detection pipeline:', pipelineErr);
    }

    return {
      status: 'ACCEPTED',
      eventId: persistResult.eventId || normalizedEvent.eventId,
      event: normalizedEvent,
    };
  }

  /**
   * Internal-only ingestion method for server-side verifiers with pre-constructed SecurityEvent.
   * Never exposed to external HTTP routes.
   */
  async ingestInternalEvent(
    event: SecurityEvent
  ): Promise<SingleIngestionResult> {
    const payloadHash = computePayloadHash(event);
    const persistResult = await this.storage.saveEvent(event, payloadHash);

    if (persistResult.isDuplicate) {
      return {
        status: 'DUPLICATE_SUPPRESSED',
        eventId: persistResult.eventId || event.eventId,
      };
    }

    try {
      this.detectionPipeline.dispatch(event);
    } catch (pipelineErr) {
      console.warn('[VELTRIX] Failed to dispatch internal event to detection pipeline:', pipelineErr);
    }

    return {
      status: 'ACCEPTED',
      eventId: persistResult.eventId || event.eventId,
      event,
    };
  }

  /**
   * Ingests a batch of up to 100 security events with per-item validation,
   * atomic deduplication, and detailed ingestion reporting.
   */
  async ingestBatchEvents(
    rawEvents: unknown[],
    tenantOrgId: string,
    isSuperAdmin: boolean = false
  ): Promise<IngestionResponseData> {
    if (!Array.isArray(rawEvents)) {
      throw new Error('INVALID_BATCH_STRUCTURE: Expected an array of events');
    }

    if (rawEvents.length === 0) {
      throw new Error('EMPTY_BATCH: Batch must contain at least 1 event');
    }

    if (rawEvents.length > 100) {
      throw new Error('BATCH_SIZE_EXCEEDED: Maximum batch size is 100 events');
    }

    // Strict Cross-Tenant check across entire batch: reject immediately if any event has foreign orgId
    for (const raw of rawEvents) {
      if (raw && typeof raw === 'object' && 'orgId' in raw) {
        const itemOrgId = (raw as Record<string, unknown>).orgId;
        if (typeof itemOrgId === 'string' && itemOrgId !== tenantOrgId && !isSuperAdmin) {
          const err = new Error('FORBIDDEN_CROSS_TENANT_ACCESS');
          (err as unknown as { code: string }).code = 'FORBIDDEN_CROSS_TENANT_ACCESS';
          throw err;
        }
      }
    }

    const results: IngestionItemResult[] = [];
    const acceptedEvents: SecurityEvent[] = [];
    let accepted = 0;
    let duplicates = 0;
    let rejected = 0;

    for (let i = 0; i < rawEvents.length; i++) {
      const itemRaw = rawEvents[i];

      // Validate single item schema
      const parseResult = SingleEventIngestSchema.safeParse(itemRaw);
      if (!parseResult.success) {
        rejected++;
        const itemEventId =
          itemRaw && typeof itemRaw === 'object' && 'eventId' in itemRaw && typeof (itemRaw as Record<string, unknown>).eventId === 'string'
            ? ((itemRaw as Record<string, unknown>).eventId as string)
            : `item-index-${i}`;

        results.push({
          eventId: itemEventId,
          status: 'REJECTED',
          message: 'Item failed schema validation',
          errors: parseResult.error.errors.map((e) => ({
            field: e.path.join('.'),
            message: e.message,
          })),
        });
        continue;
      }

      const validData = parseResult.data;
      const normalized = this.normalizeEvent(validData, tenantOrgId);

      try {
        const itemPayloadHash = computePayloadHash(itemRaw);
        const persistResult = await this.storage.saveEvent(normalized, itemPayloadHash);
        if (persistResult.isDuplicate) {
          duplicates++;
          results.push({
            eventId: normalized.eventId,
            status: 'DUPLICATE_SUPPRESSED',
            message: 'Duplicate event suppressed via idempotency check',
          });
        } else {
          accepted++;
          acceptedEvents.push(normalized);
          results.push({
            eventId: normalized.eventId,
            status: 'ACCEPTED',
          });
        }
      } catch (err: unknown) {
        rejected++;
        results.push({
          eventId: normalized.eventId,
          status: 'FAILED',
          message: err instanceof Error ? err.message : 'Database storage failure',
        });
      }
    }

    // Automatically dispatch accepted batch events to detection pipeline
    if (acceptedEvents.length > 0) {
      try {
        this.detectionPipeline.dispatchBatch(acceptedEvents);
      } catch (pipelineErr) {
        console.warn('[VELTRIX] Failed to dispatch batch events to detection pipeline:', pipelineErr);
      }
    }

    return {
      total: rawEvents.length,
      accepted,
      duplicates,
      rejected,
      results,
    };
  }

  /**
   * Queries events with filtering and cursor pagination for an authorized tenant.
   */
  async queryEvents(
    rawQuery: unknown,
    tenantOrgId: string
  ): Promise<{ events: SecurityEvent[]; total?: number; nextCursor?: string }> {
    // 1. Validate query parameters
    const parseResult = EventQueryRequestSchema.safeParse(rawQuery);
    if (!parseResult.success) {
      const errorDetails = parseResult.error.errors.map((e) => ({
        field: e.path.join('.'),
        message: e.message,
      }));
      const err = new Error('INVALID_QUERY_PARAMETERS');
      (err as unknown as { details: typeof errorDetails }).details = errorDetails;
      throw err;
    }

    const query = parseResult.data;

    // 2. Map query options to storage interface
    const storageOptions: EventQueryOptions = {
      limit: query.limit,
      cursor: query.cursor,
      startTime: query.startTime,
      endTime: query.endTime,
      eventType: query.eventType,
      severity: query.severity,
      sourceIp: query.sourceIp,
      username: query.username,
      sourceSystem: query.sourceSystem,
    };

    // 3. Execute query with tenant isolation
    const queryResult = await this.storage.getEvents(tenantOrgId, storageOptions);

    return {
      events: queryResult.items,
      total: queryResult.total ?? queryResult.items.length,
      nextCursor: queryResult.nextCursor,
    };
  }

  /**
   * Retrieves a single event by ID for an authorized tenant.
   */
  async getEventById(orgId: string, eventId: string): Promise<SecurityEvent | null> {
    if (!isValidUuid(eventId)) {
      throw new Error('INVALID_EVENT_ID: Must be a valid UUID');
    }
    return this.storage.getEventById(orgId, eventId);
  }

  /**
   * Normalizes an incoming event into a canonical SecurityEvent:
   * - Assigns RFC 9562 UUIDv7 if eventId is missing
   * - Canonicalizes timestamp to ISO 8601 UTC
   * - Sets server-side receipt timestamp (ingestedAt)
   * - Establishes default idempotencyKey if omitted
   * - Sanitizes orgId to tenantOrgId
   */
  private normalizeEvent(
    data: z.infer<typeof SingleEventIngestSchema>,
    tenantOrgId: string,
    headerIdempotencyKey?: string
  ): SecurityEvent {
    const nowIso = new Date().toISOString();
    const eventTimestamp = data.timestamp
      ? new Date(data.timestamp).toISOString()
      : nowIso;

    const eventId = data.eventId && isValidUuid(data.eventId)
      ? data.eventId
      : generateUuidV7(new Date(eventTimestamp).getTime());

    const idempotencyKey = data.idempotencyKey || headerIdempotencyKey || eventId;

    // Security: Client-supplied fields cannot independently declare an IP trusted, VPN, proxy, or malicious.
    let sanitizedMetadata: Record<string, unknown> | undefined;
    if (data.metadata && typeof data.metadata === 'object') {
      sanitizedMetadata = {};
      const securityOverrideKeys = [
        'isVpn',
        'isProxy',
        'isTorExitNode',
        'threatIntelMatch',
        'isMalicious',
        'isTrusted',
        'trustedEnrichment',
        'serverVerified',
        'trustedProvenance',
        'evidenceProvenance',
        '_provenance',
        'verifiedSignals',
      ];
      for (const [key, val] of Object.entries(data.metadata)) {
        if (securityOverrideKeys.includes(key)) {
          sanitizedMetadata['client_declared_' + key] = val;
        } else {
          sanitizedMetadata[key] = val;
        }
      }
      sanitizedMetadata.evidenceProvenance = 'UNTRUSTED_CLIENT';
      sanitizedMetadata.serverVerified = false;
    }

    return {
      eventId,
      orgId: tenantOrgId,
      timestamp: eventTimestamp,
      eventType: data.eventType,
      severity: data.severity,
      category: data.category,
      sourceIp: data.sourceIp,
      username: data.username,
      sourceSystem: data.sourceSystem,
      metadata: sanitizedMetadata,
      isSimulated: data.isSimulated ?? false,
      idempotencyKey,
      ingestedAt: nowIso,
    };
  }
}
