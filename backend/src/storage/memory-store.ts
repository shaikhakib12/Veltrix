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
import type { StorageInterface, EventQueryOptions } from './storage-interface.js';
import { signCursor, verifyCursor, computeFilterHash } from '../utils/cursor.js';

export class MemoryStore implements StorageInterface {
  // Primary stores partitioned by orgId where applicable
  private eventsByOrg: Map<string, SecurityEvent[]> = new Map();
  private eventDeduplicationKeys: Map<string, Set<string>> = new Map();
  private idempotencyRecordsByOrg: Map<string, Map<string, { payloadHash: string; eventId: string }>> = new Map();

  private incidentsByOrg: Map<string, Map<string, Incident>> = new Map();
  private rulesByOrg: Map<string, Map<string, DetectionRule>> = new Map();
  private threatIndicators: Map<string, ThreatIndicator> = new Map();
  private responseExecutionsByOrg: Map<string, Map<string, ResponseExecution>> = new Map();

  private auditLogsByOrg: Map<string, AuditLog[]> = new Map();
  private auditStateByOrg: Map<string, AuditState> = new Map();

  private static readonly GENESIS_HASH = '0'.repeat(64);

  // --- Security Events Telemetry ---

  async saveEvent(
    event: SecurityEvent,
    payloadHash?: string
  ): Promise<{ saved: boolean; isDuplicate: boolean; eventId?: string }> {
    const orgId = event.orgId;
    if (!this.eventDeduplicationKeys.has(orgId)) {
      this.eventDeduplicationKeys.set(orgId, new Set());
      this.idempotencyRecordsByOrg.set(orgId, new Map());
      this.eventsByOrg.set(orgId, []);
    }

    const idempotencyRecords = this.idempotencyRecordsByOrg.get(orgId)!;
    const idempotencyKey = event.idempotencyKey || event.eventId;

    // Payload consistency check for idempotency keys
    const existing = idempotencyRecords.get(idempotencyKey);
    if (existing) {
      if (payloadHash && existing.payloadHash && existing.payloadHash !== payloadHash) {
        const err = new Error(
          `Idempotency key '${idempotencyKey}' was previously used with a different request payload.`
        );
        (err as unknown as { code: string }).code = 'IDEMPOTENCY_PAYLOAD_MISMATCH';
        throw err;
      }
      return { saved: false, isDuplicate: true, eventId: existing.eventId };
    }

    const dedupSet = this.eventDeduplicationKeys.get(orgId)!;
    if (dedupSet.has(idempotencyKey)) {
      return { saved: false, isDuplicate: true, eventId: event.eventId };
    }

    dedupSet.add(idempotencyKey);
    idempotencyRecords.set(idempotencyKey, {
      payloadHash: payloadHash || '',
      eventId: event.eventId,
    });
    if (event.eventId !== idempotencyKey) {
      idempotencyRecords.set(event.eventId, {
        payloadHash: payloadHash || '',
        eventId: event.eventId,
      });
      dedupSet.add(event.eventId);
    }

    const orgEvents = this.eventsByOrg.get(orgId)!;
    orgEvents.push({ ...event });

    return { saved: true, isDuplicate: false, eventId: event.eventId };
  }

  async getEvents(
    orgId: string,
    options?: EventQueryOptions
  ): Promise<{ items: SecurityEvent[]; nextCursor?: string; total?: number }> {
    const events = this.eventsByOrg.get(orgId) || [];
    let filtered = [...events];

    if (options?.eventType) {
      filtered = filtered.filter((e) => e.eventType === options.eventType);
    }
    if (options?.severity) {
      filtered = filtered.filter((e) => e.severity === options.severity);
    }
    if (options?.sourceIp) {
      filtered = filtered.filter((e) => e.sourceIp === options.sourceIp);
    }
    if (options?.username) {
      filtered = filtered.filter((e) => e.username === options.username);
    }
    if (options?.sourceSystem) {
      filtered = filtered.filter((e) => e.sourceSystem === options.sourceSystem);
    }
    if (options?.startTime) {
      const startMs = new Date(options.startTime).getTime();
      filtered = filtered.filter((e) => new Date(e.timestamp).getTime() >= startMs);
    }
    if (options?.endTime) {
      const endMs = new Date(options.endTime).getTime();
      filtered = filtered.filter((e) => new Date(e.timestamp).getTime() <= endMs);
    }

    // Sort descending chronologically, tie-break deterministically by eventId
    filtered.sort((a, b) => {
      const diff = new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
      return diff !== 0 ? diff : b.eventId.localeCompare(a.eventId);
    });

    const total = filtered.length;
    const limit = options?.limit || 50;

    let startIndex = 0;
    if (options?.cursor) {
      try {
        const verified = verifyCursor(options.cursor, orgId, options);
        startIndex = verified.offset ?? 0;
      } catch (err: unknown) {
        throw new Error('INVALID_CURSOR');
      }
    }

    const paginated = filtered.slice(startIndex, startIndex + limit);
    const nextOffset = startIndex + limit;
    const filterHash = computeFilterHash(options);
    const nextCursor =
      nextOffset < filtered.length
        ? signCursor({ orgId, filterHash, offset: nextOffset })
        : undefined;

    return { items: paginated, nextCursor, total };
  }

  async getEventById(orgId: string, eventId: string): Promise<SecurityEvent | null> {
    const events = this.eventsByOrg.get(orgId) || [];
    const event = events.find((e) => e.eventId === eventId);
    return event ? { ...event } : null;
  }

  // --- Incidents Management ---

  async saveIncident(incident: Incident): Promise<void> {
    const orgId = incident.orgId;
    if (!this.incidentsByOrg.has(orgId)) {
      this.incidentsByOrg.set(orgId, new Map());
    }
    this.incidentsByOrg.get(orgId)!.set(incident.incidentId, { ...incident });
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
    const orgIncidents = Array.from(this.incidentsByOrg.get(orgId)?.values() || []);
    let filtered = [...orgIncidents];

    if (options?.status) {
      filtered = filtered.filter((i) => i.status === options.status);
    }
    if (options?.severity) {
      filtered = filtered.filter((i) => i.severity === options.severity);
    }

    filtered.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());

    const limit = options?.limit || 20;
    const startIndex = options?.cursor ? parseInt(options.cursor, 10) : 0;
    const items = filtered.slice(startIndex, startIndex + limit);
    const nextCursor =
      startIndex + limit < filtered.length ? String(startIndex + limit) : undefined;

    return { items, nextCursor };
  }

  async getIncidentById(orgId: string, incidentId: string): Promise<Incident | null> {
    const incident = this.incidentsByOrg.get(orgId)?.get(incidentId);
    return incident ? { ...incident } : null;
  }

  async updateIncident(
    orgId: string,
    incidentId: string,
    updates: Partial<Incident>
  ): Promise<Incident | null> {
    const existing = this.incidentsByOrg.get(orgId)?.get(incidentId);
    if (!existing) return null;

    const updated: Incident = {
      ...existing,
      ...updates,
      updatedAt: new Date().toISOString(),
    };
    this.incidentsByOrg.get(orgId)!.set(incidentId, updated);
    return { ...updated };
  }

  // --- Detection Rules ---

  async saveRule(rule: DetectionRule): Promise<void> {
    const orgId = rule.orgId;
    if (!this.rulesByOrg.has(orgId)) {
      this.rulesByOrg.set(orgId, new Map());
    }
    this.rulesByOrg.get(orgId)!.set(rule.ruleId, { ...rule });
  }

  async getRules(orgId: string): Promise<DetectionRule[]> {
    return Array.from(this.rulesByOrg.get(orgId)?.values() || []).map((r) => ({ ...r }));
  }

  async getRuleById(orgId: string, ruleId: string): Promise<DetectionRule | null> {
    const rule = this.rulesByOrg.get(orgId)?.get(ruleId);
    return rule ? { ...rule } : null;
  }

  async updateRule(
    orgId: string,
    ruleId: string,
    updates: Partial<DetectionRule>
  ): Promise<DetectionRule | null> {
    const existing = this.rulesByOrg.get(orgId)?.get(ruleId);
    if (!existing) return null;

    const updated: DetectionRule = {
      ...existing,
      ...updates,
      updatedAt: new Date().toISOString(),
    };
    this.rulesByOrg.get(orgId)!.set(ruleId, updated);
    return { ...updated };
  }

  // --- Threat Indicators ---

  async saveIndicator(indicator: ThreatIndicator): Promise<void> {
    const key = `${indicator.type}:${indicator.value}`;
    this.threatIndicators.set(key, { ...indicator });
  }

  async getIndicatorByValue(
    type: ThreatIndicator['type'],
    value: string
  ): Promise<ThreatIndicator | null> {
    const key = `${type}:${value}`;
    const indicator = this.threatIndicators.get(key);
    return indicator ? { ...indicator } : null;
  }

  async listIndicators(limit = 100): Promise<ThreatIndicator[]> {
    return Array.from(this.threatIndicators.values())
      .slice(0, limit)
      .map((i) => ({ ...i }));
  }

  // --- Defensive Response Executions ---

  async saveExecution(execution: ResponseExecution): Promise<void> {
    const orgId = execution.orgId;
    if (!this.responseExecutionsByOrg.has(orgId)) {
      this.responseExecutionsByOrg.set(orgId, new Map());
    }
    this.responseExecutionsByOrg.get(orgId)!.set(execution.executionId, { ...execution });
  }

  async getExecutionById(
    orgId: string,
    executionId: string
  ): Promise<ResponseExecution | null> {
    const execution = this.responseExecutionsByOrg.get(orgId)?.get(executionId);
    return execution ? { ...execution } : null;
  }

  async listExecutions(
    orgId: string,
    incidentId?: string
  ): Promise<ResponseExecution[]> {
    const executions = Array.from(this.responseExecutionsByOrg.get(orgId)?.values() || []);
    if (incidentId) {
      return executions.filter((e) => e.incidentId === incidentId).map((e) => ({ ...e }));
    }
    return executions.map((e) => ({ ...e }));
  }

  async updateExecution(
    orgId: string,
    executionId: string,
    updates: Partial<ResponseExecution>
  ): Promise<ResponseExecution | null> {
    const existing = this.responseExecutionsByOrg.get(orgId)?.get(executionId);
    if (!existing) return null;

    const updated: ResponseExecution = {
      ...existing,
      ...updates,
    };
    this.responseExecutionsByOrg.get(orgId)!.set(executionId, updated);
    return { ...updated };
  }

  // --- Cryptographic Audit Ledger ---

  async appendAuditLog(
    logData: Omit<AuditLog, 'prevHash' | 'currentHash'>
  ): Promise<AuditLog> {
    const orgId = logData.orgId;
    if (!this.auditLogsByOrg.has(orgId)) {
      this.auditLogsByOrg.set(orgId, []);
    }

    const logs = this.auditLogsByOrg.get(orgId)!;
    const prevHash =
      logs.length === 0
        ? MemoryStore.GENESIS_HASH
        : logs[logs.length - 1]!.currentHash;

    const currentHash = this.computeAuditHash(prevHash, logData);

    const fullLog: AuditLog = {
      ...logData,
      prevHash,
      currentHash,
    };

    logs.push(fullLog);

    this.auditStateByOrg.set(orgId, {
      orgId,
      lastVerifiedHash: currentHash,
      updatedAt: new Date().toISOString(),
    });

    return { ...fullLog };
  }

  async getAuditLogs(orgId: string, limit = 100): Promise<AuditLog[]> {
    const logs = this.auditLogsByOrg.get(orgId) || [];
    return logs.slice(-limit).map((l) => ({ ...l }));
  }

  async getAuditState(orgId: string): Promise<AuditState | null> {
    const state = this.auditStateByOrg.get(orgId);
    return state ? { ...state } : null;
  }

  async verifyAuditChain(
    orgId: string
  ): Promise<{ verified: boolean; length: number; brokenRecordId?: string }> {
    const logs = this.auditLogsByOrg.get(orgId) || [];
    if (logs.length === 0) {
      return { verified: true, length: 0 };
    }

    let expectedPrevHash = MemoryStore.GENESIS_HASH;

    for (const log of logs) {
      // 1. Check prevHash linkage
      if (log.prevHash !== expectedPrevHash) {
        return { verified: false, length: logs.length, brokenRecordId: log.logId };
      }

      // 2. Recompute current hash
      const recomputedHash = this.computeAuditHash(expectedPrevHash, log);
      if (recomputedHash !== log.currentHash) {
        return { verified: false, length: logs.length, brokenRecordId: log.logId };
      }

      expectedPrevHash = log.currentHash;
    }

    return { verified: true, length: logs.length };
  }

  /**
   * Test helper to simulate tampering with an immutable audit log record.
   * Used in unit and security tests to verify tamper-evidence detection.
   */
  tamperAuditLogForTesting(
    orgId: string,
    logId: string,
    alteredDetails: Record<string, unknown>
  ): boolean {
    const logs = this.auditLogsByOrg.get(orgId) || [];
    const target = logs.find((l) => l.logId === logId);
    if (!target) return false;
    target.details = alteredDetails;
    return true;
  }

  private computeAuditHash(
    prevHash: string,
    data: Omit<AuditLog, 'prevHash' | 'currentHash'>
  ): string {
    const payload = `${prevHash}|${data.logId}|${data.orgId}|${data.timestamp}|${data.action}|${data.actor.userId}|${this.canonicalStringify(data.details)}`;
    return createHash('sha256').update(payload, 'utf8').digest('hex');
  }

  /**
   * Recursive deterministic JSON serializer (RFC 8785 canonical representation)
   * to guarantee cryptographic hash repeatability regardless of object key insertion order.
   */
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

  async clearAll(): Promise<void> {
    this.eventsByOrg.clear();
    this.eventDeduplicationKeys.clear();
    this.idempotencyRecordsByOrg.clear();
    this.incidentsByOrg.clear();
    this.rulesByOrg.clear();
    this.threatIndicators.clear();
    this.responseExecutionsByOrg.clear();
    this.auditLogsByOrg.clear();
    this.auditStateByOrg.clear();
  }
}
