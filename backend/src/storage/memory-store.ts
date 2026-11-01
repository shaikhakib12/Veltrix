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

export class MemoryStore implements StorageInterface {
  // Primary stores partitioned by orgId where applicable
  private eventsByOrg: Map<string, SecurityEvent[]> = new Map();
  private eventDeduplicationKeys: Map<string, Set<string>> = new Map();
  private idempotencyRecordsByOrg: Map<string, Map<string, { payloadHash: string; eventId: string }>> = new Map();
  private detectionsByOrg: Map<string, Detection[]> = new Map();
  private detectionDedupKeys: Map<string, Set<string>> = new Map();

  private incidentsByOrg: Map<string, Map<string, Incident>> = new Map();
  private rulesByOrg: Map<string, Map<string, DetectionRule>> = new Map();
  private threatIndicators: Map<string, ThreatIndicator> = new Map();
  private responseExecutionsByOrg: Map<string, Map<string, ResponseExecution>> = new Map();

  private auditLogsByOrg: Map<string, AuditLog[]> = new Map();
  private auditStateByOrg: Map<string, AuditState> = new Map();
  private websitesByOrg: Map<string, Map<string, WebsiteAsset>> = new Map();
  private integrationsByOrg: Map<string, Map<string, Integration>> = new Map();
  private integrationsByApiKeyHash: Map<string, Integration> = new Map();
  private domainOwnership: Map<string, string> = new Map();


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

    // Payload consistency check for idempotency keys AND event IDs
    // (A different idempotency key cannot bypass event ID payload consistency)
    const existingByIdemp = idempotencyRecords.get(idempotencyKey);
    const existingByEventId = idempotencyRecords.get(event.eventId);
    const existing = existingByIdemp || existingByEventId;

    if (existing) {
      if (payloadHash && existing.payloadHash && existing.payloadHash !== payloadHash) {
        const err = new Error(
          `Idempotency key or Event ID was previously used with a different request payload.`
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
    const { trustedEvidenceContext: _discard, ...cleanEvent } = event;
    orgEvents.push({ ...cleanEvent } as SecurityEvent);

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

  // --- Threat Detections ---

  async saveDetection(
    detection: Detection
  ): Promise<{ saved: boolean; isDuplicate: boolean }> {
    const orgId = detection.orgId;
    if (!this.detectionsByOrg.has(orgId)) {
      this.detectionsByOrg.set(orgId, []);
      this.detectionDedupKeys.set(orgId, new Set());
    }

    const dedupKey = detection.dedupKey || detection.detectionId;
    const orgDedupKeys = this.detectionDedupKeys.get(orgId)!;
    const orgDetections = this.detectionsByOrg.get(orgId)!;

    if (orgDedupKeys.has(dedupKey) || orgDetections.some((d) => d.detectionId === detection.detectionId)) {
      return { saved: false, isDuplicate: true };
    }

    orgDedupKeys.add(dedupKey);
    orgDetections.push({ ...detection });
    return { saved: true, isDuplicate: false };
  }

  async getDetections(
    orgId: string,
    options?: DetectionQueryOptions
  ): Promise<{ items: Detection[]; nextCursor?: string; total?: number }> {
    const detections = this.detectionsByOrg.get(orgId) || [];
    let filtered = [...detections];

    if (options?.ruleId) {
      filtered = filtered.filter((d) => d.ruleId === options.ruleId);
    }
    if (options?.severity) {
      filtered = filtered.filter((d) => d.severity === options.severity);
    }
    if (options?.status) {
      filtered = filtered.filter((d) => d.status === options.status);
    }
    if (options?.siteId) {
      filtered = filtered.filter((d) => (d.evidence?.details as { siteId?: string } | undefined)?.siteId === options.siteId);
    }
    if (options?.startTime) {
      const startMs = new Date(options.startTime).getTime();
      filtered = filtered.filter((d) => new Date(d.detectedAt).getTime() >= startMs);
    }
    if (options?.endTime) {
      const endMs = new Date(options.endTime).getTime();
      filtered = filtered.filter((d) => new Date(d.detectedAt).getTime() <= endMs);
    }

    filtered.sort((a, b) => {
      const diff = new Date(b.detectedAt).getTime() - new Date(a.detectedAt).getTime();
      return diff !== 0 ? diff : b.detectionId.localeCompare(a.detectionId);
    });

    const total = filtered.length;
    const limit = options?.limit || 50;

    let startIndex = 0;
    if (options?.cursor) {
      try {
        const verified = verifyCursor(options.cursor, orgId, options as any);
        startIndex = verified.offset ?? 0;
      } catch {
        throw new Error('INVALID_CURSOR');
      }
    }

    const paginated = filtered.slice(startIndex, startIndex + limit);
    const nextOffset = startIndex + limit;
    const filterHash = computeFilterHash(options as any);
    const nextCursor =
      nextOffset < filtered.length
        ? signCursor({ orgId, filterHash, offset: nextOffset })
        : undefined;

    return { items: paginated, nextCursor, total };
  }

  async getDetectionById(orgId: string, detectionId: string): Promise<Detection | null> {
    const detections = this.detectionsByOrg.get(orgId) || [];
    const found = detections.find((d) => d.detectionId === detectionId);
    return found ? { ...found } : null;
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
      siteId?: string;
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
    if (options?.siteId) {
      filtered = filtered.filter((i) => i.siteId === options.siteId);
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
    const key = indicator.indicatorId || `${indicator.type}:${indicator.value}:${indicator.orgId || 'global'}`;
    this.threatIndicators.set(key, { ...indicator });
  }

  async getIndicatorById(indicatorId: string, orgId?: string): Promise<ThreatIndicator | null> {
    for (const ind of this.threatIndicators.values()) {
      if (ind.indicatorId === indicatorId) {
        if (orgId && ind.orgId && ind.orgId !== 'global' && ind.orgId !== orgId) {
          return null; // Cross-tenant isolation
        }
        return { ...ind };
      }
    }
    return null;
  }

  async getIndicatorByValue(
    type: ThreatIndicator['type'],
    value: string,
    orgId?: string
  ): Promise<ThreatIndicator | null> {
    for (const ind of this.threatIndicators.values()) {
      if (ind.type === type && ind.value === value) {
        if (orgId && ind.orgId && ind.orgId !== 'global' && ind.orgId !== orgId) {
          continue; // Skip indicators belonging to another tenant
        }
        return { ...ind };
      }
    }
    return null;
  }

  async listIndicators(orgId?: string, limit = 100): Promise<ThreatIndicator[]> {
    return Array.from(this.threatIndicators.values())
      .filter((i) => !orgId || !i.orgId || i.orgId === 'global' || i.orgId === orgId)
      .slice(0, limit)
      .map((i) => ({ ...i }));
  }

  async updateIndicator(
    indicatorId: string,
    updates: Partial<ThreatIndicator>,
    orgId?: string
  ): Promise<ThreatIndicator | null> {
    for (const [key, ind] of this.threatIndicators.entries()) {
      if (ind.indicatorId === indicatorId) {
        if (orgId && ind.orgId && ind.orgId !== 'global' && ind.orgId !== orgId) {
          const err = new Error('FORBIDDEN_CROSS_TENANT_ACCESS');
          (err as unknown as { code: string }).code = 'FORBIDDEN_CROSS_TENANT_ACCESS';
          throw err;
        }
        const updated = { ...ind, ...updates, indicatorId: ind.indicatorId };
        this.threatIndicators.set(key, updated);
        return { ...updated };
      }
    }
    return null;
  }

  async deleteIndicator(indicatorId: string, orgId?: string): Promise<boolean> {
    for (const [key, ind] of this.threatIndicators.entries()) {
      if (ind.indicatorId === indicatorId) {
        if (orgId && ind.orgId && ind.orgId !== 'global' && ind.orgId !== orgId) {
          const err = new Error('FORBIDDEN_CROSS_TENANT_ACCESS');
          (err as unknown as { code: string }).code = 'FORBIDDEN_CROSS_TENANT_ACCESS';
          throw err;
        }
        this.threatIndicators.delete(key);
        return true;
      }
    }
    return false;
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


  // --- Website Asset Inventory (TASK-601, TASK-602) ---

  async saveWebsite(site: WebsiteAsset): Promise<WebsiteAsset> {
    const orgId = site.orgId;
    const normalizedDomain = site.primaryDomain.toLowerCase().trim();

    // Atomic cross-tenant domain ownership check
    const existingOwnerOrg = this.domainOwnership.get(normalizedDomain);
    if (existingOwnerOrg && existingOwnerOrg !== orgId) {
      const err = new Error(`DOMAIN_ALREADY_CLAIMED: Domain '${normalizedDomain}' is already claimed by another organization.`);
      (err as any).name = 'ConditionalCheckFailedException';
      throw err;
    }

    if (!this.websitesByOrg.has(orgId)) {
      this.websitesByOrg.set(orgId, new Map());
    }
    const orgSites = this.websitesByOrg.get(orgId)!;
    orgSites.set(site.siteId, { ...site, primaryDomain: normalizedDomain });
    this.domainOwnership.set(normalizedDomain, orgId);
    return { ...site, primaryDomain: normalizedDomain };
  }

  async getWebsites(
    orgId: string,
    options?: { status?: string; limit?: number; cursor?: string }
  ): Promise<{ items: WebsiteAsset[]; nextCursor?: string; total?: number }> {
    const orgSites = this.websitesByOrg.get(orgId);
    if (!orgSites) {
      return { items: [], total: 0 };
    }

    let items = Array.from(orgSites.values());

    if (options?.status) {
      items = items.filter((s) => s.status === options.status);
    }

    // Sort descending by createdAt
    items.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());

    const total = items.length;
    const limit = options?.limit || 50;

    let startIndex = 0;
    if (options?.cursor) {
      try {
        const decoded = JSON.parse(Buffer.from(options.cursor, 'base64').toString('utf8'));
        if (typeof decoded.offset === 'number') {
          startIndex = decoded.offset;
        }
      } catch {
        // invalid cursor, start from 0
      }
    }

    const pageItems = items.slice(startIndex, startIndex + limit);
    let nextCursor: string | undefined = undefined;

    if (startIndex + limit < items.length) {
      nextCursor = Buffer.from(JSON.stringify({ offset: startIndex + limit })).toString('base64');
    }

    return {
      items: pageItems.map((s) => ({ ...s })),
      total,
      nextCursor,
    };
  }

  async getWebsiteById(orgId: string, siteId: string): Promise<WebsiteAsset | null> {
    const orgSites = this.websitesByOrg.get(orgId);
    if (!orgSites) return null;
    const site = orgSites.get(siteId);
    return site ? { ...site } : null;
  }

  async getWebsiteByDomain(domain: string): Promise<WebsiteAsset | null> {
    const normalizedDomain = domain.toLowerCase().trim();
    for (const orgSites of this.websitesByOrg.values()) {
      for (const site of orgSites.values()) {
        if (
          site.primaryDomain.toLowerCase() === normalizedDomain ||
          site.approvedSubdomains.some((sub) => sub.toLowerCase() === normalizedDomain)
        ) {
          return { ...site };
        }
      }
    }
    return null;
  }

  async updateWebsite(
    orgId: string,
    siteId: string,
    updates: Partial<WebsiteAsset>
  ): Promise<WebsiteAsset | null> {
    const orgSites = this.websitesByOrg.get(orgId);
    if (!orgSites) return null;
    const site = orgSites.get(siteId);
    if (!site) return null;

    const updatedSite: WebsiteAsset = {
      ...site,
      ...updates,
      siteId: site.siteId, // immutable
      orgId: site.orgId,   // immutable
      updatedAt: new Date().toISOString(),
    };

    orgSites.set(siteId, updatedSite);
    return { ...updatedSite };
  }

  async deleteWebsite(orgId: string, siteId: string): Promise<boolean> {
    const orgSites = this.websitesByOrg.get(orgId);
    if (!orgSites) return false;
    const site = orgSites.get(siteId);
    if (site) {
      this.domainOwnership.delete(site.primaryDomain.toLowerCase().trim());
    }
    return orgSites.delete(siteId);
  }

  // --- Integration Management (TASK-603, TASK-606) ---

  async saveIntegration(integration: Integration): Promise<Integration> {
    const orgId = integration.orgId;
    if (!this.integrationsByOrg.has(orgId)) {
      this.integrationsByOrg.set(orgId, new Map());
    }
    const orgIntegrations = this.integrationsByOrg.get(orgId)!;
    orgIntegrations.set(integration.integrationId, { ...integration });
    this.integrationsByApiKeyHash.set(integration.apiKeyHash, { ...integration });
    return { ...integration };
  }

  async getIntegrations(orgId: string, siteId?: string): Promise<Integration[]> {
    const orgIntegrations = this.integrationsByOrg.get(orgId);
    if (!orgIntegrations) return [];

    let items = Array.from(orgIntegrations.values());
    if (siteId) {
      items = items.filter((i) => i.siteId === siteId);
    }
    items.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
    return items.map((i) => ({ ...i }));
  }

  async getIntegrationById(orgId: string, integrationId: string): Promise<Integration | null> {
    const orgIntegrations = this.integrationsByOrg.get(orgId);
    if (!orgIntegrations) return null;
    const item = orgIntegrations.get(integrationId);
    return item ? { ...item } : null;
  }

  async getIntegrationByApiKeyHash(apiKeyHash: string): Promise<Integration | null> {
    const item = this.integrationsByApiKeyHash.get(apiKeyHash);
    return item ? { ...item } : null;
  }

  async updateIntegration(
    orgId: string,
    integrationId: string,
    updates: Partial<Integration>
  ): Promise<Integration | null> {
    const orgIntegrations = this.integrationsByOrg.get(orgId);
    if (!orgIntegrations) return null;
    const item = orgIntegrations.get(integrationId);
    if (!item) return null;

    // If apiKeyHash changed, update the lookup map
    if (updates.apiKeyHash && updates.apiKeyHash !== item.apiKeyHash) {
      this.integrationsByApiKeyHash.delete(item.apiKeyHash);
    }

    const updatedItem: Integration = {
      ...item,
      ...updates,
      integrationId: item.integrationId, // immutable
      orgId: item.orgId,                 // immutable
      updatedAt: new Date().toISOString(),
    };

    orgIntegrations.set(integrationId, updatedItem);
    this.integrationsByApiKeyHash.set(updatedItem.apiKeyHash, updatedItem);
    return { ...updatedItem };
  }

  async deleteIntegration(orgId: string, integrationId: string): Promise<boolean> {
    const orgIntegrations = this.integrationsByOrg.get(orgId);
    if (!orgIntegrations) return false;
    const item = orgIntegrations.get(integrationId);
    if (item) {
      this.integrationsByApiKeyHash.delete(item.apiKeyHash);
    }
    return orgIntegrations.delete(integrationId);
  }

  async clearAll(): Promise<void> {
    this.eventsByOrg.clear();
    this.detectionsByOrg.clear();
    this.detectionDedupKeys.clear();
    this.eventDeduplicationKeys.clear();
    this.idempotencyRecordsByOrg.clear();
    this.incidentsByOrg.clear();
    this.rulesByOrg.clear();
    this.threatIndicators.clear();
    this.responseExecutionsByOrg.clear();
    this.auditLogsByOrg.clear();
    this.auditStateByOrg.clear();
    this.websitesByOrg.clear();
    this.integrationsByOrg.clear();
    this.integrationsByApiKeyHash.clear();
    this.domainOwnership.clear();
  }
}
