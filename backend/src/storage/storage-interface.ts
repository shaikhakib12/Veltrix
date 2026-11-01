import type {
  SecurityEvent,
  Incident,
  IncidentStatus,
  Severity,
  DetectionRule,
  Detection,
  DetectionQueryOptions,
  ThreatIndicator,
  ResponseExecution,
  AuditLog,
  AuditState,
  WebsiteAsset,
  Integration,
} from '@veltrix/shared';

export interface EventQueryOptions {
  limit?: number;
  cursor?: string;
  eventType?: string;
  severity?: Severity;
  sourceIp?: string;
  username?: string;
  sourceSystem?: string;
  startTime?: string;
  endTime?: string;
}

export interface StorageInterface {
  // --- Security Events Telemetry ---
  saveEvent(
    event: SecurityEvent,
    payloadHash?: string
  ): Promise<{ saved: boolean; isDuplicate: boolean; eventId?: string }>;
  getEvents(
    orgId: string,
    options?: EventQueryOptions
  ): Promise<{ items: SecurityEvent[]; nextCursor?: string; total?: number }>;
  getEventById(orgId: string, eventId: string): Promise<SecurityEvent | null>;

  // --- Threat Detections ---
  saveDetection(
    detection: Detection
  ): Promise<{ saved: boolean; isDuplicate: boolean }>;
  getDetections(
    orgId: string,
    options?: DetectionQueryOptions
  ): Promise<{ items: Detection[]; nextCursor?: string; total?: number }>;
  getDetectionById(orgId: string, detectionId: string): Promise<Detection | null>;

  // --- Incidents Management ---
  saveIncident(incident: Incident): Promise<void>;
  getIncidents(
    orgId: string,
    options?: {
      status?: IncidentStatus;
      severity?: Severity;
      siteId?: string;
      limit?: number;
      cursor?: string;
    }
  ): Promise<{ items: Incident[]; nextCursor?: string }>;
  getIncidentById(orgId: string, incidentId: string): Promise<Incident | null>;
  updateIncident(
    orgId: string,
    incidentId: string,
    updates: Partial<Incident>
  ): Promise<Incident | null>;

  // --- Detection Rules ---
  saveRule(rule: DetectionRule): Promise<void>;
  getRules(orgId: string): Promise<DetectionRule[]>;
  getRuleById(orgId: string, ruleId: string): Promise<DetectionRule | null>;
  updateRule(
    orgId: string,
    ruleId: string,
    updates: Partial<DetectionRule>
  ): Promise<DetectionRule | null>;

  saveDetectionRule(rule: DetectionRule): Promise<void>;
  getDetectionRules(orgId: string): Promise<DetectionRule[]>;
  getDetectionRuleById(orgId: string, ruleId: string): Promise<DetectionRule | null>;
  updateDetectionRule(
    orgId: string,
    ruleId: string,
    updates: Partial<DetectionRule>
  ): Promise<DetectionRule | null>;

  // --- Threat Indicators ---
  saveIndicator(indicator: ThreatIndicator): Promise<void>;
  getIndicatorByValue(
    type: ThreatIndicator['type'],
    value: string,
    orgId?: string
  ): Promise<ThreatIndicator | null>;
  getIndicatorById(indicatorId: string, orgId?: string): Promise<ThreatIndicator | null>;
  listIndicators(orgId?: string, limit?: number): Promise<ThreatIndicator[]>;
  updateIndicator(
    indicatorId: string,
    updates: Partial<ThreatIndicator>,
    orgId?: string
  ): Promise<ThreatIndicator | null>;
  deleteIndicator(indicatorId: string, orgId?: string): Promise<boolean>;

  // --- Defensive Response Executions ---
  saveExecution(execution: ResponseExecution): Promise<void>;
  getExecutionById(orgId: string, executionId: string): Promise<ResponseExecution | null>;
  listExecutions(orgId: string, incidentId?: string): Promise<ResponseExecution[]>;
  updateExecution(
    orgId: string,
    executionId: string,
    updates: Partial<ResponseExecution>
  ): Promise<ResponseExecution | null>;

  // --- Cryptographic Audit Ledger ---
  appendAuditLog(
    log: Omit<AuditLog, 'prevHash' | 'currentHash'>
  ): Promise<AuditLog>;
  getAuditLogs(orgId: string, limit?: number): Promise<AuditLog[]>;
  getAuditState(orgId: string): Promise<AuditState | null>;
  verifyAuditChain(
    orgId: string
  ): Promise<{ verified: boolean; length: number; brokenRecordId?: string }>;


  // --- Website Asset Inventory (TASK-601, TASK-602) ---
  saveWebsite(site: WebsiteAsset): Promise<WebsiteAsset>;
  getWebsites(
    orgId: string,
    options?: { status?: string; limit?: number; cursor?: string }
  ): Promise<{ items: WebsiteAsset[]; nextCursor?: string; total?: number }>;
  getWebsiteById(orgId: string, siteId: string): Promise<WebsiteAsset | null>;
  getWebsiteByDomain(domain: string): Promise<WebsiteAsset | null>;
  updateWebsite(
    orgId: string,
    siteId: string,
    updates: Partial<WebsiteAsset>
  ): Promise<WebsiteAsset | null>;
  deleteWebsite(orgId: string, siteId: string): Promise<boolean>;

  // --- Integration Management (TASK-603, TASK-606) ---
  saveIntegration(integration: Integration): Promise<Integration>;
  getIntegrations(orgId: string, siteId?: string): Promise<Integration[]>;
  getIntegrationById(orgId: string, integrationId: string): Promise<Integration | null>;
  getIntegrationByApiKeyHash(apiKeyHash: string): Promise<Integration | null>;
  updateIntegration(
    orgId: string,
    integrationId: string,
    updates: Partial<Integration>
  ): Promise<Integration | null>;
  deleteIntegration(orgId: string, integrationId: string): Promise<boolean>;

  // --- Reset (for test isolation) ---
  clearAll?(): Promise<void>;
}
