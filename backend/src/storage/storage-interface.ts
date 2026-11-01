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

  // --- Incidents Management ---
  saveIncident(incident: Incident): Promise<void>;
  getIncidents(
    orgId: string,
    options?: {
      status?: IncidentStatus;
      severity?: Severity;
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

  // --- Threat Indicators ---
  saveIndicator(indicator: ThreatIndicator): Promise<void>;
  getIndicatorByValue(
    type: ThreatIndicator['type'],
    value: string
  ): Promise<ThreatIndicator | null>;
  listIndicators(limit?: number): Promise<ThreatIndicator[]>;

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

  // --- Reset (for test isolation) ---
  clearAll?(): Promise<void>;
}
