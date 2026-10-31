/**
 * VELTRIX: Autonomous Cyber Threat Detection & Response Platform
 * Shared Domain Types and Data Contracts
 */

// ==========================================
// 1. Organization & User RBAC
// ==========================================

export type UserRole = 'SUPER_ADMIN' | 'ORG_ADMIN' | 'SECURITY_ANALYST' | 'READ_ONLY_VIEWER';

export interface Organization {
  orgId: string;
  name: string;
  tier: 'COMMUNITY' | 'PROFESSIONAL' | 'ENTERPRISE';
  createdAt: string;
  updatedAt: string;
  settings?: {
    retentionDays: number;
    autoResponseEnabled: boolean;
    requireMFA: boolean;
  };
}

export interface User {
  userId: string;
  orgId: string;
  email: string;
  fullName: string;
  role: UserRole;
  createdAt: string;
  lastLoginAt?: string;
  status: 'ACTIVE' | 'SUSPENDED' | 'PENDING_VERIFICATION';
}

// ==========================================
// 2. Security Events (Telemetry Ingestion)
// ==========================================

export type EventSeverity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type EventCategory = 
  | 'AUTHENTICATION' 
  | 'NETWORK' 
  | 'PRIVILEGE' 
  | 'API' 
  | 'DATA_ACCESS' 
  | 'SYSTEM';

export interface SecurityEventInput {
  eventId?: string;
  orgId?: string; // Overridden by backend authorizer if passed from authenticated client
  timestamp?: string; // Defaults to now
  eventType: string; // e.g. auth.login.failed, iam.role.elevate
  severity?: EventSeverity;
  category: EventCategory;
  sourceIp: string;
  username: string;
  sourceSystem: string;
  metadata?: Record<string, unknown>;
  isSimulated?: boolean;
}

export interface SecurityEvent {
  eventId: string;
  orgId: string;
  timestamp: string; // ISO 8601 UTC
  eventType: string;
  severity: EventSeverity;
  category: EventCategory;
  sourceIp: string;
  username: string;
  sourceSystem: string;
  metadata: Record<string, unknown>;
  idempotencyHash: string;
  isSimulated: boolean;
  receivedAt: string;
}

// ==========================================
// 3. Threat Detection Rules (Sigma-Inspired)
// ==========================================

export interface MitreAttackReference {
  tactic: string;
  techniqueId: string; // e.g. T1110.001
  techniqueName: string;
  subTechniqueId?: string;
  url: string;
}

export interface RuleCondition {
  field: string;
  operator: 'equals' | 'not_equals' | 'contains' | 'greater_than' | 'in' | 'regex';
  value: string | number | boolean | string[];
}

export interface DetectionRule {
  ruleId: string;
  orgId: string; // 'GLOBAL' or specific orgId for custom overrides
  name: string;
  description: string;
  severity: EventSeverity;
  category: EventCategory;
  mitreAttack: MitreAttackReference;
  timeWindowSeconds: number;
  threshold: number;
  groupBy: 'sourceIp' | 'username' | 'sourceSystem';
  conditions: RuleCondition[];
  recommendedAction: ResponseActionType;
  requiresApproval: boolean;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface DetectionTrigger {
  triggerId: string;
  ruleId: string;
  ruleName: string;
  orgId: string;
  timestamp: string;
  severity: EventSeverity;
  mitreAttack: MitreAttackReference;
  entityKey: string; // e.g. "IP:198.51.100.42" or "USER:sarah.connors"
  contributingEventIds: string[];
  matchedCount: number;
  explanation: string;
  isSimulated: boolean;
}

// ==========================================
// 4. Incidents & Event Correlation
// ==========================================

export type IncidentStatus = 'NEW' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'FALSE_POSITIVE';

export interface AttackTimelineStep {
  stepId: string;
  timestamp: string;
  phase: string; // e.g. "Reconnaissance", "Credential Access", "Privilege Escalation", "Exfiltration"
  mitreId: string;
  description: string;
  sourceIp: string;
  username: string;
  severity: EventSeverity;
  eventId: string;
}

export interface RiskScoreBreakdown {
  totalScore: number; // 0 - 100
  tier: EventSeverity;
  baseScore: number;
  frequencyMultiplier: number;
  assetMultiplier: number;
  threatMultiplier: number;
  sequenceBonus: number;
  factors: Array<{
    name: string;
    impact: string;
    description: string;
  }>;
  explanation: string;
}

export interface Incident {
  incidentId: string;
  orgId: string;
  title: string;
  description: string;
  status: IncidentStatus;
  severity: EventSeverity;
  riskScore: number; // 0 - 100
  riskBreakdown: RiskScoreBreakdown;
  attackVector: string; // Primary attack type
  targetUser?: string;
  sourceIp: string;
  correlatedEventIds: string[];
  timeline: AttackTimelineStep[];
  assignee?: string;
  recommendedResponse: ResponseActionType;
  requiresApproval: boolean;
  containmentStatus: 'NONE' | 'PENDING_APPROVAL' | 'CONTAINED' | 'REVERTED';
  notes: Array<{
    author: string;
    timestamp: string;
    content: string;
  }>;
  isSimulated: boolean;
  createdAt: string;
  updatedAt: string;
}

// ==========================================
// 5. Threat Intelligence
// ==========================================

export type ThreatIndicatorType = 'IP' | 'DOMAIN' | 'FILE_HASH_SHA256' | 'CIDR';

export interface ThreatIndicator {
  indicatorId: string;
  type: ThreatIndicatorType;
  value: string;
  severity: EventSeverity;
  confidence: number; // 0 - 100
  threatType: 'TOR_EXIT_NODE' | 'BOTNET_C2' | 'BRUTE_FORCE_SOURCE' | 'DATA_EXFILTRATION_HOST' | 'VPN_PROXY';
  description: string;
  country?: string;
  asn?: string;
  lastSeen: string;
  isSimulated?: boolean;
}

// ==========================================
// 6. Automated Defensive Response (SOAR)
// ==========================================

export type ResponseActionType = 
  | 'REVOKE_SESSION' 
  | 'SUSPEND_USER' 
  | 'BLOCK_IP' 
  | 'STEP_UP_AUTH' 
  | 'ESCALATE_ALERT' 
  | 'UNBLOCK_IP' 
  | 'REINSTATE_USER';

export type ResponseExecutionStatus = 
  | 'PENDING_APPROVAL' 
  | 'APPROVED' 
  | 'REJECTED' 
  | 'EXECUTING' 
  | 'SUCCESS' 
  | 'FAILED' 
  | 'ROLLED_BACK';

export interface ResponsePolicy {
  policyId: string;
  orgId: string;
  name: string;
  action: ResponseActionType;
  autoExecuteSeverityThreshold: EventSeverity; // e.g. CRITICAL triggers immediately without human
  requiresApproval: boolean;
  rollbackSupported: boolean;
  enabled: boolean;
}

export interface ResponseExecution {
  executionId: string;
  orgId: string;
  incidentId: string;
  action: ResponseActionType;
  targetEntity: string; // e.g. IP or Username
  status: ResponseExecutionStatus;
  requestedBy: string; // 'SYSTEM_AUTONOMOUS' or Analyst user
  approvedBy?: string;
  executedAt?: string;
  rollbackAt?: string;
  details: string;
  isSimulated: boolean;
}

// ==========================================
// 7. Cryptographic Security Audit Trail
// ==========================================

export interface AuditRecordPayload {
  actor: string;
  action: string;
  targetResource: string;
  result: 'SUCCESS' | 'FAILURE' | 'DENIED';
  metadata: Record<string, unknown>;
}

export interface AuditRecord {
  logId: string;
  orgId: string;
  timestamp: string;
  actor: string;
  action: string;
  targetResource: string;
  result: 'SUCCESS' | 'FAILURE' | 'DENIED';
  metadata: Record<string, unknown>;
  previousHash: string;
  integrityHash: string; // SHA-256(previousHash + JSON.stringify(record))
}

export interface AuditVerificationResult {
  verified: boolean;
  totalRecordsChecked: number;
  brokenRecordId?: string;
  error?: string;
  timestamp: string;
}

// ==========================================
// 8. Simulation Lab
// ==========================================

export interface SimulationScenario {
  id: string;
  name: string;
  description: string;
  category: EventCategory;
  severity: EventSeverity;
  mitreTechniques: string[];
  estimatedDurationSeconds: number;
  eventsCount: number;
  targetUser: string;
  attackerIp: string;
}

export interface SimulationExecutionResult {
  scenarioId: string;
  status: 'COMPLETED' | 'FAILED';
  injectedEventsCount: number;
  triggeredRules: string[];
  correlatedIncidentId?: string;
  riskScore: number;
  durationMs: number;
  events: SecurityEvent[];
}
