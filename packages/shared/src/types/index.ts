import type {
  EVENT_CATEGORIES,
  SUPPORTED_EVENT_TYPES,
  SEVERITIES,
  INCIDENT_STATUSES,
  RESPONSE_ACTION_TYPES,
  RESPONSE_EXECUTION_STATUSES,
  USER_ROLES,
  AUDIT_ACTION_TYPES,
} from '../constants/index.js';

export type EventCategory = (typeof EVENT_CATEGORIES)[number];
export type SupportedEventType = (typeof SUPPORTED_EVENT_TYPES)[number];
export type Severity = (typeof SEVERITIES)[number];
export type IncidentStatus = (typeof INCIDENT_STATUSES)[number];
export type ResponseActionType = (typeof RESPONSE_ACTION_TYPES)[number];
export type ResponseExecutionStatus = (typeof RESPONSE_EXECUTION_STATUSES)[number];
export type UserRole = (typeof USER_ROLES)[number];
export type AuditActionType = (typeof AUDIT_ACTION_TYPES)[number];

export interface SecurityEvent {
  eventId: string;
  orgId: string;
  timestamp: string; // ISO 8601 UTC
  eventType: string;
  severity: Severity;
  category: EventCategory;
  sourceIp: string;
  username?: string;
  sourceSystem: string;
  metadata?: Record<string, unknown>;
  isSimulated?: boolean;
  idempotencyKey?: string;
  ingestedAt?: string; // Server-side ISO 8601 UTC receipt timestamp
}

export interface IngestionItemResult {
  eventId: string;
  status: 'ACCEPTED' | 'DUPLICATE_SUPPRESSED' | 'REJECTED' | 'FAILED';
  message?: string;
  errors?: Array<{ field: string; message: string }>;
}

export interface IngestionResponseData {
  total: number;
  accepted: number;
  duplicates: number;
  rejected: number;
  results: IngestionItemResult[];
}

export interface DetectionRule {
  ruleId: string;
  orgId: string;
  name: string;
  description: string;
  category: EventCategory;
  severity: Severity;
  mitreAttack?: {
    techniqueId: string;
    techniqueName: string;
    tactic: string;
  };
  condition: Record<string, unknown>;
  slidingWindowSeconds: number;
  threshold: number;
  isEnabled: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface RiskScoreFactors {
  baseSeverity: number;
  frequencyMultiplier: number;
  assetCriticalityMultiplier: number;
  threatIntelMultiplier: number;
  attackSequenceBonus: number;
  finalScore: number;
}

export interface TimelineEntry {
  timestamp: string;
  eventType: string;
  description: string;
  sourceIp?: string;
  username?: string;
  mitreTactic?: string;
}

export interface Incident {
  incidentId: string;
  orgId: string;
  title: string;
  description: string;
  severity: Severity;
  riskScore: number;
  riskFactors: RiskScoreFactors;
  status: IncidentStatus;
  assignedTo?: string;
  associatedEventIds: string[];
  timeline: TimelineEntry[];
  suggestedResponses: ResponseActionType[];
  notes?: Array<{
    noteId: string;
    author: string;
    content: string;
    timestamp: string;
  }>;
  createdAt: string;
  updatedAt: string;
}

export interface ThreatIndicator {
  indicatorId: string;
  type: 'IP' | 'DOMAIN' | 'HASH' | 'USER_AGENT';
  value: string;
  threatType: string;
  severity: Severity;
  confidence: number; // 0 - 100
  source: string;
  firstSeen: string;
  lastSeen: string;
  isFlagged: boolean;
  metadata?: Record<string, unknown>;
}

export interface ResponseExecution {
  executionId: string;
  incidentId: string;
  orgId: string;
  actionType: ResponseActionType;
  target: string;
  parameters?: Record<string, unknown>;
  status: ResponseExecutionStatus;
  requestedBy: string;
  approvedBy?: string;
  executedAt?: string;
  result?: {
    success: boolean;
    message: string;
    details?: Record<string, unknown>;
  };
  isSimulated: boolean;
  rollbackCapable: boolean;
  rolledBackAt?: string;
}

export interface AuditLog {
  logId: string;
  orgId: string;
  timestamp: string; // ISO 8601 UTC
  action: AuditActionType;
  actor: {
    userId: string;
    role: UserRole;
    ipAddress?: string;
  };
  details: Record<string, unknown>;
  prevHash: string;
  currentHash: string;
}

export interface AuditState {
  orgId: string;
  lastVerifiedHash: string;
  updatedAt: string;
}

export interface AuthUser {
  userId: string;
  username: string;
  email: string;
  role: UserRole;
  orgId: string;
  createdAt: string;
}

export interface AuthTokens {
  accessToken: string;
  refreshToken?: string;
  expiresIn: number;
  tokenType: 'Bearer';
}

export interface TokenPayload {
  userId: string;
  email: string;
  username: string;
  role: UserRole;
  orgId: string;
  iat?: number;
  exp?: number;
  iss?: string;
  aud?: string;
}

export interface AuthSession {
  user: AuthUser;
  tokens: AuthTokens;
}

export interface ApiResponse<T> {
  success: boolean;
  data: T;
  meta?: {
    requestId?: string;
    timestamp: string;
    cursor?: string;
    hasMore?: boolean;
    total?: number;
  };
}

export interface ApiErrorResponse {
  success: false;
  error: {
    code: string;
    message: string;
    details?: unknown;
    requestId?: string;
  };
}

export interface PaginatedQuery {
  limit?: number;
  cursor?: string;
  sortOrder?: 'ASC' | 'DESC';
}

export interface EventQueryFilter extends PaginatedQuery {
  startTime?: string;
  endTime?: string;
  eventType?: string;
  severity?: Severity;
  sourceIp?: string;
  username?: string;
  sourceSystem?: string;
}
