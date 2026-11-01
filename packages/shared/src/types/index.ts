import type {
  EVENT_CATEGORIES,
  SUPPORTED_EVENT_TYPES,
  SEVERITIES,
  INCIDENT_STATUSES,
  RESPONSE_ACTION_TYPES,
  RESPONSE_EXECUTION_STATUSES,
  USER_ROLES,
  AUDIT_ACTION_TYPES,
  WEBSITE_ENVIRONMENTS,
  WEBSITE_STATUSES,
  RISK_TIERS,
  VERIFICATION_METHODS,
  INTEGRATION_TYPES,
  INTEGRATION_STATUSES,
  WEB_CONFIDENCE_TIERS,
  WEB_ATTACK_TYPES,
  RISK_BANDS,
} from '../constants/index.js';

export type EventCategory = (typeof EVENT_CATEGORIES)[number];
export type SupportedEventType = (typeof SUPPORTED_EVENT_TYPES)[number];
export type Severity = (typeof SEVERITIES)[number];
export type IncidentStatus = (typeof INCIDENT_STATUSES)[number];
export type ResponseActionType = (typeof RESPONSE_ACTION_TYPES)[number];
export type ResponseExecutionStatus = (typeof RESPONSE_EXECUTION_STATUSES)[number];
export type UserRole = (typeof USER_ROLES)[number];
export type AuditActionType = (typeof AUDIT_ACTION_TYPES)[number];

export type WebConfidenceTier = (typeof WEB_CONFIDENCE_TIERS)[number];
export type WebAttackType = (typeof WEB_ATTACK_TYPES)[number];
export type RiskBand = (typeof RISK_BANDS)[number];

export type EvidenceProvenance =
  | 'TRUSTED_SERVER_COMPONENT'
  | 'AUTHENTICATED_COLLECTOR'
  | 'UNTRUSTED_CLIENT';

/**
 * Internal-only trusted evidence context used by approved server components
 * (such as active verification workers, canary probes, and internal audit jobs).
 * External clients, SDK users, webhooks, and integrations cannot construct this.
 */
export interface InternalTrustedEvidenceContext {
  verifiedProvenance: 'TRUSTED_SERVER_COMPONENT' | 'AUTHENTICATED_COLLECTOR';
  verifiedSignalIdentifiers: string[];
  verifierIdentity: string;
  verificationTimestamp: string;
  evidenceReferences: string[];
}

export interface WebSecurityEventMetadata {
  siteId?: string;
  domain?: string;
  httpMethod?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD' | 'OPTIONS';
  requestUri?: string;
  httpStatus?: number;
  responseTimeMs?: number;
  userAgent?: string;
  clientDeclaredAttackType?: string;
  matchedPatterns?: string[];
  wafAction?: 'ALLOW' | 'BLOCK' | 'CHALLENGE' | 'LOG';
  isBot?: boolean;
  ja3Fingerprint?: string;
  confidenceLevel?: WebConfidenceTier;
  corroboratingSignals?: string[];
  untrustedClientSignals?: string[];
  serverVerified?: boolean;
  evidenceProvenance?: EvidenceProvenance;
  verifiedSignals?: string[];
  responseSample?: string;
  errorMessage?: string;
  [key: string]: unknown;
}

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
  metadata?: WebSecurityEventMetadata | Record<string, unknown>;
  isSimulated?: boolean;
  idempotencyKey?: string;
  ingestedAt?: string; // Server-side ISO 8601 UTC receipt timestamp
  trustedEvidenceContext?: InternalTrustedEvidenceContext;
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

export interface DetectionEvidence {
  matchedRuleId: string;
  matchedThreshold: number;
  actualCount?: number;
  timeWindowSeconds?: number;
  targetEntity?: {
    type: 'IP' | 'USER' | 'SYSTEM' | 'RESOURCE';
    value: string;
  };
  triggeringEvents: string[]; // eventIds
  details: Record<string, unknown>;
}

export interface Detection {
  detectionId: string;
  ruleId: string;
  ruleName: string;
  orgId: string;
  severity: Severity;
  confidence: number; // 0 - 100
  category: EventCategory;
  title: string;
  description: string;
  detectedAt: string; // ISO 8601 UTC
  relatedEventIds: string[];
  evidence: DetectionEvidence;
  mitreAttack?: {
    techniqueId: string;
    techniqueName: string;
    tactic: string;
  };
  status?: 'ACTIVE' | 'RESOLVED' | 'SUPPRESSED';
  dedupKey?: string;
  ttl?: number;
}

export interface DetectionQueryOptions {
  ruleId?: string;
  severity?: Severity;
  status?: 'ACTIVE' | 'RESOLVED' | 'SUPPRESSED';
  siteId?: string;
  startTime?: string;
  endTime?: string;
  limit?: number;
  cursor?: string;
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

export interface WebRiskFactors extends RiskScoreFactors {
  vulnerabilityMatchTerm: number;
  riskBand: RiskBand;
  calculationExplanation: string;
  contributingFactors: {
    eventCount: number;
    detectedAttackTypes: string[];
    highestConfidence: WebConfidenceTier;
    assetEnvironment: string;
    threatIntelStatus: string;
    vulnerabilityOverlap?: {
      overlapLevel: 'EXACT' | 'PATH' | 'ASSET' | 'NONE';
      weight: number;
      findingCvss: number;
      confidenceMultiplier: number;
      termValue: number;
    };
  };
}

export interface TimelineEntry {
  timestamp: string;
  eventType: string;
  description: string;
  sourceIp?: string;
  username?: string;
  mitreTactic?: string;
  details?: Record<string, unknown>;
}

export interface VulnerabilityFindingSummary {
  findingId: string;
  siteId: string;
  vulnType: string;
  targetUri: string;
  targetParameter?: string;
  cvssScore: number;
  severity: Severity;
  status: 'OPEN' | 'CONFIRMED' | 'IN_REMEDIATION' | 'RESOLVED' | 'ACCEPTED_RISK' | 'FALSE_POSITIVE';
}

export interface Incident {
  incidentId: string;
  orgId: string;
  title: string;
  description: string;
  severity: Severity;
  riskScore: number;
  riskFactors: RiskScoreFactors | WebRiskFactors;
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

  // Website Asset Monitoring extensions (Phase 7)
  siteId?: string;
  domain?: string;
  sourceIp?: string;
  attackTypes?: string[];
  highestConfidence?: WebConfidenceTier;
  riskBand?: RiskBand;
  webRiskFactors?: WebRiskFactors;
}

export type IndicatorProvenance = 'VERIFIED_FEED' | 'MANUAL_ANALYST';

export interface ThreatIndicator {
  indicatorId: string;
  type: 'IP' | 'DOMAIN' | 'HASH' | 'USER_AGENT';
  value: string;
  threatType: string;
  severity: Severity;
  confidence: number; // 0 - 100
  source: string;
  provenance: IndicatorProvenance;
  orgId?: string; // Tenant-specific for manual indicators, 'global' or undefined for global verified feeds
  submittedBy?: string; // Verified username of manual analyst
  retrievedAt?: string; // Retrieval timestamp for external feeds
  firstSeen: string;
  lastSeen: string;
  expiresAt?: string;
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

export type WebsiteEnvironment = (typeof WEBSITE_ENVIRONMENTS)[number];
export type WebsiteStatus = (typeof WEBSITE_STATUSES)[number];
export type RiskTier = (typeof RISK_TIERS)[number];
export type VerificationMethod = (typeof VERIFICATION_METHODS)[number];

export interface WebsiteHealth {
  telemetryStatus: 'HEALTHY' | 'DEGRADED' | 'INACTIVE';
  lastEventReceivedAt?: string;
  eventsPerMinute?: number;
}

export interface WebsiteAsset {
  siteId: string;
  orgId: string;
  name: string;
  primaryDomain: string;
  approvedSubdomains: string[];
  environment: WebsiteEnvironment;
  status: WebsiteStatus;
  riskTier: RiskTier;
  tags: string[];
  verificationToken: string;
  tokenHash?: string;
  tokenCreatedAt: string;
  dnsTxtRecord: {
    host: string;
    value: string;
  };
  httpChallenge: {
    url: string;
    expectedBody: {
      veltrixChallengeToken: string;
      orgId: string;
    };
  };
  verifiedAt?: string;
  expiresAt?: string;
  gracePeriodEndsAt?: string;
  verificationAttempts?: number;
  lastVerificationAttemptAt?: string;
  scanBlocked: boolean;
  health: WebsiteHealth;
  createdAt: string;
  updatedAt: string;
}

export type IntegrationType = (typeof INTEGRATION_TYPES)[number];
export type IntegrationStatus = (typeof INTEGRATION_STATUSES)[number];

export interface IntegrationHealth {
  status: 'HEALTHY' | 'DEGRADED' | 'INACTIVE' | 'ERROR';
  eventsReceived: number;
  lastError?: string;
  lastSuccessAt?: string;
  lastFailedAt?: string;
}

export interface Integration {
  integrationId: string;
  orgId: string;
  siteId?: string;
  name: string;
  type: IntegrationType;
  status: IntegrationStatus;
  description?: string;
  apiKeyPrefix: string;
  apiKeyHash: string;
  secretKey?: string;
  lastSeenAt?: string;
  health: IntegrationHealth;
  createdAt: string;
  updatedAt: string;
}
