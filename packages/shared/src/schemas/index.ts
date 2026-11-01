import { z } from 'zod';
import {
  EVENT_CATEGORIES,
  SUPPORTED_EVENT_TYPES,
  SEVERITIES,
  INCIDENT_STATUSES,
  RESPONSE_ACTION_TYPES,
  USER_ROLES,
  WEBSITE_ENVIRONMENTS,
  WEBSITE_STATUSES,
  RISK_TIERS,
  VERIFICATION_METHODS,
  INTEGRATION_TYPES,
  INTEGRATION_STATUSES,
} from '../constants/index.js';

export const SeveritySchema = z.enum(SEVERITIES);
export const EventCategorySchema = z.enum(EVENT_CATEGORIES);
export const SupportedEventTypeSchema = z.enum(SUPPORTED_EVENT_TYPES);
export const IncidentStatusSchema = z.enum(INCIDENT_STATUSES);
export const ResponseActionTypeSchema = z.enum(RESPONSE_ACTION_TYPES);
export const UserRoleSchema = z.enum(USER_ROLES);

export const SecurityEventSchema = z.object({
  eventId: z.string().uuid({ message: 'Must be a valid UUID' }),
  orgId: z.string().min(1, 'orgId is required'),
  timestamp: z.string().datetime({ message: 'Must be valid ISO 8601 UTC timestamp' }),
  eventType: SupportedEventTypeSchema,
  severity: SeveritySchema,
  category: EventCategorySchema,
  sourceIp: z.string().ip({ version: 'v4', message: 'Must be valid IPv4 address' })
    .or(z.string().ip({ version: 'v6', message: 'Must be valid IPv6 address' })),
  username: z.string().optional(),
  sourceSystem: z.string().min(1, 'sourceSystem is required'),
  metadata: z.record(z.unknown()).optional(),
  isSimulated: z.boolean().optional().default(false),
  idempotencyKey: z.string().optional(),
  ingestedAt: z.string().datetime({ message: 'Must be valid ISO 8601 UTC timestamp' }).optional(),
}).strict();

// Schema for client-submitted event (eventId, orgId, timestamp are optional on ingest)
export const SingleEventIngestSchema = z.object({
  eventId: z.string().uuid({ message: 'Must be a valid UUID (UUIDv7 or UUIDv4)' }).optional(),
  orgId: z.string().min(1, 'orgId cannot be empty').optional(),
  timestamp: z.string().datetime({ offset: true, message: 'Must be valid ISO 8601 timestamp' }).optional(),
  eventType: SupportedEventTypeSchema,
  severity: SeveritySchema,
  category: EventCategorySchema,
  sourceIp: z.string().ip({ version: 'v4', message: 'Must be valid IPv4 address' })
    .or(z.string().ip({ version: 'v6', message: 'Must be valid IPv6 address' })),
  username: z.string().optional(),
  sourceSystem: z.string().min(1, 'sourceSystem is required'),
  metadata: z.record(z.unknown()).optional(),
  isSimulated: z.boolean().optional().default(false),
  idempotencyKey: z.string().optional(),
}).strict();

export const BatchSecurityEventsSchema = z.object({
  events: z.array(SingleEventIngestSchema).min(1, 'Batch must contain at least 1 event').max(100, 'Batch limit is 100 events'),
}).strict();

export const EventQueryRequestSchema = z.object({
  limit: z.coerce.number().int().min(1, 'Limit must be at least 1').max(100, 'Limit cannot exceed 100').default(50),
  cursor: z.string().optional(),
  startTime: z.string().datetime({ offset: true, message: 'startTime must be valid ISO 8601 timestamp' }).optional(),
  endTime: z.string().datetime({ offset: true, message: 'endTime must be valid ISO 8601 timestamp' }).optional(),
  eventType: SupportedEventTypeSchema.optional(),
  severity: SeveritySchema.optional(),
  sourceIp: z.string().ip({ version: 'v4' }).or(z.string().ip({ version: 'v6' })).optional(),
  username: z.string().optional(),
  sourceSystem: z.string().optional(),
}).refine(
  (data) => {
    if (data.startTime && data.endTime) {
      return new Date(data.startTime).getTime() <= new Date(data.endTime).getTime();
    }
    return true;
  },
  {
    message: 'startTime must be chronologically before or equal to endTime',
    path: ['startTime'],
  }
);

export const DetectionRuleSchema = z.object({
  ruleId: z.string().min(1),
  orgId: z.string().min(1),
  name: z.string().min(3),
  description: z.string().min(5),
  category: EventCategorySchema,
  severity: SeveritySchema,
  mitreAttack: z.object({
    techniqueId: z.string(),
    techniqueName: z.string(),
    tactic: z.string(),
  }).optional(),
  condition: z.record(z.unknown()),
  slidingWindowSeconds: z.number().int().positive().max(86400),
  threshold: z.number().int().positive(),
  isEnabled: z.boolean().default(true),
});

export const IncidentUpdateSchema = z.object({
  status: IncidentStatusSchema.optional(),
  assignedTo: z.string().optional(),
  severity: SeveritySchema.optional(),
  note: z.string().min(1).max(2000).optional(),
});

export const ResponseExecutionRequestSchema = z.object({
  incidentId: z.string().min(1),
  actionType: ResponseActionTypeSchema,
  target: z.string().min(1),
  parameters: z.record(z.unknown()).optional(),
  isSimulated: z.boolean().default(true),
});

export const ResponseApprovalSchema = z.object({
  executionId: z.string().min(1),
  approved: z.boolean(),
  reason: z.string().min(3),
});

// Auth Schemas (TASK-301)
export const AuthLoginRequestSchema = z.object({
  email: z.string().email('Invalid email address format'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
  orgId: z.string().optional(),
});

export const AuthRegisterRequestSchema = z.object({
  email: z.string().email('Invalid email address format'),
  password: z
    .string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[0-9]/, 'Password must contain at least one number')
    .regex(/[^A-Za-z0-9]/, 'Password must contain at least one special character'),
  username: z.string().min(3, 'Username must be at least 3 characters'),
  role: UserRoleSchema.default('SECURITY_ANALYST'),
  orgId: z.string().min(1, 'Organization ID is required'),
});

export const AuthRefreshRequestSchema = z.object({
  refreshToken: z.string().min(1, 'Refresh token is required'),
});

// Detection Schemas (TASK-501 to TASK-504)
export const DetectionEvidenceSchema = z.object({
  matchedRuleId: z.string().min(1),
  matchedThreshold: z.number().int().positive(),
  actualCount: z.number().int().nonnegative().optional(),
  timeWindowSeconds: z.number().int().positive().optional(),
  targetEntity: z
    .object({
      type: z.enum(['IP', 'USER', 'SYSTEM', 'RESOURCE']),
      value: z.string().min(1),
    })
    .optional(),
  triggeringEvents: z.array(z.string()).optional(),
  details: z.record(z.unknown()).optional(),
});

export const DetectionSchema = z.object({
  detectionId: z.string().min(1),
  ruleId: z.string().min(1),
  ruleName: z.string().min(1),
  orgId: z.string().min(1),
  severity: SeveritySchema,
  confidence: z.number().min(0).max(100),
  category: EventCategorySchema,
  title: z.string().min(3),
  description: z.string().min(5),
  detectedAt: z.string().datetime(),
  relatedEventIds: z.array(z.string()),
  evidence: DetectionEvidenceSchema,
  mitreAttack: z
    .object({
      techniqueId: z.string(),
      techniqueName: z.string(),
      tactic: z.string(),
    })
    .optional(),
  status: z.enum(['ACTIVE', 'RESOLVED', 'SUPPRESSED']).default('ACTIVE'),
  dedupKey: z.string().optional(),
  ttl: z.number().int().positive().optional(),
});

export const DetectionQuerySchema = z
  .object({
    limit: z.coerce.number().int().min(1).max(100).default(50),
    cursor: z.string().optional(),
    ruleId: z.string().optional(),
    severity: SeveritySchema.optional(),
    status: z.enum(['ACTIVE', 'RESOLVED', 'SUPPRESSED']).optional(),
    startTime: z.string().datetime({ message: 'startTime must be a valid ISO 8601 UTC timestamp' }).optional(),
    endTime: z.string().datetime({ message: 'endTime must be a valid ISO 8601 UTC timestamp' }).optional(),
  })
  .refine(
    (data) => {
      if (data.startTime && data.endTime) {
        return new Date(data.startTime) <= new Date(data.endTime);
      }
      return true;
    },
    {
      message: 'startTime must be before or equal to endTime',
      path: ['startTime'],
    }
  );

export const DetectionRunRequestSchema = z.object({
  startTime: z.string().datetime({ message: 'startTime must be a valid ISO 8601 UTC timestamp' }).optional(),
  endTime: z.string().datetime({ message: 'endTime must be a valid ISO 8601 UTC timestamp' }).optional(),
  ruleIds: z.array(z.string()).optional(),
  limit: z.coerce.number().int().min(1).max(1000).default(500),
  persistDetections: z.boolean().default(true),
});

export const DetectionRuleUpdateSchema = z.object({
  isEnabled: z.boolean().optional(),
  severity: SeveritySchema.optional(),
  threshold: z.number().int().positive().optional(),
  slidingWindowSeconds: z.number().int().positive().max(86400).optional(),
  condition: z.record(z.unknown()).optional(),
});

export const DetectionRuleTestRequestSchema = z.object({
  ruleId: z.string().min(1),
  threshold: z.number().int().positive().optional(),
  slidingWindowSeconds: z.number().int().positive().max(86400).optional(),
  sampleEvents: z.array(SingleEventIngestSchema).min(1).max(100),
});


export const ThreatIndicatorCreateSchema = z.object({
  type: z.enum(['IP', 'DOMAIN', 'HASH', 'USER_AGENT']),
  value: z.string().min(1, 'Value is required'),
  threatType: z.string().min(1, 'Threat type is required'),
  severity: SeveritySchema,
  confidence: z.number().int().min(0).max(100),
  source: z.string().optional(),
  description: z.string().optional(),
  firstSeen: z.string().datetime({ offset: true }).optional(),
  lastSeen: z.string().datetime({ offset: true }).optional(),
  expiresAt: z.string().datetime({ offset: true }).optional(),
  isFlagged: z.boolean().default(true),
  metadata: z.record(z.unknown()).optional(),
}).strict();

export const FeedIndicatorIngestSchema = z.object({
  type: z.enum(['IP', 'DOMAIN', 'HASH', 'USER_AGENT']),
  value: z.string().min(1, 'Value is required'),
  threatType: z.string().min(1, 'Threat type is required'),
  severity: SeveritySchema,
  confidence: z.number().int().min(0).max(100),
  description: z.string().optional(),
  firstSeen: z.string().datetime({ offset: true }).optional(),
  lastSeen: z.string().datetime({ offset: true }).optional(),
  expiresAt: z.string().datetime({ offset: true }).optional(),
  isFlagged: z.boolean().default(true),
  metadata: z.record(z.unknown()).optional(),
}).strict();

export const ThreatIndicatorUpdateSchema = z.object({
  severity: SeveritySchema.optional(),
  confidence: z.number().int().min(0).max(100).optional(),
  isFlagged: z.boolean().optional(),
  expiresAt: z.string().datetime({ offset: true }).optional(),
  metadata: z.record(z.unknown()).optional(),
}).strict();

export const WebsiteEnvironmentSchema = z.enum(WEBSITE_ENVIRONMENTS);
export const WebsiteStatusSchema = z.enum(WEBSITE_STATUSES);
export const RiskTierSchema = z.enum(RISK_TIERS);
export const VerificationMethodSchema = z.enum(VERIFICATION_METHODS);
export const IntegrationTypeSchema = z.enum(INTEGRATION_TYPES);
export const IntegrationStatusSchema = z.enum(INTEGRATION_STATUSES);

export const FQDN_REGEX = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

export const WebsiteCreateRequestSchema = z.object({
  name: z.string().min(2, 'Name must be at least 2 characters').max(100, 'Name must be at most 100 characters'),
  primaryDomain: z.string().trim().toLowerCase().regex(FQDN_REGEX, 'Must be a valid FQDN domain (e.g. app.example.com)'),
  approvedSubdomains: z.array(z.string().trim().toLowerCase().regex(FQDN_REGEX, 'Invalid subdomain FQDN')).default([]),
  environment: WebsiteEnvironmentSchema.default('PRODUCTION'),
  riskTier: RiskTierSchema.default('MEDIUM'),
  tags: z.array(z.string().min(1).max(50)).default([]),
}).strict();

export const WebsiteUpdateRequestSchema = z.object({
  name: z.string().min(2).max(100).optional(),
  approvedSubdomains: z.array(z.string().trim().toLowerCase().regex(FQDN_REGEX, 'Invalid subdomain FQDN')).optional(),
  environment: WebsiteEnvironmentSchema.optional(),
  riskTier: RiskTierSchema.optional(),
  tags: z.array(z.string().min(1).max(50)).optional(),
}).strict();

export const DomainVerifyRequestSchema = z.object({
  method: VerificationMethodSchema,
}).strict();

export const IntegrationCreateRequestSchema = z.object({
  name: z.string().min(2, 'Name must be at least 2 characters').max(100, 'Name must be at most 100 characters'),
  type: IntegrationTypeSchema,
  siteId: z.string().optional(),
  description: z.string().max(500).optional(),
}).strict();

export const IntegrationUpdateRequestSchema = z.object({
  name: z.string().min(2).max(100).optional(),
  status: IntegrationStatusSchema.optional(),
  description: z.string().max(500).optional(),
}).strict();
