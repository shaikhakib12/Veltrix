import { z } from 'zod';
import {
  EVENT_CATEGORIES,
  SUPPORTED_EVENT_TYPES,
  SEVERITIES,
  INCIDENT_STATUSES,
  RESPONSE_ACTION_TYPES,
  USER_ROLES,
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
