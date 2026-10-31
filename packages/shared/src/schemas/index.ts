import { z } from 'zod';
import {
  EVENT_CATEGORIES,
  SEVERITIES,
  INCIDENT_STATUSES,
  RESPONSE_ACTION_TYPES,
  USER_ROLES,
} from '../constants/index.js';

export const SeveritySchema = z.enum(SEVERITIES);
export const EventCategorySchema = z.enum(EVENT_CATEGORIES);
export const IncidentStatusSchema = z.enum(INCIDENT_STATUSES);
export const ResponseActionTypeSchema = z.enum(RESPONSE_ACTION_TYPES);
export const UserRoleSchema = z.enum(USER_ROLES);

export const SecurityEventSchema = z.object({
  eventId: z.string().uuid(),
  orgId: z.string().min(1, 'orgId is required'),
  timestamp: z.string().datetime({ message: 'Must be valid ISO 8601 UTC timestamp' }),
  eventType: z.string().min(1, 'eventType is required'),
  severity: SeveritySchema,
  category: EventCategorySchema,
  sourceIp: z.string().ip({ version: 'v4', message: 'Must be valid IPv4 address' })
    .or(z.string().ip({ version: 'v6', message: 'Must be valid IPv6 address' })),
  username: z.string().optional(),
  sourceSystem: z.string().min(1, 'sourceSystem is required'),
  metadata: z.record(z.unknown()).optional(),
  isSimulated: z.boolean().optional().default(false),
  idempotencyKey: z.string().optional(),
});

export const BatchSecurityEventsSchema = z.object({
  events: z.array(SecurityEventSchema).min(1).max(100, 'Batch limit is 100 events'),
});

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
