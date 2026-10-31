import { z } from 'zod';

export const SecurityEventInputSchema = z.object({
  eventId: z.string().uuid().optional(),
  orgId: z.string().min(1).optional(),
  timestamp: z.string().datetime({ offset: true }).optional().or(z.string().regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/)),
  eventType: z.string().min(3).max(100),
  severity: z.enum(['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).optional(),
  category: z.enum(['AUTHENTICATION', 'NETWORK', 'PRIVILEGE', 'API', 'DATA_ACCESS', 'SYSTEM']),
  sourceIp: z.string().ip({ version: 'v4' }).or(z.string().ip({ version: 'v6' })).or(z.string().regex(/^(\d{1,3}\.){3}\d{1,3}$/)),
  username: z.string().min(1).max(150),
  sourceSystem: z.string().min(1).max(100),
  metadata: z.record(z.unknown()).optional(),
  isSimulated: z.boolean().optional(),
});

export const BatchSecurityEventInputSchema = z.object({
  events: z.array(SecurityEventInputSchema).min(1).max(100),
});

export type ValidatedSecurityEventInput = z.infer<typeof SecurityEventInputSchema>;
