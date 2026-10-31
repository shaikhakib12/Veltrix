import { SecurityEvent, EventSeverity } from '../shared/types/index.js';
import { ValidatedSecurityEventInput } from './validator.js';
import { computeIdempotencyHash, generateId } from '../shared/utils/crypto.js';

export function normalizeEvent(
  input: ValidatedSecurityEventInput,
  authenticatedOrgId: string
): SecurityEvent {
  const eventId = input.eventId || generateId('evt');
  const orgId = authenticatedOrgId;
  const timestamp = input.timestamp ? new Date(input.timestamp).toISOString() : new Date().toISOString();
  const receivedAt = new Date().toISOString();

  let severity: EventSeverity = input.severity || 'INFO';
  if (!input.severity) {
    if (input.eventType.includes('failed') || input.eventType.includes('anomaly')) {
      severity = 'MEDIUM';
    } else if (input.eventType.includes('escalate') || input.eventType.includes('exfiltration')) {
      severity = 'HIGH';
    } else if (input.eventType.includes('c2') || input.eventType.includes('ransomware')) {
      severity = 'CRITICAL';
    }
  }

  const sourceIp = input.sourceIp.trim();
  const username = input.username.trim().toLowerCase();
  const sourceSystem = input.sourceSystem.trim();
  const metadata = input.metadata || {};
  const isSimulated = Boolean(input.isSimulated);

  const idempotencyHash = computeIdempotencyHash(
    orgId,
    input.eventType,
    sourceIp,
    username,
    timestamp
  );

  return {
    eventId,
    orgId,
    timestamp,
    eventType: input.eventType,
    severity,
    category: input.category,
    sourceIp,
    username,
    sourceSystem,
    metadata,
    idempotencyHash,
    isSimulated,
    receivedAt,
  };
}
