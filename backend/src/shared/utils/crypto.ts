import { createHash, randomUUID } from 'crypto';

/**
 * Computes a SHA-256 hash of any input payload.
 */
export function sha256(data: string | object): string {
  const content = typeof data === 'string' ? data : JSON.stringify(data);
  return createHash('sha256').update(content).digest('hex');
}

/**
 * Generates an event idempotency hash to detect duplicate re-transmissions.
 * Formula: SHA-256(orgId + eventType + sourceIp + username + minuteTimestamp)
 */
export function computeIdempotencyHash(
  orgId: string,
  eventType: string,
  sourceIp: string,
  username: string,
  timestampIso: string
): string {
  // Truncate timestamp to minute to catch burst duplicates
  const minuteWindow = timestampIso.slice(0, 16); // e.g. "2026-10-31T22:15"
  return sha256(`${orgId}:${eventType}:${sourceIp}:${username}:${minuteWindow}`);
}

/**
 * Generates a standard UUID
 */
export function generateId(prefix?: string): string {
  const id = randomUUID();
  return prefix ? `${prefix}-${id.slice(0, 8)}` : id;
}
