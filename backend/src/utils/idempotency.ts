import { createHash } from 'node:crypto';

/**
 * Deterministically serializes any JavaScript value into a canonical JSON string:
 * - Recursively sorts object keys alphabetically
 * - Eliminates whitespace variation
 * - Ignores volatile or transport-specific fields like `idempotencyKey` when hashing payload data
 */
export function canonicalizeJson(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return '[' + value.map(canonicalizeJson).join(',') + ']';
  }

  const obj = value as Record<string, unknown>;
  const sortedKeys = Object.keys(obj).sort();
  const entries: string[] = [];

  for (const key of sortedKeys) {
    // Exclude undefined values and transport idempotencyKey from semantic payload hash
    if (obj[key] === undefined || key === 'idempotencyKey') {
      continue;
    }
    entries.push(`${JSON.stringify(key)}:${canonicalizeJson(obj[key])}`);
  }

  return '{' + entries.join(',') + '}';
}

/**
 * Computes a deterministic SHA-256 hash of a request payload.
 * Guarantee: Two payloads with identical semantic properties (regardless of key order
 * or formatting whitespace) produce the exact same hex digest.
 */
export function computePayloadHash(payload: unknown): string {
  const canonical = canonicalizeJson(payload);
  return createHash('sha256').update(canonical, 'utf8').digest('hex');
}
