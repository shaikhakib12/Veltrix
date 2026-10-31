import { randomBytes } from 'node:crypto';

/**
 * Generates an RFC 9562 UUIDv7 based on current timestamp (millisecond precision)
 * and cryptographically secure random bits.
 *
 * Layout:
 * - 48 bits: Unix timestamp in milliseconds
 * - 4 bits: Version 7 (0b0111 = 0x7)
 * - 12 bits: Random bits
 * - 2 bits: Variant 1 (0b10 = 0x8, 0x9, 0xa, 0xb)
 * - 62 bits: Random bits
 */
export function generateUuidV7(timestampMs: number = Date.now()): string {
  const bytes = randomBytes(16);
  const ts = BigInt(timestampMs);

  // 48-bit timestamp (big endian)
  bytes[0] = Number((ts >> 40n) & 0xffn);
  bytes[1] = Number((ts >> 32n) & 0xffn);
  bytes[2] = Number((ts >> 24n) & 0xffn);
  bytes[3] = Number((ts >> 16n) & 0xffn);
  bytes[4] = Number((ts >> 8n) & 0xffn);
  bytes[5] = Number(ts & 0xffn);

  // Version 7: 0x70 | (random & 0x0f)
  bytes[6] = 0x70 | ((bytes[6] ?? 0) & 0x0f);

  // Variant 1: 0x80 | (random & 0x3f)
  bytes[8] = 0x80 | ((bytes[8] ?? 0) & 0x3f);

  const hex = bytes.toString('hex');
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20),
  ].join('-');
}

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function isValidUuid(id: string): boolean {
  return typeof id === 'string' && UUID_REGEX.test(id);
}

/**
 * Extracts the ISO date string (YYYY-MM-DD) encoded in the high 48-bits of an RFC 9562 UUIDv7.
 * Enables direct O(1) DynamoDB time-sharded partition key lookup (ORG#{orgId}#DATE#{YYYY-MM-DD})
 * without executing an unbounded full-table scan.
 *
 * Returns null if the UUID is not a valid version 7 identifier.
 */
export function extractDateFromUuidV7(uuid: string): string | null {
  if (!isValidUuid(uuid)) return null;

  // Check version nibble: 13th character (index 14 with dashes) must be '7'
  if (uuid.charAt(14) !== '7') {
    return null;
  }

  const hexTs = uuid.slice(0, 8) + uuid.slice(9, 13);
  const timestampMs = parseInt(hexTs, 16);

  if (isNaN(timestampMs) || timestampMs <= 0) {
    return null;
  }

  return new Date(timestampMs).toISOString().slice(0, 10); // YYYY-MM-DD
}
