import { createHmac, createHash } from 'node:crypto';
import type { EventQueryOptions } from '../storage/storage-interface.js';

export interface CursorPayload {
  orgId: string;
  filterHash: string;
  offset?: number;
  exclusiveStartKey?: Record<string, unknown>;
  issuedAt: number;
}

/**
 * Computes a deterministic SHA-256 fingerprint of query filters to bind the cursor
 * strictly to the query context it was issued for, preventing cursor reuse across mismatched queries.
 */
export function computeFilterHash(options?: EventQueryOptions): string {
  if (!options) return 'all';
  const canonical = [
    options.eventType || '',
    options.severity || '',
    options.sourceIp || '',
    options.username || '',
    options.sourceSystem || '',
    options.startTime || '',
    options.endTime || '',
  ].join('|');
  return createHash('sha256').update(canonical, 'utf8').digest('hex').slice(0, 16);
}

/**
 * Signs a pagination cursor using HMAC-SHA256.
 * Returns a URL-safe Base64 string with detached HMAC signature: `<base64Data>.<hmacSignature>`
 */
export function signCursor(
  payload: Omit<CursorPayload, 'issuedAt'>,
  secret?: string
): string {
  const cursorSecret =
    secret ||
    process.env.JWT_SECRET ||
    'veltrix-default-cursor-secret-signing-key-32chars';

  const fullPayload: CursorPayload = {
    ...payload,
    issuedAt: Date.now(),
  };

  const jsonStr = JSON.stringify(fullPayload);
  const base64Data = Buffer.from(jsonStr, 'utf8').toString('base64url');
  const hmac = createHmac('sha256', cursorSecret).update(base64Data).digest('base64url');

  return `${base64Data}.${hmac}`;
}

/**
 * Verifies and decodes a signed pagination cursor:
 * 1. Validates HMAC signature against tampering.
 * 2. Enforces tenant binding (rejects cross-tenant cursors).
 * 3. Enforces query filter binding (rejects cursor reuse across different filters).
 * 4. Enforces non-negative integer offset boundary.
 * 5. Enforces cursor TTL (24-hour expiration window).
 */
export function verifyCursor(
  cursorStr: string,
  expectedOrgId: string,
  currentOptions?: EventQueryOptions,
  secret?: string
): CursorPayload {
  if (!cursorStr || typeof cursorStr !== 'string') {
    throw new Error('INVALID_CURSOR: Missing cursor parameter');
  }

  const parts = cursorStr.split('.');
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    throw new Error('INVALID_CURSOR: Malformed cursor format or missing signature');
  }

  const [base64Data, hmac] = parts;
  const cursorSecret =
    secret ||
    process.env.JWT_SECRET ||
    'veltrix-default-cursor-secret-signing-key-32chars';

  const expectedHmac = createHmac('sha256', cursorSecret).update(base64Data).digest('base64url');

  if (hmac !== expectedHmac) {
    throw new Error('INVALID_CURSOR: Tampered cursor or signature verification failure');
  }

  let payload: CursorPayload;
  try {
    payload = JSON.parse(Buffer.from(base64Data, 'base64url').toString('utf8'));
  } catch {
    throw new Error('INVALID_CURSOR: Unparseable cursor payload');
  }

  if (!payload || typeof payload !== 'object') {
    throw new Error('INVALID_CURSOR: Invalid payload structure');
  }

  // 1. Enforce strict Tenant Binding
  if (payload.orgId !== expectedOrgId) {
    throw new Error('INVALID_CURSOR: Cross-tenant cursor reuse prohibited');
  }

  // 2. Enforce Query Filter Binding
  const expectedFilterHash = computeFilterHash(currentOptions);
  if (payload.filterHash !== expectedFilterHash) {
    throw new Error('INVALID_CURSOR: Cursor is bound to different query filters and cannot be reused');
  }

  // 3. Enforce Non-Negative Integer Offset
  if (payload.offset !== undefined) {
    if (!Number.isInteger(payload.offset) || payload.offset < 0) {
      throw new Error('INVALID_CURSOR: Offset must be a non-negative integer');
    }
  }

  // 4. Enforce Cursor Expiration (24 hours TTL)
  const MAX_CURSOR_AGE_MS = 24 * 60 * 60 * 1000;
  if (Date.now() - payload.issuedAt > MAX_CURSOR_AGE_MS) {
    throw new Error('INVALID_CURSOR: Cursor has expired');
  }

  return payload;
}
