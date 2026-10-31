import { describe, it, expect } from 'vitest';
import { SecurityEventInputSchema } from '../src/ingestion/validator.js';
import { normalizeEvent } from '../src/ingestion/normalizer.js';
import { computeIdempotencyHash } from '../src/shared/utils/crypto.js';

describe('Module B: Security Event Ingestion & Normalization', () => {
  it('should validate a compliant security event input', () => {
    const input = {
      eventType: 'auth.login.failed',
      category: 'AUTHENTICATION',
      sourceIp: '198.51.100.42',
      username: 'sarah.connors',
      sourceSystem: 'auth.service.corp',
      metadata: { attempt: 1 },
    };

    const parsed = SecurityEventInputSchema.safeParse(input);
    expect(parsed.success).toBe(true);
  });

  it('should reject malformed event input missing required fields', () => {
    const malformed = {
      eventType: 'auth.login.failed',
      // missing category, sourceIp, username, sourceSystem
    };

    const parsed = SecurityEventInputSchema.safeParse(malformed);
    expect(parsed.success).toBe(false);
  });

  it('should normalize event and compute SHA-256 idempotency hash', () => {
    const input = {
      eventType: 'auth.login.failed',
      category: 'AUTHENTICATION' as const,
      sourceIp: '198.51.100.42 ',
      username: ' Sarah.Connors ',
      sourceSystem: 'auth.service.corp',
    };

    const orgId = 'org-test-123';
    const normalized = normalizeEvent(input, orgId);

    expect(normalized.orgId).toBe(orgId);
    expect(normalized.sourceIp).toBe('198.51.100.42');
    expect(normalized.username).toBe('sarah.connors');
    expect(normalized.eventId).toBeDefined();
    expect(normalized.idempotencyHash).toHaveLength(64); // SHA-256 hex length
  });

  it('should generate matching idempotency hashes for duplicate retransmissions within same minute', () => {
    const timestamp = '2026-10-31T22:15:30.000Z';
    const hash1 = computeIdempotencyHash('org-1', 'auth.login.failed', '1.2.3.4', 'admin', timestamp);
    const hash2 = computeIdempotencyHash('org-1', 'auth.login.failed', '1.2.3.4', 'admin', '2026-10-31T22:15:45.000Z');
    const hashDifferentMinute = computeIdempotencyHash('org-1', 'auth.login.failed', '1.2.3.4', 'admin', '2026-10-31T22:16:00.000Z');

    expect(hash1).toBe(hash2);
    expect(hash1).not.toBe(hashDifferentMinute);
  });
});
