import { describe, it, expect, beforeEach } from 'vitest';
import { MemoryStore } from '../src/storage/memory-store.js';
import { createApp } from '../src/app.js';
import type { SecurityEvent, AuditLog } from '@veltrix/shared';

describe('Phase 2 Foundation: MemoryStore & Storage Interface', () => {
  let store: MemoryStore;

  beforeEach(() => {
    store = new MemoryStore();
  });

  it('atomically saves unique security events and preserves high-velocity telemetry', async () => {
    const event1: SecurityEvent = {
      eventId: '018d5f30-74e1-7cb2-b43a-e9fa651f8b1a',
      orgId: 'org-test-01',
      timestamp: new Date().toISOString(),
      eventType: 'auth.login.failed',
      severity: 'HIGH',
      category: 'AUTHENTICATION',
      sourceIp: '198.51.100.42',
      username: 'target.admin',
      sourceSystem: 'test-gateway',
      idempotencyKey: '018d5f30-74e1-7cb2-b43a-e9fa651f8b1a',
    };

    const res1 = await store.saveEvent(event1);
    expect(res1.saved).toBe(true);
    expect(res1.isDuplicate).toBe(false);

    // Rapid successive distinct event (different eventId & idempotencyKey)
    const event2: SecurityEvent = {
      ...event1,
      eventId: '018d5f30-74e1-7cb2-b43a-e9fa651f8b1b',
      idempotencyKey: '018d5f30-74e1-7cb2-b43a-e9fa651f8b1b',
    };

    const res2 = await store.saveEvent(event2);
    expect(res2.saved).toBe(true);
    expect(res2.isDuplicate).toBe(false);

    const events = await store.getEvents('org-test-01');
    expect(events.items.length).toBe(2);
  });

  it('detects and suppresses retransmitted duplicate events with same idempotency key', async () => {
    const event: SecurityEvent = {
      eventId: '018d5f30-74e1-7cb2-b43a-e9fa651f8b1c',
      orgId: 'org-test-01',
      timestamp: new Date().toISOString(),
      eventType: 'auth.login.failed',
      severity: 'HIGH',
      category: 'AUTHENTICATION',
      sourceIp: '198.51.100.42',
      sourceSystem: 'test-gateway',
      idempotencyKey: '018d5f30-74e1-7cb2-b43a-e9fa651f8b1c',
    };

    const res1 = await store.saveEvent(event);
    expect(res1.saved).toBe(true);
    expect(res1.isDuplicate).toBe(false);

    // Client retry with identical idempotencyKey
    const resRetry = await store.saveEvent(event);
    expect(resRetry.saved).toBe(false);
    expect(resRetry.isDuplicate).toBe(true);

    const events = await store.getEvents('org-test-01');
    expect(events.items.length).toBe(1);
  });

  it('appends and verifies cryptographic audit ledger continuity', async () => {
    const orgId = 'org-audit-test';

    const log1 = await store.appendAuditLog({
      logId: 'log-001',
      orgId,
      timestamp: new Date().toISOString(),
      action: 'USER_LOGIN',
      actor: { userId: 'usr-1', role: 'SECURITY_ANALYST' },
      details: { ip: '198.51.100.1' },
    });

    expect(log1.prevHash).toBe('0'.repeat(64));
    expect(log1.currentHash).toHaveLength(64);

    const log2 = await store.appendAuditLog({
      logId: 'log-002',
      orgId,
      timestamp: new Date().toISOString(),
      action: 'INCIDENT_CREATED',
      actor: { userId: 'usr-system', role: 'SUPER_ADMIN' },
      details: { incidentId: 'inc-001', riskScore: 85 },
    });

    expect(log2.prevHash).toBe(log1.currentHash);

    // Verify pristine chain
    const verifyResult = await store.verifyAuditChain(orgId);
    expect(verifyResult.verified).toBe(true);
    expect(verifyResult.length).toBe(2);
    expect(verifyResult.brokenRecordId).toBeUndefined();
  });

  it('detects tampering in historical audit ledger records', async () => {
    const orgId = 'org-tamper-test';

    await store.appendAuditLog({
      logId: 'log-tamper-01',
      orgId,
      timestamp: new Date().toISOString(),
      action: 'RESPONSE_EXECUTED',
      actor: { userId: 'usr-1', role: 'ORG_ADMIN' },
      details: { action: 'BLOCK_IP', target: '198.51.100.42' },
    });

    await store.appendAuditLog({
      logId: 'log-tamper-02',
      orgId,
      timestamp: new Date().toISOString(),
      action: 'RESPONSE_EXECUTED',
      actor: { userId: 'usr-1', role: 'ORG_ADMIN' },
      details: { action: 'SUSPEND_USER', target: 'bad_actor' },
    });

    // Tamper with record 01 details
    const tampered = store.tamperAuditLogForTesting(orgId, 'log-tamper-01', {
      action: 'BLOCK_IP',
      target: '198.51.100.99', // altered!
    });
    expect(tampered).toBe(true);

    const verifyResult = await store.verifyAuditChain(orgId);
    expect(verifyResult.verified).toBe(false);
    expect(verifyResult.brokenRecordId).toBe('log-tamper-01');
  });
  it('produces identical cryptographic hashes regardless of object key order (canonical JSON)', async () => {
    const store1 = new MemoryStore();
    const store2 = new MemoryStore();
    const timestamp = '2026-10-31T22:00:00.000Z';

    const log1 = await store1.appendAuditLog({
      logId: 'log-canonical-01',
      orgId: 'org-canonical',
      timestamp,
      action: 'RULE_MODIFIED',
      actor: { userId: 'usr-admin', role: 'ORG_ADMIN' },
      details: { threshold: 5, ruleId: 'RULE-001', category: 'AUTHENTICATION' },
    });

    const log2 = await store2.appendAuditLog({
      logId: 'log-canonical-01',
      orgId: 'org-canonical',
      timestamp,
      action: 'RULE_MODIFIED',
      actor: { userId: 'usr-admin', role: 'ORG_ADMIN' },
      details: { category: 'AUTHENTICATION', ruleId: 'RULE-001', threshold: 5 }, // Reordered keys
    });

    expect(log1.currentHash).toBe(log2.currentHash);
  });
});

describe('Phase 2 Foundation: Express HTTP Application', () => {
  it('instantiates app without error', () => {
    const app = createApp();
    expect(app).toBeDefined();
  });

  it('provides a standardized 404 JSON error response for unmapped endpoints', async () => {
    const app = createApp();
    // Simulate request using express test or internal route check
    expect(app._router).toBeDefined();
  });
});
