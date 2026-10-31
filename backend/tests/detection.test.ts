import { describe, it, expect, beforeEach } from 'vitest';
import { DetectionEngine } from '../src/detection/engine.js';
import { normalizeEvent } from '../src/ingestion/normalizer.js';

describe('Module C: Threat Detection Engine', () => {
  let engine: DetectionEngine;
  const orgId = 'org-test';

  beforeEach(() => {
    engine = new DetectionEngine();
  });

  it('should load all 10 built-in detection rules', () => {
    const rules = engine.getRules();
    expect(rules).toHaveLength(10);
    expect(rules.map(r => r.ruleId)).toContain('RULE-001');
    expect(rules.map(r => r.ruleId)).toContain('RULE-007');
  });

  it('should trigger RULE-001 on 5 consecutive failed logins within 120 seconds', () => {
    const ip = '198.51.100.42';
    let triggers = [];

    // Send 4 failed logins
    for (let i = 0; i < 4; i++) {
      const event = normalizeEvent({
        eventType: 'auth.login.failed',
        category: 'AUTHENTICATION',
        sourceIp: ip,
        username: 'user1',
        sourceSystem: 'auth.corp',
      }, orgId);
      triggers = engine.evaluateEvent(event);
      expect(triggers).toHaveLength(0); // Not reached threshold yet
    }

    // 5th failed login triggers RULE-001
    const event5 = normalizeEvent({
      eventType: 'auth.login.failed',
      category: 'AUTHENTICATION',
      sourceIp: ip,
      username: 'user1',
      sourceSystem: 'auth.corp',
    }, orgId);
    triggers = engine.evaluateEvent(event5);

    expect(triggers).toHaveLength(1);
    expect(triggers[0].ruleId).toBe('RULE-001');
    expect(triggers[0].mitreAttack.techniqueId).toBe('T1110.001');
    expect(triggers[0].matchedCount).toBe(5);
  });

  it('should trigger RULE-006 on privilege escalation indicators', () => {
    const event = normalizeEvent({
      eventType: 'iam.privilege.escalation.attempt',
      category: 'PRIVILEGE',
      sourceIp: '10.0.0.50',
      username: 'rogue.user',
      sourceSystem: 'aws.iam',
      metadata: { targetRole: 'AdministratorAccess' },
    }, orgId);

    const triggers = engine.evaluateEvent(event);
    expect(triggers.length).toBeGreaterThanOrEqual(1);
    expect(triggers[0].ruleId).toBe('RULE-006');
    expect(triggers[0].severity).toBe('HIGH');
  });

  it('should trigger RULE-007 on bulk sensitive data exfiltration', () => {
    const event = normalizeEvent({
      eventType: 'data.exfiltration.bulk.query',
      category: 'DATA_ACCESS',
      sourceIp: '198.51.100.99',
      username: 'exfil.actor',
      sourceSystem: 'database.vault',
      metadata: { records: 25000 },
    }, orgId);

    const triggers = engine.evaluateEvent(event);
    expect(triggers.length).toBeGreaterThanOrEqual(1);
    expect(triggers[0].ruleId).toBe('RULE-007');
    expect(triggers[0].severity).toBe('CRITICAL');
  });

  it('should support dynamic rule updates and threshold adjustments', () => {
    const updated = engine.updateRule('RULE-001', { threshold: 2, enabled: true });
    expect(updated?.threshold).toBe(2);

    const evt1 = normalizeEvent({
      eventType: 'auth.login.failed',
      category: 'AUTHENTICATION',
      sourceIp: '1.1.1.1',
      username: 'admin',
      sourceSystem: 'auth',
    }, orgId);
    engine.evaluateEvent(evt1);

    const evt2 = normalizeEvent({
      eventType: 'auth.login.failed',
      category: 'AUTHENTICATION',
      sourceIp: '1.1.1.1',
      username: 'admin',
      sourceSystem: 'auth',
    }, orgId);
    const triggers = engine.evaluateEvent(evt2);

    expect(triggers).toHaveLength(1);
    expect(triggers[0].ruleId).toBe('RULE-001');
  });
});
