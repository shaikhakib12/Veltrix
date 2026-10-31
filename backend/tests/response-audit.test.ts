import { describe, it, expect, beforeEach } from 'vitest';
import { ResponseEngine } from '../src/response/handler.js';
import { AuditLogger } from '../src/audit/integrityChain.js';
import { MemoryStore } from '../src/shared/db/memoryStore.js';
import { Incident } from '../src/shared/types/index.js';

describe('Module H & I: Defensive Response & Cryptographic Audit Trail', () => {
  let store: MemoryStore;
  let auditLogger: AuditLogger;
  let responseEngine: ResponseEngine;

  beforeEach(() => {
    store = MemoryStore.getInstance();
    store.reset();
    auditLogger = new AuditLogger(store);
    responseEngine = new ResponseEngine(store, auditLogger);
  });

  it('should queue high-impact actions for approval when approval is required', () => {
    const mockIncident: Incident = {
      incidentId: 'inc-test-01',
      orgId: 'org-enterprise-01',
      title: 'High Severity Attack',
      description: 'Test',
      status: 'NEW',
      severity: 'CRITICAL',
      riskScore: 90,
      riskBreakdown: {} as any,
      attackVector: 'Brute Force',
      sourceIp: '198.51.100.42',
      correlatedEventIds: ['evt-1'],
      timeline: [],
      recommendedResponse: 'BLOCK_IP',
      requiresApproval: true,
      containmentStatus: 'NONE',
      notes: [],
      isSimulated: true,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    store.incidents.set(mockIncident.incidentId, mockIncident);

    const execution = responseEngine.triggerResponse(mockIncident, 'BLOCK_IP', 'SYSTEM');
    expect(execution.status).toBe('PENDING_APPROVAL');
    expect(store.activeBlockedIps.has('198.51.100.42')).toBe(false);

    // Now Analyst approves the containment
    const approved = responseEngine.approveAction(execution.executionId, 'Alex Vance (Lead Analyst)');
    expect(approved.status).toBe('SUCCESS');
    expect(store.activeBlockedIps.has('198.51.100.42')).toBe(true);
    expect(mockIncident.containmentStatus).toBe('CONTAINED');
  });

  it('should support containment rollback (e.g. Unblock IP)', () => {
    const mockIncident: Incident = {
      incidentId: 'inc-test-02',
      orgId: 'org-enterprise-01',
      title: 'Attack',
      description: 'Test',
      status: 'NEW',
      severity: 'HIGH',
      riskScore: 70,
      riskBreakdown: {} as any,
      attackVector: 'Spray',
      sourceIp: '203.0.113.5',
      correlatedEventIds: [],
      timeline: [],
      recommendedResponse: 'BLOCK_IP',
      requiresApproval: false,
      containmentStatus: 'NONE',
      notes: [],
      isSimulated: true,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    const execution = responseEngine.triggerResponse(mockIncident, 'BLOCK_IP', 'AUTONOMOUS', true);
    expect(store.activeBlockedIps.has('203.0.113.5')).toBe(true);

    // Rollback
    const rolledBack = responseEngine.rollbackAction(execution.executionId, 'Alex Vance');
    expect(rolledBack.status).toBe('ROLLED_BACK');
    expect(store.activeBlockedIps.has('203.0.113.5')).toBe(false);
  });

  it('should maintain a valid SHA-256 cryptographic audit chain and detect tampering', () => {
    // Append 3 audit records
    auditLogger.log('org-1', 'user-1', 'LOGIN', 'WEB_PORTAL', 'SUCCESS');
    auditLogger.log('org-1', 'user-1', 'RULE_UPDATE', 'RULE-001', 'SUCCESS', { threshold: 3 });
    auditLogger.log('org-1', 'system', 'CONTAINMENT_EXEC', 'IP:198.51.100.42', 'SUCCESS');

    // Verification on pristine chain
    const verification = auditLogger.verifyChain();
    expect(verification.verified).toBe(true);
    expect(verification.totalRecordsChecked).toBeGreaterThanOrEqual(4); // includes genesis

    // Intentionally tamper with a historical record
    const target = store.auditLogs[1];
    target.action = 'TAMPERED_ACTION_MALICIOUS';

    // Verification should immediately detect tampering and fail
    const tamperedVerification = auditLogger.verifyChain();
    expect(tamperedVerification.verified).toBe(false);
    expect(tamperedVerification.brokenRecordId).toBe(target.logId);
    expect(tamperedVerification.error).toContain('Tampering detected');
  });
});
