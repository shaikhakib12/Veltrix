import { describe, it, expect, beforeEach } from 'vitest';
import { CorrelationEngine } from '../src/correlation/engine.js';
import { RiskEngine } from '../src/risk-engine/scorer.js';
import { MemoryStore } from '../src/shared/db/memoryStore.js';
import { DetectionTrigger, SecurityEvent } from '../src/shared/types/index.js';

describe('Module D & E: Event Correlation & Explainable Risk Scoring', () => {
  let store: MemoryStore;
  let correlationEngine: CorrelationEngine;

  beforeEach(() => {
    store = MemoryStore.getInstance();
    store.reset();
    correlationEngine = new CorrelationEngine(store);
  });

  it('should calculate an explainable risk score with factor breakdown', () => {
    const calculation = RiskEngine.calculate({
      baseSeverity: 'HIGH',
      eventCount: 6,
      targetAccount: 'ciso@cyberdefend.corp', // Privileged identity
      sourceIp: '198.51.100.42',
      threatIndicator: store.indicators.get('198.51.100.42'), // Confirmed Tor exit node
      killChainStagesCount: 3, // Multi-stage attack
    });

    expect(calculation.totalScore).toBeGreaterThanOrEqual(75);
    expect(calculation.tier).toBe('CRITICAL');
    expect(calculation.factors).toHaveLength(5);
    expect(calculation.explanation).toContain('CRITICAL');
    expect(calculation.baseScore).toBe(65);
    expect(calculation.sequenceBonus).toBe(25);
  });

  it('should correlate multiple detection triggers into a unified incident timeline', () => {
    const trigger1: DetectionTrigger = {
      triggerId: 'trig-1',
      ruleId: 'RULE-001',
      ruleName: 'Distributed Brute-Force Authentication Attempt',
      orgId: 'org-enterprise-01',
      timestamp: new Date().toISOString(),
      severity: 'HIGH',
      mitreAttack: {
        tactic: 'Credential Access',
        techniqueId: 'T1110.001',
        techniqueName: 'Brute Force',
        url: '',
      },
      entityKey: 'sourceIp:198.51.100.42',
      contributingEventIds: ['evt-1', 'evt-2', 'evt-3', 'evt-4', 'evt-5'],
      matchedCount: 5,
      explanation: '5 failed logins',
      isSimulated: true,
    };

    const incident1 = correlationEngine.correlateTrigger(trigger1);
    expect(incident1.incidentId).toBeDefined();
    expect(incident1.timeline).toHaveLength(1);
    expect(incident1.sourceIp).toBe('198.51.100.42');

    // Second trigger from the same attacker targeting same user
    const trigger2: DetectionTrigger = {
      triggerId: 'trig-2',
      ruleId: 'RULE-006',
      ruleName: 'Privilege Escalation Indicator',
      orgId: 'org-enterprise-01',
      timestamp: new Date().toISOString(),
      severity: 'HIGH',
      mitreAttack: {
        tactic: 'Privilege Escalation',
        techniqueId: 'T1068',
        techniqueName: 'Exploitation for Privilege Escalation',
        url: '',
      },
      entityKey: 'sourceIp:198.51.100.42',
      contributingEventIds: ['evt-6'],
      matchedCount: 1,
      explanation: 'IAM role escalation attempted',
      isSimulated: true,
    };

    const correlatedIncident = correlationEngine.correlateTrigger(trigger2);
    // Should merge into the same incident rather than creating duplicate
    expect(correlatedIncident.incidentId).toBe(incident1.incidentId);
    expect(correlatedIncident.timeline).toHaveLength(2);
    expect(correlatedIncident.correlatedEventIds).toHaveLength(6);
  });
});
