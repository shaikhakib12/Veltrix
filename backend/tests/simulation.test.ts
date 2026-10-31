import { describe, it, expect, beforeEach } from 'vitest';
import { SimulationRunner } from '../src/simulation/runner.js';
import { MemoryStore } from '../src/shared/db/memoryStore.js';

describe('Module K: Simulation Lab Scenarios', () => {
  let runner: SimulationRunner;
  let store: MemoryStore;

  beforeEach(() => {
    store = MemoryStore.getInstance();
    store.reset();
    runner = new SimulationRunner(store);
  });

  it('should list all 6 competition demo scenarios', () => {
    const scenarios = runner.getScenarios();
    expect(scenarios).toHaveLength(6);
    expect(scenarios.map(s => s.id)).toEqual([
      'sim-brute-force',
      'sim-impossible-travel',
      'sim-account-takeover-chain',
      'sim-privilege-escalation',
      'sim-data-exfiltration',
      'sim-api-burst-dos',
    ]);
  });

  it('should execute the Brute-Force scenario and trigger RULE-001', async () => {
    const result = await runner.executeScenario('sim-brute-force');
    expect(result.status).toBe('COMPLETED');
    expect(result.injectedEventsCount).toBe(6);
    expect(result.triggeredRules.some(r => r.includes('Brute-Force'))).toBe(true);
    expect(result.correlatedIncidentId).toBeDefined();
    expect(result.riskScore).toBeGreaterThanOrEqual(50);
  });

  it('should execute the Multi-Stage Account Takeover breach sequence', async () => {
    const result = await runner.executeScenario('sim-account-takeover-chain');
    expect(result.status).toBe('COMPLETED');
    expect(result.injectedEventsCount).toBe(8);
    expect(result.triggeredRules.length).toBeGreaterThanOrEqual(2);
    expect(result.correlatedIncidentId).toBeDefined();
    
    // Risk score should be CRITICAL (>= 75) due to multi-stage sequence bonus
    expect(result.riskScore).toBeGreaterThanOrEqual(75);

    // Verify incident timeline progression in memory store
    const incident = store.incidents.get(result.correlatedIncidentId!);
    expect(incident).toBeDefined();
    expect(incident?.severity).toBe('CRITICAL');
    expect(incident?.timeline.length).toBeGreaterThanOrEqual(2);
  });
});
