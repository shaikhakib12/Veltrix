import { 
  DetectionTrigger, 
  Incident, 
  AttackTimelineStep, 
  SecurityEvent, 
  ThreatIndicator 
} from '../shared/types/index.js';
import { generateId } from '../shared/utils/crypto.js';
import { RiskEngine } from '../risk-engine/scorer.js';
import { MemoryStore } from '../shared/db/memoryStore.js';

export class CorrelationEngine {
  private store: MemoryStore;

  constructor(store?: MemoryStore) {
    this.store = store || MemoryStore.getInstance();
  }

  /**
   * Processes a detection trigger and correlates it into an existing or new Incident.
   */
  public correlateTrigger(trigger: DetectionTrigger, triggeringEvent?: SecurityEvent): Incident {
    // 1. Extract primary entity tokens
    const parts = trigger.entityKey.split(':');
    const entityType = parts[0];
    const entityValue = parts.slice(1).join(':');

    const sourceIp = triggeringEvent?.sourceIp || (entityType === 'sourceIp' ? entityValue : '0.0.0.0');
    const targetUser = triggeringEvent?.username || (entityType === 'username' ? entityValue : undefined);

    // 2. Check for active open incident matching this IP or User within the past 15 minutes
    const nowMs = Date.now();
    const correlationWindowMs = 15 * 60 * 1000; // 15 minutes

    let existingIncident: Incident | undefined;
    for (const inc of this.store.incidents.values()) {
      if (inc.status === 'RESOLVED' || inc.status === 'FALSE_POSITIVE') continue;
      const incTimeMs = new Date(inc.createdAt).getTime();
      if (nowMs - incTimeMs > correlationWindowMs) continue;

      if (inc.sourceIp === sourceIp || (targetUser && inc.targetUser === targetUser)) {
        existingIncident = inc;
        break;
      }
    }

    // 3. Resolve Threat Intelligence for IP
    const threatIndicator = this.store.indicators.get(sourceIp);

    // 4. Build or append timeline step
    const timelineStep: AttackTimelineStep = {
      stepId: generateId('step'),
      timestamp: trigger.timestamp,
      phase: trigger.mitreAttack.tactic,
      mitreId: trigger.mitreAttack.techniqueId,
      description: trigger.explanation,
      sourceIp,
      username: targetUser || 'SYSTEM',
      severity: trigger.severity,
      eventId: triggeringEvent?.eventId || trigger.contributingEventIds[0] || 'evt-unknown',
    };

    if (existingIncident) {
      // Merge into existing incident
      existingIncident.timeline.push(timelineStep);
      for (const evtId of trigger.contributingEventIds) {
        if (!existingIncident.correlatedEventIds.includes(evtId)) {
          existingIncident.correlatedEventIds.push(evtId);
        }
      }

      // Recalculate unique kill-chain tactics
      const uniqueTactics = new Set(existingIncident.timeline.map(s => s.phase));
      const riskBreakdown = RiskEngine.calculate({
        baseSeverity: existingIncident.severity === 'CRITICAL' || trigger.severity === 'CRITICAL' ? 'CRITICAL' : 'HIGH',
        eventCount: existingIncident.correlatedEventIds.length,
        targetAccount: existingIncident.targetUser,
        sourceIp: existingIncident.sourceIp,
        threatIndicator,
        killChainStagesCount: uniqueTactics.size,
      });

      existingIncident.riskScore = riskBreakdown.totalScore;
      existingIncident.severity = riskBreakdown.tier;
      existingIncident.riskBreakdown = riskBreakdown;
      existingIncident.updatedAt = new Date().toISOString();

      // Check if attack sequence has escalated to multi-stage compromise
      if (uniqueTactics.size >= 3) {
        existingIncident.title = `Coordinated Multi-Stage Attack Sequence (${existingIncident.targetUser || existingIncident.sourceIp})`;
        existingIncident.attackVector = 'Multi-Stage Account Compromise & Exfiltration';
        existingIncident.recommendedResponse = 'SUSPEND_USER';
        existingIncident.requiresApproval = true;
      }

      this.store.incidents.set(existingIncident.incidentId, existingIncident);
      return existingIncident;
    } else {
      // Create new Incident
      const incidentId = generateId('inc');
      const uniqueTactics = new Set([trigger.mitreAttack.tactic]);

      const riskBreakdown = RiskEngine.calculate({
        baseSeverity: trigger.severity,
        eventCount: trigger.contributingEventIds.length,
        targetAccount: targetUser,
        sourceIp,
        threatIndicator,
        killChainStagesCount: uniqueTactics.size,
      });

      const newIncident: Incident = {
        incidentId,
        orgId: trigger.orgId,
        title: `${trigger.ruleName} - Target: ${targetUser || sourceIp}`,
        description: trigger.explanation,
        status: 'NEW',
        severity: riskBreakdown.tier,
        riskScore: riskBreakdown.totalScore,
        riskBreakdown,
        attackVector: trigger.mitreAttack.techniqueName,
        targetUser,
        sourceIp,
        correlatedEventIds: [...trigger.contributingEventIds],
        timeline: [timelineStep],
        recommendedResponse: trigger.severity === 'CRITICAL' ? 'BLOCK_IP' : 'STEP_UP_AUTH',
        requiresApproval: trigger.severity === 'CRITICAL' || trigger.severity === 'HIGH',
        containmentStatus: 'NONE',
        notes: [
          {
            author: 'VELTRIX Autonomous Detection Engine',
            timestamp: new Date().toISOString(),
            content: `Incident initialized from detection trigger ${trigger.ruleId} (${trigger.ruleName}). Initial risk assessment: ${riskBreakdown.totalScore}/100.`,
          }
        ],
        isSimulated: trigger.isSimulated,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };

      this.store.incidents.set(incidentId, newIncident);
      return newIncident;
    }
  }
}
