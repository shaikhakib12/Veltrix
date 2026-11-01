import { createHash } from 'node:crypto';
import type {
  Detection,
  Incident,
  IncidentStatus,
  ResponseActionType,
  SecurityEvent,
  Severity,
  TimelineEntry,
  WebConfidenceTier,
} from '@veltrix/shared';
import type { StorageInterface } from '../storage/storage-interface.js';
import { RiskScoringEngine } from '../risk/engine.js';
import { VulnerabilityCorrelator } from './vuln-correlator.js';
import type { CorrelationResult } from './types.js';
import { generateUuidV7 } from '../utils/uuid.js';

export interface CorrelationEngineOptions {
  windowSeconds?: number;
  riskEngine?: RiskScoringEngine;
  vulnCorrelator?: VulnerabilityCorrelator;
}

export class AttackCorrelationEngine {
  private readonly windowSeconds: number;
  private readonly riskEngine: RiskScoringEngine;
  private readonly vulnCorrelator: VulnerabilityCorrelator;
  private readonly storage: StorageInterface;

  // Active correlation key tracking: correlationKey -> incidentId
  private activeIncidents = new Map<string, string>();

  constructor(storage: StorageInterface, options?: CorrelationEngineOptions) {
    this.storage = storage;
    this.windowSeconds = options?.windowSeconds ?? 900; // 15 minutes sliding window
    this.riskEngine = options?.riskEngine ?? new RiskScoringEngine();
    this.vulnCorrelator = options?.vulnCorrelator ?? new VulnerabilityCorrelator();
  }

  getRiskEngine(): RiskScoringEngine {
    return this.riskEngine;
  }

  getVulnCorrelator(): VulnerabilityCorrelator {
    return this.vulnCorrelator;
  }

  /**
   * Computes a deterministic correlation fingerprint for grouping related activity:
   * SHA-256(orgId:siteId:sourceIp:windowBucket)
   */
  computeCorrelationKey(
    orgId: string,
    siteId: string | undefined,
    sourceIp: string,
    timestampMs: number
  ): { correlationKey: string; windowBucket: number } {
    const windowBucket = Math.floor(timestampMs / (this.windowSeconds * 1000));
    const canonical = `${orgId}:${siteId || 'global'}:${sourceIp}:${windowBucket}`;
    const correlationKey = createHash('sha256').update(canonical, 'utf8').digest('hex');
    return { correlationKey, windowBucket };
  }

  /**
   * Correlates an incoming detection with active incidents or creates a new incident.
   */
  async correlateDetection(
    detection: Detection,
    _associatedEvents?: SecurityEvent[]
  ): Promise<CorrelationResult | null> {
    const orgId = detection.orgId;
    const details = detection.evidence?.details || {};
    const siteId = typeof details.siteId === 'string' ? details.siteId : undefined;
    const domain = typeof details.domain === 'string' ? details.domain : undefined;
    const sourceIp = detection.evidence?.targetEntity?.type === 'IP'
      ? detection.evidence.targetEntity.value
      : (typeof details.sourceIp === 'string' ? details.sourceIp : '0.0.0.0');

    const detectionTimeMs = new Date(detection.detectedAt).getTime();
    const { correlationKey } = this.computeCorrelationKey(
      orgId,
      siteId,
      sourceIp,
      detectionTimeMs
    );

    // 1. Check if an active incident already exists for this correlation bucket
    let incidentId = this.activeIncidents.get(correlationKey);
    let existingIncident: Incident | null = null;

    if (incidentId) {
      existingIncident = await this.storage.getIncidentById(orgId, incidentId);
    }

    // If not found in active map, check storage for recent open incident from the same IP/site
    if (!existingIncident) {
      const recentIncidents = await this.storage.getIncidents(orgId, { limit: 20 });
      for (const inc of recentIncidents.items) {
        if (
          inc.status !== 'RESOLVED' &&
          inc.status !== 'FALSE_POSITIVE' &&
          inc.sourceIp === sourceIp &&
          (!siteId || inc.siteId === siteId)
        ) {
          const incTime = new Date(inc.createdAt).getTime();
          if (Math.abs(detectionTimeMs - incTime) <= this.windowSeconds * 1000) {
            existingIncident = inc;
            incidentId = inc.incidentId;
            this.activeIncidents.set(correlationKey, incidentId);
            break;
          }
        }
      }
    }

    // 2. Extract attack type and target details
    const attackType = (typeof details.attackType === 'string'
      ? details.attackType
      : detection.ruleId.replace('RULE-', 'ATTACK-')).toUpperCase();

    const targetUri = typeof details.requestUri === 'string' ? details.requestUri : '/';
    const confidenceLevel: WebConfidenceTier = (typeof details.confidenceLevel === 'string'
      ? details.confidenceLevel
      : 'SUSPICIOUS_ATTEMPT') as WebConfidenceTier;

    // 3. Vulnerability-aware correlation check (TASK-705)
    let vulnOverlap;
    if (siteId) {
      const matchedVuln = await this.vulnCorrelator.findMatchingVulnerability(
        siteId,
        attackType,
        targetUri
      );
      if (matchedVuln) {
        const level = this.vulnCorrelator.determineOverlapLevel(matchedVuln, targetUri);
        vulnOverlap = this.riskEngine.computeVulnerabilityMatchTerm(
          level,
          matchedVuln.cvssScore,
          confidenceLevel
        );
      }
    }

    // 4. Query threat intelligence status for attacker IP
    let isThreatFlagged = false;
    let threatSeverity: Severity | undefined;
    try {
      const indicator = await this.storage.getIndicatorByValue('IP', sourceIp, orgId);
      if (indicator && indicator.isFlagged) {
        isThreatFlagged = true;
        threatSeverity = indicator.severity;
      }
    } catch {
      // Best-effort lookup
    }

    // 5. Update or Create Incident
    if (existingIncident) {
      // --- UPDATE EXISTING INCIDENT ---
      const updatedEventIds = Array.from(
        new Set([...existingIncident.associatedEventIds, ...detection.relatedEventIds])
      );

      const existingAttackTypes = new Set(existingIncident.attackTypes || []);
      existingAttackTypes.add(attackType);
      const uniqueAttackTypes = Array.from(existingAttackTypes);

      // Determine highest confidence tier
      let highestConfidence: WebConfidenceTier = existingIncident.highestConfidence || 'SUSPICIOUS_ATTEMPT';
      if (
        confidenceLevel === 'CONFIRMED_EXPLOITATION' ||
        highestConfidence === 'CONFIRMED_EXPLOITATION'
      ) {
        highestConfidence = 'CONFIRMED_EXPLOITATION';
      } else if (
        confidenceLevel === 'POTENTIAL_EXPLOITATION' ||
        highestConfidence === 'POTENTIAL_EXPLOITATION'
      ) {
        highestConfidence = 'POTENTIAL_EXPLOITATION';
      } else if (
        confidenceLevel === 'BLOCKED_ATTEMPT' &&
        highestConfidence === 'SUSPICIOUS_ATTEMPT'
      ) {
        highestConfidence = 'BLOCKED_ATTEMPT';
      }

      // Collect all severities
      const allSeverities: Severity[] = [existingIncident.severity, detection.severity];
      if (highestConfidence === 'CONFIRMED_EXPLOITATION') {
        allSeverities.push('CRITICAL');
      }

      // Recompute risk score
      const riskResult = this.riskEngine.calculateRisk({
        detectionsSeverity: allSeverities,
        eventCount: updatedEventIds.length,
        uniqueAttackTypes,
        highestConfidence,
        isThreatIntelFlagged: isThreatFlagged,
        threatIntelSeverity: threatSeverity,
        vulnerabilityOverlap: vulnOverlap,
      });

      // Append new timeline entry
      const newTimelineEntry: TimelineEntry = {
        timestamp: detection.detectedAt,
        eventType: `web.attack.${attackType.toLowerCase()}`,
        description: `${detection.title}: ${detection.description}`,
        sourceIp,
        details: {
          detectionId: detection.detectionId,
          ruleId: detection.ruleId,
          targetUri,
          confidenceLevel,
        },
      };

      const updatedTimeline = [...existingIncident.timeline, newTimelineEntry].sort(
        (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
      );

      // Upgrade severity if higher
      const highestSeverity: Severity =
        riskResult.score >= 75
          ? 'CRITICAL'
          : riskResult.score >= 50
          ? 'HIGH'
          : riskResult.score >= 25
          ? 'MEDIUM'
          : 'LOW';

      // Suggested SOAR responses
      const suggestedResponses: ResponseActionType[] = ['BLOCK_IP'];
      if (riskResult.score >= 50) {
        suggestedResponses.push('REVOKE_SESSION', 'STEP_UP_AUTH');
      }

      const updatedIncident: Incident = {
        ...existingIncident,
        severity: highestSeverity,
        riskScore: riskResult.score,
        riskBand: riskResult.riskBand,
        riskFactors: riskResult.factors,
        webRiskFactors: riskResult.factors,
        highestConfidence,
        attackTypes: uniqueAttackTypes,
        associatedEventIds: updatedEventIds,
        timeline: updatedTimeline,
        suggestedResponses,
        updatedAt: new Date().toISOString(),
      };

      await this.storage.saveIncident(updatedIncident);

      return {
        incident: updatedIncident,
        isNewIncident: false,
        correlationKey,
      };
    } else {
      // --- CREATE NEW CORRELATED INCIDENT ---
      const uniqueAttackTypes = [attackType];
      const riskResult = this.riskEngine.calculateRisk({
        detectionsSeverity: [detection.severity],
        eventCount: detection.relatedEventIds.length,
        uniqueAttackTypes,
        highestConfidence: confidenceLevel,
        isThreatIntelFlagged: isThreatFlagged,
        threatIntelSeverity: threatSeverity,
        vulnerabilityOverlap: vulnOverlap,
      });

      const initialTimeline: TimelineEntry[] = [
        {
          timestamp: detection.detectedAt,
          eventType: `web.attack.${attackType.toLowerCase()}`,
          description: `${detection.title}: ${detection.description}`,
          sourceIp,
          details: {
            detectionId: detection.detectionId,
            ruleId: detection.ruleId,
            targetUri,
            confidenceLevel,
          },
        },
      ];

      const initialSeverity: Severity =
        riskResult.score >= 75
          ? 'CRITICAL'
          : riskResult.score >= 50
          ? 'HIGH'
          : riskResult.score >= 25
          ? 'MEDIUM'
          : 'LOW';

      const suggestedResponses: ResponseActionType[] = ['BLOCK_IP'];
      if (riskResult.score >= 50) {
        suggestedResponses.push('REVOKE_SESSION', 'STEP_UP_AUTH');
      }

      const newIncidentId = generateUuidV7(detectionTimeMs);
      const newIncident: Incident = {
        incidentId: newIncidentId,
        orgId,
        siteId,
        domain,
        sourceIp,
        title: `Correlated Web Attack from ${sourceIp} targeting ${domain || siteId || 'asset'}`,
        description: `Correlated ${uniqueAttackTypes.join(', ')} attack activity detected from IP ${sourceIp} targeting website assets.`,
        severity: initialSeverity,
        riskScore: riskResult.score,
        riskBand: riskResult.riskBand,
        riskFactors: riskResult.factors,
        webRiskFactors: riskResult.factors,
        highestConfidence: confidenceLevel,
        attackTypes: uniqueAttackTypes,
        status: 'NEW' as IncidentStatus,
        associatedEventIds: [...detection.relatedEventIds],
        timeline: initialTimeline,
        suggestedResponses,
        createdAt: detection.detectedAt,
        updatedAt: detection.detectedAt,
      };

      await this.storage.saveIncident(newIncident);
      this.activeIncidents.set(correlationKey, newIncidentId);

      return {
        incident: newIncident,
        isNewIncident: true,
        correlationKey,
      };
    }
  }

  /**
   * Resets active in-memory correlation tracking (for test suite cleanup).
   */
  clear(): void {
    this.activeIncidents.clear();
    this.vulnCorrelator.clear();
  }
}
