import { createHash } from 'node:crypto';
import type {
  SecurityEvent,
  Detection,
  DetectionRule,
  DetectionEvidence,
  EventCategory,
  Severity,
} from '@veltrix/shared';
import type { DetectionRuleInterface, RuleEvaluationContext } from '../types.js';
import { generateUuidV7 } from '../../utils/uuid.js';

export abstract class BaseDetectionRule implements DetectionRuleInterface {
  abstract readonly id: string;
  abstract readonly name: string;
  abstract readonly description: string;
  abstract readonly category: EventCategory;
  abstract readonly defaultSeverity: Severity;
  abstract readonly defaultThreshold: number;
  abstract readonly defaultSlidingWindowSeconds: number;
  abstract readonly mitreAttack?: {
    techniqueId: string;
    techniqueName: string;
    tactic: string;
  };

  abstract evaluate(
    context: RuleEvaluationContext,
    ruleConfig?: Partial<DetectionRule>
  ): Promise<Detection[]>;

  /**
   * Filters events strictly by the target organization ID (defense-in-depth tenant boundary)
   * and relevant event types, returning them sorted ascending by timestamp.
   */
  protected filterAndSortEvents(
    context: RuleEvaluationContext,
    relevantEventTypes: string[]
  ): SecurityEvent[] {
    const { events, organizationId } = context;
    if (!Array.isArray(events) || events.length === 0) {
      return [];
    }

    const typeSet = new Set(relevantEventTypes);

    return events
      .filter((e) => e.orgId === organizationId && typeSet.has(e.eventType))
      .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
  }

  /**
   * Computes a deterministic SHA-256 deduplication fingerprint for a detection finding
   * to guarantee that repeated runs over the same underlying events do not generate redundant alerts.
   */
  protected computeDedupKey(
    orgId: string,
    ruleId: string,
    entityKey: string,
    eventIds: string[]
  ): string {
    const sortedIds = [...eventIds].sort().join(',');
    const canonical = `${orgId}|${ruleId}|${entityKey}|${sortedIds}`;
    return createHash('sha256').update(canonical, 'utf8').digest('hex');
  }

  /**
   * Factory method to build a fully structured, explainable Detection finding.
   */
  protected createDetection(params: {
    orgId: string;
    severity?: Severity;
    confidence: number;
    title: string;
    description: string;
    relatedEventIds: string[];
    evidence: DetectionEvidence;
    detectedAt?: string;
  }): Detection {
    const detectedAt = params.detectedAt || new Date().toISOString();
    const dedupKey = this.computeDedupKey(
      params.orgId,
      this.id,
      params.evidence.targetEntity?.value || 'global',
      params.relatedEventIds
    );

    const ttlEpoch = Math.floor(new Date(detectedAt).getTime() / 1000) + 90 * 86400; // 90 days retention

    return {
      detectionId: generateUuidV7(new Date(detectedAt).getTime()),
      ruleId: this.id,
      ruleName: this.name,
      orgId: params.orgId,
      severity: params.severity || this.defaultSeverity,
      confidence: Math.min(100, Math.max(0, params.confidence)),
      category: this.category,
      title: params.title,
      description: params.description,
      detectedAt,
      relatedEventIds: params.relatedEventIds,
      evidence: params.evidence,
      mitreAttack: this.mitreAttack,
      status: 'ACTIVE',
      dedupKey,
      ttl: ttlEpoch,
    };
  }
}
