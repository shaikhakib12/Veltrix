import type {
  SecurityEvent,
  Detection,
  DetectionRule,
  ThreatIndicator,
  EventCategory,
  Severity,
} from '@veltrix/shared';

export interface RuleEvaluationContext {
  organizationId: string;
  events: SecurityEvent[];
  currentTime?: Date;
  threatIndicators?: ThreatIndicator[];
  customConfig?: Record<string, unknown>;
}

export interface DetectionRuleInterface {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly category: EventCategory;
  readonly defaultSeverity: Severity;
  readonly defaultThreshold: number;
  readonly defaultSlidingWindowSeconds: number;
  readonly mitreAttack?: {
    techniqueId: string;
    techniqueName: string;
    tactic: string;
  };

  /**
   * Evaluates a collection of normalized security events for an authorized organization.
   * Returns an array of structured Detection findings with full explainable evidence.
   */
  evaluate(
    context: RuleEvaluationContext,
    ruleConfig?: Partial<DetectionRule>
  ): Promise<Detection[]>;
}

export interface EngineEvaluationOptions {
  ruleIds?: string[];
  startTime?: string;
  endTime?: string;
  persistDetections?: boolean;
}

export interface EngineEvaluationResult {
  organizationId: string;
  totalEvaluatedEvents: number;
  matchedDetectionsCount: number;
  detections: Detection[];
  executionTimeMs: number;
  evaluatedRuleIds: string[];
}
