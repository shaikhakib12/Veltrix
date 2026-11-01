import type {
  SecurityEvent,
  Detection,
  DetectionRule,
} from '@veltrix/shared';
import type {
  DetectionRuleInterface,
  RuleEvaluationContext,
  EngineEvaluationOptions,
  EngineEvaluationResult,
} from './types.js';
import {
  Rule001BruteForce,
  Rule002PasswordSpray,
  Rule003CredentialStuffingSuccess,
  Rule004ImpossibleTravel,
  Rule005SuspiciousIp,
  Rule006PrivilegeEscalation,
  Rule007UnusualDataAccess,
  Rule008ExcessiveApiRequests,
  Rule009MultiAccountRecon,
  Rule010OffHoursAnomaly,
} from './rules/index.js';
import type { StorageInterface } from '../storage/storage-interface.js';

export class DetectionEngine {
  private rules: Map<string, DetectionRuleInterface> = new Map();
  private storage?: StorageInterface;

  constructor(storage?: StorageInterface) {
    this.storage = storage;
    this.registerDefaultRules();
  }

  /**
   * Registers all 10 built-in Sigma-inspired detection rules.
   */
  private registerDefaultRules(): void {
    const defaultRules: DetectionRuleInterface[] = [
      new Rule001BruteForce(),
      new Rule002PasswordSpray(),
      new Rule003CredentialStuffingSuccess(),
      new Rule004ImpossibleTravel(),
      new Rule005SuspiciousIp(),
      new Rule006PrivilegeEscalation(),
      new Rule007UnusualDataAccess(),
      new Rule008ExcessiveApiRequests(),
      new Rule009MultiAccountRecon(),
      new Rule010OffHoursAnomaly(),
    ];

    for (const rule of defaultRules) {
      this.rules.set(rule.id, rule);
    }
  }

  /**
   * Returns a list of all registered rule definitions.
   */
  getRegisteredRules(): DetectionRuleInterface[] {
    return Array.from(this.rules.values());
  }

  /**
   * Retrieves a registered rule by its ID.
   */
  getRule(ruleId: string): DetectionRuleInterface | undefined {
    return this.rules.get(ruleId);
  }

  /**
   * Registers or replaces a detection rule.
   */
  registerRule(rule: DetectionRuleInterface): void {
    this.rules.set(rule.id, rule);
  }

  /**
   * Evaluates security events against registered rules for an authorized tenant.
   * Enforces strict organization isolation, rule enablement status, and deduplication.
   */
  async evaluate(
    context: RuleEvaluationContext,
    options?: EngineEvaluationOptions
  ): Promise<EngineEvaluationResult> {
    const startTime = Date.now();
    const orgId = context.organizationId;

    if (!orgId || typeof orgId !== 'string') {
      throw new Error('INVALID_ORGANIZATION_ID: Tenant organization ID is required');
    }

    // 1. Fetch tenant rule overrides if storage is available
    let storedRules: DetectionRule[] = [];
    if (this.storage) {
      try {
        storedRules = await this.storage.getDetectionRules(orgId);
      } catch {
        storedRules = [];
      }
    }

    const storedRuleMap = new Map(storedRules.map((r) => [r.ruleId, r]));

    // 2. Select rules to evaluate
    const candidateRuleIds = options?.ruleIds && options.ruleIds.length > 0
      ? options.ruleIds.filter((id) => this.rules.has(id))
      : Array.from(this.rules.keys());

    const activeRules: Array<{ rule: DetectionRuleInterface; config?: Partial<DetectionRule> }> = [];

    for (const ruleId of candidateRuleIds) {
      const rule = this.rules.get(ruleId);
      if (!rule) continue;

      const override = storedRuleMap.get(ruleId);
      // Skip if explicitly disabled in tenant configuration
      if (override && override.isEnabled === false) {
        continue;
      }

      activeRules.push({ rule, config: override });
    }

    // 3. Execute active rules
    const allDetections: Detection[] = [];
    const evaluatedRuleIds: string[] = [];
    const seenDedupKeys = new Set<string>();

    for (const { rule, config } of activeRules) {
      evaluatedRuleIds.push(rule.id);
      try {
        const findings = await rule.evaluate(context, config);

        for (const finding of findings) {
          // In-memory deduplication within current evaluation run
          const dedupKey = finding.dedupKey || finding.detectionId;
          if (seenDedupKeys.has(dedupKey)) {
            continue;
          }
          seenDedupKeys.add(dedupKey);

          // Save to persistent storage if requested and storage adapter is present
          if (options?.persistDetections && this.storage) {
            try {
              const saveResult = await this.storage.saveDetection(finding);
              if (!saveResult.isDuplicate) {
                allDetections.push(finding);
              }
            } catch {
              allDetections.push(finding);
            }
          } else {
            allDetections.push(finding);
          }
        }
      } catch (err: unknown) {
        // Individual rule failure does not crash the overall detection pipeline
        console.error(`Error executing detection rule ${rule.id}:`, err);
      }
    }

    return {
      organizationId: orgId,
      totalEvaluatedEvents: context.events.length,
      matchedDetectionsCount: allDetections.length,
      detections: allDetections,
      executionTimeMs: Date.now() - startTime,
      evaluatedRuleIds,
    };
  }

  /**
   * Dry-runs a rule definition against a sample array of events without persisting findings.
   * Useful for SOC analysts tuning rule thresholds via POST /api/v1/detection-rules/test.
   */
  async dryRunRule(
    ruleDef: Partial<DetectionRule> & { ruleId: string },
    sampleEvents: SecurityEvent[],
    orgId: string
  ): Promise<{ matched: boolean; matchedCount: number; detections: Detection[] }> {
    const rule = this.rules.get(ruleDef.ruleId);
    if (!rule) {
      throw new Error(`RULE_NOT_FOUND: Detection rule '${ruleDef.ruleId}' is not registered`);
    }

    const context: RuleEvaluationContext = {
      organizationId: orgId,
      events: sampleEvents,
      currentTime: new Date(),
    };

    const detections = await rule.evaluate(context, ruleDef);

    return {
      matched: detections.length > 0,
      matchedCount: detections.length,
      detections,
    };
  }
}
