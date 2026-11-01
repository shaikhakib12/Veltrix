import type { Detection, DetectionRule, EventCategory, Severity } from '@veltrix/shared';
import { BaseDetectionRule } from './base-rule.js';
import type { RuleEvaluationContext } from '../types.js';

export class Rule006PrivilegeEscalation extends BaseDetectionRule {
  readonly id = 'RULE-006';
  readonly name = 'Privilege Escalation Indicator';
  readonly description =
    'Detects unauthorized administrative role assumptions, policy mutations granting excessive permissions, or privilege escalation events.';
  readonly category: EventCategory = 'PRIVILEGE';
  readonly defaultSeverity: Severity = 'CRITICAL';
  readonly defaultThreshold = 1;
  readonly defaultSlidingWindowSeconds = 300;
  readonly mitreAttack = {
    techniqueId: 'T1068',
    techniqueName: 'Exploitation for Privilege Escalation',
    tactic: 'Privilege Escalation',
  };

  async evaluate(
    context: RuleEvaluationContext,
    ruleConfig?: Partial<DetectionRule>
  ): Promise<Detection[]> {
    const events = this.filterAndSortEvents(context, [
      'privilege.escalation',
      'privilege.role.assumed',
      'privilege.policy.mutation',
    ]);

    if (events.length === 0) {
      return [];
    }

    const detections: Detection[] = [];

    for (const event of events) {
      const isSensitiveEscalation =
        event.eventType === 'privilege.escalation' ||
        event.severity === 'CRITICAL' ||
        event.severity === 'HIGH' ||
        event.metadata?.role === 'Administrator' ||
        event.metadata?.policyGrant === '*' ||
        event.metadata?.isAuthorized === false;

      if (isSensitiveEscalation) {
        const actor = event.username || event.sourceIp;
        const details = (event.metadata || {}) as Record<string, unknown>;

        const detection = this.createDetection({
          orgId: context.organizationId,
          severity: ruleConfig?.severity || this.defaultSeverity,
          confidence: 90,
          title: `Privilege Escalation Activity: ${actor}`,
          description: `Suspicious privilege modification event '${event.eventType}' executed by actor '${actor}' (action: ${details.action || 'role/policy mutation'}).`,
          relatedEventIds: [event.eventId],
          detectedAt: event.timestamp,
          evidence: {
            matchedRuleId: this.id,
            matchedThreshold: 1,
            actualCount: 1,
            timeWindowSeconds: this.defaultSlidingWindowSeconds,
            targetEntity: {
              type: event.username ? 'USER' : 'IP',
              value: actor,
            },
            triggeringEvents: [event.eventId],
            details: {
              actor,
              eventType: event.eventType,
              sourceIp: event.sourceIp,
              metadata: details,
            },
          },
        });

        detections.push(detection);
      }
    }

    return detections;
  }
}
