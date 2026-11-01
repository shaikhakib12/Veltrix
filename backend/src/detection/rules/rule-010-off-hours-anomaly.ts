import type { Detection, DetectionRule, EventCategory, Severity } from '@veltrix/shared';
import { BaseDetectionRule } from './base-rule.js';
import type { RuleEvaluationContext } from '../types.js';

export class Rule010OffHoursAnomaly extends BaseDetectionRule {
  readonly id = 'RULE-010';
  readonly name = 'Off-Hours Administrative Anomaly';
  readonly description =
    'Detects sensitive administrative actions, privilege policy modifications, or service disruptions executed outside configured organization business hours.';
  readonly category: EventCategory = 'SYSTEM';
  readonly defaultSeverity: Severity = 'HIGH';
  readonly defaultThreshold = 1;
  readonly defaultSlidingWindowSeconds = 300;
  readonly mitreAttack = {
    techniqueId: 'T1078',
    techniqueName: 'Valid Accounts',
    tactic: 'Persistence',
  };

  async evaluate(
    context: RuleEvaluationContext,
    ruleConfig?: Partial<DetectionRule>
  ): Promise<Detection[]> {
    // Configurable working hours in UTC (defaults: 06:00 to 22:00)
    const condition = (ruleConfig?.condition || {}) as Record<string, unknown>;
    const businessStartHour = typeof condition.startHour === 'number' ? condition.startHour : 6;
    const businessEndHour = typeof condition.endHour === 'number' ? condition.endHour : 22;

    const events = this.filterAndSortEvents(context, [
      'admin.action',
      'privilege.policy.mutation',
      'system.service.stop',
      'system.file.modify',
    ]);

    if (events.length === 0) {
      return [];
    }

    const detections: Detection[] = [];

    for (const event of events) {
      const eventDate = new Date(event.timestamp);
      const utcHour = eventDate.getUTCHours();
      const isWeekend = eventDate.getUTCDay() === 0 || eventDate.getUTCDay() === 6; // Sunday=0, Saturday=6

      // Off-hours if before businessStartHour, at/after businessEndHour, or weekend
      const isOffHours = utcHour < businessStartHour || utcHour >= businessEndHour || isWeekend;

      if (isOffHours) {
        const actor = event.username || event.sourceIp;
        const action = (event.metadata?.action as string) || event.eventType;

        const detection = this.createDetection({
          orgId: context.organizationId,
          severity: ruleConfig?.severity || this.defaultSeverity,
          confidence: 80,
          title: `Off-Hours Administrative Activity by ${actor}`,
          description: `Sensitive administrative action '${action}' executed outside authorized business hours at ${eventDate.toISOString()} UTC (business window: ${String(businessStartHour).padStart(2, '0')}:00 - ${String(businessEndHour).padStart(2, '0')}:00 UTC).`,
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
              sourceIp: event.sourceIp,
              action,
              utcHour,
              businessStartHour,
              businessEndHour,
              isWeekend,
              timestampUtc: event.timestamp,
            },
          },
        });

        detections.push(detection);
      }
    }

    return detections;
  }
}
