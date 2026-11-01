import type { Detection, DetectionRule, EventCategory, Severity } from '@veltrix/shared';
import { BaseDetectionRule } from './base-rule.js';
import type { RuleEvaluationContext } from '../types.js';

export class Rule002PasswordSpray extends BaseDetectionRule {
  readonly id = 'RULE-002';
  readonly name = 'Password Spraying Across Multiple Accounts';
  readonly description =
    'Detects a single source IP address attempting authentication against multiple distinct user accounts within a sliding temporal window.';
  readonly category: EventCategory = 'AUTHENTICATION';
  readonly defaultSeverity: Severity = 'HIGH';
  readonly defaultThreshold = 3; // distinct usernames
  readonly defaultSlidingWindowSeconds = 300;
  readonly mitreAttack = {
    techniqueId: 'T1110.003',
    techniqueName: 'Password Spraying',
    tactic: 'Credential Access',
  };

  async evaluate(
    context: RuleEvaluationContext,
    ruleConfig?: Partial<DetectionRule>
  ): Promise<Detection[]> {
    const threshold = ruleConfig?.threshold ?? this.defaultThreshold;
    const windowSeconds = ruleConfig?.slidingWindowSeconds ?? this.defaultSlidingWindowSeconds;
    const windowMs = windowSeconds * 1000;

    const events = this.filterAndSortEvents(context, ['auth.login.failed']);
    if (events.length === 0) {
      return [];
    }

    // Group failed logins by source IP
    const eventsByIp = new Map<string, typeof events>();
    for (const event of events) {
      if (!event.username) continue; // Must have username to count distinct targets
      const ip = event.sourceIp;
      if (!eventsByIp.has(ip)) {
        eventsByIp.set(ip, []);
      }
      eventsByIp.get(ip)!.push(event);
    }

    const detections: Detection[] = [];

    for (const [sourceIp, ipEvents] of eventsByIp.entries()) {
      let left = 0;
      for (let right = 0; right < ipEvents.length; right++) {
        const rightEvent = ipEvents[right]!;
        const rightTime = new Date(rightEvent.timestamp).getTime();

        while (left < right && rightTime - new Date(ipEvents[left]!.timestamp).getTime() > windowMs) {
          left++;
        }

        const windowEvents = ipEvents.slice(left, right + 1);
        const distinctUsernames = [...new Set(windowEvents.map((e) => e.username!).filter(Boolean))];

        if (distinctUsernames.length >= threshold) {
          const relatedEventIds = windowEvents.map((e) => e.eventId);

          const detection = this.createDetection({
            orgId: context.organizationId,
            severity: ruleConfig?.severity || this.defaultSeverity,
            confidence: 90,
            title: `Password Spraying Detected from ${sourceIp}`,
            description: `Source IP ${sourceIp} targeted ${distinctUsernames.length} distinct user accounts (${distinctUsernames.slice(0, 5).join(', ')}${distinctUsernames.length > 5 ? '...' : ''}) within ${windowSeconds}s.`,
            relatedEventIds,
            detectedAt: rightEvent.timestamp,
            evidence: {
              matchedRuleId: this.id,
              matchedThreshold: threshold,
              actualCount: distinctUsernames.length,
              timeWindowSeconds: windowSeconds,
              targetEntity: {
                type: 'IP',
                value: sourceIp,
              },
              triggeringEvents: relatedEventIds,
              details: {
                sourceIp,
                distinctTargetedCount: distinctUsernames.length,
                targetedAccounts: distinctUsernames,
                totalAttempts: windowEvents.length,
              },
            },
          });

          detections.push(detection);
          left = right + 1;
        }
      }
    }

    return detections;
  }
}
