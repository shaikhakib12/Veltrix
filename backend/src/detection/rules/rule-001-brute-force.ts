import type { Detection, DetectionRule, EventCategory, Severity } from '@veltrix/shared';
import { BaseDetectionRule } from './base-rule.js';
import type { RuleEvaluationContext } from '../types.js';

export class Rule001BruteForce extends BaseDetectionRule {
  readonly id = 'RULE-001';
  readonly name = 'Distributed Brute-Force Authentication Attempt';
  readonly description =
    'Detects repeated authentication failures originating from a single source IP address within a sliding temporal window.';
  readonly category: EventCategory = 'AUTHENTICATION';
  readonly defaultSeverity: Severity = 'HIGH';
  readonly defaultThreshold = 5;
  readonly defaultSlidingWindowSeconds = 120;
  readonly mitreAttack = {
    techniqueId: 'T1110.001',
    techniqueName: 'Password Guessing',
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
      const ip = event.sourceIp;
      if (!eventsByIp.has(ip)) {
        eventsByIp.set(ip, []);
      }
      eventsByIp.get(ip)!.push(event);
    }

    const detections: Detection[] = [];

    for (const [sourceIp, ipEvents] of eventsByIp.entries()) {
      // Evaluate sliding window over chronological events
      let left = 0;
      for (let right = 0; right < ipEvents.length; right++) {
        const rightEvent = ipEvents[right]!;
        const rightTime = new Date(rightEvent.timestamp).getTime();

        while (left < right && rightTime - new Date(ipEvents[left]!.timestamp).getTime() > windowMs) {
          left++;
        }

        const countInWindow = right - left + 1;
        if (countInWindow >= threshold) {
          const windowEvents = ipEvents.slice(left, right + 1);
          const relatedEventIds = windowEvents.map((e) => e.eventId);
          const usernames = [...new Set(windowEvents.map((e) => e.username).filter(Boolean))];

          const detection = this.createDetection({
            orgId: context.organizationId,
            severity: ruleConfig?.severity || this.defaultSeverity,
            confidence: 85,
            title: `Brute Force Authentication Detected from ${sourceIp}`,
            description: `${countInWindow} failed authentication attempts detected from IP ${sourceIp} targeting ${usernames.length > 0 ? usernames.join(', ') : 'multiple accounts'} within ${windowSeconds}s.`,
            relatedEventIds,
            detectedAt: rightEvent.timestamp,
            evidence: {
              matchedRuleId: this.id,
              matchedThreshold: threshold,
              actualCount: countInWindow,
              timeWindowSeconds: windowSeconds,
              targetEntity: {
                type: 'IP',
                value: sourceIp,
              },
              triggeringEvents: relatedEventIds,
              details: {
                sourceIp,
                attemptCount: countInWindow,
                targetedUsernames: usernames,
                firstAttempt: windowEvents[0]!.timestamp,
                lastAttempt: windowEvents[windowEvents.length - 1]!.timestamp,
              },
            },
          });

          detections.push(detection);
          // Advance left pointer to the end of the triggering batch to prevent overlapping duplicate alerts on each incremental event
          left = right + 1;
        }
      }
    }

    return detections;
  }
}
