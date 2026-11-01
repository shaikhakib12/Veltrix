import type { Detection, DetectionRule, EventCategory, Severity } from '@veltrix/shared';
import { BaseDetectionRule } from './base-rule.js';
import type { RuleEvaluationContext } from '../types.js';

export class Rule003CredentialStuffingSuccess extends BaseDetectionRule {
  readonly id = 'RULE-003';
  readonly name = 'Compromise After Failure / Credential Stuffing Success';
  readonly description =
    'Detects a successful authentication immediately following repeated failed login attempts against the same account within a sliding temporal window.';
  readonly category: EventCategory = 'AUTHENTICATION';
  readonly defaultSeverity: Severity = 'CRITICAL';
  readonly defaultThreshold = 2; // failed attempts prior to success
  readonly defaultSlidingWindowSeconds = 600;
  readonly mitreAttack = {
    techniqueId: 'T1078',
    techniqueName: 'Valid Accounts',
    tactic: 'Initial Access',
  };

  async evaluate(
    context: RuleEvaluationContext,
    ruleConfig?: Partial<DetectionRule>
  ): Promise<Detection[]> {
    const threshold = ruleConfig?.threshold ?? this.defaultThreshold;
    const windowSeconds = ruleConfig?.slidingWindowSeconds ?? this.defaultSlidingWindowSeconds;
    const windowMs = windowSeconds * 1000;

    const events = this.filterAndSortEvents(context, ['auth.login.failed', 'auth.login.success']);
    if (events.length === 0) {
      return [];
    }

    // Group events by target username
    const eventsByUser = new Map<string, typeof events>();
    for (const event of events) {
      if (!event.username) continue;
      const user = event.username.toLowerCase();
      if (!eventsByUser.has(user)) {
        eventsByUser.set(user, []);
      }
      eventsByUser.get(user)!.push(event);
    }

    const detections: Detection[] = [];

    for (const [username, userEvents] of eventsByUser.entries()) {
      for (let i = 0; i < userEvents.length; i++) {
        const current = userEvents[i];
        if (!current || current.eventType !== 'auth.login.success') {
          continue;
        }

        const successTime = new Date(current.timestamp).getTime();

        // Count preceding failures within the sliding window
        const priorFailures = userEvents
          .slice(0, i)
          .filter(
            (e) =>
              e.eventType === 'auth.login.failed' &&
              successTime - new Date(e.timestamp).getTime() <= windowMs &&
              successTime >= new Date(e.timestamp).getTime()
          );

        if (priorFailures.length >= threshold) {
          const triggeringEvents = [...priorFailures.map((e) => e.eventId), current.eventId];
          const failureIps = [...new Set(priorFailures.map((e) => e.sourceIp))];

          const detection = this.createDetection({
            orgId: context.organizationId,
            severity: ruleConfig?.severity || this.defaultSeverity,
            confidence: 95,
            title: `Account Compromise After Failures: ${username}`,
            description: `Account '${username}' logged in successfully from IP ${current.sourceIp} after ${priorFailures.length} prior failed attempts (from IPs: ${failureIps.join(', ')}) within ${windowSeconds}s.`,
            relatedEventIds: triggeringEvents,
            detectedAt: current.timestamp,
            evidence: {
              matchedRuleId: this.id,
              matchedThreshold: threshold,
              actualCount: priorFailures.length,
              timeWindowSeconds: windowSeconds,
              targetEntity: {
                type: 'USER',
                value: username,
              },
              triggeringEvents,
              details: {
                targetUser: username,
                priorFailuresCount: priorFailures.length,
                successIp: current.sourceIp,
                failureIps,
                successTimestamp: current.timestamp,
              },
            },
          });

          detections.push(detection);
        }
      }
    }

    return detections;
  }
}
