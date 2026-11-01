import type { Detection, DetectionRule, EventCategory, Severity } from '@veltrix/shared';
import { BaseDetectionRule } from './base-rule.js';
import type { RuleEvaluationContext } from '../types.js';

export class Rule009MultiAccountRecon extends BaseDetectionRule {
  readonly id = 'RULE-009';
  readonly name = 'Multi-Account Targeted Reconnaissance';
  readonly description =
    'Detects a single source IP address actively probing, scanning, or enumerating multiple user accounts within a sliding temporal window.';
  readonly category: EventCategory = 'AUTHENTICATION';
  readonly defaultSeverity: Severity = 'MEDIUM';
  readonly defaultThreshold = 4; // distinct handles probed
  readonly defaultSlidingWindowSeconds = 180;
  readonly mitreAttack = {
    techniqueId: 'T1595',
    techniqueName: 'Active Scanning',
    tactic: 'Reconnaissance',
  };

  async evaluate(
    context: RuleEvaluationContext,
    ruleConfig?: Partial<DetectionRule>
  ): Promise<Detection[]> {
    const threshold = ruleConfig?.threshold ?? this.defaultThreshold;
    const windowSeconds = ruleConfig?.slidingWindowSeconds ?? this.defaultSlidingWindowSeconds;
    const windowMs = windowSeconds * 1000;

    const events = this.filterAndSortEvents(context, [
      'recon.account.probe',
      'auth.login.failed',
    ]);

    if (events.length === 0) {
      return [];
    }

    const eventsByIp = new Map<string, typeof events>();
    for (const event of events) {
      if (!event.username) continue;
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
        const distinctHandles = [...new Set(windowEvents.map((e) => e.username!).filter(Boolean))];

        // Check if enumeration telemetry indicators exist (probing nonexistent accounts or explicit recon probes)
        
        if (distinctHandles.length >= threshold) {
          const relatedEventIds = windowEvents.map((e) => e.eventId);

          const detection = this.createDetection({
            orgId: context.organizationId,
            severity: ruleConfig?.severity || this.defaultSeverity,
            confidence: 75,
            title: `Account Enumeration / Reconnaissance from ${sourceIp}`,
            description: `Source IP ${sourceIp} probed ${distinctHandles.length} user handles (${distinctHandles.slice(0, 5).join(', ')}) within ${windowSeconds}s.`,
            relatedEventIds,
            detectedAt: rightEvent.timestamp,
            evidence: {
              matchedRuleId: this.id,
              matchedThreshold: threshold,
              actualCount: distinctHandles.length,
              timeWindowSeconds: windowSeconds,
              targetEntity: {
                type: 'IP',
                value: sourceIp,
              },
              triggeringEvents: relatedEventIds,
              details: {
                sourceIp,
                probedUsernames: distinctHandles,
                probeCount: distinctHandles.length,
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
