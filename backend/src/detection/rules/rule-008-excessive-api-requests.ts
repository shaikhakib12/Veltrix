import type { Detection, DetectionRule, EventCategory, Severity } from '@veltrix/shared';
import { BaseDetectionRule } from './base-rule.js';
import type { RuleEvaluationContext } from '../types.js';

export class Rule008ExcessiveApiRequests extends BaseDetectionRule {
  readonly id = 'RULE-008';
  readonly name = 'Excessive / Burst API Requests';
  readonly description =
    'Detects abnormal API request volumes or denial-of-service bursts exceeding 100 requests per minute originating from a single source.';
  readonly category: EventCategory = 'API';
  readonly defaultSeverity: Severity = 'MEDIUM';
  readonly defaultThreshold = 100;
  readonly defaultSlidingWindowSeconds = 60;
  readonly mitreAttack = {
    techniqueId: 'T1499',
    techniqueName: 'Endpoint Denial of Service',
    tactic: 'Impact',
  };

  async evaluate(
    context: RuleEvaluationContext,
    ruleConfig?: Partial<DetectionRule>
  ): Promise<Detection[]> {
    const threshold = ruleConfig?.threshold ?? this.defaultThreshold;
    const windowSeconds = ruleConfig?.slidingWindowSeconds ?? this.defaultSlidingWindowSeconds;
    const windowMs = windowSeconds * 1000;

    const events = this.filterAndSortEvents(context, ['api.request', 'api.request.burst', 'api.anomaly']);
    if (events.length === 0) {
      return [];
    }

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
      let left = 0;
      for (let right = 0; right < ipEvents.length; right++) {
        const rightEvent = ipEvents[right]!;
        const rightTime = new Date(rightEvent.timestamp).getTime();

        while (left < right && rightTime - new Date(ipEvents[left]!.timestamp).getTime() > windowMs) {
          left++;
        }

        const countInWindow = right - left + 1;
        // Also check if an explicit burst event carries requestCount metadata
        const currentMeta = (rightEvent.metadata || {}) as Record<string, unknown>;
        const burstCount = typeof currentMeta.requestCount === 'number' ? currentMeta.requestCount : countInWindow;

        if (burstCount >= threshold) {
          const windowEvents = ipEvents.slice(left, right + 1);
          const relatedEventIds = windowEvents.map((e) => e.eventId);

          const detection = this.createDetection({
            orgId: context.organizationId,
            severity: ruleConfig?.severity || this.defaultSeverity,
            confidence: 80,
            title: `Excessive API Request Burst from ${sourceIp}`,
            description: `IP ${sourceIp} generated ${burstCount} API requests within ${windowSeconds}s, exceeding configured threshold of ${threshold} req/min.`,
            relatedEventIds,
            detectedAt: rightEvent.timestamp,
            evidence: {
              matchedRuleId: this.id,
              matchedThreshold: threshold,
              actualCount: burstCount,
              timeWindowSeconds: windowSeconds,
              targetEntity: {
                type: 'IP',
                value: sourceIp,
              },
              triggeringEvents: relatedEventIds,
              details: {
                sourceIp,
                requestCount: burstCount,
                endpoints: [...new Set(windowEvents.map((e) => (e.metadata?.endpoint as string) || '/api'))],
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
