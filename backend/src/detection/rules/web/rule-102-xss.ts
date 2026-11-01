import type {
  Detection,
  DetectionRule,
  EventCategory,
  Severity,
} from '@veltrix/shared';
import { BaseDetectionRule } from '../base-rule.js';
import type { RuleEvaluationContext } from '../../types.js';
import { normalizeWebTelemetry, normalizeWebTelemetryAsync } from '../../web-parser.js';

export class Rule102CrossSiteScripting extends BaseDetectionRule {
  readonly id = 'RULE-102';
  readonly name = 'Cross-Site Scripting (XSS) Probing & Injection Attempt';
  readonly description =
    'Identifies suspicious Cross-Site Scripting (XSS) payloads, inline event handlers, javascript: pseudo-protocols, or DOM injection attempts in web request telemetry.';
  readonly category: EventCategory = 'NETWORK';
  readonly defaultSeverity: Severity = 'MEDIUM';
  readonly defaultThreshold = 1;
  readonly defaultSlidingWindowSeconds = 300;
  readonly mitreAttack = {
    techniqueId: 'T1059.007',
    techniqueName: 'Command and Scripting Interpreter: JavaScript',
    tactic: 'Execution',
  };

  /**
   * High-fidelity Cross-Site Scripting detection patterns.
   */
  private readonly xssPatterns: Array<{ name: string; regex: RegExp }> = [
    {
      name: 'EXPLICIT_SCRIPT_TAG',
      regex: /<script\b[^>]*>(.*?)?(<\/script>)?/i,
    },
    {
      name: 'HTML_EVENT_HANDLER',
      regex: /<[a-z0-9_-]+\b[^>]*(onload|onerror|onclick|onmouseover|onfocus|onblur|autofocus)\s*=\s*['"]?[^>]*>/i,
    },
    {
      name: 'STANDALONE_EVENT_HANDLER',
      regex: /\b(onload|onerror|onclick|onmouseover|onfocus|onblur)\s*=\s*(alert|prompt|confirm|eval|document\.cookie|window\.location)\b/i,
    },
    {
      name: 'JAVASCRIPT_PSEUDO_PROTOCOL',
      regex: /\bjavascript:\s*([a-z0-9_$.(]|alert|eval|document|window)/i,
    },
    {
      name: 'DATA_URI_HTML',
      regex: /\bdata:text\/html[;,][^"'>\s]*/i,
    },
    {
      name: 'DOM_COOKIE_ACCESS',
      regex: /\b(document\.cookie|document\.location|window\.location)\b/i,
    },
    {
      name: 'COMMON_XSS_PROBE_FUNCTION',
      regex: /\b(alert|prompt|confirm)\s*\(\s*['"]?[a-z0-9_$. ]*['"]?\s*\)/i,
    },
  ];

  async evaluate(
    context: RuleEvaluationContext,
    ruleConfig?: Partial<DetectionRule>
  ): Promise<Detection[]> {
    const threshold = ruleConfig?.threshold ?? this.defaultThreshold;
    const windowSeconds = ruleConfig?.slidingWindowSeconds ?? this.defaultSlidingWindowSeconds;
    const windowMs = windowSeconds * 1000;

    const relevantTypes = [
      'web.request.normal',
      'web.attack.xss',
      'api.request',
      'api.anomaly',
    ];
    const events = this.filterAndSortEvents(context, relevantTypes);
    if (events.length === 0) {
      return [];
    }

    const detections: Detection[] = [];
    const eventsByEntity = new Map<string, Array<{ event: (typeof events)[0]; matches: string[]; meta: ReturnType<typeof normalizeWebTelemetry> }>>();

    for (const event of events) {
      const normalized = await normalizeWebTelemetryAsync(event);
      const matchedSignatures: string[] = [];

      for (const payload of normalized.decodedPayloads) {
        if (!payload || payload.length < 4) continue;

        for (const { name, regex } of this.xssPatterns) {
          if (regex.test(payload)) {
            if (!matchedSignatures.includes(name)) {
              matchedSignatures.push(name);
            }
          }
        }
      }

      if (matchedSignatures.length > 0 || (event.eventType === 'web.attack.xss' && normalized.corroboratingSignals.length > 0)) {
        const entityKey = `${normalized.siteId || 'global'}:${event.sourceIp}`;
        if (!eventsByEntity.has(entityKey)) {
          eventsByEntity.set(entityKey, []);
        }
        eventsByEntity.get(entityKey)!.push({
          event,
          matches: matchedSignatures,
          meta: normalized,
        });
      }
    }

    for (const entityEvents of eventsByEntity.values()) {
      if (entityEvents.length === 0) continue;

      let windowStart = 0;
      for (let windowEnd = 0; windowEnd < entityEvents.length; windowEnd++) {
        const endItem = entityEvents[windowEnd];
        if (!endItem) continue;
        const endTime = new Date(endItem.event.timestamp).getTime();

        while (windowStart < windowEnd) {
          const startItem = entityEvents[windowStart];
          if (!startItem) {
            windowStart++;
            continue;
          }
          if (endTime - new Date(startItem.event.timestamp).getTime() > windowMs) {
            windowStart++;
          } else {
            break;
          }
        }

        const windowSlice = entityEvents.slice(windowStart, windowEnd + 1);
        if (windowSlice.length >= threshold) {
          const triggeringEvents = windowSlice.map((item) => item.event);
          const latestItem = windowSlice[windowSlice.length - 1];
          if (!latestItem) continue;

          const matchedPatterns = Array.from(new Set(windowSlice.flatMap((item) => item.matches)));

          let highestConfidence = latestItem.meta.confidenceLevel;
          for (const item of windowSlice) {
            if (item.meta.confidenceLevel === 'CONFIRMED_EXPLOITATION') {
              highestConfidence = 'CONFIRMED_EXPLOITATION';
              break;
            }
            if (
              item.meta.confidenceLevel === 'POTENTIAL_EXPLOITATION' &&
              highestConfidence !== 'CONFIRMED_EXPLOITATION'
            ) {
              highestConfidence = 'POTENTIAL_EXPLOITATION';
            }
          }

          let severity: Severity = this.defaultSeverity;
          let confidenceScore = 70;

          if (highestConfidence === 'CONFIRMED_EXPLOITATION') {
            severity = 'CRITICAL';
            confidenceScore = 95;
          } else if (highestConfidence === 'POTENTIAL_EXPLOITATION') {
            severity = 'HIGH';
            confidenceScore = 85;
          } else if (highestConfidence === 'BLOCKED_ATTEMPT') {
            severity = 'LOW';
            confidenceScore = 60;
          } else {
            severity = windowSlice.length > 3 ? 'HIGH' : 'MEDIUM';
            confidenceScore = 70;
          }

          const detection = this.createDetection({
            orgId: context.organizationId,
            severity,
            confidence: confidenceScore,
            title: `Cross-Site Scripting (XSS) Attack Detected (${highestConfidence})`,
            description: `Identified ${windowSlice.length} XSS payload injection attempt(s) targeting ${latestItem.meta.normalizedPath} from IP ${latestItem.event.sourceIp}.`,
            relatedEventIds: triggeringEvents.map((e) => e.eventId),
            detectedAt: latestItem.event.timestamp,
            evidence: {
              matchedRuleId: this.id,
              matchedThreshold: threshold,
              actualCount: windowSlice.length,
              timeWindowSeconds: windowSeconds,
              targetEntity: {
                type: 'IP',
                value: latestItem.event.sourceIp,
              },
              triggeringEvents: triggeringEvents.map((e) => e.eventId),
              details: {
                siteId: latestItem.meta.siteId,
                domain: latestItem.meta.domain,
                sourceIp: latestItem.event.sourceIp,
                requestUri: latestItem.meta.rawUri,
                httpMethod: latestItem.meta.httpMethod,
                matchedPatterns,
                confidenceLevel: highestConfidence,
                evidenceProvenance: latestItem.meta.evidenceProvenance,
                corroboratingSignals: latestItem.meta.corroboratingSignals,
                attackType: 'XSS',
              },
            },
          });

          detections.push(detection);
          windowStart = windowEnd + 1;
        }
      }
    }

    return detections;
  }
}
