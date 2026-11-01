import type {
  Detection,
  DetectionRule,
  EventCategory,
  Severity,
} from '@veltrix/shared';
import { BaseDetectionRule } from '../base-rule.js';
import type { RuleEvaluationContext } from '../../types.js';
import { normalizeWebTelemetry } from '../../web-parser.js';

export class Rule103PathTraversal extends BaseDetectionRule {
  readonly id = 'RULE-103';
  readonly name = 'Path Traversal & Local File Inclusion Attempt';
  readonly description =
    'Identifies path traversal sequences (../, ..\\), directory climbing, sensitive operating system file targets, or PHP wrapper abuse in web request telemetry.';
  readonly category: EventCategory = 'NETWORK';
  readonly defaultSeverity: Severity = 'HIGH';
  readonly defaultThreshold = 1;
  readonly defaultSlidingWindowSeconds = 300;
  readonly mitreAttack = {
    techniqueId: 'T1083',
    techniqueName: 'File and Directory Discovery',
    tactic: 'Discovery',
  };

  /**
   * High-fidelity Path Traversal / LFI detection patterns.
   */
  private readonly traversalPatterns: Array<{ name: string; regex: RegExp }> = [
    {
      name: 'DIRECTORY_CLIMBING_SEQUENCE',
      regex: /(\.\.[\/\\]|%2e%2e[\/\\]|\.\.%2f|\.\.%5c|%2e%2e%2f|%2e%2e%5c|\.\.\.\.[\/\\])/i,
    },
    {
      name: 'UNIX_SYSTEM_FILE_TARGET',
      regex: /(\/|\\)?etc[\/\\](passwd|shadow|hosts|group|issue|crontab|resolv\.conf)\b/i,
    },
    {
      name: 'PROC_FILESYSTEM_ACCESS',
      regex: /(\/|\\)?proc[\/\\](self|version|cpuinfo|environ|cmdline)\b/i,
    },
    {
      name: 'WINDOWS_SYSTEM_FILE_TARGET',
      regex: /(\b|[\/\\])(windows[\/\\]win\.ini|boot\.ini|system32[\/\\]drivers[\/\\]etc[\/\\]hosts)\b/i,
    },
    {
      name: 'SENSITIVE_CONFIG_TARGET',
      regex: /(\b|[\/\\])(\.env|\.git[\/\\]config|\.git[\/\\]HEAD|web\.config|wp-config\.php)\b/i,
    },
    {
      name: 'LFI_WRAPPER_PROTOCOL',
      regex: /\b(php:\/\/filter|php:\/\/input|data:\/\/text\/plain|expect:\/\/|file:\/\/)\b/i,
    },
    {
      name: 'NULL_BYTE_INJECTION',
      regex: /(%00|\x00)/i,
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
      'web.attack.traversal',
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
      const normalized = normalizeWebTelemetry(event);
      const matchedSignatures: string[] = [];

      const candidates = [
        normalized.rawUri,
        normalized.normalizedPath,
        ...normalized.decodedPayloads,
      ];

      for (const candidate of candidates) {
        if (!candidate || candidate.length < 3) continue;

        for (const { name, regex } of this.traversalPatterns) {
          if (regex.test(candidate)) {
            if (!matchedSignatures.includes(name)) {
              matchedSignatures.push(name);
            }
          }
        }
      }

      if (matchedSignatures.length > 0 || (event.eventType === 'web.attack.traversal' && normalized.corroboratingSignals.length > 0)) {
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
          let confidenceScore = 80;

          if (highestConfidence === 'CONFIRMED_EXPLOITATION') {
            severity = 'CRITICAL';
            confidenceScore = 98;
          } else if (highestConfidence === 'POTENTIAL_EXPLOITATION') {
            severity = 'HIGH';
            confidenceScore = 88;
          } else if (highestConfidence === 'BLOCKED_ATTEMPT') {
            severity = 'LOW';
            confidenceScore = 60;
          } else {
            severity = windowSlice.length > 3 ? 'HIGH' : 'MEDIUM';
            confidenceScore = 75;
          }

          const detection = this.createDetection({
            orgId: context.organizationId,
            severity,
            confidence: confidenceScore,
            title: `Path Traversal & LFI Attempt Detected (${highestConfidence})`,
            description: `Identified ${windowSlice.length} path traversal / directory climbing attempt(s) targeting ${latestItem.meta.normalizedPath} from IP ${latestItem.event.sourceIp}.`,
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
                corroboratingSignals: latestItem.meta.corroboratingSignals,
                attackType: 'PATH_TRAVERSAL',
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
