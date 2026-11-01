import type {
  Detection,
  DetectionRule,
  EventCategory,
  Severity,
} from '@veltrix/shared';
import { BaseDetectionRule } from '../base-rule.js';
import type { RuleEvaluationContext } from '../../types.js';
import { normalizeWebTelemetry } from '../../web-parser.js';

export class Rule104BotActivity extends BaseDetectionRule {
  readonly id = 'RULE-104';
  readonly name = 'Malicious Bot, Scraper & Endpoint Reconnaissance Activity';
  readonly description =
    'Identifies automated scanner behavior, aggressive web scraping, high-frequency 404/403 endpoint enumeration, or known offensive security tool signatures.';
  readonly category: EventCategory = 'NETWORK';
  readonly defaultSeverity: Severity = 'MEDIUM';
  readonly defaultThreshold = 5;
  readonly defaultSlidingWindowSeconds = 120;
  readonly mitreAttack = {
    techniqueId: 'T1595.002',
    techniqueName: 'Active Scanning: Vulnerability Scanning',
    tactic: 'Reconnaissance',
  };

  /**
   * Sensitive endpoint enumeration patterns commonly probed by automated scanners.
   */
  private readonly sensitiveEndpointPatterns: RegExp[] = [
    /\/\.(env|git|svn|hg|ds_store|bak|old|sql|tar\.gz|zip|conf|cfg)\b/i,
    /\/wp-(admin|login|config|content|includes)\b/i,
    /\/(phpmyadmin|pma|adminer|actuator|swagger|api-docs|solr|cpanel|webmail|cgi-bin)\b/i,
    /\/(server-status|server-info|\.aws|\.ssh|credentials|database\.sqlite)\b/i,
  ];

  /**
   * Known security scanners and automated tooling user-agents.
   */
  private readonly aggressiveToolUserAgents: RegExp[] = [
    /\b(sqlmap|nikto|nmap|masscan|zgrab|wpscan|dirbuster|gobuster|ffuf|acunetix|nessus|openvas|hydra|burpcollaborator)\b/i,
  ];

  /**
   * Scripting libraries (require corroborating enumeration/frequency to flag).
   */
  private readonly scriptUserAgents: RegExp[] = [
    /\b(curl|python-requests|python-urllib|go-http-client|apache-httpclient|aiohttp|wget|httpx)\b/i,
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
      'web.attack.bot',
      'api.request',
      'api.request.burst',
      'network.port.scan',
    ];
    const events = this.filterAndSortEvents(context, relevantTypes);
    if (events.length === 0) {
      return [];
    }

    const detections: Detection[] = [];
    const eventsByEntity = new Map<string, Array<{ event: (typeof events)[0]; meta: ReturnType<typeof normalizeWebTelemetry>; isProbe: boolean; hasToolUa: boolean }>>();

    for (const event of events) {
      const normalized = normalizeWebTelemetry(event);
      const ua = normalized.userAgent || '';
      const path = normalized.normalizedPath;

      const isSensitivePath = this.sensitiveEndpointPatterns.some((rx) => rx.test(path));
      const isErrorStatus = normalized.httpStatus === 404 || normalized.httpStatus === 403 || normalized.httpStatus === 401;
      const isEnumerationProbe = isSensitivePath || isErrorStatus;

      const hasAggressiveToolUa = this.aggressiveToolUserAgents.some((rx) => rx.test(ua));
      const hasScriptUa = this.scriptUserAgents.some((rx) => rx.test(ua));

      const isSuspicious =
        hasAggressiveToolUa ||
        (hasScriptUa && isEnumerationProbe) ||
        (isSensitivePath && isErrorStatus) ||
        event.eventType === 'web.attack.bot' ||
        normalized.isBot === true;

      if (isSuspicious) {
        const entityKey = `${normalized.siteId || 'global'}:${event.sourceIp}`;
        if (!eventsByEntity.has(entityKey)) {
          eventsByEntity.set(entityKey, []);
        }
        eventsByEntity.get(entityKey)!.push({
          event,
          meta: normalized,
          isProbe: isEnumerationProbe,
          hasToolUa: hasAggressiveToolUa,
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
        const hasTool = windowSlice.some((i) => i.hasToolUa);

        if (windowSlice.length >= threshold) {
          const triggeringEvents = windowSlice.map((item) => item.event);
          const latestItem = windowSlice[windowSlice.length - 1];
          if (!latestItem) continue;

          const probedPaths = Array.from(new Set(windowSlice.map((item) => item.meta.normalizedPath)));

          let severity: Severity = 'MEDIUM';
          let confidenceScore = 75;

          if (hasTool && windowSlice.length >= 5) {
            severity = 'HIGH';
            confidenceScore = 90;
          } else if (windowSlice.length > 15) {
            severity = 'HIGH';
            confidenceScore = 85;
          }

          const detection = this.createDetection({
            orgId: context.organizationId,
            severity,
            confidence: confidenceScore,
            title: `Malicious Bot & Automated Reconnaissance Detected`,
            description: `Detected ${windowSlice.length} automated reconnaissance request(s) from IP ${latestItem.event.sourceIp} probing sensitive paths across ${probedPaths.length} endpoint(s).`,
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
                userAgent: latestItem.meta.userAgent,
                probedPaths: probedPaths.slice(0, 10),
                totalProbesCount: windowSlice.length,
                hasKnownScannerTool: hasTool,
                attackType: 'BOT_ACTIVITY',
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
