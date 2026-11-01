import type {
  Detection,
  DetectionRule,
  EventCategory,
  Severity,
} from '@veltrix/shared';
import { BaseDetectionRule } from '../base-rule.js';
import type { RuleEvaluationContext } from '../../types.js';
import { normalizeWebTelemetry } from '../../web-parser.js';

export class Rule101SqlInjection extends BaseDetectionRule {
  readonly id = 'RULE-101';
  readonly name = 'SQL Injection Probing & Exploitation Attempt';
  readonly description =
    'Identifies suspicious SQL injection patterns, boolean-based bypasses, union extraction, or execution anomalies in web request telemetry.';
  readonly category: EventCategory = 'NETWORK';
  readonly defaultSeverity: Severity = 'HIGH';
  readonly defaultThreshold = 1;
  readonly defaultSlidingWindowSeconds = 300;
  readonly mitreAttack = {
    techniqueId: 'T1190',
    techniqueName: 'Exploit Public-Facing Application',
    tactic: 'Initial Access',
  };

  /**
   * High-fidelity SQL injection detection patterns.
   */
  private readonly sqliPatterns: Array<{ name: string; regex: RegExp }> = [
    // Boolean-based injections: ' OR 1=1, ' OR '1'='1', ' OR 'a'='a', 1' OR '1'='1'--
    {
      name: 'BOOLEAN_BASED_OR_TRUE',
      regex: /('|"|`|\b)\s*(or|and)\s+['"]?(\w+)['"]?\s*=\s*['"]?\3['"]?(\s*--|\s*#|\s*\/\*|$)/i,
    },
    {
      name: 'NUMERIC_OR_EQUALITY',
      regex: /['"]?\s*(or|and)\s+(\d+)\s*=\s*\2(\s*--|\s*#|\s*\/\*|$)/i,
    },
    // Union-based data extraction: UNION SELECT, UNION ALL SELECT
    {
      name: 'UNION_SELECT',
      regex: /\bunion\s+(all\s+|distinct\s+)?select\b/i,
    },
    // Stacked queries with dangerous DML/DDL: ; DROP TABLE, ; INSERT INTO
    {
      name: 'STACKED_QUERY_DML_DDL',
      regex: /;\s*(drop\s+(table|database)|delete\s+from|insert\s+into|update\s+\w+\s+set|truncate\s+table|create\s+table)\b/i,
    },
    // Schema enumeration: information_schema, sys.tables, sqlite_master
    {
      name: 'SCHEMA_ENUMERATION',
      regex: /\b(information_schema\.(tables|columns)|sys\.(tables|objects)|sqlite_master|pg_catalog\.pg_tables)\b/i,
    },
    // Time-based blind injection: SLEEP(5), BENCHMARK(1000000), WAITFOR DELAY '0:0:5'
    {
      name: 'TIME_BASED_BLIND',
      regex: /\b(sleep\s*\(\s*\d+\s*\)|benchmark\s*\(\s*\d+,\s*.*?\)|pg_sleep\s*\(\s*\d+\s*\)|waitfor\s+delay\s+['"]\d+:\d+:\d+['"])/i,
    },
    // Authentication bypass comment tokens: admin'--, admin' #, ' /*!50000
    {
      name: 'AUTH_BYPASS_COMMENT',
      regex: /\b(admin|root|administrator)['"]?\s*(--|#|\/\*)/i,
    },
    // MySQL comment evasions with keywords: /*!SELECT*/
    {
      name: 'MYSQL_COMMENT_EVASION',
      regex: /\/\*![\d]*\s*(select|union|insert|delete)\b/i,
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
      'web.attack.sqli',
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

      for (const payload of normalized.decodedPayloads) {
        if (!payload || payload.length < 3) continue;

        for (const { name, regex } of this.sqliPatterns) {
          if (regex.test(payload)) {
            if (!matchedSignatures.includes(name)) {
              matchedSignatures.push(name);
            }
          }
        }
      }

      if (matchedSignatures.length > 0 || (event.eventType === 'web.attack.sqli' && normalized.corroboratingSignals.length > 0)) {
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
          let confidenceScore = 75;

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
            confidenceScore = 70;
          }

          const detection = this.createDetection({
            orgId: context.organizationId,
            severity,
            confidence: confidenceScore,
            title: `SQL Injection Attack Detected (${highestConfidence})`,
            description: `Identified ${windowSlice.length} SQL injection probing or exploitation attempt(s) targeting ${latestItem.meta.normalizedPath} from IP ${latestItem.event.sourceIp}.`,
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
                attackType: 'SQLI',
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
