import type { Detection, DetectionRule, EventCategory, Severity } from '@veltrix/shared';
import { BaseDetectionRule } from './base-rule.js';
import type { RuleEvaluationContext } from '../types.js';

export class Rule005SuspiciousIp extends BaseDetectionRule {
  readonly id = 'RULE-005';
  readonly name = 'Known Malicious / Tor / Proxy IP Activity';
  readonly description =
    'Detects telemetry, connections, or authentication attempts associated with known malicious IP indicators, Tor exit nodes, or botnet command-and-control infrastructure.';
  readonly category: EventCategory = 'NETWORK';
  readonly defaultSeverity: Severity = 'CRITICAL';
  readonly defaultThreshold = 1;
  readonly defaultSlidingWindowSeconds = 300;
  readonly mitreAttack = {
    techniqueId: 'T1090',
    techniqueName: 'Proxy',
    tactic: 'Command and Control',
  };

  // Embedded offline seed indicator set (supplemented dynamically by context.threatIndicators)
  private static readonly KNOWN_SUSPICIOUS_IPS = new Set([
    '198.51.100.66', // Known Tor Exit Node test fixture
    '203.0.113.199', // Malicious C2 Scanner fixture
    '192.0.2.100',   // Known Botnet node fixture
    '185.220.101.5', // Known Public Tor Exit Node sample
    '185.220.101.6',
    '185.220.101.7',
  ]);

  async evaluate(
    context: RuleEvaluationContext,
    ruleConfig?: Partial<DetectionRule>
  ): Promise<Detection[]> {
    const { events, threatIndicators } = context;
    if (!Array.isArray(events) || events.length === 0) {
      return [];
    }

    // Build complete set of malicious IPs from local indicators + evaluation context
    const suspiciousIps = new Set(Rule005SuspiciousIp.KNOWN_SUSPICIOUS_IPS);
    if (threatIndicators && Array.isArray(threatIndicators)) {
      for (const indicator of threatIndicators) {
        if (indicator.type === 'IP') {
          suspiciousIps.add(indicator.value);
        }
      }
    }

    // Also support customConfig configured suspicious IPs
    const customIps = context.customConfig?.suspiciousIps;
    if (Array.isArray(customIps)) {
      for (const ip of customIps) {
        if (typeof ip === 'string') suspiciousIps.add(ip);
      }
    }

    const detections: Detection[] = [];
    const eventsByIp = new Map<string, typeof events>();

    for (const event of events) {
      if (event.orgId !== context.organizationId) continue;
      const ip = event.sourceIp;
      if (suspiciousIps.has(ip) || event.metadata?.isTorExitNode === true || event.metadata?.threatIntelMatch) {
        if (!eventsByIp.has(ip)) {
          eventsByIp.set(ip, []);
        }
        eventsByIp.get(ip)!.push(event);
      }
    }

    for (const [sourceIp, matchedEvents] of eventsByIp.entries()) {
      const eventIds = matchedEvents.map((e) => e.eventId);
      const eventTypes = [...new Set(matchedEvents.map((e) => e.eventType))];
      const usernames = [...new Set(matchedEvents.map((e) => e.username).filter(Boolean))];

      const detection = this.createDetection({
        orgId: context.organizationId,
        severity: ruleConfig?.severity || this.defaultSeverity,
        confidence: 95,
        title: `Malicious / Threat Intelligence IP Activity: ${sourceIp}`,
        description: `Activity detected from confirmed malicious / high-risk IP ${sourceIp} across ${matchedEvents.length} events (types: ${eventTypes.join(', ')}).`,
        relatedEventIds: eventIds,
        detectedAt: matchedEvents[matchedEvents.length - 1]!.timestamp,
        evidence: {
          matchedRuleId: this.id,
          matchedThreshold: 1,
          actualCount: matchedEvents.length,
          timeWindowSeconds: this.defaultSlidingWindowSeconds,
          targetEntity: {
            type: 'IP',
            value: sourceIp,
          },
          triggeringEvents: eventIds,
          details: {
            sourceIp,
            matchedEventCount: matchedEvents.length,
            eventTypes,
            associatedUsers: usernames,
            indicatorSource: 'ThreatIntelligence-IOC',
          },
        },
      });

      detections.push(detection);
    }

    return detections;
  }
}
