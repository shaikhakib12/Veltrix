import type { Detection, DetectionRule, EventCategory, Severity } from '@veltrix/shared';
import { BaseDetectionRule } from './base-rule.js';
import type { RuleEvaluationContext } from '../types.js';

export class Rule004ImpossibleTravel extends BaseDetectionRule {
  readonly id = 'RULE-004';
  readonly name = 'Anomalous Geolocation / Impossible Travel';
  readonly description =
    'Detects successive successful authentications for the same user originating from geographically distant locations or disjoint public IP addresses within an impossible travel timeframe.';
  readonly category: EventCategory = 'AUTHENTICATION';
  readonly defaultSeverity: Severity = 'HIGH';
  readonly defaultThreshold = 1;
  readonly defaultSlidingWindowSeconds = 1800; // 30 minutes
  readonly mitreAttack = {
    techniqueId: 'T1078.004',
    techniqueName: 'Cloud Accounts',
    tactic: 'Defense Evasion',
  };

  async evaluate(
    context: RuleEvaluationContext,
    ruleConfig?: Partial<DetectionRule>
  ): Promise<Detection[]> {
    const windowSeconds = ruleConfig?.slidingWindowSeconds ?? this.defaultSlidingWindowSeconds;
    const windowMs = windowSeconds * 1000;

    const events = this.filterAndSortEvents(context, ['auth.login.success']);
    if (events.length === 0) {
      return [];
    }

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
      for (let i = 1; i < userEvents.length; i++) {
        const prev = userEvents[i - 1];
        const curr = userEvents[i];
        if (!prev || !curr) continue;

        // Verify VPN/proxy suppression originates from trusted enrichment provenance or corporate gateway
        const isEventTrustedVpnOrProxy = (e: typeof prev): boolean => {
          if (!e.metadata) return false;
          const hasVpnFlag = e.metadata.isVpn === true || e.metadata.isProxy === true;
          if (!hasVpnFlag) return false;
          // Provenance check: must possess recognized enrichmentSource or trusted gateway system
          const source = typeof e.metadata.enrichmentSource === 'string' ? e.metadata.enrichmentSource.toUpperCase() : '';
          const hasTrustedSource = ['MAXMIND', 'IPINFO', 'INTERNAL_VPN_REGISTRY', 'VPN_GATEWAY'].some((s) => source.includes(s));
          const isCorporateGateway = typeof e.sourceSystem === 'string' && ['corporate-vpn', 'vpn-gateway', 'ztna-gateway'].includes(e.sourceSystem.toLowerCase());
          const isExplicitlyTrusted = e.metadata.trustedEnrichment === true;
          return hasTrustedSource || isCorporateGateway || isExplicitlyTrusted;
        };

        const isVpnOrProxy = isEventTrustedVpnOrProxy(prev) || isEventTrustedVpnOrProxy(curr);
        if (isVpnOrProxy) {
          continue;
        }

        const deltaMs = new Date(curr.timestamp).getTime() - new Date(prev.timestamp).getTime();
        if (deltaMs > windowMs || deltaMs < 0) {
          continue;
        }

        // Compare IP address and location metadata
                const prevCountry = (prev.metadata?.country || prev.metadata?.locationCountry) as string | undefined;
        const currCountry = (curr.metadata?.country || curr.metadata?.locationCountry) as string | undefined;
        const prevCity = (prev.metadata?.city || prev.metadata?.locationCity) as string | undefined;
        const currCity = (curr.metadata?.city || curr.metadata?.locationCity) as string | undefined;

        const countryChanged = prevCountry && currCountry && prevCountry.toLowerCase() !== currCountry.toLowerCase();
        const cityChanged = prevCity && currCity && prevCity.toLowerCase() !== currCity.toLowerCase();

        // Impossible travel flagged when country changes rapidly (< 30 min) or disjoint public IPs change in seconds (< 60s)
        // Impossible travel requires trusted location enrichment (country or city change); never flag solely on IP change
        const isImpossibleTravel = !!(countryChanged || (cityChanged && deltaMs < 300000));

        if (isImpossibleTravel) {
          const deltaMinutes = Math.round(deltaMs / 60000);
          const locationDesc = countryChanged
            ? `from ${prevCountry} (${prev.sourceIp}) to ${currCountry} (${curr.sourceIp})`
            : `from ${prev.sourceIp} to ${curr.sourceIp}`;

          const detection = this.createDetection({
            orgId: context.organizationId,
            severity: ruleConfig?.severity || this.defaultSeverity,
            confidence: countryChanged ? 90 : 75,
            title: `Impossible Travel Detected: ${username}`,
            description: `User '${username}' authenticated from two distinct locations ${locationDesc} within ${deltaMinutes} minutes.`,
            relatedEventIds: [prev.eventId, curr.eventId],
            detectedAt: curr.timestamp,
            evidence: {
              matchedRuleId: this.id,
              matchedThreshold: 1,
              actualCount: 1,
              timeWindowSeconds: windowSeconds,
              targetEntity: {
                type: 'USER',
                value: username,
              },
              triggeringEvents: [prev.eventId, curr.eventId],
              details: {
                username,
                firstEvent: {
                  timestamp: prev.timestamp,
                  ip: prev.sourceIp,
                  country: prevCountry,
                  city: prevCity,
                },
                secondEvent: {
                  timestamp: curr.timestamp,
                  ip: curr.sourceIp,
                  country: currCountry,
                  city: currCity,
                },
                timeDeltaSeconds: Math.round(deltaMs / 1000),
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
