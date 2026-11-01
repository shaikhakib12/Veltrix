import type {
  Detection,
  DetectionRule,
  EventCategory,
  Severity,
} from '@veltrix/shared';
import { BaseDetectionRule } from '../base-rule.js';
import type { RuleEvaluationContext } from '../../types.js';
import { normalizeWebTelemetry, normalizeWebTelemetryAsync } from '../../web-parser.js';

export class Rule105AuthFlowTampering extends BaseDetectionRule {
  readonly id = 'RULE-105';
  readonly name = 'Web Authentication Flow Tampering & Credential Abuse';
  readonly description =
    'Identifies authentication endpoint brute-forcing, multi-account credential stuffing, rapid password reset abuse, or MFA flow tampering targeting website assets.';
  readonly category: EventCategory = 'AUTHENTICATION';
  readonly defaultSeverity: Severity = 'HIGH';
  readonly defaultThreshold = 3;
  readonly defaultSlidingWindowSeconds = 180;
  readonly mitreAttack = {
    techniqueId: 'T1110.003',
    techniqueName: 'Brute Force: Credential Stuffing',
    tactic: 'Credential Access',
  };

  /**
   * Sensitive authentication and account management endpoints.
   */
  private readonly authEndpoints: RegExp[] = [
    /\/(login|signin|authenticate|auth|oauth|token|session)\b/i,
    /\/(password[\/\-_]reset|forgot[\/\-_]password|reset[\/\-_]password)\b/i,
    /\/(mfa|2fa|otp|verify[\/\-_]code)\b/i,
  ];

  async evaluate(
    context: RuleEvaluationContext,
    ruleConfig?: Partial<DetectionRule>
  ): Promise<Detection[]> {
    const threshold = ruleConfig?.threshold ?? this.defaultThreshold;
    const windowSeconds = ruleConfig?.slidingWindowSeconds ?? this.defaultSlidingWindowSeconds;
    const windowMs = windowSeconds * 1000;

    const relevantTypes = [
      'auth.login.failed',
      'auth.mfa.failed',
      'auth.credential_stuffing',
      'auth.password.reset',
      'web.request.normal',
      'web.attack.api_abuse',
    ];
    const events = this.filterAndSortEvents(context, relevantTypes);
    if (events.length === 0) {
      return [];
    }

    const detections: Detection[] = [];
    const eventsByEntity = new Map<string, Array<{ event: (typeof events)[0]; meta: ReturnType<typeof normalizeWebTelemetry>; isAuthTampering: boolean }>>();

    for (const event of events) {
      const normalized = await normalizeWebTelemetryAsync(event);
      const path = normalized.normalizedPath;

      const isAuthPath = this.authEndpoints.some((rx) => rx.test(path));
      const hasWebContext = Boolean(
        normalized.siteId ||
        normalized.domain ||
        isAuthPath ||
        event.eventType === 'auth.credential_stuffing'
      );

      const isAuthFailure =
        hasWebContext &&
        (event.eventType === 'auth.login.failed' ||
          event.eventType === 'auth.mfa.failed' ||
          event.eventType === 'auth.credential_stuffing' ||
          (isAuthPath && (normalized.httpStatus === 401 || normalized.httpStatus === 403)));

      if (isAuthFailure || (isAuthPath && event.eventType === 'auth.password.reset')) {
        const entityKey = `${normalized.siteId || 'global'}:${event.sourceIp}`;
        if (!eventsByEntity.has(entityKey)) {
          eventsByEntity.set(entityKey, []);
        }
        eventsByEntity.get(entityKey)!.push({
          event,
          meta: normalized,
          isAuthTampering: true,
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

          // Check if credential stuffing (multiple distinct usernames targeted)
          const targetedUsers = Array.from(
            new Set(
              windowSlice
                .map((i) => i.event.username)
                .filter((u): u is string => typeof u === 'string' && u.length > 0)
            )
          );

          const isCredentialStuffing = targetedUsers.length >= 2;

          let severity: Severity = this.defaultSeverity;
          let confidenceScore = 80;

          if (isCredentialStuffing || windowSlice.length >= 8) {
            severity = 'CRITICAL';
            confidenceScore = 92;
          } else if (windowSlice.length >= 5) {
            severity = 'HIGH';
            confidenceScore = 85;
          }

          const detection = this.createDetection({
            orgId: context.organizationId,
            severity,
            confidence: confidenceScore,
            title: isCredentialStuffing
              ? `Credential Stuffing & Authentication Flow Abuse Detected`
              : `Repeated Authentication Failure & Flow Tampering Detected`,
            description: `Identified ${windowSlice.length} authentication failure/tampering event(s) targeting ${latestItem.meta.normalizedPath} from IP ${latestItem.event.sourceIp}${
              isCredentialStuffing ? ` across ${targetedUsers.length} distinct account(s)` : ''
            }.`,
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
                targetedUsernames: targetedUsers,
                isCredentialStuffing,
                attackType: 'AUTH_TAMPERING',
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
