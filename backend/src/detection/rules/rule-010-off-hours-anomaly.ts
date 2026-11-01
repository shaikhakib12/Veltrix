import type { Detection, DetectionRule, EventCategory, Severity } from '@veltrix/shared';
import { BaseDetectionRule } from './base-rule.js';
import type { RuleEvaluationContext } from '../types.js';
import { isValidIanaTimezone } from '../../utils/timezone.js';

export class Rule010OffHoursAnomaly extends BaseDetectionRule {
  readonly id = 'RULE-010';
  readonly name = 'Off-Hours Administrative Anomaly';
  readonly description =
    'Detects sensitive administrative actions, privilege policy modifications, or service disruptions executed outside configured organization business hours.';
  readonly category: EventCategory = 'SYSTEM';
  readonly defaultSeverity: Severity = 'HIGH';
  readonly defaultThreshold = 1;
  readonly defaultSlidingWindowSeconds = 300;
  readonly mitreAttack = {
    techniqueId: 'T1078',
    techniqueName: 'Valid Accounts',
    tactic: 'Persistence',
  };

  /**
   * Resolves local business hour and weekday for an event date.
   * Prioritizes full IANA timezone identifiers (e.g. 'America/New_York', 'Europe/London')
   * with automatic Daylight Saving Time (DST) calculation via standard Intl.DateTimeFormat.
   * Falls back to numeric timezoneOffsetHours or UTC if timezone is omitted or invalid.
   */
  private resolveLocalTime(
    eventDate: Date,
    timezone?: string,
    timezoneOffsetHours: number = 0
  ): { localHour: number; localDay: number; effectiveTz: string } {
    if (timezone && typeof timezone === 'string' && timezone.trim().length > 0) {
      try {
        const formatter = new Intl.DateTimeFormat('en-US', {
          timeZone: timezone.trim(),
          hour12: false,
          weekday: 'short',
          hour: 'numeric',
        });
        const parts = formatter.formatToParts(eventDate);
        const hourStr = parts.find((p) => p.type === 'hour')?.value;
        const weekdayStr = parts.find((p) => p.type === 'weekday')?.value;

        const dayMap: Record<string, number> = {
          Sun: 0,
          Mon: 1,
          Tue: 2,
          Wed: 3,
          Thu: 4,
          Fri: 5,
          Sat: 6,
        };

        if (hourStr !== undefined && weekdayStr !== undefined && dayMap[weekdayStr] !== undefined) {
          const parsedHour = parseInt(hourStr, 10);
          return {
            localHour: parsedHour === 24 ? 0 : parsedHour,
            localDay: dayMap[weekdayStr]!,
            effectiveTz: timezone.trim(),
          };
        }
      } catch {
        // Fallback to offsetHours if IANA identifier is invalid or unsupported
      }
    }

    // Fallback: apply numeric timezoneOffsetHours relative to UTC
    const localTimeMs = eventDate.getTime() + timezoneOffsetHours * 3600 * 1000;
    const localDate = new Date(localTimeMs);
    return {
      localHour: localDate.getUTCHours(),
      localDay: localDate.getUTCDay(),
      effectiveTz: timezoneOffsetHours !== 0 ? `UTC${timezoneOffsetHours >= 0 ? '+' : ''}${timezoneOffsetHours}` : 'UTC',
    };
  }

  async evaluate(
    context: RuleEvaluationContext,
    ruleConfig?: Partial<DetectionRule>
  ): Promise<Detection[]> {
    // Configurable working hours (defaults: 06:00 to 22:00 local)
    const condition = (ruleConfig?.condition || {}) as Record<string, unknown>;
    const businessStartHour = typeof condition.startHour === 'number' ? condition.startHour : 6;
    const businessEndHour = typeof condition.endHour === 'number' ? condition.endHour : 22;
    // IANA timezone identifier (e.g. 'America/New_York', 'Europe/London', 'Asia/Tokyo')
    const timezone = typeof condition.timezone === 'string' ? condition.timezone : undefined;

    // Safety Policy: If tenant configured an invalid timezone, do NOT silently fall back to UTC.
    // Record a clear configuration error and safely skip evaluation until corrected.
    if (timezone !== undefined && !isValidIanaTimezone(timezone)) {
      console.error(
        `[VELTRIX-RULE-010-CONFIG-ERROR] Tenant '${context.organizationId}' has configured an invalid IANA timezone: '${timezone}'. Skipping off-hours anomaly evaluation to prevent misleading detections until configuration is corrected.`
      );
      return [];
    }
    // Organization-configurable timezone offset in hours relative to UTC (default: 0)
    const timezoneOffsetHours = typeof condition.timezoneOffsetHours === 'number' ? condition.timezoneOffsetHours : 0;
    // Organization-configurable weekend days (default: Sunday=0, Saturday=6)
    const weekendDays: number[] = Array.isArray(condition.weekendDays) ? condition.weekendDays : [0, 6];

    const events = this.filterAndSortEvents(context, [
      'admin.action',
      'privilege.policy.mutation',
      'system.service.stop',
      'system.file.modify',
    ]);

    if (events.length === 0) {
      return [];
    }

    const detections: Detection[] = [];

    for (const event of events) {
      const eventDate = new Date(event.timestamp);
      const utcHour = eventDate.getUTCHours();

      // Resolve local hour and day taking into account IANA timezone with DST
      const { localHour, localDay, effectiveTz } = this.resolveLocalTime(
        eventDate,
        timezone,
        timezoneOffsetHours
      );

      const isWeekend = weekendDays.includes(localDay);

      // Off-hours if outside local businessStartHour..businessEndHour or on configured weekend
      const isOffHours = localHour < businessStartHour || localHour >= businessEndHour || isWeekend;

      if (isOffHours) {
        const actor = event.username || event.sourceIp;
        const action = (event.metadata?.action as string) || event.eventType;

        const detection = this.createDetection({
          orgId: context.organizationId,
          severity: ruleConfig?.severity || this.defaultSeverity,
          confidence: 80,
          title: `Off-Hours Administrative Activity by ${actor}`,
          description: `Sensitive administrative action '${action}' executed outside authorized business hours at ${eventDate.toISOString()} UTC (business window: ${String(businessStartHour).padStart(2, '0')}:00 - ${String(businessEndHour).padStart(2, '0')}:00 local in ${effectiveTz}).`,
          relatedEventIds: [event.eventId],
          detectedAt: event.timestamp,
          evidence: {
            matchedRuleId: this.id,
            matchedThreshold: 1,
            actualCount: 1,
            timeWindowSeconds: this.defaultSlidingWindowSeconds,
            targetEntity: {
              type: event.username ? 'USER' : 'IP',
              value: actor,
            },
            triggeringEvents: [event.eventId],
            details: {
              actor,
              sourceIp: event.sourceIp,
              action,
              utcHour,
              localHour,
              localDay,
              effectiveTz,
              timezone: timezone || undefined,
              timezoneOffsetHours,
              businessStartHour,
              businessEndHour,
              isWeekend,
              timestampUtc: event.timestamp,
            },
          },
        });

        detections.push(detection);
      }
    }

    return detections;
  }
}
