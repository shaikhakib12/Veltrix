import type { Detection, DetectionRule, EventCategory, Severity } from '@veltrix/shared';
import { BaseDetectionRule } from './base-rule.js';
import type { RuleEvaluationContext } from '../types.js';

export class Rule007UnusualDataAccess extends BaseDetectionRule {
  readonly id = 'RULE-007';
  readonly name = 'Bulk Sensitive Data Access / Exfiltration';
  readonly description =
    'Detects abnormal data exfiltration, mass record exports exceeding 10,000 records, or suspicious volume from sensitive data stores.';
  readonly category: EventCategory = 'DATA_ACCESS';
  readonly defaultSeverity: Severity = 'HIGH';
  readonly defaultThreshold = 10000; // records accessed
  readonly defaultSlidingWindowSeconds = 300;
  readonly mitreAttack = {
    techniqueId: 'T1530',
    techniqueName: 'Data from Cloud Storage Object',
    tactic: 'Exfiltration',
  };

  async evaluate(
    context: RuleEvaluationContext,
    ruleConfig?: Partial<DetectionRule>
  ): Promise<Detection[]> {
    const threshold = ruleConfig?.threshold ?? this.defaultThreshold;

    const events = this.filterAndSortEvents(context, [
      'data.access',
      'data.access.bulk',
      'data.exfiltration',
    ]);

    if (events.length === 0) {
      return [];
    }

    const detections: Detection[] = [];

    for (const event of events) {
      const metadata = (event.metadata || {}) as Record<string, unknown>;
      const recordCount = typeof metadata.recordCount === 'number' ? metadata.recordCount : 0;
      const bytesTransferred = typeof metadata.bytesTransferred === 'number' ? metadata.bytesTransferred : 0;

      const isBulkExfiltration =
        event.eventType === 'data.exfiltration' ||
        event.eventType === 'data.access.bulk' ||
        recordCount >= threshold ||
        bytesTransferred >= 50 * 1024 * 1024; // >= 50MB

      if (isBulkExfiltration) {
        const targetResource = (metadata.resource || metadata.database || metadata.target || 'sensitive-data-store') as string;
        const actor = event.username || event.sourceIp;

        const detection = this.createDetection({
          orgId: context.organizationId,
          severity: event.eventType === 'data.exfiltration' ? 'CRITICAL' : (ruleConfig?.severity || this.defaultSeverity),
          confidence: 85,
          title: `Bulk Data Access / Exfiltration Detected by ${actor}`,
          description: `Anomalous data transfer detected from resource '${targetResource}' by actor '${actor}': ${recordCount > 0 ? `${recordCount.toLocaleString()} records` : `${(bytesTransferred / 1024 / 1024).toFixed(1)} MB`}.`,
          relatedEventIds: [event.eventId],
          detectedAt: event.timestamp,
          evidence: {
            matchedRuleId: this.id,
            matchedThreshold: threshold,
            actualCount: recordCount || Math.round(bytesTransferred / 1024),
            timeWindowSeconds: this.defaultSlidingWindowSeconds,
            targetEntity: {
              type: 'RESOURCE',
              value: targetResource,
            },
            triggeringEvents: [event.eventId],
            details: {
              actor,
              sourceIp: event.sourceIp,
              targetResource,
              recordCount,
              bytesTransferred,
              eventType: event.eventType,
            },
          },
        });

        detections.push(detection);
      }
    }

    return detections;
  }
}
