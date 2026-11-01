import type {
  Detection,
  Incident,
  SecurityEvent,
  VulnerabilityFindingSummary,
} from '@veltrix/shared';

export interface CorrelationWindowBucket {
  bucketKey: string;
  orgId: string;
  siteId?: string;
  domain?: string;
  sourceIp: string;
  windowStart: string;
  windowEnd: string;
  detections: Detection[];
  events: SecurityEvent[];
  attackTypes: Set<string>;
}

export interface CorrelationResult {
  incident: Incident;
  isNewIncident: boolean;
  correlationKey: string;
}

export interface VulnerabilityCorrelatorInterface {
  findMatchingVulnerability(
    siteId: string,
    attackType: string,
    targetUri: string,
    parameter?: string
  ): Promise<VulnerabilityFindingSummary | null>;
}
