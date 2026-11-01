import type {
  Severity,
  WebConfidenceTier,
  RiskBand,
  WebsiteEnvironment,
  WebRiskFactors,
} from '@veltrix/shared';

export interface VulnerabilityOverlapMatch {
  overlapLevel: 'EXACT' | 'PATH' | 'ASSET' | 'NONE';
  weight: number;
  findingCvss: number;
  confidenceMultiplier: number;
  termValue: number;
}

export interface RiskCalculationInput {
  detectionsSeverity: Severity[];
  eventCount: number;
  uniqueAttackTypes: string[];
  highestConfidence: WebConfidenceTier;
  assetEnvironment?: WebsiteEnvironment;
  isThreatIntelFlagged?: boolean;
  threatIntelSeverity?: Severity;
  vulnerabilityOverlap?: VulnerabilityOverlapMatch;
}

export interface RiskEngineResult {
  score: number;
  riskBand: RiskBand;
  factors: WebRiskFactors;
  explanation: string;
}
