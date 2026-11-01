import type {
  Severity,
  WebConfidenceTier,
  RiskBand,
  WebsiteEnvironment,
  WebRiskFactors,
} from '@veltrix/shared';
import type { RiskCalculationInput, RiskEngineResult } from './types.js';

export class RiskScoringEngine {
  /**
   * Base severity numerical values (S_base).
   */
  private readonly severityBaseScore: Record<Severity, number> = {
    CRITICAL: 40,
    HIGH: 30,
    MEDIUM: 20,
    LOW: 10,
  };

  /**
   * Asset criticality multipliers (M_asset).
   */
  private readonly assetMultipliers: Record<WebsiteEnvironment, number> = {
    PRODUCTION: 1.3,
    STAGING: 1.0,
    DEVELOPMENT: 0.8,
  };

  /**
   * Confidence multipliers for vulnerability overlap term (K_confidence).
   */
  private readonly confidenceMultipliers: Record<WebConfidenceTier, number> = {
    CONFIRMED_EXPLOITATION: 1.0,
    POTENTIAL_EXPLOITATION: 0.8,
    SUSPICIOUS_ATTEMPT: 0.4,
    BLOCKED_ATTEMPT: 0.1,
  };

  /**
   * Attack surface overlap factor weights (w_overlap).
   */
  private readonly overlapWeights = {
    EXACT: 25,
    PATH: 15,
    ASSET: 5,
    NONE: 0,
  };

  /**
   * Calculates Frequency Multiplier (M_freq) based on event / detection count.
   */
  calculateFrequencyMultiplier(eventCount: number): number {
    if (eventCount > 15) return 1.5;
    if (eventCount >= 6) return 1.3;
    if (eventCount >= 2) return 1.15;
    return 1.0;
  }

  /**
   * Calculates Threat Intelligence Multiplier (M_threat) based on reputation status.
   */
  calculateThreatMultiplier(isFlagged?: boolean, severity?: Severity): number {
    if (!isFlagged) return 1.0;
    if (severity === 'CRITICAL' || severity === 'HIGH') return 1.4;
    return 1.2;
  }

  /**
   * Computes Risk Band from numerical score (0 to 100).
   * Low: 0–24, Medium: 25–49, High: 50–74, Critical: 75–100.
   */
  computeRiskBand(score: number): RiskBand {
    if (score >= 75) return 'CRITICAL';
    if (score >= 50) return 'HIGH';
    if (score >= 25) return 'MEDIUM';
    return 'LOW';
  }

  /**
   * Evaluates the Configurable Risk Contribution Model:
   * RiskScore = min(100, max(0, Round(S_base * M_freq * M_asset * M_threat + C_vuln_match + B_sequence)))
   */
  calculateRisk(input: RiskCalculationInput): RiskEngineResult {
    // 1. S_base: Highest detection severity in the correlated incident
    let baseSeverity = 10;
    if (input.detectionsSeverity.includes('CRITICAL')) {
      baseSeverity = this.severityBaseScore.CRITICAL;
    } else if (input.detectionsSeverity.includes('HIGH')) {
      baseSeverity = this.severityBaseScore.HIGH;
    } else if (input.detectionsSeverity.includes('MEDIUM')) {
      baseSeverity = this.severityBaseScore.MEDIUM;
    } else if (input.detectionsSeverity.includes('LOW')) {
      baseSeverity = this.severityBaseScore.LOW;
    }

    // 2. M_freq: Frequency Multiplier
    const freqMultiplier = this.calculateFrequencyMultiplier(input.eventCount);

    // 3. M_asset: Asset Criticality Multiplier
    const env = input.assetEnvironment || 'PRODUCTION';
    const assetMultiplier = this.assetMultipliers[env] ?? 1.0;

    // 4. M_threat: Threat Intelligence Multiplier
    const threatMultiplier = this.calculateThreatMultiplier(
      input.isThreatIntelFlagged,
      input.threatIntelSeverity
    );

    // 5. C_vuln_match: Vulnerability Correlation Term
    let vulnTerm = 0;
    let vulnOverlapDetails = input.vulnerabilityOverlap;

    if (vulnOverlapDetails) {
      vulnTerm = vulnOverlapDetails.termValue;
    } else {
      vulnOverlapDetails = {
        overlapLevel: 'NONE',
        weight: 0,
        findingCvss: 0,
        confidenceMultiplier: this.confidenceMultipliers[input.highestConfidence] ?? 0.4,
        termValue: 0,
      };
    }

    // 6. B_sequence: Multi-stage attack progression bonus
    // Applied when 2 or more distinct attack categories occur in sequence (e.g. Bot recon + SQLi)
    const sequenceBonus = input.uniqueAttackTypes.length >= 2 ? 10 : 0;

    // 7. Base product term
    const baseProduct = baseSeverity * freqMultiplier * assetMultiplier * threatMultiplier;
    const safeBaseProduct = Number.isFinite(baseProduct) ? baseProduct : 10;
    const safeVulnTerm = Number.isFinite(vulnTerm) ? vulnTerm : 0;

    // 8. Final Raw Score & Capping
    const rawScore = safeBaseProduct + safeVulnTerm + sequenceBonus;
    const safeScore = Number.isFinite(rawScore) ? rawScore : 0;
    const finalScore = Math.min(100, Math.max(0, Math.round(safeScore)));
    const riskBand = this.computeRiskBand(finalScore);

    // 9. Transparent explanation string
    const explanation =
      `RiskScore ${finalScore}/100 (${riskBand}): Round(` +
      `S_base(${baseSeverity}) * ` +
      `M_freq(${freqMultiplier.toFixed(2)}) * ` +
      `M_asset(${assetMultiplier.toFixed(2)}) * ` +
      `M_threat(${threatMultiplier.toFixed(2)}) + ` +
      `C_vuln(${safeVulnTerm.toFixed(1)}) + ` +
      `B_seq(${sequenceBonus}))`;

    const factors: WebRiskFactors = {
      baseSeverity,
      frequencyMultiplier: freqMultiplier,
      assetCriticalityMultiplier: assetMultiplier,
      threatIntelMultiplier: threatMultiplier,
      vulnerabilityMatchTerm: vulnTerm,
      attackSequenceBonus: sequenceBonus,
      finalScore,
      riskBand,
      calculationExplanation: explanation,
      contributingFactors: {
        eventCount: input.eventCount,
        detectedAttackTypes: input.uniqueAttackTypes,
        highestConfidence: input.highestConfidence,
        assetEnvironment: env,
        threatIntelStatus: input.isThreatIntelFlagged ? 'FLAGGED_MALICIOUS' : 'CLEAN',
        vulnerabilityOverlap: vulnOverlapDetails,
      },
    };

    return {
      score: finalScore,
      riskBand,
      factors,
      explanation,
    };
  }

  /**
   * Helper to compute C_vuln_match term:
   * C_vuln_match = w_overlap * (CVSS_finding / 10) * K_confidence
   */
  computeVulnerabilityMatchTerm(
    overlapLevel: 'EXACT' | 'PATH' | 'ASSET' | 'NONE',
    findingCvss: number,
    confidence: WebConfidenceTier
  ): {
    overlapLevel: 'EXACT' | 'PATH' | 'ASSET' | 'NONE';
    weight: number;
    findingCvss: number;
    confidenceMultiplier: number;
    termValue: number;
  } {
    const weight = this.overlapWeights[overlapLevel] ?? 0;
    const kConfidence = this.confidenceMultipliers[confidence] ?? 0.4;
    const safeCvss =
      typeof findingCvss === 'number' && Number.isFinite(findingCvss)
        ? Math.min(10, Math.max(0, findingCvss))
        : 0;
    const cvssRatio = safeCvss / 10;
    const termValue = Math.round(weight * cvssRatio * kConfidence * 10) / 10;

    return {
      overlapLevel,
      weight,
      findingCvss: safeCvss,
      confidenceMultiplier: kConfidence,
      termValue,
    };
  }
}
