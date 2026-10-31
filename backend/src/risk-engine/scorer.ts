import { EventSeverity, RiskScoreBreakdown, ThreatIndicator } from '../shared/types/index.js';

export interface RiskCalculationInput {
  baseSeverity: EventSeverity;
  eventCount: number;
  targetAccount?: string;
  sourceIp: string;
  threatIndicator?: ThreatIndicator;
  killChainStagesCount: number; // Distinct MITRE tactics involved
  isPrivilegedTarget?: boolean;
}

export class RiskEngine {
  public static calculate(input: RiskCalculationInput): RiskScoreBreakdown {
    // 1. Base Score
    let baseScore = 20;
    switch (input.baseSeverity) {
      case 'CRITICAL': baseScore = 85; break;
      case 'HIGH': baseScore = 65; break;
      case 'MEDIUM': baseScore = 40; break;
      case 'LOW': baseScore = 20; break;
      case 'INFO': baseScore = 10; break;
    }

    // 2. Frequency Multiplier
    let freqMultiplier = 1.0;
    if (input.eventCount > 5) {
      freqMultiplier = 1.30;
    } else if (input.eventCount >= 3) {
      freqMultiplier = 1.15;
    }

    // 3. Asset Privilege Multiplier
    let assetMultiplier = 1.0;
    const isPrivileged = input.isPrivilegedTarget || 
      (input.targetAccount && /admin|root|ciso|secops|lead|iam/i.test(input.targetAccount));
    if (isPrivileged) {
      assetMultiplier = 1.35;
    }

    // 4. Threat Intelligence Multiplier
    let threatMultiplier = 1.0;
    if (input.threatIndicator) {
      if (input.threatIndicator.threatType === 'BOTNET_C2' || input.threatIndicator.severity === 'CRITICAL') {
        threatMultiplier = 1.40;
      } else if (input.threatIndicator.threatType === 'TOR_EXIT_NODE' || input.threatIndicator.threatType === 'VPN_PROXY') {
        threatMultiplier = 1.20;
      }
    }

    // 5. Attack Sequence Bonus
    let sequenceBonus = 0;
    if (input.killChainStagesCount >= 3) {
      sequenceBonus = 25; // Coordinated multi-stage breach
    } else if (input.killChainStagesCount === 2) {
      sequenceBonus = 15;
    }

    // Mathematical aggregation
    const rawScore = Math.round((baseScore * freqMultiplier * assetMultiplier * threatMultiplier) + sequenceBonus);
    const totalScore = Math.min(100, Math.max(0, rawScore));

    // Determine Risk Tier
    let tier: EventSeverity = 'LOW';
    if (totalScore >= 75) {
      tier = 'CRITICAL';
    } else if (totalScore >= 50) {
      tier = 'HIGH';
    } else if (totalScore >= 25) {
      tier = 'MEDIUM';
    }

    const factors = [
      {
        name: 'Base Severity',
        impact: `${baseScore} pts`,
        description: `Baseline score for ${input.baseSeverity} severity detection rule.`,
      },
      {
        name: 'Velocity Multiplier',
        impact: `x${freqMultiplier.toFixed(2)}`,
        description: `${input.eventCount} correlated events observed within sliding correlation window.`,
      },
      {
        name: 'Target Asset Value',
        impact: `x${assetMultiplier.toFixed(2)}`,
        description: isPrivileged 
          ? `Privileged identity target (${input.targetAccount}) increases operational blast radius.` 
          : 'Standard non-privileged target asset.',
      },
      {
        name: 'Threat Intelligence Score',
        impact: `x${threatMultiplier.toFixed(2)}`,
        description: input.threatIndicator 
          ? `Source IP ${input.sourceIp} confirmed ${input.threatIndicator.threatType} (${input.threatIndicator.confidence}% confidence).` 
          : 'No known malicious reputation indicators identified for source IP.',
      },
      {
        name: 'Attack Sequence Depth',
        impact: `+${sequenceBonus} pts`,
        description: input.killChainStagesCount >= 2 
          ? `Multi-stage attack sequence identified across ${input.killChainStagesCount} MITRE ATT&CK tactics.` 
          : 'Single-stage isolated anomaly.',
      }
    ];

    const explanation = `Calculated risk score of ${totalScore}/100 (${tier}). Driven by ${baseScore} baseline severity, multiplied by ${freqMultiplier.toFixed(2)}x frequency, ${assetMultiplier.toFixed(2)}x asset criticality, and an attack sequence bonus of +${sequenceBonus} across ${input.killChainStagesCount} MITRE tactics.`;

    return {
      totalScore,
      tier,
      baseScore,
      frequencyMultiplier: freqMultiplier,
      assetMultiplier,
      threatMultiplier,
      sequenceBonus,
      factors,
      explanation,
    };
  }
}
