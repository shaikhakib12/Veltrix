/**
 * VELTRIX Vulnerability Risk Scoring Engine (TASK-806)
 *
 * Implements multi-factor risk scoring, explainable calculation breakdowns,
 * asset-level security posture grading, and differential baseline comparisons.
 *
 * Invariants:
 * - Deterministic, non-random risk scores between 0 and 100.
 * - Multi-factor weighted evaluation combining CVSS v3.1, severity, and confidence.
 * - Differential baseline comparisons to identify new, recurring, and resolved findings.
 */

import type { ScannerFinding, VulnerabilitySeverity, FindingConfidence } from '../types.js';
import { calculateCvss, type CvssCalculationResult } from './cvss-calculator.js';

export interface FindingRiskScore {
  readonly score: number; // 0 - 100
  readonly cvss: CvssCalculationResult;
  readonly severity: VulnerabilitySeverity;
  readonly confidence: FindingConfidence;
  readonly factors: {
    readonly baseCvssScore: number;
    readonly severityMultiplier: number;
    readonly confidenceMultiplier: number;
    readonly explanation: string;
  };
}

export interface SiteSecurityPosture {
  readonly overallScore: number; // 0 - 100 (100 = best, 0 = worst)
  readonly letterGrade: 'A' | 'B' | 'C' | 'D' | 'F';
  readonly totalFindings: number;
  readonly criticalCount: number;
  readonly highCount: number;
  readonly mediumCount: number;
  readonly lowCount: number;
  readonly infoCount: number;
  readonly topRisks: readonly string[];
}

export interface DifferentialBaselineComparison {
  readonly newFindings: readonly ScannerFinding[];
  readonly recurringFindings: readonly ScannerFinding[];
  readonly resolvedFindings: readonly ScannerFinding[];
  readonly deltaScore: number;
  readonly summary: string;
}

const SEVERITY_MULTIPLIERS: Record<VulnerabilitySeverity, number> = {
  CRITICAL: 1.0,
  HIGH: 0.85,
  MEDIUM: 0.6,
  LOW: 0.35,
  INFORMATIONAL: 0.15,
};

const CONFIDENCE_MULTIPLIERS: Record<FindingConfidence, number> = {
  CONFIRMED: 1.0,
  HIGH: 0.85,
  MEDIUM: 0.65,
  LOW: 0.4,
};

export class ScoringEngine {
  /**
   * Calculates a deterministic, multi-factor risk score (0-100) for an individual finding.
   */
  public calculateFindingRisk(finding: ScannerFinding): FindingRiskScore {
    const cvss = calculateCvss(finding.vulnerabilityType, {
      reflectionContext: finding.evidence?.reflectionContext as string | undefined,
    });

    const severityMult = SEVERITY_MULTIPLIERS[finding.severity] ?? 0.35;
    const confidenceMult = CONFIDENCE_MULTIPLIERS[finding.confidence] ?? 0.4;

    // Formula: cvss.score * 10 * severityMult * confidenceMult
    // Normalized to 0-100 bound
    const rawScore = cvss.score * 10 * severityMult * confidenceMult;
    const score = Math.min(100, Math.max(0, Math.round(rawScore)));

    const explanation = `Base CVSS ${cvss.score} scaled by severity factor ${severityMult} (${finding.severity}) and confidence factor ${confidenceMult} (${finding.confidence}). Final risk score: ${score}/100.`;

    return {
      score,
      cvss,
      severity: finding.severity,
      confidence: finding.confidence,
      factors: {
        baseCvssScore: cvss.score,
        severityMultiplier: severityMult,
        confidenceMultiplier: confidenceMult,
        explanation,
      },
    };
  }

  /**
   * Aggregates findings to compute an overall asset security posture score (0-100) and letter grade.
   */
  public calculateSitePosture(findings: readonly ScannerFinding[]): SiteSecurityPosture {
    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;
    let lowCount = 0;
    let infoCount = 0;

    let totalPenalty = 0;

    for (const f of findings) {
      switch (f.severity) {
        case 'CRITICAL':
          criticalCount++;
          totalPenalty += 35;
          break;
        case 'HIGH':
          highCount++;
          totalPenalty += 20;
          break;
        case 'MEDIUM':
          mediumCount++;
          totalPenalty += 8;
          break;
        case 'LOW':
          lowCount++;
          totalPenalty += 3;
          break;
        case 'INFORMATIONAL':
          infoCount++;
          totalPenalty += 0.5;
          break;
      }
    }

    const overallScore = Math.max(0, Math.min(100, Math.round(100 - totalPenalty)));

    let letterGrade: 'A' | 'B' | 'C' | 'D' | 'F';
    if (criticalCount > 0 || overallScore < 50) {
      letterGrade = 'F';
    } else if (highCount > 1 || overallScore < 65) {
      letterGrade = 'D';
    } else if (highCount === 1 || mediumCount > 3 || overallScore < 75) {
      letterGrade = 'C';
    } else if (mediumCount > 0 || lowCount > 2 || overallScore < 90) {
      letterGrade = 'B';
    } else {
      letterGrade = 'A';
    }

    const topRisks = findings
      .filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH' || f.severity === 'MEDIUM')
      .slice(0, 5)
      .map((f) => f.title);

    return {
      overallScore,
      letterGrade,
      totalFindings: findings.length,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      infoCount,
      topRisks: Object.freeze(topRisks),
    };
  }

  /**
   * Performs differential comparison between current findings and a baseline scan.
   */
  public compareWithBaseline(
    currentFindings: readonly ScannerFinding[],
    baselineFindings: readonly ScannerFinding[]
  ): DifferentialBaselineComparison {
    const baselineMap = new Map<string, ScannerFinding>();
    for (const f of baselineFindings) {
      baselineMap.set(this.fingerprintFinding(f), f);
    }

    const currentMap = new Map<string, ScannerFinding>();
    const newFindings: ScannerFinding[] = [];
    const recurringFindings: ScannerFinding[] = [];

    for (const f of currentFindings) {
      const fp = this.fingerprintFinding(f);
      currentMap.set(fp, f);
      if (baselineMap.has(fp)) {
        recurringFindings.push(f);
      } else {
        newFindings.push(f);
      }
    }

    const resolvedFindings: ScannerFinding[] = [];
    for (const [fp, bf] of baselineMap.entries()) {
      if (!currentMap.has(fp)) {
        resolvedFindings.push(bf);
      }
    }

    const currentPosture = this.calculateSitePosture(currentFindings);
    const baselinePosture = this.calculateSitePosture(baselineFindings);
    const deltaScore = currentPosture.overallScore - baselinePosture.overallScore;

    let summary: string;
    if (deltaScore > 0) {
      summary = `Security posture improved by +${deltaScore} points (${resolvedFindings.length} resolved, ${newFindings.length} new).`;
    } else if (deltaScore < 0) {
      summary = `Security posture degraded by ${deltaScore} points (${newFindings.length} new findings detected).`;
    } else {
      summary = `Security posture unchanged (${recurringFindings.length} recurring findings).`;
    }

    return {
      newFindings: Object.freeze(newFindings),
      recurringFindings: Object.freeze(recurringFindings),
      resolvedFindings: Object.freeze(resolvedFindings),
      deltaScore,
      summary,
    };
  }

  private fingerprintFinding(f: ScannerFinding): string {
    const ep = f.endpoint || '';
    return `${f.ruleId}:${f.vulnerabilityType}:${f.url}:${ep}`;
  }
}
