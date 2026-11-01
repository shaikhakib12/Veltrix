import type { VulnerabilityFindingSummary } from '@veltrix/shared';
import type { VulnerabilityCorrelatorInterface } from './types.js';

/**
 * In-memory registry and evaluator for known open website vulnerability findings.
 * Enables vulnerability-aware attack prioritization (TASK-705) when active probes target known flaws.
 */
export class VulnerabilityCorrelator implements VulnerabilityCorrelatorInterface {
  private findingsBySite = new Map<string, VulnerabilityFindingSummary[]>();

  /**
   * Registers or updates an open vulnerability finding for an asset (e.g. from Phase 8 scans).
   */
  registerFinding(finding: VulnerabilityFindingSummary): void {
    if (!this.findingsBySite.has(finding.siteId)) {
      this.findingsBySite.set(finding.siteId, []);
    }
    const list = this.findingsBySite.get(finding.siteId)!;
    const existingIdx = list.findIndex((f) => f.findingId === finding.findingId);
    if (existingIdx !== -1) {
      list[existingIdx] = finding;
    } else {
      list.push(finding);
    }
  }

  /**
   * Clears registered findings (useful for test resets).
   */
  clear(): void {
    this.findingsBySite.clear();
  }

  /**
   * Finds the closest matching open vulnerability finding for a targeted website asset.
   * Returns match type: EXACT, PATH, ASSET, or NONE.
   */
  async findMatchingVulnerability(
    siteId: string,
    attackType: string,
    targetUri: string,
    parameter?: string
  ): Promise<VulnerabilityFindingSummary | null> {
    const findings = this.findingsBySite.get(siteId);
    if (!findings || findings.length === 0) {
      return null;
    }

    // Filter to active/open findings only
    const openFindings = findings.filter(
      (f) => f.status === 'OPEN' || f.status === 'CONFIRMED' || f.status === 'IN_REMEDIATION'
    );

    // 1. Exact Match: URI and parameter match
    if (parameter) {
      const exact = openFindings.find(
        (f) =>
          f.targetUri.toLowerCase() === targetUri.toLowerCase() &&
          f.targetParameter?.toLowerCase() === parameter.toLowerCase()
      );
      if (exact) return exact;
    }

    // 2. Path Match: Target path matches
    const pathMatch = openFindings.find((f) => {
      const fPath = f.targetUri.split('?')[0]?.toLowerCase();
      const aPath = targetUri.split('?')[0]?.toLowerCase();
      return fPath && aPath && fPath === aPath;
    });
    if (pathMatch) return pathMatch;

    // 3. Asset-Level Match: Attack type matches open finding on asset
    const assetMatch = openFindings.find(
      (f) => f.vulnType.toUpperCase() === attackType.toUpperCase()
    );
    if (assetMatch) return assetMatch;

    return null;
  }

  /**
   * Determines the overlap classification level between an attack and a matched finding.
   */
  determineOverlapLevel(
    finding: VulnerabilityFindingSummary | null,
    targetUri: string,
    parameter?: string
  ): 'EXACT' | 'PATH' | 'ASSET' | 'NONE' {
    if (!finding) return 'NONE';

    const fUri = finding.targetUri.toLowerCase();
    const aUri = targetUri.toLowerCase();
    const fPath = fUri.split('?')[0];
    const aPath = aUri.split('?')[0];

    if (
      parameter &&
      finding.targetParameter &&
      finding.targetParameter.toLowerCase() === parameter.toLowerCase() &&
      fPath === aPath
    ) {
      return 'EXACT';
    }

    if (fPath === aPath) {
      return 'PATH';
    }

    return 'ASSET';
  }
}
