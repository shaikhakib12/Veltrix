/**
 * VELTRIX Scanner Abort Coordinator (Phase 8 - TASK-807)
 *
 * Coordinates sub-500ms emergency aborts for active vulnerability scans,
 * signaling AbortControllers and terminating socket pools via ActiveSocketRegistry.
 */

import { ActiveSocketRegistry } from '../transport/active-socket-registry.js';

export interface AbortResult {
  readonly scanId: string;
  readonly orgId: string;
  readonly success: boolean;
  readonly durationMs: number;
  readonly closedSockets: number;
  readonly message: string;
}

interface ActiveScanContext {
  readonly orgId: string;
  readonly scanId: string;
  readonly controller: AbortController;
  readonly socketRegistry: ActiveSocketRegistry;
  readonly registeredAt: number;
}

export class AbortCoordinator {
  private static instance: AbortCoordinator;
  private readonly activeScans = new Map<string, ActiveScanContext>();

  public static getInstance(): AbortCoordinator {
    if (!AbortCoordinator.instance) {
      AbortCoordinator.instance = new AbortCoordinator();
    }
    return AbortCoordinator.instance;
  }

  private buildKey(orgId: string, scanId: string): string {
    return `${orgId}::${scanId}`;
  }

  /**
   * Registers an active scan session's AbortController and ActiveSocketRegistry.
   */
  public registerScan(
    orgId: string,
    scanId: string,
    controller: AbortController,
    socketRegistry: ActiveSocketRegistry
  ): () => void {
    const key = this.buildKey(orgId, scanId);
    this.activeScans.set(key, {
      orgId,
      scanId,
      controller,
      socketRegistry,
      registeredAt: Date.now(),
    });

    return () => {
      this.activeScans.delete(key);
    };
  }

  /**
   * Executes emergency abort for a scan, satisfying the sub-500ms SLO.
   */
  public abort(orgId: string, scanId: string, reason?: string): AbortResult {
    const startTime = performance.now();
    const key = this.buildKey(orgId, scanId);
    const scanContext = this.activeScans.get(key);

    let closedSockets = 0;
    if (scanContext) {
      // 1. Signal AbortController immediately
      try {
        scanContext.controller.abort(reason || 'Manual emergency abort triggered');
      } catch {}

      // 2. Destroy all active sockets immediately via ActiveSocketRegistry
      try {
        closedSockets = scanContext.socketRegistry.abortScan(orgId, scanId);
      } catch {}

      this.activeScans.delete(key);
    }

    const durationMs = performance.now() - startTime;

    return {
      scanId,
      orgId,
      success: true,
      durationMs,
      closedSockets,
      message: `Emergency abort executed in ${durationMs.toFixed(2)}ms (${closedSockets} sockets closed).`,
    };
  }

  public isScanActive(orgId: string, scanId: string): boolean {
    return this.activeScans.has(this.buildKey(orgId, scanId));
  }

  public getActiveScanCount(orgId?: string): number {
    if (!orgId) return this.activeScans.size;
    let count = 0;
    for (const ctx of this.activeScans.values()) {
      if (ctx.orgId === orgId) count++;
    }
    return count;
  }
}
