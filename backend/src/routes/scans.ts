import { Router, type Request, type Response } from 'express';
import { z } from 'zod';
import { authenticate, requireBearerAuth } from '../middleware/auth.js';
import { enforceTenantIsolation } from '../middleware/tenant.js';
import { requireRole } from '../middleware/rbac.js';
import { getStorage } from '../storage/index.js';
import {
  ScanOrchestrator,
  type ScanRecord,
  type ScanProfile,
} from '../scanner/orchestration/scan-orchestrator.js';

export interface ScanJobRecord {
  scanId: string;
  orgId: string;
  siteId: string;
  targetDomain: string;
  profile: 'PASSIVE_BASELINE' | 'STANDARD_ACTIVE' | 'FULL_AUDIT';
  status: 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'ABORTED' | 'FAILED';
  currentStage: 'DISCOVERY' | 'CRAWL' | 'PASSIVE_EVALUATION' | 'ACTIVE_PROBING' | 'REPORT_GENERATION';
  progressPercent: number;
  findingsCount: number;
  startedAt: string;
  completedAt?: string;
  durationSeconds?: number;
}

const CreateScanSchema = z.object({
  siteId: z.string().min(1, 'siteId is required'),
  profile: z.enum(['PASSIVE_BASELINE', 'STANDARD_ACTIVE', 'FULL_AUDIT']).default('STANDARD_ACTIVE'),
  maxDepth: z.number().int().min(1).max(5).optional(),
  maxPages: z.number().int().min(1).max(1000).optional(),
  rateLimitRps: z.number().int().min(1).max(20).optional(),
  excludedPaths: z.array(z.string()).optional(),
});

export function getScanRegistryForOrg(orgId: string): ScanRecord[] {
  const storage = getStorage();
  const orchestrator = ScanOrchestrator.getOrCreateInstance(storage);
  return orchestrator.getScansForOrg(orgId);
}

export function resetScansForTesting(): void {
  ScanOrchestrator.resetInstanceForTesting();
}

export function createScansRouter(): Router {
  const router = Router();
  const storage = getStorage();
  const orchestrator = ScanOrchestrator.getOrCreateInstance(storage);

  router.use(requireBearerAuth);
  router.use(authenticate);
  router.use(enforceTenantIsolation);

  /**
   * POST /api/v1/scans
   * Launches a new vulnerability scan for a domain-verified website.
   * RBAC: SECURITY_ANALYST, ORG_ADMIN, SUPER_ADMIN.
   * FULL_AUDIT requires ORG_ADMIN or SUPER_ADMIN.
   */
  router.post(
    '/',
    requireRole('SUPER_ADMIN', 'ORG_ADMIN', 'SECURITY_ANALYST'),
    async (req: Request, res: Response) => {
      try {
        const orgId = req.tenantOrgId!;
        const parseResult = CreateScanSchema.safeParse(req.body);
        if (!parseResult.success) {
          return res.status(400).json({
            success: false,
            error: {
              code: 'VALIDATION_ERROR',
              message: 'Invalid scan launch parameters.',
              details: parseResult.error.errors,
            },
          });
        }

        const { siteId, profile, maxDepth, maxPages, rateLimitRps, excludedPaths } = parseResult.data;

        // Deep/full audit scans require ORG_ADMIN or SUPER_ADMIN role
        if (profile === 'FULL_AUDIT' && req.user?.role !== 'ORG_ADMIN' && req.user?.role !== 'SUPER_ADMIN') {
          return res.status(403).json({
            success: false,
            error: {
              code: 'INSUFFICIENT_PRIVILEGES',
              message: 'Full audit scan profile requires ORG_ADMIN or SUPER_ADMIN role.',
            },
          });
        }

        // Launch real scan through orchestrator
        const scan = await orchestrator.launchScan({
          orgId,
          siteId,
          profile: profile as ScanProfile,
          maxDepth,
          maxPages,
          rateLimitRps,
          excludedPaths,
          requestedBy: req.user?.userId,
        });

        return res.status(201).json({
          success: true,
          data: scan,
          message: `Scan '${scan.scanId}' started for domain '${scan.targetDomain}'.`,
        });
      } catch (err: any) {
        if (err?.statusCode) {
          return res.status(err.statusCode).json({
            success: false,
            error: {
              code: err.code || 'SCAN_ERROR',
              message: err.message,
              details: err.details,
            },
          });
        }

        console.error('[VELTRIX] Scan launch error:', err);
        return res.status(500).json({
          success: false,
          error: {
            code: 'INTERNAL_SERVER_ERROR',
            message: err?.message || 'Failed to initialize vulnerability scan.',
          },
        });
      }
    }
  );

  /**
   * GET /api/v1/scans
   * Lists vulnerability scans for the tenant.
   */
  router.get('/', async (req: Request, res: Response) => {
    const orgId = req.tenantOrgId!;
    const siteId = req.query.siteId as string | undefined;
    const status = req.query.status as string | undefined;

    let items = orchestrator.getScansForOrg(orgId);
    if (siteId) {
      items = items.filter((s) => s.siteId === siteId);
    }
    if (status) {
      items = items.filter((s) => s.status.toLowerCase() === status.toLowerCase());
    }

    return res.status(200).json({
      success: true,
      data: {
        items,
        total: items.length,
      },
      meta: {
        timestamp: new Date().toISOString(),
      },
    });
  });

  /**
   * GET /api/v1/scans/:scanId
   */
  router.get('/:scanId', async (req: Request, res: Response) => {
    const orgId = req.tenantOrgId!;
    const scanId = req.params.scanId;
    if (!scanId) {
      return res.status(400).json({
        success: false,
        error: { code: 'INVALID_SCAN_ID', message: 'scanId parameter is required' },
      });
    }

    const scan = orchestrator.getScanById(orgId, scanId);
    if (!scan) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'SCAN_NOT_FOUND',
          message: `Scan '${scanId}' was not found.`,
        },
      });
    }

    return res.status(200).json({
      success: true,
      data: scan,
    });
  });

  /**
   * POST /api/v1/scans/:scanId/abort
   * Emergency abort endpoint satisfying sub-500ms SLO.
   * RBAC: SECURITY_ANALYST, ORG_ADMIN, SUPER_ADMIN.
   */
  router.post(
    '/:scanId/abort',
    requireRole('SUPER_ADMIN', 'ORG_ADMIN', 'SECURITY_ANALYST'),
    async (req: Request, res: Response) => {
      try {
        const orgId = req.tenantOrgId!;
        const scanId = req.params.scanId;
        if (!scanId) {
          return res.status(400).json({
            success: false,
            error: { code: 'INVALID_SCAN_ID', message: 'scanId parameter is required' },
          });
        }
        const reason = req.body?.reason as string | undefined;

        const scan = orchestrator.abortScan(orgId, scanId, reason);

        return res.status(200).json({
          success: true,
          data: scan,
          message: `Scan '${scanId}' was aborted.`,
        });
      } catch (err: any) {
        if (err?.statusCode) {
          return res.status(err.statusCode).json({
            success: false,
            error: {
              code: err.code || 'ABORT_ERROR',
              message: err.message,
            },
          });
        }

        return res.status(500).json({
          success: false,
          error: {
            code: 'INTERNAL_SERVER_ERROR',
            message: err?.message || 'Failed to abort vulnerability scan.',
          },
        });
      }
    }
  );

  return router;
}
