import { Router, type Request, type Response } from 'express';
import { z } from 'zod';
import { randomUUID } from 'node:crypto';
import { authenticate, requireBearerAuth } from '../middleware/auth.js';
import { enforceTenantIsolation } from '../middleware/tenant.js';
import { getStorage } from '../storage/index.js';
import { DomainOwnershipVerifier } from '../scanner/verification/verifier.js';

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
});

// In-memory tenant scan registry
const tenantScans = new Map<string, ScanJobRecord[]>();

export function getScanRegistryForOrg(orgId: string): ScanJobRecord[] {
  let list = tenantScans.get(orgId);
  if (!list) {
    list = [];
    tenantScans.set(orgId, list);
  }
  return list;
}

export function resetScansForTesting(): void {
  tenantScans.clear();
}

export function createScansRouter(): Router {
  const router = Router();
  const storage = getStorage();

  router.use(requireBearerAuth);
  router.use(authenticate);
  router.use(enforceTenantIsolation);

  /**
   * POST /api/v1/scans
   * Launches a new vulnerability scan for a domain-verified website.
   */
  router.post('/', async (req: Request, res: Response) => {
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

      const { siteId, profile } = parseResult.data;
      const site = await storage.getWebsiteById(orgId, siteId);
      if (!site) {
        return res.status(404).json({
          success: false,
          error: {
            code: 'WEBSITE_NOT_FOUND',
            message: `Website '${siteId}' was not found in organization '${orgId}'.`,
          },
        });
      }

      // Strict Domain Verification Gate (Phase 8 Task 801/805)
      const authCheck = DomainOwnershipVerifier.isScanAuthorized(site);
      if (!authCheck.authorized) {
        return res.status(403).json({
          success: false,
          error: {
            code: 'SCAN_UNAUTHORIZED_UNVERIFIED_DOMAIN',
            message: authCheck.message || 'Scanning is blocked until domain ownership verification succeeds.',
            details: {
              siteId: site.siteId,
              domain: site.primaryDomain,
              status: site.status,
              scanBlocked: site.scanBlocked,
              reasonCode: authCheck.code,
            },
          },
        });
      }

      const scanId = `scan-${Date.now()}-${randomUUID().slice(0, 8)}`;
      const nowIso = new Date().toISOString();

      const newScan: ScanJobRecord = {
        scanId,
        orgId,
        siteId,
        targetDomain: site.primaryDomain,
        profile,
        status: 'RUNNING',
        currentStage: profile === 'PASSIVE_BASELINE' ? 'PASSIVE_EVALUATION' : 'CRAWL',
        progressPercent: 25,
        findingsCount: 0,
        startedAt: nowIso,
      };

      const scansList = getScanRegistryForOrg(orgId);
      scansList.unshift(newScan);

      return res.status(201).json({
        success: true,
        data: newScan,
        message: `Scan '${scanId}' started for domain '${site.primaryDomain}'.`,
      });
    } catch (err: unknown) {
      console.error('[VELTRIX] Scan launch error:', err);
      return res.status(500).json({
        success: false,
        error: {
          code: 'INTERNAL_SERVER_ERROR',
          message: (err as Error)?.message || 'Failed to initialize vulnerability scan.',
        },
      });
    }
  });

  /**
   * GET /api/v1/scans
   * Lists vulnerability scans for the tenant.
   */
  router.get('/', async (req: Request, res: Response) => {
    const orgId = req.tenantOrgId!;
    const siteId = req.query.siteId as string | undefined;
    const status = req.query.status as string | undefined;

    let items = getScanRegistryForOrg(orgId);
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

    const items = getScanRegistryForOrg(orgId);
    const scan = items.find((s) => s.scanId === scanId);
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
   */
  router.post('/:scanId/abort', async (req: Request, res: Response) => {
    const orgId = req.tenantOrgId!;
    const scanId = req.params.scanId;

    const items = getScanRegistryForOrg(orgId);
    const scan = items.find((s) => s.scanId === scanId);
    if (!scan) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'SCAN_NOT_FOUND',
          message: `Scan '${scanId}' was not found.`,
        },
      });
    }

    scan.status = 'ABORTED';
    scan.completedAt = new Date().toISOString();

    return res.status(200).json({
      success: true,
      data: scan,
      message: `Scan '${scanId}' was aborted.`,
    });
  });

  return router;
}

