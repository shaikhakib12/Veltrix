import { Router, Request, Response } from 'express';
import {
  type ApiResponse,
  type ApiErrorResponse,
  type ThreatIndicator,
  ThreatIndicatorCreateSchema,
} from '@veltrix/shared';
import { authenticate } from '../middleware/auth.js';
import { enforceTenantIsolation } from '../middleware/tenant.js';
import { requireRole } from '../middleware/rbac.js';
import type { StorageInterface } from '../storage/storage-interface.js';
import { getStorage } from '../storage/index.js';
import { generateUuidV7 } from '../utils/uuid.js';

export const AUTHORIZED_THREAT_INTEL_PROVIDERS = [
  'ABUSE_CH',
  'ALIENVAULT',
  'ALIENVAULT_OTX',
  'TOR_PROJECT',
  'INTERNAL_THREAT_INTEL',
  'ADMIN_MANAGED',
  'CISA_KNOWN_EXPLOITED',
  'MANDIANT',
  'VIRUSTOTAL',
] as const;

export function isAuthorizedThreatIntelSource(source: string): boolean {
  if (!source || typeof source !== 'string') return false;
  const upper = source.trim().toUpperCase();
  if (upper.length === 0) return false;
  return (
    AUTHORIZED_THREAT_INTEL_PROVIDERS.some((p) => upper.includes(p)) ||
    upper.startsWith('ADMIN_') ||
    upper.startsWith('INTERNAL_')
  );
}

export function createThreatIndicatorsRouter(storage?: StorageInterface): Router {
  const router = Router();
  const store = storage || getStorage();

  // All endpoints require authentication and tenant context
  router.use(authenticate);
  router.use(enforceTenantIsolation);

  /**
   * GET /api/v1/threat-indicators
   * Lists active threat intelligence indicators.
   */
  router.get('/', async (req: Request, res: Response) => {
    try {
      const limit = req.query.limit ? parseInt(req.query.limit as string, 10) : 100;
      const indicators = await store.listIndicators(limit);

      const response: ApiResponse<{ indicators: ThreatIndicator[] }> = {
        success: true,
        data: { indicators },
        meta: {
          timestamp: new Date().toISOString(),
        },
      };
      res.status(200).json(response);
    } catch (err: unknown) {
      console.error('[VELTRIX] Error listing threat indicators:', err);
      const errorResponse: ApiErrorResponse = {
        success: false,
        error: {
          code: 'INDICATOR_LIST_ERROR',
          message: 'Failed to retrieve threat indicators',
        },
      };
      res.status(500).json(errorResponse);
    }
  });

  /**
   * POST /api/v1/threat-indicators
   * Creates or updates a verified threat indicator record.
   * Restricted to SECURITY_ANALYST, ORG_ADMIN, or SUPER_ADMIN.
   * Rejects unauthorized callers (e.g. VIEWER) with 403 Forbidden.
   */
  router.post(
    '/',
    requireRole('SUPER_ADMIN', 'ORG_ADMIN', 'SECURITY_ANALYST'),
    async (req: Request, res: Response) => {
      try {
        const parseResult = ThreatIndicatorCreateSchema.safeParse(req.body);
        if (!parseResult.success) {
          const errorResponse: ApiErrorResponse = {
            success: false,
            error: {
              code: 'VALIDATION_FAILED',
              message: 'Invalid threat indicator parameters',
              details: parseResult.error.errors.map((e) => ({
                field: e.path.join('.'),
                message: e.message,
              })),
            },
          };
          res.status(400).json(errorResponse);
          return;
        }

        const data = parseResult.data;

        // Verify source provenance: must be an authorized provider or admin-managed source
        if (!isAuthorizedThreatIntelSource(data.source)) {
          const errorResponse: ApiErrorResponse = {
            success: false,
            error: {
              code: 'UNAUTHORIZED_INDICATOR_SOURCE',
              message: `Threat indicator source '${data.source}' is not an authorized threat intelligence provider. Authorized sources: ${AUTHORIZED_THREAT_INTEL_PROVIDERS.join(', ')}, or ADMIN_* / INTERNAL_*.`,
            },
          };
          res.status(400).json(errorResponse);
          return;
        }

        const nowIso = new Date().toISOString();
        const indicator: ThreatIndicator = {
          indicatorId: generateUuidV7(),
          type: data.type,
          value: data.value,
          threatType: data.threatType,
          severity: data.severity,
          confidence: data.confidence,
          source: data.source.trim(),
          firstSeen: data.firstSeen || nowIso,
          lastSeen: data.lastSeen || nowIso,
          isFlagged: data.isFlagged ?? true,
          metadata: {
            ...data.metadata,
            ...(data.expiresAt ? { expiresAt: data.expiresAt } : {}),
            createdBy: req.user?.username || 'system',
            provenanceVerified: true,
          },
        };

        await store.saveIndicator(indicator);

        const response: ApiResponse<ThreatIndicator> = {
          success: true,
          data: indicator,
          meta: {
            timestamp: nowIso,
          },
        };
        res.status(201).json(response);
      } catch (err: unknown) {
        console.error('[VELTRIX] Error saving threat indicator:', err);
        const errorResponse: ApiErrorResponse = {
          success: false,
          error: {
            code: 'INDICATOR_SAVE_ERROR',
            message: 'Failed to save threat indicator',
          },
        };
        res.status(500).json(errorResponse);
      }
    }
  );

  return router;
}
