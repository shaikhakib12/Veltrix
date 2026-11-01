import { Router, Request, Response } from 'express';
import {
  type ApiResponse,
  type ApiErrorResponse,
  type ThreatIndicator,
  ThreatIndicatorCreateSchema,
  FeedIndicatorIngestSchema,
  ThreatIndicatorUpdateSchema,
} from '@veltrix/shared';
import { authenticate } from '../middleware/auth.js';
import { enforceTenantIsolation } from '../middleware/tenant.js';
import { requireRole } from '../middleware/rbac.js';
import type { StorageInterface } from '../storage/storage-interface.js';
import { getStorage } from '../storage/index.js';
import { generateUuidV7 } from '../utils/uuid.js';

export const AUTHORIZED_EXTERNAL_FEED_PROVIDERS = [
  'VIRUSTOTAL',
  'ABUSE_CH',
  'ALIENVAULT_OTX',
  'TOR_PROJECT',
  'CISA_KNOWN_EXPLOITED',
  'MANDIANT',
] as const;

/**
 * Registry of authorized threat intelligence feed integrations.
 * Verified feed tokens authenticate the external integration identity,
 * and the provider identity is assigned server-side based on this registry.
 */
export const REGISTERED_FEED_INTEGRATIONS: Record<
  string,
  { provider: typeof AUTHORIZED_EXTERNAL_FEED_PROVIDERS[number]; name: string }
> = {
  'feed-token-virustotal-prod': { provider: 'VIRUSTOTAL', name: 'VirusTotal Threat Feed' },
  'feed-token-abusech-prod': { provider: 'ABUSE_CH', name: 'Abuse.ch ThreatFox Feed' },
  'feed-token-alienvault-prod': { provider: 'ALIENVAULT_OTX', name: 'AlienVault OTX Feed' },
  'feed-token-cisa-prod': { provider: 'CISA_KNOWN_EXPLOITED', name: 'CISA KEV Feed' },
  'feed-token-tor-prod': { provider: 'TOR_PROJECT', name: 'Tor Project Exit Node Feed' },
};

export function createThreatIndicatorsRouter(storage?: StorageInterface): Router {
  const router = Router();
  const store = storage || getStorage();

  // ==========================================================================
  // Workflow 1: Verified Feed Ingestion (Authenticated Integration Identity)
  // ==========================================================================
  /**
   * POST /api/v1/threat-indicators/feed
   * Ingests verified external threat intelligence from registered feed providers.
   * Authenticates integration identity via x-feed-token or Authorization Bearer.
   * The provider identity is assigned SERVER-SIDE from the integration registry;
   * clients cannot choose or forge the source provider name.
   */
  router.post('/feed', async (req: Request, res: Response) => {
    try {
      // 1. Authenticate integration identity
      const rawHeader = req.headers['x-feed-token'] || req.headers.authorization;
      const feedToken = Array.isArray(rawHeader)
        ? rawHeader[0]
        : typeof rawHeader === 'string' && rawHeader.startsWith('Bearer ')
          ? rawHeader.slice(7).trim()
          : typeof rawHeader === 'string'
            ? rawHeader.trim()
            : '';

      const integration = feedToken ? REGISTERED_FEED_INTEGRATIONS[feedToken] : undefined;
      if (!integration) {
        const errorResponse: ApiErrorResponse = {
          success: false,
          error: {
            code: 'UNAUTHORIZED_FEED_INTEGRATION',
            message: 'Invalid or missing feed integration credentials. Integration identity must be authorized.',
          },
        };
        res.status(401).json(errorResponse);
        return;
      }

      // 2. Validate payload
      const parseResult = FeedIndicatorIngestSchema.safeParse(req.body);
      if (!parseResult.success) {
        const errorResponse: ApiErrorResponse = {
          success: false,
          error: {
            code: 'VALIDATION_FAILED',
            message: 'Invalid feed indicator parameters',
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
      const nowIso = new Date().toISOString();

      // 3. Assign provider identity SERVER-SIDE based on verified integration
      const indicator: ThreatIndicator = {
        indicatorId: generateUuidV7(),
        type: data.type,
        value: data.value,
        threatType: data.threatType,
        severity: data.severity,
        confidence: data.confidence,
        source: integration.provider, // SERVER-ASSIGNED!
        provenance: 'VERIFIED_FEED',   // Verified external feed
        orgId: 'global',
        retrievedAt: nowIso,
        firstSeen: data.firstSeen || nowIso,
        lastSeen: data.lastSeen || nowIso,
        expiresAt: data.expiresAt,
        isFlagged: data.isFlagged ?? true,
        metadata: {
          ...data.metadata,
          integrationName: integration.name,
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
      console.error('[VELTRIX] Error ingesting feed indicator:', err);
      const errorResponse: ApiErrorResponse = {
        success: false,
        error: {
          code: 'FEED_INGEST_ERROR',
          message: 'Failed to ingest verified feed indicator',
        },
      };
      res.status(500).json(errorResponse);
    }
  });

  // ==========================================================================
  // Workflow 2: Manual Analyst Management (Authenticated User Sessions)
  // ==========================================================================
  // All analyst management routes require user authentication and tenant isolation
  router.use(authenticate);
  router.use(enforceTenantIsolation);

  /**
   * GET /api/v1/threat-indicators
   * Lists indicators accessible to the authenticated tenant (verified global feeds + tenant's manual indicators).
   */
  router.get('/', async (req: Request, res: Response) => {
    try {
      const orgId = req.tenantOrgId!;
      const limit = req.query.limit ? parseInt(req.query.limit as string, 10) : 100;
      const indicators = await store.listIndicators(orgId, limit);

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
   * Creates a manual analyst threat indicator for this tenant.
   * Restricted to SECURITY_ANALYST, ORG_ADMIN, or SUPER_ADMIN.
   * Strictly prohibits analysts from impersonating external feeds (e.g. VIRUSTOTAL).
   */
  router.post(
    '/',
    requireRole('SUPER_ADMIN', 'ORG_ADMIN', 'SECURITY_ANALYST'),
    async (req: Request, res: Response) => {
      try {
        const orgId = req.tenantOrgId!;

        // 1. Anti-Impersonation Check: Analysts cannot claim external feed sources or unrestricted prefixes
        if (req.body && typeof req.body === 'object' && 'source' in req.body) {
          const rawSource = String(req.body.source || '').trim().toUpperCase();
          const isImpersonatingExternal = (AUTHORIZED_EXTERNAL_FEED_PROVIDERS as readonly string[]).includes(rawSource);
          const isImpersonatingPrefix = rawSource.startsWith('ADMIN_') || rawSource.startsWith('INTERNAL_');

          if (isImpersonatingExternal || (isImpersonatingPrefix && rawSource !== 'MANUAL_ENTRY')) {
            const errorResponse: ApiErrorResponse = {
              success: false,
              error: {
                code: 'IMPERSONATION_PROHIBITED',
                message: `Manual analysts cannot impersonate external threat intelligence providers ('${req.body.source}') or claim internal feed status. Manual indicators must use source 'MANUAL_ENTRY' or omit the source field.`,
              },
            };
            res.status(400).json(errorResponse);
            return;
          }
        }

        // 2. Validate payload
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
        const nowIso = new Date().toISOString();

        // 3. Assign manual analyst provenance derived from verified JWT claims
        const indicator: ThreatIndicator = {
          indicatorId: generateUuidV7(),
          type: data.type,
          value: data.value,
          threatType: data.threatType,
          severity: data.severity,
          confidence: data.confidence,
          source: 'MANUAL_ENTRY',          // Explicitly manual
          provenance: 'MANUAL_ANALYST',     // Clearly distinguished from verified feed
          orgId,                           // Tenant-scoped
          submittedBy: req.user!.username, // Derived from verified JWT claims
          firstSeen: data.firstSeen || nowIso,
          lastSeen: data.lastSeen || nowIso,
          expiresAt: data.expiresAt,
          isFlagged: data.isFlagged ?? true,
          metadata: {
            ...data.metadata,
            description: data.description,
            submitterRole: req.user!.role,
            isManual: true,
            provenanceVerified: false,
          },
        };

        await store.saveIndicator(indicator);

        // 4. Record manual submission in cryptographic audit ledger
        try {
          await store.appendAuditLog({
            logId: generateUuidV7(),
            orgId,
            action: 'RULE_MODIFIED',
            actor: {
              userId: req.user!.userId,
              role: req.user!.role,
              ipAddress: req.ip || '127.0.0.1',
            },
            details: {
              action: 'threat_indicator.manual_create',
              resource: `indicator:${indicator.indicatorId}`,
              type: indicator.type,
              value: indicator.value,
              threatType: indicator.threatType,
              provenance: 'MANUAL_ANALYST',
              submittedBy: req.user!.username,
            },
            timestamp: nowIso,
          });
        } catch (auditErr) {
          console.warn('[VELTRIX] Failed to write audit log for manual indicator:', auditErr);
        }

        const response: ApiResponse<ThreatIndicator> = {
          success: true,
          data: indicator,
          meta: {
            timestamp: nowIso,
          },
        };
        res.status(201).json(response);
      } catch (err: unknown) {
        console.error('[VELTRIX] Error saving manual threat indicator:', err);
        const errorResponse: ApiErrorResponse = {
          success: false,
          error: {
            code: 'INDICATOR_SAVE_ERROR',
            message: 'Failed to save manual threat indicator',
          },
        };
        res.status(500).json(errorResponse);
      }
    }
  );

  /**
   * PATCH /api/v1/threat-indicators/:indicatorId
   * Modifies an existing manual threat indicator.
   * Rejects unauthorized callers (e.g. VIEWER) with 403 Forbidden.
   * Prohibits modification of verified feed indicators by tenant analysts.
   */
  router.patch(
    '/:indicatorId',
    requireRole('SUPER_ADMIN', 'ORG_ADMIN', 'SECURITY_ANALYST'),
    async (req: Request, res: Response) => {
      try {
        const orgId = req.tenantOrgId!;
        const indicatorId = req.params.indicatorId;
        if (!indicatorId) {
          res.status(400).json({ success: false, error: { code: 'INVALID_REQUEST', message: 'Indicator ID is required' } });
          return;
        }

        const parseResult = ThreatIndicatorUpdateSchema.safeParse(req.body);
        if (!parseResult.success) {
          const errorResponse: ApiErrorResponse = {
            success: false,
            error: {
              code: 'VALIDATION_FAILED',
              message: 'Invalid threat indicator update parameters',
            },
          };
          res.status(400).json(errorResponse);
          return;
        }

        const existing = await store.getIndicatorById(indicatorId, orgId);
        if (!existing) {
          const errorResponse: ApiErrorResponse = {
            success: false,
            error: {
              code: 'NOT_FOUND',
              message: `Threat indicator '${indicatorId}' not found`,
            },
          };
          res.status(404).json(errorResponse);
          return;
        }

        // Prohibit tenant analysts from modifying verified external feeds
        if (existing.provenance === 'VERIFIED_FEED' && req.user?.role !== 'SUPER_ADMIN') {
          const errorResponse: ApiErrorResponse = {
            success: false,
            error: {
              code: 'CANNOT_MODIFY_VERIFIED_FEED',
              message: 'Verified external threat intelligence feeds cannot be modified by tenant analysts.',
            },
          };
          res.status(403).json(errorResponse);
          return;
        }

        const updated = await store.updateIndicator(indicatorId, parseResult.data, orgId);

        const response: ApiResponse<ThreatIndicator> = {
          success: true,
          data: updated!,
          meta: {
            timestamp: new Date().toISOString(),
          },
        };
        res.status(200).json(response);
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        if (message.includes('FORBIDDEN_CROSS_TENANT_ACCESS')) {
          res.status(403).json({
            success: false,
            error: { code: 'FORBIDDEN_CROSS_TENANT_ACCESS', message: 'Cross-tenant indicator access denied' },
          });
          return;
        }
        res.status(500).json({
          success: false,
          error: { code: 'INDICATOR_UPDATE_ERROR', message: 'Failed to update threat indicator' },
        });
      }
    }
  );

  return router;
}
