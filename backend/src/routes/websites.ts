import { Router, type Request, type Response } from 'express';
import { randomUUID, randomBytes } from 'node:crypto';
import {
  WebsiteCreateRequestSchema,
  WebsiteUpdateRequestSchema,
  DomainVerifyRequestSchema,
  type WebsiteAsset,
  type IncidentStatus,
} from '@veltrix/shared';
import { authenticate, requireBearerAuth } from '../middleware/auth.js';
import { enforceTenantIsolation } from '../middleware/tenant.js';
import { requireRole } from '../middleware/rbac.js';
import { getStorage } from '../storage/index.js';
import {
  DomainVerificationService,
  type DnsResolverInterface,
  type HttpFetcherInterface,
} from '../services/domain-verification.js';

export function createWebsitesRouter(options?: {
  dnsResolver?: DnsResolverInterface;
  httpFetcher?: HttpFetcherInterface;
}) {
  const router = Router();
  const storage = getStorage();
  const verifier = new DomainVerificationService(
    storage,
    options?.dnsResolver,
    options?.httpFetcher
  );

  // All endpoints require authentication and tenant isolation
  router.use(requireBearerAuth);
  router.use(authenticate);
  router.use(enforceTenantIsolation);

  // 1. Register Website Asset (POST /api/v1/websites)
  router.post(
    '/',
    requireRole('SUPER_ADMIN', 'ORG_ADMIN'),
    async (req: Request, res: Response) => {
      const parseResult = WebsiteCreateRequestSchema.safeParse(req.body);
      if (!parseResult.success) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Invalid website registration parameters.',
            details: parseResult.error.errors,
          },
        });
      }

      const orgId = req.tenantOrgId!;
      const data = parseResult.data;

      // Check for cross-tenant conflict: Is this primary domain already claimed and verified elsewhere?
      const existingDomainSite = await storage.getWebsiteByDomain(data.primaryDomain);
      if (
        existingDomainSite &&
        existingDomainSite.orgId !== orgId &&
        existingDomainSite.status === 'VERIFIED'
      ) {
        return res.status(409).json({
          success: false,
          error: {
            code: 'DOMAIN_ALREADY_CLAIMED',
            message: `Domain '${data.primaryDomain}' is already claimed and verified by another organization.`,
          },
        });
      }

      const siteId = `site-${randomUUID()}`;
      const challenge = DomainVerificationService.generateChallenge(orgId, data.primaryDomain);
      const nowIso = new Date().toISOString();

      const newSite: WebsiteAsset = {
        siteId,
        orgId,
        name: data.name,
        primaryDomain: data.primaryDomain,
        approvedSubdomains: data.approvedSubdomains,
        environment: data.environment,
        status: 'PENDING_VERIFICATION',
        riskTier: data.riskTier,
        tags: data.tags,
        verificationToken: challenge.token,
        tokenHash: challenge.tokenHash,
        tokenCreatedAt: nowIso,
        dnsTxtRecord: challenge.dnsTxtRecord,
        httpChallenge: challenge.httpChallenge,
        scanBlocked: true, // Unverified domains are strictly blocked from scanning
        health: {
          telemetryStatus: 'INACTIVE',
          eventsPerMinute: 0,
        },
        createdAt: nowIso,
        updatedAt: nowIso,
      };

      try {
        await storage.saveWebsite(newSite);
      } catch (err: unknown) {
        const msg = (err as Error)?.message || '';
        if (
          msg.includes('DOMAIN_ALREADY_CLAIMED') ||
          (err as { name?: string })?.name === 'ConditionalCheckFailedException' ||
          (err as { name?: string })?.name === 'TransactionCanceledException'
        ) {
          return res.status(409).json({
            success: false,
            error: {
              code: 'DOMAIN_ALREADY_CLAIMED',
              message: `Domain '${data.primaryDomain}' is already claimed by another organization.`,
            },
          });
        }
        throw err;
      }

      // Audit log
      await storage.appendAuditLog({
        logId: `audit-site-reg-${Date.now()}-${randomBytes(4).toString('hex')}`,
        orgId,
        timestamp: nowIso,
        action: 'WEBSITE_REGISTERED',
        actor: {
          userId: req.user?.userId || 'unknown-user',
          role: req.user?.role || 'ORG_ADMIN',
          ipAddress: req.ip,
        },
        details: {
          siteId,
          primaryDomain: data.primaryDomain,
          environment: data.environment,
          riskTier: data.riskTier,
        },
      });

      return res.status(201).json({
        success: true,
        site: newSite,
      });
    }
  );

  // 2. List Websites (GET /api/v1/websites)
  router.get(
    '/',
    requireRole('SUPER_ADMIN', 'ORG_ADMIN', 'SECURITY_ANALYST', 'READ_ONLY_VIEWER', 'AUDITOR'),
    async (req: Request, res: Response) => {
      const orgId = req.tenantOrgId!;
      const status = req.query.status as string | undefined;
      const limit = req.query.limit ? parseInt(req.query.limit as string, 10) : 50;
      const cursor = req.query.cursor as string | undefined;

      const result = await storage.getWebsites(orgId, { status, limit, cursor });

      return res.status(200).json({
        success: true,
        total: result.total || result.items.length,
        sites: result.items,
        meta: {
          timestamp: new Date().toISOString(),
          cursor: result.nextCursor,
          hasMore: !!result.nextCursor,
        },
      });
    }
  );

  // 3. Get Website Details (GET /api/v1/websites/:siteId)
  router.get(
    '/:siteId',
    requireRole('SUPER_ADMIN', 'ORG_ADMIN', 'SECURITY_ANALYST', 'READ_ONLY_VIEWER', 'AUDITOR'),
    async (req: Request, res: Response) => {
      const orgId = req.tenantOrgId!;
      const siteId = req.params.siteId as string;

      const site = await storage.getWebsiteById(orgId, siteId);
      if (!site) {
        return res.status(404).json({
          success: false,
          error: {
            code: 'WEBSITE_NOT_FOUND',
            message: `Website '${siteId}' not found in organization '${orgId}'.`,
          },
        });
      }

      return res.status(200).json({
        success: true,
        site,
      });
    }
  );

  // 4. Update Website Metadata (PATCH /api/v1/websites/:siteId)
  router.patch(
    '/:siteId',
    requireRole('SUPER_ADMIN', 'ORG_ADMIN'),
    async (req: Request, res: Response) => {
      const parseResult = WebsiteUpdateRequestSchema.safeParse(req.body);
      if (!parseResult.success) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Invalid website update parameters.',
            details: parseResult.error.errors,
          },
        });
      }

      const orgId = req.tenantOrgId!;
      const siteId = req.params.siteId as string;

      const existing = await storage.getWebsiteById(orgId, siteId);
      if (!existing) {
        return res.status(404).json({
          success: false,
          error: {
            code: 'WEBSITE_NOT_FOUND',
            message: `Website '${siteId}' not found in organization '${orgId}'.`,
          },
        });
      }

      const updated = await storage.updateWebsite(orgId, siteId, parseResult.data);

      await storage.appendAuditLog({
        logId: `audit-site-upd-${Date.now()}-${randomBytes(4).toString('hex')}`,
        orgId,
        timestamp: new Date().toISOString(),
        action: 'WEBSITE_UPDATED',
        actor: {
          userId: req.user?.userId || 'unknown-user',
          role: req.user?.role || 'ORG_ADMIN',
          ipAddress: req.ip,
        },
        details: {
          siteId,
          updates: parseResult.data,
        },
      });

      return res.status(200).json({
        success: true,
        site: updated,
      });
    }
  );

  // 5. Trigger Domain Ownership Verification (POST /api/v1/websites/:siteId/verify)
  router.post(
    '/:siteId/verify',
    requireRole('SUPER_ADMIN', 'ORG_ADMIN'),
    async (req: Request, res: Response) => {
      const parseResult = DomainVerifyRequestSchema.safeParse(req.body);
      if (!parseResult.success) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Invalid verification method. Must be DNS_TXT or HTTP_CHALLENGE.',
            details: parseResult.error.errors,
          },
        });
      }

      const orgId = req.tenantOrgId!;
      const siteId = req.params.siteId as string;
      const { method } = parseResult.data;

      const result = await verifier.verifyDomain(orgId, siteId, method);

      if (result.status === 'RATE_LIMITED') {
        return res.status(429).json({
          success: false,
          error: result.error,
        });
      }

      if (!result.verified) {
        return res.status(400).json({
          success: false,
          error: result.error,
        });
      }

      return res.status(200).json({
        success: true,
        verified: true,
        status: result.status,
        verifiedAt: result.verifiedAt,
        expiresAt: result.expiresAt,
        message: result.message,
      });
    }
  );

  // 6. Revoke Domain Verification (POST /api/v1/websites/:siteId/revoke)
  router.post(
    '/:siteId/revoke',
    requireRole('SUPER_ADMIN', 'ORG_ADMIN'),
    async (req: Request, res: Response) => {
      const orgId = req.tenantOrgId!;
      const siteId = req.params.siteId as string;
      const reason = req.body?.reason || 'Administrative revocation';

      const updated = await verifier.revokeVerification(
        orgId,
        siteId,
        reason,
        req.user?.userId || 'unknown-admin'
      );

      if (!updated) {
        return res.status(404).json({
          success: false,
          error: {
            code: 'WEBSITE_NOT_FOUND',
            message: `Website '${siteId}' not found in organization '${orgId}'.`,
          },
        });
      }

      return res.status(200).json({
        success: true,
        site: updated,
        message: `Website '${siteId}' verification revoked. Asset placed in GRACE_PERIOD with immediate scan freeze.`,
      });
    }
  );

  // 7. Delete Website Asset (DELETE /api/v1/websites/:siteId)
  router.delete(
    '/:siteId',
    requireRole('SUPER_ADMIN', 'ORG_ADMIN'),
    async (req: Request, res: Response) => {
      const orgId = req.tenantOrgId!;
      const siteId = req.params.siteId as string;

      const existing = await storage.getWebsiteById(orgId, siteId);
      if (!existing) {
        return res.status(404).json({
          success: false,
          error: {
            code: 'WEBSITE_NOT_FOUND',
            message: `Website '${siteId}' not found in organization '${orgId}'.`,
          },
        });
      }

      await storage.deleteWebsite(orgId, siteId);

      await storage.appendAuditLog({
        logId: `audit-site-del-${Date.now()}-${randomBytes(4).toString('hex')}`,
        orgId,
        timestamp: new Date().toISOString(),
        action: 'WEBSITE_DELETED',
        actor: {
          userId: req.user?.userId || 'unknown-user',
          role: req.user?.role || 'ORG_ADMIN',
          ipAddress: req.ip,
        },
        details: {
          siteId,
          primaryDomain: existing.primaryDomain,
        },
      });

      return res.status(200).json({
        success: true,
        message: `Website asset '${siteId}' successfully deleted.`,
      });
    }
  );

  // 8. Query Detections for Website Asset (GET /api/v1/websites/:siteId/detections)
  router.get('/:siteId/detections', async (req: Request, res: Response) => {
    const orgId = req.tenantOrgId!;
    const siteId = req.params.siteId as string;

    const existing = await storage.getWebsiteById(orgId, siteId);
    if (!existing) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'WEBSITE_NOT_FOUND',
          message: `Website '${siteId}' not found in organization '${orgId}'.`,
        },
      });
    }

    const limit = req.query.limit ? parseInt(req.query.limit as string, 10) : 100;
    const cursor = req.query.cursor as string | undefined;
    const detections = await storage.getDetections(orgId, { siteId, limit, cursor });

    return res.status(200).json({
      success: true,
      data: {
        siteId,
        items: detections.items,
        total: detections.items.length,
        nextCursor: detections.nextCursor,
      },
      meta: {
        timestamp: new Date().toISOString(),
      },
    });
  });

  // 9. Query Correlated Incidents for Website Asset (GET /api/v1/websites/:siteId/incidents)
  router.get('/:siteId/incidents', async (req: Request, res: Response) => {
    const orgId = req.tenantOrgId!;
    const siteId = req.params.siteId as string;

    const existing = await storage.getWebsiteById(orgId, siteId);
    if (!existing) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'WEBSITE_NOT_FOUND',
          message: `Website '${siteId}' not found in organization '${orgId}'.`,
        },
      });
    }

    const limit = req.query.limit ? parseInt(req.query.limit as string, 10) : 50;
    const status = req.query.status as IncidentStatus | undefined;
    const cursor = req.query.cursor as string | undefined;
    const incidents = await storage.getIncidents(orgId, { siteId, status, limit, cursor });

    return res.status(200).json({
      success: true,
      data: {
        siteId,
        items: incidents.items,
        total: incidents.items.length,
        nextCursor: incidents.nextCursor,
      },
      meta: {
        timestamp: new Date().toISOString(),
      },
    });
  });

  // 10. Query Website Risk Summary & Posture (GET /api/v1/websites/:siteId/risk-summary)
  router.get('/:siteId/risk-summary', async (req: Request, res: Response) => {
    const orgId = req.tenantOrgId!;
    const siteId = req.params.siteId as string;

    const existing = await storage.getWebsiteById(orgId, siteId);
    if (!existing) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'WEBSITE_NOT_FOUND',
          message: `Website '${siteId}' not found in organization '${orgId}'.`,
        },
      });
    }

    const incidentsResult = await storage.getIncidents(orgId, { siteId, limit: 50 });
    const detectionsResult = await storage.getDetections(orgId, { siteId, limit: 100 });

    // Identify highest active risk
    let currentRiskScore = 0;
    let currentRiskBand: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW';
    let factors: any = {
      baseSeverity: 0,
      frequencyMultiplier: 1.0,
      assetMultiplier: 1.0,
      threatMultiplier: 1.0,
      vulnerabilityTerm: 0,
      sequenceBonus: 0,
      explanation: 'No threat incidents detected.',
    };

    if (incidentsResult.items.length > 0) {
      const highestIncident = incidentsResult.items.reduce((prev, cur) =>
        cur.riskScore > (prev?.riskScore ?? -1) ? cur : prev,
        incidentsResult.items[0]
      );
      if (highestIncident) {
        currentRiskScore = highestIncident.riskScore;
        currentRiskBand = highestIncident.riskBand || (
          highestIncident.riskScore >= 75 ? 'CRITICAL' :
          highestIncident.riskScore >= 50 ? 'HIGH' :
          highestIncident.riskScore >= 25 ? 'MEDIUM' : 'LOW'
        );
        factors = highestIncident.webRiskFactors || {
          baseSeverity: highestIncident.severity === 'CRITICAL' ? 40 : highestIncident.severity === 'HIGH' ? 30 : 20,
          frequencyMultiplier: 1.0,
          assetMultiplier: 1.0,
          threatMultiplier: 1.0,
          vulnerabilityTerm: 0,
          sequenceBonus: 0,
          explanation: highestIncident.description,
        };
      }
    }

    const attackTypesSet = new Set<string>();
    for (const inc of incidentsResult.items) {
      if (Array.isArray(inc.attackTypes)) {
        inc.attackTypes.forEach((t) => attackTypesSet.add(t));
      }
    }
    for (const det of detectionsResult.items) {
      const at = (det.evidence?.details as { attackType?: string } | undefined)?.attackType;
      if (at) attackTypesSet.add(at);
    }

    return res.status(200).json({
      success: true,
      data: {
        siteId,
        domain: existing.primaryDomain,
        environment: existing.environment,
        riskTier: existing.riskTier,
        currentRiskScore,
        currentRiskBand,
        factors,
        detectedAttackTypes: Array.from(attackTypesSet),
        totalIncidentsCount: incidentsResult.items.length,
        totalDetectionsCount: detectionsResult.items.length,
        latestIncidents: incidentsResult.items.slice(0, 5),
        latestDetections: detectionsResult.items.slice(0, 10),
      },
      meta: {
        timestamp: new Date().toISOString(),
      },
    });
  });

  // 11. Query Website Attack Sequence Timeline (GET /api/v1/websites/:siteId/timeline)
  router.get('/:siteId/timeline', async (req: Request, res: Response) => {
    const orgId = req.tenantOrgId!;
    const siteId = req.params.siteId as string;

    const existing = await storage.getWebsiteById(orgId, siteId);
    if (!existing) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'WEBSITE_NOT_FOUND',
          message: `Website '${siteId}' not found in organization '${orgId}'.`,
        },
      });
    }

    const incidentsResult = await storage.getIncidents(orgId, { siteId, limit: 50 });
    const detectionsResult = await storage.getDetections(orgId, { siteId, limit: 100 });

    const items: Array<{
      timestamp: string;
      type: 'INCIDENT' | 'DETECTION';
      title: string;
      description: string;
      severity: string;
      sourceIp?: string;
      details?: Record<string, unknown>;
    }> = [];

    for (const inc of incidentsResult.items) {
      items.push({
        timestamp: inc.createdAt,
        type: 'INCIDENT',
        title: inc.title,
        description: inc.description,
        severity: inc.severity,
        sourceIp: inc.sourceIp,
        details: {
          incidentId: inc.incidentId,
          riskScore: inc.riskScore,
          riskBand: inc.riskBand,
          attackTypes: inc.attackTypes,
        },
      });
    }

    for (const det of detectionsResult.items) {
      const sourceIp =
        det.evidence?.targetEntity?.type === 'IP'
          ? det.evidence.targetEntity.value
          : typeof (det.evidence?.details as Record<string, unknown> | undefined)?.sourceIp === 'string'
          ? ((det.evidence?.details as Record<string, unknown>).sourceIp as string)
          : undefined;

      items.push({
        timestamp: det.detectedAt,
        type: 'DETECTION',
        title: det.ruleName,
        description: det.description,
        severity: det.severity,
        sourceIp,
        details: det.evidence?.details as Record<string, unknown> | undefined,
      });
    }

    // Sort chronological descending
    items.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

    return res.status(200).json({
      success: true,
      data: {
        siteId,
        domain: existing.primaryDomain,
        items,
      },
      meta: {
        timestamp: new Date().toISOString(),
        total: items.length,
      },
    });
  });

  // 12. Query Website Attacks (GET /api/v1/websites/:siteId/attacks)
  router.get('/:siteId/attacks', async (req: Request, res: Response) => {
    const orgId = req.tenantOrgId!;
    const siteId = req.params.siteId as string;

    const existing = await storage.getWebsiteById(orgId, siteId);
    if (!existing) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'WEBSITE_NOT_FOUND',
          message: `Website '${siteId}' not found in organization '${orgId}'.`,
        },
      });
    }

    const limit = req.query.limit ? parseInt(req.query.limit as string, 10) : 100;
    const detections = await storage.getDetections(orgId, { siteId, limit });

    return res.status(200).json({
      success: true,
      data: {
        siteId,
        items: detections.items,
        total: detections.items.length,
      },
      meta: {
        timestamp: new Date().toISOString(),
      },
    });
  });

  return router;
}
