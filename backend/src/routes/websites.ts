import { Router, type Request, type Response } from 'express';
import { randomUUID, randomBytes } from 'node:crypto';
import {
  WebsiteCreateRequestSchema,
  WebsiteUpdateRequestSchema,
  DomainVerifyRequestSchema,
  type WebsiteAsset,
} from '@veltrix/shared';
import { authenticate } from '../middleware/auth.js';
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

      await storage.saveWebsite(newSite);

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
    requireRole('SUPER_ADMIN', 'ORG_ADMIN', 'SECURITY_ANALYST', 'READ_ONLY_VIEWER'),
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
    requireRole('SUPER_ADMIN', 'ORG_ADMIN', 'SECURITY_ANALYST', 'READ_ONLY_VIEWER'),
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

  return router;
}
