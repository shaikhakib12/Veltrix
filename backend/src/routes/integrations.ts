import { Router, type Request, type Response } from 'express';
import { randomUUID, randomBytes, createHash } from 'node:crypto';
import {
  IntegrationCreateRequestSchema,
  IntegrationUpdateRequestSchema,
  type Integration,
} from '@veltrix/shared';
import { authenticate } from '../middleware/auth.js';
import { enforceTenantIsolation } from '../middleware/tenant.js';
import { requireRole } from '../middleware/rbac.js';
import { getStorage } from '../storage/index.js';

export function createIntegrationsRouter() {
  const router = Router();
  const storage = getStorage();

  // All endpoints require authentication and tenant isolation
  router.use(authenticate);
  router.use(enforceTenantIsolation);

  // Helper to generate cryptographically random secret API key
  function generateApiKey(): { secretKey: string; apiKeyPrefix: string; apiKeyHash: string } {
    const rawKey = randomBytes(24).toString('base64url');
    const secretKey = `vltx_live_${rawKey}`;
    const apiKeyPrefix = secretKey.slice(0, 18); // e.g. "vltx_live_ab12cd34"
    const apiKeyHash = createHash('sha256').update(secretKey).digest('hex');
    return { secretKey, apiKeyPrefix, apiKeyHash };
  }

  // 1. Register Integration (POST /api/v1/integrations)
  router.post(
    '/',
    requireRole('SUPER_ADMIN', 'ORG_ADMIN'),
    async (req: Request, res: Response) => {
      const parseResult = IntegrationCreateRequestSchema.safeParse(req.body);
      if (!parseResult.success) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Invalid integration registration parameters.',
            details: parseResult.error.errors,
          },
        });
      }

      const orgId = req.tenantOrgId!;
      const data = parseResult.data;

      // If siteId provided, verify that the website belongs to this organization
      if (data.siteId) {
        const site = await storage.getWebsiteById(orgId, data.siteId);
        if (!site) {
          return res.status(404).json({
            success: false,
            error: {
              code: 'WEBSITE_NOT_FOUND',
              message: `Associated website '${data.siteId}' not found in organization '${orgId}'.`,
            },
          });
        }
      }

      const integrationId = `int-${randomUUID()}`;
      const { secretKey, apiKeyPrefix, apiKeyHash } = generateApiKey();
      const nowIso = new Date().toISOString();

      const newIntegration: Integration = {
        integrationId,
        orgId,
        siteId: data.siteId,
        name: data.name,
        type: data.type,
        status: 'ACTIVE',
        description: data.description,
        apiKeyPrefix,
        apiKeyHash,
        health: {
          status: 'INACTIVE',
          eventsReceived: 0,
        },
        createdAt: nowIso,
        updatedAt: nowIso,
      };

      await storage.saveIntegration(newIntegration);

      // Audit log (Never log secret keys!)
      await storage.appendAuditLog({
        logId: `audit-int-reg-${Date.now()}-${randomBytes(4).toString('hex')}`,
        orgId,
        timestamp: nowIso,
        action: 'INTEGRATION_CREATED',
        actor: {
          userId: req.user?.userId || 'unknown-user',
          role: req.user?.role || 'ORG_ADMIN',
          ipAddress: req.ip,
        },
        details: {
          integrationId,
          name: data.name,
          type: data.type,
          siteId: data.siteId,
          apiKeyPrefix,
        },
      });

      // Secret key is returned ONLY in the creation response
      return res.status(201).json({
        success: true,
        integration: {
          ...newIntegration,
          secretKey, // Revealed once to the caller
        },
        message: 'Integration created successfully. Securely record the secretKey; it will not be displayed again.',
      });
    }
  );

  // 2. List Integrations (GET /api/v1/integrations)
  router.get(
    '/',
    requireRole('SUPER_ADMIN', 'ORG_ADMIN', 'SECURITY_ANALYST', 'READ_ONLY_VIEWER'),
    async (req: Request, res: Response) => {
      const orgId = req.tenantOrgId!;
      const siteId = req.query.siteId as string | undefined;

      const items = await storage.getIntegrations(orgId, siteId);

      // Sanitize: never return secretKey or apiKeyHash
      const sanitized = items.map(({ secretKey, apiKeyHash, ...rest }) => rest);

      return res.status(200).json({
        success: true,
        total: sanitized.length,
        integrations: sanitized,
      });
    }
  );

  // 3. Get Integration Details (GET /api/v1/integrations/:integrationId)
  router.get(
    '/:integrationId',
    requireRole('SUPER_ADMIN', 'ORG_ADMIN', 'SECURITY_ANALYST', 'READ_ONLY_VIEWER'),
    async (req: Request, res: Response) => {
      const orgId = req.tenantOrgId!;
      const integrationId = req.params.integrationId as string;

      const item = await storage.getIntegrationById(orgId, integrationId);
      if (!item) {
        return res.status(404).json({
          success: false,
          error: {
            code: 'INTEGRATION_NOT_FOUND',
            message: `Integration '${integrationId}' not found in organization '${orgId}'.`,
          },
        });
      }

      const { secretKey, apiKeyHash, ...sanitized } = item;
      return res.status(200).json({
        success: true,
        integration: sanitized,
      });
    }
  );

  // 4. Update Integration Metadata (PATCH /api/v1/integrations/:integrationId)
  router.patch(
    '/:integrationId',
    requireRole('SUPER_ADMIN', 'ORG_ADMIN'),
    async (req: Request, res: Response) => {
      const parseResult = IntegrationUpdateRequestSchema.safeParse(req.body);
      if (!parseResult.success) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Invalid integration update parameters.',
            details: parseResult.error.errors,
          },
        });
      }

      const orgId = req.tenantOrgId!;
      const integrationId = req.params.integrationId as string;

      const existing = await storage.getIntegrationById(orgId, integrationId);
      if (!existing) {
        return res.status(404).json({
          success: false,
          error: {
            code: 'INTEGRATION_NOT_FOUND',
            message: `Integration '${integrationId}' not found in organization '${orgId}'.`,
          },
        });
      }

      const updated = await storage.updateIntegration(orgId, integrationId, parseResult.data);
      if (!updated) {
        return res.status(500).json({
          success: false,
          error: { code: 'UPDATE_FAILED', message: 'Failed to update integration.' },
        });
      }

      const { secretKey, apiKeyHash, ...sanitized } = updated;
      return res.status(200).json({
        success: true,
        integration: sanitized,
      });
    }
  );

  // 5. Rotate Integration API Key (POST /api/v1/integrations/:integrationId/rotate-key)
  router.post(
    '/:integrationId/rotate-key',
    requireRole('SUPER_ADMIN', 'ORG_ADMIN'),
    async (req: Request, res: Response) => {
      const orgId = req.tenantOrgId!;
      const integrationId = req.params.integrationId as string;

      const existing = await storage.getIntegrationById(orgId, integrationId);
      if (!existing) {
        return res.status(404).json({
          success: false,
          error: {
            code: 'INTEGRATION_NOT_FOUND',
            message: `Integration '${integrationId}' not found in organization '${orgId}'.`,
          },
        });
      }

      const { secretKey, apiKeyPrefix, apiKeyHash } = generateApiKey();
      await storage.updateIntegration(orgId, integrationId, {
        apiKeyPrefix,
        apiKeyHash,
      });

      const nowIso = new Date().toISOString();
      await storage.appendAuditLog({
        logId: `audit-int-rot-${Date.now()}-${randomBytes(4).toString('hex')}`,
        orgId,
        timestamp: nowIso,
        action: 'INTEGRATION_ROTATED',
        actor: {
          userId: req.user?.userId || 'unknown-user',
          role: req.user?.role || 'ORG_ADMIN',
          ipAddress: req.ip,
        },
        details: {
          integrationId,
          apiKeyPrefix,
        },
      });

      return res.status(200).json({
        success: true,
        secretKey,
        apiKeyPrefix,
        message: 'Integration API key rotated successfully. The previous key is immediately invalidated.',
      });
    }
  );

  // 6. Revoke Integration (POST /api/v1/integrations/:integrationId/revoke)
  router.post(
    '/:integrationId/revoke',
    requireRole('SUPER_ADMIN', 'ORG_ADMIN'),
    async (req: Request, res: Response) => {
      const orgId = req.tenantOrgId!;
      const integrationId = req.params.integrationId as string;

      const existing = await storage.getIntegrationById(orgId, integrationId);
      if (!existing) {
        return res.status(404).json({
          success: false,
          error: {
            code: 'INTEGRATION_NOT_FOUND',
            message: `Integration '${integrationId}' not found in organization '${orgId}'.`,
          },
        });
      }

      const updated = await storage.updateIntegration(orgId, integrationId, {
        status: 'REVOKED',
      });

      const nowIso = new Date().toISOString();
      await storage.appendAuditLog({
        logId: `audit-int-rev-${Date.now()}-${randomBytes(4).toString('hex')}`,
        orgId,
        timestamp: nowIso,
        action: 'INTEGRATION_REVOKED',
        actor: {
          userId: req.user?.userId || 'unknown-user',
          role: req.user?.role || 'ORG_ADMIN',
          ipAddress: req.ip,
        },
        details: {
          integrationId,
          status: 'REVOKED',
        },
      });

      return res.status(200).json({
        success: true,
        integration: updated,
        message: `Integration '${integrationId}' has been revoked. All further requests using its credentials will be rejected.`,
      });
    }
  );

  // 7. Get Integration Health (GET /api/v1/integrations/:integrationId/health)
  router.get(
    '/:integrationId/health',
    requireRole('SUPER_ADMIN', 'ORG_ADMIN', 'SECURITY_ANALYST', 'READ_ONLY_VIEWER'),
    async (req: Request, res: Response) => {
      const orgId = req.tenantOrgId!;
      const integrationId = req.params.integrationId as string;

      const item = await storage.getIntegrationById(orgId, integrationId);
      if (!item) {
        return res.status(404).json({
          success: false,
          error: {
            code: 'INTEGRATION_NOT_FOUND',
            message: `Integration '${integrationId}' not found in organization '${orgId}'.`,
          },
        });
      }

      return res.status(200).json({
        success: true,
        integrationId: item.integrationId,
        status: item.status,
        health: item.health,
        lastSeenAt: item.lastSeenAt,
      });
    }
  );

  // 8. Delete Integration (DELETE /api/v1/integrations/:integrationId)
  router.delete(
    '/:integrationId',
    requireRole('SUPER_ADMIN', 'ORG_ADMIN'),
    async (req: Request, res: Response) => {
      const orgId = req.tenantOrgId!;
      const integrationId = req.params.integrationId as string;

      const existing = await storage.getIntegrationById(orgId, integrationId);
      if (!existing) {
        return res.status(404).json({
          success: false,
          error: {
            code: 'INTEGRATION_NOT_FOUND',
            message: `Integration '${integrationId}' not found in organization '${orgId}'.`,
          },
        });
      }

      await storage.deleteIntegration(orgId, integrationId);

      const nowIso = new Date().toISOString();
      await storage.appendAuditLog({
        logId: `audit-int-del-${Date.now()}-${randomBytes(4).toString('hex')}`,
        orgId,
        timestamp: nowIso,
        action: 'INTEGRATION_DELETED',
        actor: {
          userId: req.user?.userId || 'unknown-user',
          role: req.user?.role || 'ORG_ADMIN',
          ipAddress: req.ip,
        },
        details: {
          integrationId,
          name: existing.name,
        },
      });

      return res.status(200).json({
        success: true,
        message: `Integration '${integrationId}' successfully deleted.`,
      });
    }
  );

  return router;
}
