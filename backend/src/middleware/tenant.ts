import type { Request, Response, NextFunction } from 'express';
import type { ApiErrorResponse } from '@veltrix/shared';

/**
 * Enforces strict multi-tenant data isolation and protects against parameter tampering.
 * Must run after the `authenticate` middleware.
 *
 * Rules:
 * 1. An authenticated user can only operate within their cryptographically assigned `orgId`.
 * 2. Scans `x-organization-id` header, `req.query.orgId`, `req.params.orgId`, and `req.body.orgId`.
 * 3. For SUPER_ADMIN: Can access any specified organization.
 * 4. For all other roles: Every specified organization parameter MUST match `req.user.orgId`.
 *    Any mismatch is rejected with 403 Forbidden (FORBIDDEN_CROSS_TENANT_ACCESS).
 * 5. Sanitizes and binds `req.tenantOrgId` for downstream repository execution.
 */
export function enforceTenantIsolation(req: Request, res: Response, next: NextFunction): void {
  if (!req.user) {
    const errorResponse: ApiErrorResponse = {
      success: false,
      error: {
        code: 'UNAUTHORIZED',
        message: 'Authentication is required before tenant verification.',
      },
    };
    res.status(401).json(errorResponse);
    return;
  }

  const userOrgId = req.user.orgId;
  const headerOrgId = req.headers['x-organization-id'] as string | undefined;
  const queryOrgId = req.query.orgId as string | undefined;
  const paramOrgId = req.params.orgId as string | undefined;
  const bodyOrgId = req.body && typeof req.body === 'object' && typeof req.body.orgId === 'string'
    ? (req.body.orgId as string)
    : undefined;

  // Collect all explicitly provided tenant parameters
  const specifiedOrgIds = [headerOrgId, queryOrgId, paramOrgId, bodyOrgId].filter(
    (id): id is string => typeof id === 'string' && id.trim().length > 0
  );

  const targetOrgId = specifiedOrgIds[0] || userOrgId;

  // Super Admin bypass: Global oversight allowed across all organizations
  if (req.user.role === 'SUPER_ADMIN') {
    req.tenantOrgId = targetOrgId;
    next();
    return;
  }

  // Adversarial check: Reject if ANY specified parameter does not match authenticated orgId
  for (const orgId of specifiedOrgIds) {
    if (orgId !== userOrgId) {
      const errorResponse: ApiErrorResponse = {
        success: false,
        error: {
          code: 'FORBIDDEN_CROSS_TENANT_ACCESS',
          message: `Cross-tenant access prohibited. Authenticated in organization '${userOrgId}', cannot access '${orgId}'.`,
        },
      };
      res.status(403).json(errorResponse);
      return;
    }
  }

  req.tenantOrgId = userOrgId;
  next();
}
