import type { Request, Response, NextFunction } from 'express';
import type { ApiErrorResponse } from '@veltrix/shared';

/**
 * Enforces strict multi-tenant data isolation.
 * Must run after the `authenticate` middleware.
 *
 * Rules:
 * 1. An authenticated user can only operate within their assigned `orgId`.
 * 2. If the request provides `x-organization-id` header:
 *    - For SUPER_ADMIN: Can impersonate / access any specified organization.
 *    - For all other roles: Must match `req.user.orgId`; cross-tenant access is rejected with 403 Forbidden.
 * 3. Sets `req.tenantOrgId` for downstream handlers and repositories.
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

  const requestedOrgId = (req.headers['x-organization-id'] as string) || req.user.orgId;

  // Super Admin bypass: Global oversight allowed across all organizations
  if (req.user.role === 'SUPER_ADMIN') {
    req.tenantOrgId = requestedOrgId;
    next();
    return;
  }

  // Strict tenant boundary check for non-Super-Admin callers
  if (requestedOrgId !== req.user.orgId) {
    const errorResponse: ApiErrorResponse = {
      success: false,
      error: {
        code: 'FORBIDDEN_CROSS_TENANT_ACCESS',
        message: `Cross-tenant access prohibited. Authenticated in organization '${req.user.orgId}', cannot access '${requestedOrgId}'.`,
      },
    };
    res.status(403).json(errorResponse);
    return;
  }

  req.tenantOrgId = req.user.orgId;
  next();
}
