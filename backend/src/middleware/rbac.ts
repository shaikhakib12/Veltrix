import type { Request, Response, NextFunction } from 'express';
import type { UserRole, ApiErrorResponse } from '@veltrix/shared';

/**
 * Enforces Role-Based Access Control (RBAC) on API endpoints.
 * Must run after `authenticate` middleware.
 *
 * Roles:
 * - SUPER_ADMIN: Always permitted across all operations.
 * - ORG_ADMIN: Organization administrator.
 * - SECURITY_ANALYST: Operational analyst for triage and detection.
 * - READ_ONLY_VIEWER: Read-only access; mutations prohibited.
 */
export function requireRole(...allowedRoles: UserRole[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      const errorResponse: ApiErrorResponse = {
        success: false,
        error: {
          code: 'UNAUTHORIZED',
          message: 'Authentication required before checking permissions.',
        },
      };
      res.status(401).json(errorResponse);
      return;
    }

    // SUPER_ADMIN has global privileges across all administrative operations
    if (req.user.role === 'SUPER_ADMIN') {
      next();
      return;
    }

    if (!allowedRoles.includes(req.user.role)) {
      const errorResponse: ApiErrorResponse = {
        success: false,
        error: {
          code: 'FORBIDDEN_INSUFFICIENT_PERMISSIONS',
          message: `User role '${req.user.role}' lacks permission for this endpoint. Required one of: [${allowedRoles.join(', ')}].`,
        },
      };
      res.status(403).json(errorResponse);
      return;
    }

    next();
  };
}
