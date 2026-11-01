import type { Request, Response, NextFunction } from 'express';
import { createHash } from 'node:crypto';
import type { ApiErrorResponse } from '@veltrix/shared';
import { getAuthProvider } from '../auth/index.js';
import { getStorage } from '../storage/index.js';

export async function authenticate(req: Request, res: Response, next: NextFunction): Promise<void> {
  const apiKeyHeader = req.headers['x-api-key'] || req.headers['x-integration-key'];
  const authHeader = req.headers.authorization;

  // Case 1: Integration API Key Authentication (TASK-603)
  if (apiKeyHeader) {
    const rawApiKey = Array.isArray(apiKeyHeader) ? apiKeyHeader[0] : apiKeyHeader;
    if (!rawApiKey || typeof rawApiKey !== 'string' || !rawApiKey.trim()) {
      const errorResponse: ApiErrorResponse = {
        success: false,
        error: {
          code: 'UNAUTHORIZED_INVALID_API_KEY',
          message: 'Supplied x-api-key is empty or invalid.',
        },
      };
      res.status(401).json(errorResponse);
      return;
    }

    const apiKeyHash = createHash('sha256').update(rawApiKey.trim()).digest('hex');
    const storage = getStorage();
    const integration = await storage.getIntegrationByApiKeyHash(apiKeyHash);

    if (!integration) {
      const errorResponse: ApiErrorResponse = {
        success: false,
        error: {
          code: 'UNAUTHORIZED_INVALID_API_KEY',
          message: 'The supplied API key was not found or is invalid.',
        },
      };
      res.status(401).json(errorResponse);
      return;
    }

    if (integration.status === 'REVOKED') {
      const errorResponse: ApiErrorResponse = {
        success: false,
        error: {
          code: 'UNAUTHORIZED_REVOKED_API_KEY',
          message: `The integration '${integration.name}' (${integration.integrationId}) has been revoked.`,
        },
      };
      res.status(401).json(errorResponse);
      return;
    }

    if (integration.status === 'INACTIVE') {
      const errorResponse: ApiErrorResponse = {
        success: false,
        error: {
          code: 'FORBIDDEN_INACTIVE_INTEGRATION',
          message: `The integration '${integration.name}' is inactive.`,
        },
      };
      res.status(403).json(errorResponse);
      return;
    }

    // Attach user and tenant context to Request
    req.user = {
      userId: integration.integrationId,
      username: integration.name,
      email: `${integration.integrationId}@integration.veltrix.local`,
      role: 'SECURITY_ANALYST',
      orgId: integration.orgId,
    };
    req.tenantOrgId = integration.orgId;
    req.integration = integration;

    // Asynchronously update lastSeenAt
    storage
      .updateIntegration(integration.orgId, integration.integrationId, {
        lastSeenAt: new Date().toISOString(),
      })
      .catch((err) => {
        console.error('[VELTRIX-AUTH] Failed to update integration lastSeenAt:', err);
      });

    next();
    return;
  }

  // Case 2: Bearer Token Authentication (Cognito / JWT)
  if (!authHeader) {
    const errorResponse: ApiErrorResponse = {
      success: false,
      error: {
        code: 'UNAUTHORIZED_MISSING_TOKEN',
        message: 'Authentication required. Supply Authorization header with Bearer token or x-api-key header.',
      },
    };
    res.status(401).json(errorResponse);
    return;
  }

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer' || !parts[1]) {
    const errorResponse: ApiErrorResponse = {
      success: false,
      error: {
        code: 'UNAUTHORIZED_INVALID_TOKEN_FORMAT',
        message: 'Invalid Authorization header format. Expected "Bearer <token>".',
      },
    };
    res.status(401).json(errorResponse);
    return;
  }

  const token = parts[1];

  try {
    const authProvider = getAuthProvider();
    const payload = await authProvider.verifyToken(token);
    req.user = payload;
    req.tenantOrgId = payload.orgId;
    next();
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);

    let errorCode = 'UNAUTHORIZED_INVALID_TOKEN';
    let errorMessage = 'The supplied authentication token is invalid or tampered with.';

    if (message === 'TOKEN_EXPIRED') {
      errorCode = 'UNAUTHORIZED_EXPIRED_TOKEN';
      errorMessage = 'The authentication token has expired. Please refresh your session.';
    } else if (message === 'TOKEN_REVOKED') {
      errorCode = 'UNAUTHORIZED_REVOKED_TOKEN';
      errorMessage = 'The authentication token has been revoked / logged out.';
    }

    const errorResponse: ApiErrorResponse = {
      success: false,
      error: {
        code: errorCode,
        message: errorMessage,
      },
    };
    res.status(401).json(errorResponse);
  }
}
