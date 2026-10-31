import type { Request, Response, NextFunction } from 'express';
import type { ApiErrorResponse } from '@veltrix/shared';
import { getAuthProvider } from '../auth/index.js';

export async function authenticate(req: Request, res: Response, next: NextFunction): Promise<void> {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    const errorResponse: ApiErrorResponse = {
      success: false,
      error: {
        code: 'UNAUTHORIZED_MISSING_TOKEN',
        message: 'Authorization header is missing. Bearer token is required.',
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
