import { Router, type Request, type Response } from 'express';
import {
  AuthLoginRequestSchema,
  AuthRegisterRequestSchema,
  AuthRefreshRequestSchema,
  type ApiResponse,
  type ApiErrorResponse,
  type AuthUser,
  type AuthSession,
} from '@veltrix/shared';
import type { RefreshResult } from '../auth/auth-interface.js';
import { getAuthProvider } from '../auth/index.js';
import { authenticate } from '../middleware/auth.js';

export function createAuthRouter(): Router {
  const router = Router();

  // POST /auth/register
  router.post('/register', async (req: Request, res: Response) => {
    const parseResult = AuthRegisterRequestSchema.safeParse(req.body);
    if (!parseResult.success) {
      const errorResponse: ApiErrorResponse = {
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Invalid registration parameters',
          details: parseResult.error.errors,
        },
      };
      res.status(400).json(errorResponse);
      return;
    }

    try {
      const authProvider = getAuthProvider();
      const user = await authProvider.register(parseResult.data);
      const response: ApiResponse<AuthUser> = {
        success: true,
        data: user,
        meta: {
          timestamp: new Date().toISOString(),
        },
      };
      res.status(201).json(response);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      if (message === 'USER_ALREADY_EXISTS') {
        const errorResponse: ApiErrorResponse = {
          success: false,
          error: {
            code: 'CONFLICT',
            message: 'A user with this email address already exists',
          },
        };
        res.status(409).json(errorResponse);
        return;
      }

      res.status(500).json({
        success: false,
        error: {
          code: 'REGISTRATION_FAILED',
          message,
        },
      });
    }
  });

  // POST /auth/login
  router.post('/login', async (req: Request, res: Response) => {
    const parseResult = AuthLoginRequestSchema.safeParse(req.body);
    if (!parseResult.success) {
      const errorResponse: ApiErrorResponse = {
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Invalid login parameters',
          details: parseResult.error.errors,
        },
      };
      res.status(400).json(errorResponse);
      return;
    }

    try {
      const authProvider = getAuthProvider();
      const session = await authProvider.login(parseResult.data);
      const response: ApiResponse<AuthSession> = {
        success: true,
        data: session,
        meta: {
          timestamp: new Date().toISOString(),
        },
      };
      res.status(200).json(response);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      if (message === 'INVALID_CREDENTIALS') {
        const errorResponse: ApiErrorResponse = {
          success: false,
          error: {
            code: 'UNAUTHORIZED_INVALID_CREDENTIALS',
            message: 'Invalid email address or password provided',
          },
        };
        res.status(401).json(errorResponse);
        return;
      }

      if (message === 'ORGANIZATION_MISMATCH') {
        const errorResponse: ApiErrorResponse = {
          success: false,
          error: {
            code: 'FORBIDDEN_ORGANIZATION_MISMATCH',
            message: 'User does not belong to the requested organization',
          },
        };
        res.status(403).json(errorResponse);
        return;
      }

      res.status(500).json({
        success: false,
        error: {
          code: 'AUTHENTICATION_FAILED',
          message,
        },
      });
    }
  });

  // POST /auth/refresh (With Refresh Token Rotation)
  router.post('/refresh', async (req: Request, res: Response) => {
    const parseResult = AuthRefreshRequestSchema.safeParse(req.body);
    if (!parseResult.success) {
      const errorResponse: ApiErrorResponse = {
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Invalid refresh request',
          details: parseResult.error.errors,
        },
      };
      res.status(400).json(errorResponse);
      return;
    }

    try {
      const authProvider = getAuthProvider();
      const tokens = await authProvider.refresh(parseResult.data.refreshToken);
      const response: ApiResponse<RefreshResult> = {
        success: true,
        data: tokens,
        meta: {
          timestamp: new Date().toISOString(),
        },
      };
      res.status(200).json(response);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      const isReuse = message === 'TOKEN_REVOKED_REUSE_DETECTED';
      const errorResponse: ApiErrorResponse = {
        success: false,
        error: {
          code: isReuse ? 'UNAUTHORIZED_REFRESH_TOKEN_REUSE_DETECTED' : 'UNAUTHORIZED_INVALID_REFRESH_TOKEN',
          message: isReuse
            ? 'Refresh token reuse detected. Token family invalidated for security.'
            : `Unable to refresh token: ${message}`,
        },
      };
      res.status(401).json(errorResponse);
    }
  });

  // POST /auth/logout (Protected, revokes access token and optional refresh token)
  router.post('/logout', authenticate, async (req: Request, res: Response) => {
    const authHeader = req.headers.authorization;
    const refreshToken = (req.body?.refreshToken as string) || undefined;

    if (authHeader) {
      const token = authHeader.split(' ')[1];
      if (token) {
        const authProvider = getAuthProvider();
        await authProvider.logout(token, refreshToken);
      }
    }

    const response: ApiResponse<{ message: string }> = {
      success: true,
      data: {
        message: 'Session terminated and token invalidated successfully',
      },
      meta: {
        timestamp: new Date().toISOString(),
      },
    };
    res.status(200).json(response);
  });

  // GET /auth/me (Protected)
  router.get('/me', authenticate, async (req: Request, res: Response) => {
    const response: ApiResponse<typeof req.user> = {
      success: true,
      data: req.user,
      meta: {
        timestamp: new Date().toISOString(),
      },
    };
    res.status(200).json(response);
  });

  return router;
}
