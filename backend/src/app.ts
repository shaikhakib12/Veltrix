import express from 'express';
import cors from 'cors';
import { PLATFORM_INFO, type ApiResponse, type ApiErrorResponse } from '@veltrix/shared';

export function createApp() {
  const app = express();

  // Configure CORS origin restriction
  const allowedOrigins = [
    process.env.FRONTEND_URL || 'http://localhost:5173',
    'http://localhost:3000',
    'http://127.0.0.1:5173',
  ];

  app.use(
    cors({
      origin: (origin, callback) => {
        // Allow requests with no origin (e.g. mobile apps, curl, server-to-server)
        if (!origin || allowedOrigins.includes(origin)) {
          callback(null, true);
        } else {
          callback(new Error(`Origin '${origin}' not allowed by CORS policy`));
        }
      },
      credentials: true,
    })
  );

  app.use(express.json({ limit: '1mb' }));

  // Basic Health Check
  app.get('/health', (_req, res) => {
    res.status(200).json({
      status: 'ok',
      timestamp: new Date().toISOString(),
      service: 'veltrix-backend',
      mode: process.env.STORAGE_MODE || 'memory',
    });
  });

  // Status & Telemetry Metadata Endpoint
  app.get('/api/v1/status', async (_req, res) => {
    const response: ApiResponse<{
      platform: typeof PLATFORM_INFO;
      storageMode: string;
      environment: string;
      uptimeSeconds: number;
    }> = {
      success: true,
      data: {
        platform: PLATFORM_INFO,
        storageMode: process.env.STORAGE_MODE || 'memory',
        environment: process.env.NODE_ENV || 'development',
        uptimeSeconds: Math.floor(process.uptime()),
      },
      meta: {
        timestamp: new Date().toISOString(),
      },
    };
    res.status(200).json(response);
  });

  // Standardized 404 Handler for Unmatched Routes
  app.use((_req, res) => {
    const errorResponse: ApiErrorResponse = {
      success: false,
      error: {
        code: 'NOT_FOUND',
        message: 'The requested resource or endpoint does not exist',
      },
    };
    res.status(404).json(errorResponse);
  });

  // Global Error Handler with Production Sanitization
  app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    console.error('[VELTRIX] Unhandled Error:', err);
    const isProd = process.env.NODE_ENV === 'production';
    const errorResponse: ApiErrorResponse = {
      success: false,
      error: {
        code: 'INTERNAL_SERVER_ERROR',
        message: isProd ? 'An unexpected internal error occurred' : (err.message || 'An unexpected error occurred'),
      },
    };
    res.status(500).json(errorResponse);
  });

  return app;
}
