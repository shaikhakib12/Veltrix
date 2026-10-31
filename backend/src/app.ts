import express from 'express';
import cors from 'cors';
import { PLATFORM_INFO, type ApiResponse } from '@veltrix/shared';

export function createApp() {
  const app = express();

  app.use(cors());
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

  // Global Error Handler
  app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    console.error('[VELTRIX] Unhandled Error:', err);
    res.status(500).json({
      success: false,
      error: {
        code: 'INTERNAL_SERVER_ERROR',
        message: err.message || 'An unexpected error occurred',
      },
    });
  });

  return app;
}
