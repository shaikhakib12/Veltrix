import express from 'express';
import cors from 'cors';
import { PLATFORM_INFO, type ApiResponse, type ApiErrorResponse } from '@veltrix/shared';
import { createAuthRouter } from './routes/auth.js';
import { createEventsRouter } from './routes/events.js';
import { createDetectionsRouter } from './routes/detections.js';
import { createDetectionRulesRouter } from './routes/detection-rules.js';
import { createThreatIndicatorsRouter } from './routes/threat-indicators.js';
import { createWebsitesRouter } from './routes/websites.js';
import { createIntegrationsRouter } from './routes/integrations.js';
import { createIncidentsRouter } from './routes/incidents.js';
import { createDashboardRouter } from './routes/dashboard.js';
import { createDemoRouter } from './routes/demo.js';
import { createAuditRouter } from './routes/audit.js';
import { createResponseRouter } from './routes/response.js';
import { createScansRouter } from './routes/scans.js';
import { createFindingsRouter } from './routes/findings.js';
import { authenticate } from './middleware/auth.js';
import { enforceTenantIsolation } from './middleware/tenant.js';
import { requireRole } from './middleware/rbac.js';

export function createApp() {
  const app = express();

  // Configure CORS origin restriction with support for Vercel edge domains
  const configuredOrigin = (process.env.FRONTEND_URL || '').replace(/\/$/, '');
  const allowedOrigins = [
    configuredOrigin,
    'http://localhost:5173',
    'http://localhost:3000',
    'http://127.0.0.1:5173',
  ].filter(Boolean);

  app.use(
    cors({
      origin: (origin, callback) => {
        if (
          !origin ||
          allowedOrigins.includes(origin) ||
          origin.endsWith('.vercel.app') ||
          allowedOrigins.includes('*')
        ) {
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

  // Authentication Routes (TASK-301)
  app.use('/api/v1/auth', createAuthRouter());

  // Telemetry Ingestion & Query Routes (TASK-401, TASK-402)
  app.use('/api/v1/events', createEventsRouter());

  // Threat Detection & Query Routes (TASK-501 to TASK-504)
  app.use('/api/v1/detections', createDetectionsRouter());
  app.use('/api/v1/detection-rules', createDetectionRulesRouter());
  app.use('/api/v1/threat-indicators', createThreatIndicatorsRouter());

  // Website Asset Inventory & Integration Routes (TASK-601 to TASK-603)
  app.use('/api/v1/websites', createWebsitesRouter());
  app.use('/api/v1/integrations', createIntegrationsRouter());

  // Correlated Incident Management Routes (TASK-706, TASK-707)
  app.use('/api/v1/incidents', createIncidentsRouter());

  // Aggregated SOC console read model (Phase 11)
  app.use('/api/v1/dashboard', createDashboardRouter());

  // Approval-gated response queue & tamper-evident audit ledger (Phase 10 read/act surface)
  app.use('/api/v1/response', createResponseRouter());
  app.use('/api/v1/audit', createAuditRouter());

  // Authorized Vulnerability Scans & Findings (Phase 8)
  app.use('/api/v1/scans', createScansRouter());
  app.use('/api/v1/findings', createFindingsRouter());

  // Development-only deterministic demo dataset
  app.use('/api/v1/demo', createDemoRouter());

  // Multi-Tenant Isolation Verification Route (TASK-303)
  app.get(
    '/api/v1/tenant/telemetry-overview',
    authenticate,
    enforceTenantIsolation,
    (req, res) => {
      res.status(200).json({
        success: true,
        data: {
          orgId: req.tenantOrgId,
          user: req.user?.username,
          role: req.user?.role,
          message: `Authorized access granted for organization '${req.tenantOrgId}'.`,
        },
      });
    }
  );

  // RBAC Protected Administrative Route (TASK-304: requires ORG_ADMIN or SUPER_ADMIN)
  app.post(
    '/api/v1/admin/rules',
    authenticate,
    enforceTenantIsolation,
    requireRole('ORG_ADMIN'),
    (req, res) => {
      res.status(200).json({
        success: true,
        data: {
          orgId: req.tenantOrgId,
          authorizedBy: req.user?.email,
          message: 'Detection rule mutation permitted by administrator role.',
        },
      });
    }
  );

  // RBAC Protected Super Admin Route (TASK-304: requires SUPER_ADMIN)
  app.post(
    '/api/v1/admin/global-oversight',
    authenticate,
    requireRole('SUPER_ADMIN'),
    (req, res) => {
      res.status(200).json({
        success: true,
        data: {
          authorizedBy: req.user?.email,
          message: 'Cross-tenant platform administrative action permitted.',
        },
      });
    }
  );

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
