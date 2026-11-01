import { Router, Request, Response } from 'express';
import {
  type ApiResponse,
  type ApiErrorResponse,
  DetectionQuerySchema,
  DetectionRunRequestSchema,
  type Detection,
} from '@veltrix/shared';
import { authenticate } from '../middleware/auth.js';
import { enforceTenantIsolation } from '../middleware/tenant.js';
import { requireRole } from '../middleware/rbac.js';
import type { StorageInterface } from '../storage/storage-interface.js';
import { getStorage } from '../storage/index.js';
import { DetectionEngine } from '../detection/engine.js';

export function createDetectionsRouter(
  storage?: StorageInterface,
  engine?: DetectionEngine
): Router {
  const router = Router();
  const store = storage || getStorage();
  const detectionEngine = engine || new DetectionEngine(store);

  // Tenant Authentication & Isolation applied to all detection endpoints
  router.use(authenticate);
  router.use(enforceTenantIsolation);

  /**
   * POST /api/v1/detections/run
   * Triggers on-demand evaluation of detection rules across telemetry events.
   * Restricted to authorized SOC analysts and administrators.
   */
  router.post(
    '/run',
    requireRole('SUPER_ADMIN', 'ORG_ADMIN', 'SECURITY_ANALYST'),
    async (req: Request, res: Response) => {
      try {
        const parseResult = DetectionRunRequestSchema.safeParse(req.body || {});
        if (!parseResult.success) {
          const errorResponse: ApiErrorResponse = {
            success: false,
            error: {
              code: 'VALIDATION_FAILED',
              message: 'Invalid detection evaluation request parameters',
              details: parseResult.error.errors.map((e) => ({
                field: e.path.join('.'),
                message: e.message,
              })),
            },
          };
          res.status(400).json(errorResponse);
          return;
        }

        const orgId = req.tenantOrgId!;
        const { startTime, endTime, ruleIds, limit, persistDetections } = parseResult.data;

        // Query historical events within requested time window
        const eventQuery = await store.getEvents(orgId, {
          startTime,
          endTime,
          limit: limit || 500,
        });

        // Evaluate detection engine
        const evaluationResult = await detectionEngine.evaluate(
          {
            organizationId: orgId,
            events: eventQuery.items,
            currentTime: new Date(),
          },
          {
            ruleIds,
            persistDetections: persistDetections ?? true,
          }
        );

        const response: ApiResponse<typeof evaluationResult> = {
          success: true,
          data: evaluationResult,
          meta: {
            timestamp: new Date().toISOString(),
          },
        };

        res.status(200).json(response);
      } catch (err: unknown) {
        console.error('[VELTRIX] Detection evaluation error:', err);
        const errorResponse: ApiErrorResponse = {
          success: false,
          error: {
            code: 'DETECTION_EXECUTION_ERROR',
            message: err instanceof Error ? err.message : 'Failed to execute detection engine',
          },
        };
        res.status(500).json(errorResponse);
      }
    }
  );

  /**
   * GET /api/v1/detections
   * Queries generated threat detections with keyset pagination and filtering.
   */
  router.get('/', async (req: Request, res: Response) => {
    try {
      const parseResult = DetectionQuerySchema.safeParse(req.query);
      if (!parseResult.success) {
        const errorResponse: ApiErrorResponse = {
          success: false,
          error: {
            code: 'INVALID_QUERY_PARAMETERS',
            message: 'Query parameters failed validation',
            details: parseResult.error.errors.map((e) => ({
              field: e.path.join('.'),
              message: e.message,
            })),
          },
        };
        res.status(400).json(errorResponse);
        return;
      }

      const orgId = req.tenantOrgId!;
      const options = parseResult.data;

      const queryResult = await store.getDetections(orgId, options);

      const response: ApiResponse<{
        items: Detection[];
        nextCursor?: string;
        total?: number;
      }> = {
        success: true,
        data: {
          items: queryResult.items,
          nextCursor: queryResult.nextCursor,
          total: queryResult.total,
        },
        meta: {
          timestamp: new Date().toISOString(),
          cursor: queryResult.nextCursor,
          hasMore: !!queryResult.nextCursor,
          total: queryResult.total,
        },
      };

      res.status(200).json(response);
    } catch (err: unknown) {
      if (err instanceof Error && err.message.startsWith('INVALID_CURSOR')) {
        const errorResponse: ApiErrorResponse = {
          success: false,
          error: {
            code: 'INVALID_CURSOR',
            message: 'Provided pagination cursor is invalid or tampered',
          },
        };
        res.status(400).json(errorResponse);
        return;
      }

      console.error('[VELTRIX] Query detections error:', err);
      const errorResponse: ApiErrorResponse = {
        success: false,
        error: {
          code: 'STORAGE_QUERY_ERROR',
          message: 'Failed to query threat detections',
        },
      };
      res.status(500).json(errorResponse);
    }
  });

  /**
   * GET /api/v1/detections/:detectionId
   * Retrieves a single detection record by its unique ID.
   */
  router.get('/:detectionId', async (req: Request, res: Response) => {
    try {
      const orgId = req.tenantOrgId!;
      const detectionId = req.params.detectionId;

      if (!detectionId) {
        const errorResponse: ApiErrorResponse = {
          success: false,
          error: {
            code: 'INVALID_REQUEST',
            message: 'Detection ID path parameter is required',
          },
        };
        res.status(400).json(errorResponse);
        return;
      }

      const detection = await store.getDetectionById(orgId, detectionId);

      if (!detection || detection.orgId !== orgId) {
        const errorResponse: ApiErrorResponse = {
          success: false,
          error: {
            code: 'NOT_FOUND',
            message: `Detection with ID '${detectionId}' was not found for this organization`,
          },
        };
        res.status(404).json(errorResponse);
        return;
      }

      const response: ApiResponse<Detection> = {
        success: true,
        data: detection,
        meta: {
          timestamp: new Date().toISOString(),
        },
      };

      res.status(200).json(response);
    } catch (err: unknown) {
      console.error(`[VELTRIX] Error fetching detection ${req.params.detectionId}:`, err);
      const errorResponse: ApiErrorResponse = {
        success: false,
        error: {
          code: 'STORAGE_RETRIEVAL_ERROR',
          message: 'Failed to retrieve detection',
        },
      };
      res.status(500).json(errorResponse);
    }
  });

  return router;
}
