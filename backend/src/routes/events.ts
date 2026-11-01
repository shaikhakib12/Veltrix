import { Router, type Request, type Response } from 'express';
import type { ApiResponse, ApiErrorResponse, SecurityEvent, IngestionResponseData } from '@veltrix/shared';
import { authenticate } from '../middleware/auth.js';
import { enforceTenantIsolation } from '../middleware/tenant.js';
import { requireRole } from '../middleware/rbac.js';
import { EventService } from '../services/event-service.js';
import type { StorageInterface } from '../storage/storage-interface.js';

export function createEventsRouter(storage?: StorageInterface): Router {
  const router = Router();
  const eventService = new EventService(storage);

  /**
   * POST /api/v1/events
   * High-throughput event ingestion supporting single and batch (up to 100) events.
   * Enforces authentication, tenant isolation, and RBAC (read-only viewers prohibited).
   */
  router.post(
    '/',
    authenticate,
    enforceTenantIsolation,
    requireRole('SUPER_ADMIN', 'ORG_ADMIN', 'SECURITY_ANALYST'),
    async (req: Request, res: Response): Promise<void> => {
      const tenantOrgId = req.tenantOrgId!;
      const isSuperAdmin = req.user?.role === 'SUPER_ADMIN';
      const headerIdempotencyKey = (req.headers['idempotency-key'] || req.headers['x-idempotency-key']) as string | undefined;

      try {
        const body = req.body;

        // Determine if request is Batch or Single
        const isBatch =
          body &&
          typeof body === 'object' &&
          ('events' in body || Array.isArray(body));

        if (isBatch) {
          const rawEvents = Array.isArray(body) ? body : (body as { events: unknown[] }).events;

          if (!Array.isArray(rawEvents)) {
            const errorResponse: ApiErrorResponse = {
              success: false,
              error: {
                code: 'BAD_REQUEST',
                message: 'Invalid batch structure. Expected "events" array.',
              },
            };
            res.status(400).json(errorResponse);
            return;
          }

          if (rawEvents.length === 0) {
            const errorResponse: ApiErrorResponse = {
              success: false,
              error: {
                code: 'BAD_REQUEST',
                message: 'Batch must contain at least 1 event.',
              },
            };
            res.status(400).json(errorResponse);
            return;
          }

          if (rawEvents.length > 100) {
            const errorResponse: ApiErrorResponse = {
              success: false,
              error: {
                code: 'BATCH_SIZE_EXCEEDED',
                message: 'Batch size exceeds maximum limit of 100 events.',
              },
            };
            res.status(400).json(errorResponse);
            return;
          }

          const batchResult = await eventService.ingestBatchEvents(
            rawEvents,
            tenantOrgId,
            isSuperAdmin
          );

          // If every item was rejected, return 422 Unprocessable Entity
          if (batchResult.rejected === batchResult.total && batchResult.accepted === 0 && batchResult.duplicates === 0) {
            const errorResponse: ApiErrorResponse = {
              success: false,
              error: {
                code: 'BATCH_VALIDATION_FAILED',
                message: 'All events in the batch failed validation.',
                details: batchResult.results,
              },
            };
            res.status(422).json(errorResponse);
            return;
          }

          const response: ApiResponse<IngestionResponseData> = {
            success: true,
            data: batchResult,
            meta: {
              timestamp: new Date().toISOString(),
              total: batchResult.total,
            },
          };
          res.status(202).json(response);
          return;
        }

        // Single Event Ingestion
        if (!body || typeof body !== 'object' || Object.keys(body).length === 0) {
          const errorResponse: ApiErrorResponse = {
            success: false,
            error: {
              code: 'BAD_REQUEST',
              message: 'Request body must be a valid JSON security event object.',
            },
          };
          res.status(400).json(errorResponse);
          return;
        }

        const singleResult = await eventService.ingestSingleEvent(
          body,
          tenantOrgId,
          isSuperAdmin,
          headerIdempotencyKey
        );

        const response: ApiResponse<{
          status: 'ACCEPTED' | 'DUPLICATE_SUPPRESSED';
          eventId: string;
          event?: SecurityEvent;
        }> = {
          success: true,
          data: singleResult,
          meta: {
            timestamp: new Date().toISOString(),
          },
        };

        res.status(202).json(response);
      } catch (err: unknown) {
        const errorObj = err as { code?: string; message?: string; details?: unknown };

        if (errorObj.code === 'IDEMPOTENCY_PAYLOAD_MISMATCH') {
          const errorResponse: ApiErrorResponse = {
            success: false,
            error: {
              code: 'IDEMPOTENCY_PAYLOAD_MISMATCH',
              message:
                errorObj.message ||
                'Idempotency key was previously used with a different request payload.',
            },
          };
          res.status(409).json(errorResponse);
          return;
        }

        if (errorObj.code === 'FORBIDDEN_CROSS_TENANT_ACCESS') {
          const errorResponse: ApiErrorResponse = {
            success: false,
            error: {
              code: 'FORBIDDEN_CROSS_TENANT_ACCESS',
              message: 'Cross-tenant event injection rejected.',
            },
          };
          res.status(403).json(errorResponse);
          return;
        }

        if (errorObj.message === 'VALIDATION_FAILED') {
          const errorResponse: ApiErrorResponse = {
            success: false,
            error: {
              code: 'VALIDATION_FAILED',
              message: 'Incoming event payload failed schema validation.',
              details: errorObj.details,
            },
          };
          res.status(400).json(errorResponse);
          return;
        }

        if (errorObj.message?.startsWith('BATCH_SIZE_EXCEEDED')) {
          const errorResponse: ApiErrorResponse = {
            success: false,
            error: {
              code: 'BATCH_SIZE_EXCEEDED',
              message: errorObj.message,
            },
          };
          res.status(400).json(errorResponse);
          return;
        }

        const errorResponse: ApiErrorResponse = {
          success: false,
          error: {
            code: 'INTERNAL_SERVER_ERROR',
            message: 'An unexpected error occurred during event ingestion.',
          },
        };
        res.status(500).json(errorResponse);
      }
    }
  );

  /**
   * GET /api/v1/events
   * Query security events with filtering and cursor pagination within the authenticated organization.
   * Accessible by all authenticated roles (SUPER_ADMIN, ORG_ADMIN, SECURITY_ANALYST, READ_ONLY_VIEWER).
   */
  router.get(
    '/',
    authenticate,
    enforceTenantIsolation,
    async (req: Request, res: Response): Promise<void> => {
      const tenantOrgId = req.tenantOrgId!;

      try {
        const queryResult = await eventService.queryEvents(req.query, tenantOrgId);

        const response: ApiResponse<{
          events: SecurityEvent[];
          total: number;
          nextCursor?: string;
        }> = {
          success: true,
          data: {
            events: queryResult.events.map(({ trustedEvidenceContext: _discard, ...e }) => e as SecurityEvent),
            total: queryResult.total ?? queryResult.events.length,
            nextCursor: queryResult.nextCursor,
          },
          meta: {
            timestamp: new Date().toISOString(),
            cursor: queryResult.nextCursor,
            hasMore: Boolean(queryResult.nextCursor),
            total: queryResult.total,
          },
        };

        res.status(200).json(response);
      } catch (err: unknown) {
        const errorObj = err as { message?: string; details?: unknown };

        if (errorObj.message === 'INVALID_QUERY_PARAMETERS') {
          const errorResponse: ApiErrorResponse = {
            success: false,
            error: {
              code: 'INVALID_QUERY_PARAMETERS',
              message: 'Invalid query filters or date range.',
              details: errorObj.details,
            },
          };
          res.status(400).json(errorResponse);
          return;
        }

        if (errorObj.message === 'INVALID_CURSOR') {
          const errorResponse: ApiErrorResponse = {
            success: false,
            error: {
              code: 'INVALID_CURSOR',
              message: 'The supplied pagination cursor is invalid, expired, or belongs to another tenant.',
            },
          };
          res.status(400).json(errorResponse);
          return;
        }

        const errorResponse: ApiErrorResponse = {
          success: false,
          error: {
            code: 'INTERNAL_SERVER_ERROR',
            message: 'An unexpected error occurred during event retrieval.',
          },
        };
        res.status(500).json(errorResponse);
      }
    }
  );

  /**
   * GET /api/v1/events/:eventId
   * Fetch single security event by ID within tenant boundary.
   */
  router.get(
    '/:eventId',
    authenticate,
    enforceTenantIsolation,
    async (req: Request, res: Response): Promise<void> => {
      const tenantOrgId = req.tenantOrgId!;
      const eventId = req.params.eventId as string;

      try {
        const event = await eventService.getEventById(tenantOrgId, eventId);

        if (!event) {
          const errorResponse: ApiErrorResponse = {
            success: false,
            error: {
              code: 'EVENT_NOT_FOUND',
              message: `Event '${eventId}' not found in organization '${tenantOrgId}'.`,
            },
          };
          res.status(404).json(errorResponse);
          return;
        }

        const { trustedEvidenceContext: _discard, ...publicEvent } = event;

        const response: ApiResponse<SecurityEvent> = {
          success: true,
          data: publicEvent as SecurityEvent,
          meta: {
            timestamp: new Date().toISOString(),
          },
        };

        res.status(200).json(response);
      } catch (err: unknown) {
        const errorObj = err as { message?: string };
        if (errorObj.message?.startsWith('INVALID_EVENT_ID')) {
          const errorResponse: ApiErrorResponse = {
            success: false,
            error: {
              code: 'INVALID_EVENT_ID',
              message: 'Event ID must be a valid UUID.',
            },
          };
          res.status(400).json(errorResponse);
          return;
        }

        const errorResponse: ApiErrorResponse = {
          success: false,
          error: {
            code: 'INTERNAL_SERVER_ERROR',
            message: 'Failed to retrieve event.',
          },
        };
        res.status(500).json(errorResponse);
      }
    }
  );

  return router;
}
