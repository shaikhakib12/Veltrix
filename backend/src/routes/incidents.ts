import { Router, Request, Response } from 'express';
import {
  type ApiResponse,
  type ApiErrorResponse,
  type Incident,
  type IncidentStatus,
} from '@veltrix/shared';
import { authenticate, requireBearerAuth } from '../middleware/auth.js';
import { enforceTenantIsolation } from '../middleware/tenant.js';
import { requireRole } from '../middleware/rbac.js';
import type { StorageInterface } from '../storage/storage-interface.js';
import { getStorage } from '../storage/index.js';

export function createIncidentsRouter(storage?: StorageInterface): Router {
  const router = Router();
  const store = storage || getStorage();

  router.use(requireBearerAuth);
  router.use(authenticate);
  router.use(enforceTenantIsolation);

  /**
   * GET /api/v1/incidents
   * Lists correlated security incidents for the tenant.
   */
  router.get('/', async (req: Request, res: Response) => {
    try {
      const orgId = req.tenantOrgId!;
      const status = req.query.status as IncidentStatus | undefined;
      const siteId = req.query.siteId as string | undefined;
      const limit = req.query.limit ? parseInt(req.query.limit as string, 10) : 50;
      const cursor = req.query.cursor as string | undefined;

      const result = await store.getIncidents(orgId, {
        status,
        siteId,
        limit,
        cursor,
      });

      const response: ApiResponse<{
        items: Incident[];
        nextCursor?: string;
        total: number;
      }> = {
        success: true,
        data: {
          items: result.items,
          nextCursor: result.nextCursor,
          total: result.items.length,
        },
        meta: {
          timestamp: new Date().toISOString(),
          cursor: result.nextCursor,
          hasMore: !!result.nextCursor,
          total: result.items.length,
        },
      };

      res.status(200).json(response);
    } catch (err: unknown) {
      console.error('[VELTRIX] Query incidents error:', err);
      const errorResponse: ApiErrorResponse = {
        success: false,
        error: {
          code: 'STORAGE_QUERY_ERROR',
          message: 'Failed to query incidents',
        },
      };
      res.status(500).json(errorResponse);
    }
  });

  /**
   * GET /api/v1/incidents/:incidentId
   * Retrieves an incident by its unique ID.
   */
  router.get('/:incidentId', async (req: Request, res: Response) => {
    try {
      const orgId = req.tenantOrgId!;
      const incidentId = String(req.params.incidentId || '');

      const incident = await store.getIncidentById(orgId, incidentId);
      if (!incident || incident.orgId !== orgId) {
        const errorResponse: ApiErrorResponse = {
          success: false,
          error: {
            code: 'NOT_FOUND',
            message: `Incident '${incidentId}' not found`,
          },
        };
        res.status(404).json(errorResponse);
        return;
      }

      const response: ApiResponse<Incident> = {
        success: true,
        data: incident,
        meta: {
          timestamp: new Date().toISOString(),
        },
      };

      res.status(200).json(response);
    } catch (err: unknown) {
      console.error(`[VELTRIX] Error fetching incident ${req.params.incidentId}:`, err);
      const errorResponse: ApiErrorResponse = {
        success: false,
        error: {
          code: 'STORAGE_RETRIEVAL_ERROR',
          message: 'Failed to retrieve incident',
        },
      };
      res.status(500).json(errorResponse);
    }
  });

  /**
   * PATCH /api/v1/incidents/:incidentId
   * Updates an incident status, assignment, or notes.
   */
  router.patch(
    '/:incidentId',
    requireRole('SECURITY_ANALYST', 'ORG_ADMIN', 'SUPER_ADMIN'),
    async (req: Request, res: Response) => {
      try {
        const orgId = req.tenantOrgId!;
        const incidentId = String(req.params.incidentId || '');
        const { status, assignedTo, note } = req.body || {};

        const incident = await store.getIncidentById(orgId, incidentId);
        if (!incident || incident.orgId !== orgId) {
          const errorResponse: ApiErrorResponse = {
            success: false,
            error: {
              code: 'NOT_FOUND',
              message: `Incident '${incidentId}' not found`,
            },
          };
          res.status(404).json(errorResponse);
          return;
        }

        const updates: Partial<Incident> = {
          updatedAt: new Date().toISOString(),
        };

        if (status) {
          updates.status = status;
        }
        if (assignedTo !== undefined) {
          updates.assignedTo = assignedTo;
        }
        if (note && typeof note === 'string') {
          const newNote = {
            noteId: `${Date.now()}`,
            author: req.user?.username || 'analyst',
            content: note,
            timestamp: new Date().toISOString(),
          };
          updates.notes = [...(incident.notes || []), newNote];
        }

        const updated = await store.updateIncident(orgId, incidentId, updates);

        const response: ApiResponse<Incident | null> = {
          success: true,
          data: updated,
          meta: {
            timestamp: new Date().toISOString(),
          },
        };

        res.status(200).json(response);
      } catch (err: unknown) {
        console.error(`[VELTRIX] Error updating incident ${req.params.incidentId}:`, err);
        const errorResponse: ApiErrorResponse = {
          success: false,
          error: {
            code: 'STORAGE_UPDATE_ERROR',
            message: 'Failed to update incident',
          },
        };
        res.status(500).json(errorResponse);
      }
    }
  );

  return router;
}
