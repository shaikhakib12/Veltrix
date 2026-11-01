import { Router, Request, Response } from 'express';
import {
  type ApiResponse,
  type ApiErrorResponse,
  type DetectionRule,
  DetectionRuleUpdateSchema,
  DetectionRuleTestRequestSchema,
} from '@veltrix/shared';
import { authenticate } from '../middleware/auth.js';
import { enforceTenantIsolation } from '../middleware/tenant.js';
import { requireRole } from '../middleware/rbac.js';
import type { StorageInterface } from '../storage/storage-interface.js';
import { getStorage } from '../storage/index.js';
import { DetectionEngine } from '../detection/engine.js';

export function createDetectionRulesRouter(
  storage?: StorageInterface,
  engine?: DetectionEngine
): Router {
  const router = Router();
  const store = storage || getStorage();
  const detectionEngine = engine || new DetectionEngine(store);

  // Tenant Authentication & Isolation applied to all rule management endpoints
  router.use(authenticate);
  router.use(enforceTenantIsolation);

  /**
   * GET /api/v1/detection-rules
   * Lists all registered detection rules with tenant-specific configuration overrides merged.
   */
  router.get('/', async (req: Request, res: Response) => {
    try {
      const orgId = req.tenantOrgId!;
      const registeredRules = detectionEngine.getRegisteredRules();

      // Retrieve tenant-specific rule overrides from storage
      let tenantOverrides: DetectionRule[] = [];
      try {
        tenantOverrides = await store.getDetectionRules(orgId);
      } catch {
        tenantOverrides = [];
      }
      const overrideMap = new Map(tenantOverrides.map((r) => [r.ruleId, r]));

      const rules = registeredRules.map((rule) => {
        const override = overrideMap.get(rule.id);
        return {
          ruleId: rule.id,
          orgId,
          name: rule.name,
          description: rule.description,
          category: rule.category,
          severity: override?.severity || rule.defaultSeverity,
          mitreAttack: rule.mitreAttack,
          threshold: override?.threshold ?? rule.defaultThreshold,
          slidingWindowSeconds: override?.slidingWindowSeconds ?? rule.defaultSlidingWindowSeconds,
          isEnabled: override?.isEnabled ?? true,
          condition: override?.condition ?? {},
        };
      });

      const response: ApiResponse<{ rules: typeof rules }> = {
        success: true,
        data: { rules },
        meta: {
          timestamp: new Date().toISOString(),
        },
      };

      res.status(200).json(response);
    } catch (err: unknown) {
      console.error('[VELTRIX] Error listing detection rules:', err);
      const errorResponse: ApiErrorResponse = {
        success: false,
        error: {
          code: 'RULES_RETRIEVAL_ERROR',
          message: 'Failed to list detection rules',
        },
      };
      res.status(500).json(errorResponse);
    }
  });

  /**
   * PATCH /api/v1/detection-rules/:ruleId
   * Mutates a detection rule's threshold, sliding window, severity, or enabled status for this tenant.
   * Restricted to ORG_ADMIN or SUPER_ADMIN.
   */
  router.patch(
    '/:ruleId',
    requireRole('SUPER_ADMIN', 'ORG_ADMIN'),
    async (req: Request, res: Response) => {
      try {
        const orgId = req.tenantOrgId!;
        const ruleId = req.params.ruleId;

        if (!ruleId) {
          const errorResponse: ApiErrorResponse = {
            success: false,
            error: {
              code: 'INVALID_REQUEST',
              message: 'Rule ID parameter is required',
            },
          };
          res.status(400).json(errorResponse);
          return;
        }

        const baseRule = detectionEngine.getRule(ruleId);
        if (!baseRule) {
          const errorResponse: ApiErrorResponse = {
            success: false,
            error: {
              code: 'NOT_FOUND',
              message: `Detection rule '${ruleId}' is not registered in the system`,
            },
          };
          res.status(404).json(errorResponse);
          return;
        }

        const parseResult = DetectionRuleUpdateSchema.safeParse(req.body);
        if (!parseResult.success) {
          const errorResponse: ApiErrorResponse = {
            success: false,
            error: {
              code: 'VALIDATION_FAILED',
              message: 'Invalid detection rule update parameters',
              details: parseResult.error.errors.map((e) => ({
                field: e.path.join('.'),
                message: e.message,
              })),
            },
          };
          res.status(400).json(errorResponse);
          return;
        }

        const existingOverride = await store.getDetectionRuleById(orgId, ruleId);
        const updatedConfig: DetectionRule = {
          ruleId: baseRule.id,
          orgId,
          name: baseRule.name,
          description: baseRule.description,
          category: baseRule.category,
          severity: parseResult.data.severity || existingOverride?.severity || baseRule.defaultSeverity,
          mitreAttack: baseRule.mitreAttack,
          threshold: parseResult.data.threshold ?? existingOverride?.threshold ?? baseRule.defaultThreshold,
          slidingWindowSeconds:
            parseResult.data.slidingWindowSeconds ?? existingOverride?.slidingWindowSeconds ?? baseRule.defaultSlidingWindowSeconds,
          isEnabled: parseResult.data.isEnabled ?? existingOverride?.isEnabled ?? true,
          condition: parseResult.data.condition ?? existingOverride?.condition ?? {},
          createdAt: existingOverride?.createdAt || new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        };

        await store.saveDetectionRule(updatedConfig);

        const response: ApiResponse<DetectionRule> = {
          success: true,
          data: updatedConfig,
          meta: {
            timestamp: new Date().toISOString(),
          },
        };

        res.status(200).json(response);
      } catch (err: unknown) {
        console.error(`[VELTRIX] Error updating detection rule ${req.params.ruleId}:`, err);
        const errorResponse: ApiErrorResponse = {
          success: false,
          error: {
            code: 'RULE_UPDATE_ERROR',
            message: 'Failed to update detection rule configuration',
          },
        };
        res.status(500).json(errorResponse);
      }
    }
  );

  /**
   * POST /api/v1/detection-rules/test
   * Dry-runs a detection rule configuration against sample event payloads without persistent storage.
   * Restricted to authorized analysts and administrators.
   */
  router.post(
    '/test',
    requireRole('SUPER_ADMIN', 'ORG_ADMIN', 'SECURITY_ANALYST'),
    async (req: Request, res: Response) => {
      try {
        const orgId = req.tenantOrgId!;
        const parseResult = DetectionRuleTestRequestSchema.safeParse(req.body);
        if (!parseResult.success) {
          const errorResponse: ApiErrorResponse = {
            success: false,
            error: {
              code: 'VALIDATION_FAILED',
              message: 'Invalid detection rule test parameters',
              details: parseResult.error.errors.map((e) => ({
                field: e.path.join('.'),
                message: e.message,
              })),
            },
          };
          res.status(400).json(errorResponse);
          return;
        }

        const { ruleId, threshold, slidingWindowSeconds, sampleEvents } = parseResult.data;
        const baseRule = detectionEngine.getRule(ruleId);
        if (!baseRule) {
          const errorResponse: ApiErrorResponse = {
            success: false,
            error: {
              code: 'NOT_FOUND',
              message: `Detection rule '${ruleId}' is not registered in the system`,
            },
          };
          res.status(404).json(errorResponse);
          return;
        }

        // Normalize sample events to match SecurityEvent structure
        const normalizedSampleEvents = sampleEvents.map((rawEvent, idx) => ({
          eventId: `test-event-${idx + 1}`,
          orgId,
          category: rawEvent.category || baseRule.category,
          eventType: rawEvent.eventType,
          severity: rawEvent.severity || 'MEDIUM',
          timestamp: rawEvent.timestamp ? new Date(rawEvent.timestamp).toISOString() : new Date().toISOString(),
          sourceIp: rawEvent.sourceIp,
          username: rawEvent.username,
          sourceSystem: rawEvent.sourceSystem,
          metadata: rawEvent.metadata,
        }));

        const dryRunResult = await detectionEngine.dryRunRule(
          {
            ruleId,
            threshold: threshold ?? baseRule.defaultThreshold,
            slidingWindowSeconds: slidingWindowSeconds ?? baseRule.defaultSlidingWindowSeconds,
          },
          normalizedSampleEvents,
          orgId
        );

        const response: ApiResponse<typeof dryRunResult> = {
          success: true,
          data: dryRunResult,
          meta: {
            timestamp: new Date().toISOString(),
          },
        };

        res.status(200).json(response);
      } catch (err: unknown) {
        console.error('[VELTRIX] Detection rule test execution error:', err);
        const errorResponse: ApiErrorResponse = {
          success: false,
          error: {
            code: 'TEST_EXECUTION_ERROR',
            message: err instanceof Error ? err.message : 'Failed to test detection rule',
          },
        };
        res.status(500).json(errorResponse);
      }
    }
  );

  return router;
}
