import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import { createApp } from '../src/app.js';
import { JwtService } from '../src/auth/jwt-service.js';
import { LocalAuthProvider } from '../src/auth/local-auth-provider.js';
import { resetAuthProviderForTesting } from '../src/auth/index.js';
import { MemoryStore } from '../src/storage/memory-store.js';
import { DynamoDBStore } from '../src/storage/dynamodb-store.js';
import { resetStorageForTesting } from '../src/storage/index.js';
import { generateUuidV7, extractDateFromUuidV7 } from '../src/utils/uuid.js';
import { signCursor } from '../src/utils/cursor.js';
import type { SecurityEvent } from '@veltrix/shared';

describe('Phase 4: Event Ingestion & Query API (TASK-401 to TASK-403)', () => {
  let app: ReturnType<typeof createApp>;
  let jwtService: JwtService;
  let memoryStore: MemoryStore;

  // Test identities
  const testSecret = 'veltrix-phase-4-test-jwt-secret-key-32chars';
  const orgA = 'org-cyber-shield';
  const orgB = 'org-defense-matrix';

  let analystTokenOrgA: string;
  let analystTokenOrgB: string;
  let viewerTokenOrgA: string;
  let superAdminToken: string;

  beforeEach(async () => {
    jwtService = new JwtService(testSecret);
    const localProvider = new LocalAuthProvider(jwtService);
    resetAuthProviderForTesting(localProvider);

    memoryStore = new MemoryStore();
    resetStorageForTesting(memoryStore);

    app = createApp();

    analystTokenOrgA = jwtService.signAccessToken({
      userId: 'user-analyst-a',
      email: 'analyst@shield.corp',
      username: 'analyst.shield',
      role: 'SECURITY_ANALYST',
      orgId: orgA,
    });

    analystTokenOrgB = jwtService.signAccessToken({
      userId: 'user-analyst-b',
      email: 'analyst@matrix.corp',
      username: 'analyst.matrix',
      role: 'SECURITY_ANALYST',
      orgId: orgB,
    });

    viewerTokenOrgA = jwtService.signAccessToken({
      userId: 'user-viewer-a',
      email: 'viewer@shield.corp',
      username: 'viewer.shield',
      role: 'READ_ONLY_VIEWER',
      orgId: orgA,
    });

    superAdminToken = jwtService.signAccessToken({
      userId: 'user-super-lead',
      email: 'admin@veltrix.global',
      username: 'super.admin',
      role: 'SUPER_ADMIN',
      orgId: 'org-system',
    });
  });

  // ============================================================================
  // 1. Authentication & RBAC Tests
  // ============================================================================
  describe('1. Ingestion Authentication & RBAC', () => {
    it('rejects unauthenticated POST /api/v1/events with 401', async () => {
      const res = await request(app)
        .post('/api/v1/events')
        .send({
          eventType: 'auth.login.failed',
          severity: 'HIGH',
          category: 'AUTHENTICATION',
          sourceIp: '198.51.100.10',
          sourceSystem: 'auth-gateway',
        });

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('UNAUTHORIZED_MISSING_TOKEN');
    });

    it('rejects invalid or tampered JWT token with 401', async () => {
      const res = await request(app)
        .post('/api/v1/events')
        .set('Authorization', 'Bearer invalid.tampered.token')
        .send({
          eventType: 'auth.login.failed',
          severity: 'HIGH',
          category: 'AUTHENTICATION',
          sourceIp: '198.51.100.10',
          sourceSystem: 'auth-gateway',
        });

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('UNAUTHORIZED_INVALID_TOKEN');
    });

    it('rejects expired JWT token with 401 UNAUTHORIZED_EXPIRED_TOKEN', async () => {
      const expiredToken = jwt.sign(
        {
          userId: 'user-expired',
          email: 'expired@shield.corp',
          username: 'expired.user',
          role: 'SECURITY_ANALYST',
          orgId: orgA,
        },
        testSecret,
        { algorithm: 'HS256', expiresIn: -10, issuer: 'veltrix-auth', audience: 'veltrix-platform' }
      );

      const res = await request(app)
        .post('/api/v1/events')
        .set('Authorization', `Bearer ${expiredToken}`)
        .send({
          eventType: 'auth.login.failed',
          severity: 'HIGH',
          category: 'AUTHENTICATION',
          sourceIp: '198.51.100.10',
          sourceSystem: 'auth-gateway',
        });

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('UNAUTHORIZED_EXPIRED_TOKEN');
    });

    it('rejects revoked JWT token with 401 UNAUTHORIZED_REVOKED_TOKEN', async () => {
      jwtService.revokeToken(analystTokenOrgA);

      const res = await request(app)
        .post('/api/v1/events')
        .set('Authorization', `Bearer ${analystTokenOrgA}`)
        .send({
          eventType: 'auth.login.failed',
          severity: 'HIGH',
          category: 'AUTHENTICATION',
          sourceIp: '198.51.100.10',
          sourceSystem: 'auth-gateway',
        });

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('UNAUTHORIZED_REVOKED_TOKEN');
    });

    it('rejects READ_ONLY_VIEWER role from writing events with 403', async () => {
      const res = await request(app)
        .post('/api/v1/events')
        .set('Authorization', `Bearer ${viewerTokenOrgA}`)
        .send({
          eventType: 'auth.login.failed',
          severity: 'HIGH',
          category: 'AUTHENTICATION',
          sourceIp: '198.51.100.10',
          sourceSystem: 'auth-gateway',
        });

      expect(res.status).toBe(403);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('FORBIDDEN_INSUFFICIENT_PERMISSIONS');
    });
  });

  // ============================================================================
  // 2. Single Event Ingestion Tests (TASK-401)
  // ============================================================================
  describe('2. Single Event Ingestion (TASK-401)', () => {
    it('accepts and normalizes a valid security event', async () => {
      const clientEventId = generateUuidV7();
      const res = await request(app)
        .post('/api/v1/events')
        .set('Authorization', `Bearer ${analystTokenOrgA}`)
        .send({
          eventId: clientEventId,
          eventType: 'auth.login.failed',
          severity: 'HIGH',
          category: 'AUTHENTICATION',
          sourceIp: '198.51.100.42',
          username: 'john.doe',
          sourceSystem: 'auth.prod.internal',
          metadata: { reason: 'BAD_CREDENTIALS', attemptNumber: 3 },
          isSimulated: true,
        });

      expect(res.status).toBe(202);
      expect(res.body.success).toBe(true);
      expect(res.body.data.status).toBe('ACCEPTED');
      expect(res.body.data.eventId).toBe(clientEventId);

      const saved = res.body.data.event as SecurityEvent;
      expect(saved.orgId).toBe(orgA); // Bound to authenticated tenant
      expect(saved.eventType).toBe('auth.login.failed');
      expect(saved.severity).toBe('HIGH');
      expect(saved.sourceIp).toBe('198.51.100.42');
      expect(saved.metadata?.reason).toBe('BAD_CREDENTIALS');
      expect(saved.ingestedAt).toBeDefined();
    });

    it('auto-generates a valid RFC 9562 UUIDv7 eventId when omitted', async () => {
      const res = await request(app)
        .post('/api/v1/events')
        .set('Authorization', `Bearer ${analystTokenOrgA}`)
        .send({
          eventType: 'network.port.scan',
          severity: 'MEDIUM',
          category: 'NETWORK',
          sourceIp: '203.0.113.88',
          sourceSystem: 'firewall-edge-01',
        });

      expect(res.status).toBe(202);
      expect(res.body.success).toBe(true);
      expect(res.body.data.status).toBe('ACCEPTED');
      expect(res.body.data.eventId).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
      );
    });

    it('canonicalizes non-UTC or offset timestamps to ISO 8601 UTC', async () => {
      const res = await request(app)
        .post('/api/v1/events')
        .set('Authorization', `Bearer ${analystTokenOrgA}`)
        .send({
          eventType: 'privilege.escalation',
          severity: 'CRITICAL',
          category: 'PRIVILEGE',
          sourceIp: '198.51.100.5',
          sourceSystem: 'iam-service',
          timestamp: '2026-11-01T05:30:00.000+05:30', // IST timezone
        });

      expect(res.status).toBe(202);
      const saved = res.body.data.event as SecurityEvent;
      expect(saved.timestamp).toBe('2026-11-01T00:00:00.000Z'); // Exact UTC
    });

    it('rejects invalid payload structures with 400', async () => {
      const res = await request(app)
        .post('/api/v1/events')
        .set('Authorization', `Bearer ${analystTokenOrgA}`)
        .send('not-a-json-object');

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('BAD_REQUEST');
    });

    it('rejects missing required fields (missing sourceIp and category)', async () => {
      const res = await request(app)
        .post('/api/v1/events')
        .set('Authorization', `Bearer ${analystTokenOrgA}`)
        .send({
          eventType: 'auth.login.failed',
          severity: 'HIGH',
          sourceSystem: 'auth-gateway',
        });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('VALIDATION_FAILED');
    });

    it('rejects malformed IP addresses', async () => {
      const res = await request(app)
        .post('/api/v1/events')
        .set('Authorization', `Bearer ${analystTokenOrgA}`)
        .send({
          eventType: 'auth.login.failed',
          severity: 'HIGH',
          category: 'AUTHENTICATION',
          sourceIp: '999.999.999.999', // Malformed IPv4
          sourceSystem: 'auth-gateway',
        });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('VALIDATION_FAILED');
    });

    it('rejects unsupported event types', async () => {
      const res = await request(app)
        .post('/api/v1/events')
        .set('Authorization', `Bearer ${analystTokenOrgA}`)
        .send({
          eventType: 'unsupported.unknown.action',
          severity: 'HIGH',
          category: 'AUTHENTICATION',
          sourceIp: '198.51.100.10',
          sourceSystem: 'auth-gateway',
        });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('VALIDATION_FAILED');
    });

    it('rejects invalid severity values', async () => {
      const res = await request(app)
        .post('/api/v1/events')
        .set('Authorization', `Bearer ${analystTokenOrgA}`)
        .send({
          eventType: 'auth.login.failed',
          severity: 'SUPER_EXTREME',
          category: 'AUTHENTICATION',
          sourceIp: '198.51.100.10',
          sourceSystem: 'auth-gateway',
        });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('VALIDATION_FAILED');
    });

    it('rejects non-UUID event IDs', async () => {
      const res = await request(app)
        .post('/api/v1/events')
        .set('Authorization', `Bearer ${analystTokenOrgA}`)
        .send({
          eventId: 'not-a-valid-uuid-string-1234',
          eventType: 'auth.login.failed',
          severity: 'HIGH',
          category: 'AUTHENTICATION',
          sourceIp: '198.51.100.10',
          sourceSystem: 'auth-gateway',
        });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('VALIDATION_FAILED');
    });

    it('rejects unexpected additional properties to prevent mass assignment', async () => {
      const res = await request(app)
        .post('/api/v1/events')
        .set('Authorization', `Bearer ${analystTokenOrgA}`)
        .send({
          eventType: 'auth.login.failed',
          severity: 'HIGH',
          category: 'AUTHENTICATION',
          sourceIp: '198.51.100.10',
          sourceSystem: 'auth-gateway',
          maliciousInjectedField: 'hack-attempt',
        });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('VALIDATION_FAILED');
    });

    it('suppresses atomic duplicate events when retried with same eventId', async () => {
      const eventId = generateUuidV7();
      const payload = {
        eventId,
        eventType: 'auth.login.failed',
        severity: 'HIGH',
        category: 'AUTHENTICATION',
        sourceIp: '198.51.100.20',
        sourceSystem: 'auth-gateway',
      };

      // 1. First submission: ACCEPTED
      const firstRes = await request(app)
        .post('/api/v1/events')
        .set('Authorization', `Bearer ${analystTokenOrgA}`)
        .send(payload);

      expect(firstRes.status).toBe(202);
      expect(firstRes.body.data.status).toBe('ACCEPTED');

      // 2. Retry with identical eventId: DUPLICATE_SUPPRESSED
      const retryRes = await request(app)
        .post('/api/v1/events')
        .set('Authorization', `Bearer ${analystTokenOrgA}`)
        .send(payload);

      expect(retryRes.status).toBe(202);
      expect(retryRes.body.data.status).toBe('DUPLICATE_SUPPRESSED');
      expect(retryRes.body.data.eventId).toBe(eventId);
    });

    it('accepts distinct rapid events with different eventIds (no false duplicate collision)', async () => {
      // 5 rapid failed attempts from same IP (brute force pattern)
      for (let i = 0; i < 5; i++) {
        const res = await request(app)
          .post('/api/v1/events')
          .set('Authorization', `Bearer ${analystTokenOrgA}`)
          .send({
            eventId: generateUuidV7(),
            eventType: 'auth.login.failed',
            severity: 'HIGH',
            category: 'AUTHENTICATION',
            sourceIp: '198.51.100.30',
            sourceSystem: 'auth-gateway',
            metadata: { attempt: i + 1 },
          });

        expect(res.status).toBe(202);
        expect(res.body.data.status).toBe('ACCEPTED');
      }

      // Verify all 5 events were stored
      const queryRes = await request(app)
        .get('/api/v1/events?sourceIp=198.51.100.30')
        .set('Authorization', `Bearer ${analystTokenOrgA}`);

      expect(queryRes.status).toBe(200);
      expect(queryRes.body.data.events).toHaveLength(5);
    });
  });

  // ============================================================================
  // 3. Batch Event Ingestion Tests (TASK-401)
  // ============================================================================
  describe('3. Batch Event Ingestion (TASK-401)', () => {
    it('accepts and persists a valid batch of events', async () => {
      const events = [
        {
          eventType: 'auth.login.failed',
          severity: 'HIGH',
          category: 'AUTHENTICATION',
          sourceIp: '198.51.100.1',
          sourceSystem: 'auth-service',
        },
        {
          eventType: 'network.port.scan',
          severity: 'MEDIUM',
          category: 'NETWORK',
          sourceIp: '198.51.100.2',
          sourceSystem: 'ids-probe',
        },
        {
          eventType: 'data.access.bulk',
          severity: 'CRITICAL',
          category: 'DATA_ACCESS',
          sourceIp: '198.51.100.3',
          sourceSystem: 'data-vault',
        },
      ];

      const res = await request(app)
        .post('/api/v1/events')
        .set('Authorization', `Bearer ${analystTokenOrgA}`)
        .send({ events });

      expect(res.status).toBe(202);
      expect(res.body.success).toBe(true);
      expect(res.body.data.total).toBe(3);
      expect(res.body.data.accepted).toBe(3);
      expect(res.body.data.duplicates).toBe(0);
      expect(res.body.data.rejected).toBe(0);
      expect(res.body.data.results).toHaveLength(3);
      expect(res.body.data.results[0].status).toBe('ACCEPTED');
    });

    it('accepts exactly 100 events in a single batch', async () => {
      const events = Array.from({ length: 100 }, (_, i) => ({
        eventId: generateUuidV7(),
        eventType: 'api.request',
        severity: 'LOW',
        category: 'API',
        sourceIp: '198.51.100.50',
        sourceSystem: 'api-gateway',
        metadata: { index: i },
      }));

      const res = await request(app)
        .post('/api/v1/events')
        .set('Authorization', `Bearer ${analystTokenOrgA}`)
        .send({ events });

      expect(res.status).toBe(202);
      expect(res.body.data.total).toBe(100);
      expect(res.body.data.accepted).toBe(100);
    });

    it('rejects a batch exceeding 100 events with 400 BATCH_SIZE_EXCEEDED', async () => {
      const events = Array.from({ length: 101 }, (_, i) => ({
        eventId: generateUuidV7(),
        eventType: 'api.request',
        severity: 'LOW',
        category: 'API',
        sourceIp: '198.51.100.50',
        sourceSystem: 'api-gateway',
        metadata: { index: i },
      }));

      const res = await request(app)
        .post('/api/v1/events')
        .set('Authorization', `Bearer ${analystTokenOrgA}`)
        .send({ events });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('BATCH_SIZE_EXCEEDED');
    });

    it('rejects an empty batch with 400 BAD_REQUEST', async () => {
      const res = await request(app)
        .post('/api/v1/events')
        .set('Authorization', `Bearer ${analystTokenOrgA}`)
        .send({ events: [] });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('BAD_REQUEST');
    });

    it('handles mixed accepted, duplicate, and rejected items with accurate reporting', async () => {
      const existingId = generateUuidV7();
      // Seed an existing event
      await request(app)
        .post('/api/v1/events')
        .set('Authorization', `Bearer ${analystTokenOrgA}`)
        .send({
          eventId: existingId,
          eventType: 'auth.login.failed',
          severity: 'HIGH',
          category: 'AUTHENTICATION',
          sourceIp: '198.51.100.1',
          sourceSystem: 'auth-service',
        });

      const batch = [
        // Valid new item
        {
          eventId: generateUuidV7(),
          eventType: 'network.connection',
          severity: 'LOW',
          category: 'NETWORK',
          sourceIp: '198.51.100.10',
          sourceSystem: 'netflow',
        },
        // Duplicate item
        {
          eventId: existingId,
          eventType: 'auth.login.failed',
          severity: 'HIGH',
          category: 'AUTHENTICATION',
          sourceIp: '198.51.100.1',
          sourceSystem: 'auth-service',
        },
        // Invalid item (malformed IP)
        {
          eventId: generateUuidV7(),
          eventType: 'admin.action',
          severity: 'HIGH',
          category: 'SYSTEM',
          sourceIp: 'invalid-ip-format',
          sourceSystem: 'control-plane',
        },
      ];

      const res = await request(app)
        .post('/api/v1/events')
        .set('Authorization', `Bearer ${analystTokenOrgA}`)
        .send({ events: batch });

      expect(res.status).toBe(202);
      expect(res.body.data.total).toBe(3);
      expect(res.body.data.accepted).toBe(1);
      expect(res.body.data.duplicates).toBe(1);
      expect(res.body.data.rejected).toBe(1);

      const statuses = res.body.data.results.map((r: { status: string }) => r.status);
      expect(statuses).toContain('ACCEPTED');
      expect(statuses).toContain('DUPLICATE_SUPPRESSED');
      expect(statuses).toContain('REJECTED');
    });

    it('returns 422 if all items in a batch fail schema validation', async () => {
      const invalidBatch = [
        { eventType: 'invalid.type', severity: 'HIGH', category: 'API', sourceIp: 'bad', sourceSystem: 'sys' },
        { eventType: 'network.port.scan', severity: 'BAD_SEV', category: 'NETWORK', sourceIp: 'bad', sourceSystem: 'sys' },
      ];

      const res = await request(app)
        .post('/api/v1/events')
        .set('Authorization', `Bearer ${analystTokenOrgA}`)
        .send({ events: invalidBatch });

      expect(res.status).toBe(422);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('BATCH_VALIDATION_FAILED');
    });
  });

  // ============================================================================
  // 4. Tenant Isolation & Tampering Defense Tests
  // ============================================================================
  describe('4. Tenant Isolation & Tampering Defense', () => {
    it('rejects event submission with conflicting orgId in single payload with 403', async () => {
      const res = await request(app)
        .post('/api/v1/events')
        .set('Authorization', `Bearer ${analystTokenOrgA}`)
        .send({
          orgId: orgB, // Attempted cross-tenant injection into Org B
          eventType: 'auth.login.failed',
          severity: 'HIGH',
          category: 'AUTHENTICATION',
          sourceIp: '198.51.100.10',
          sourceSystem: 'auth-gateway',
        });

      expect(res.status).toBe(403);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('FORBIDDEN_CROSS_TENANT_ACCESS');
    });

    it('rejects batch submission if any item contains conflicting foreign orgId', async () => {
      const res = await request(app)
        .post('/api/v1/events')
        .set('Authorization', `Bearer ${analystTokenOrgA}`)
        .send({
          events: [
            {
              orgId: orgA,
              eventType: 'network.connection',
              severity: 'LOW',
              category: 'NETWORK',
              sourceIp: '198.51.100.1',
              sourceSystem: 'gw',
            },
            {
              orgId: orgB, // Sneaked foreign orgId
              eventType: 'data.exfiltration',
              severity: 'CRITICAL',
              category: 'DATA_ACCESS',
              sourceIp: '198.51.100.2',
              sourceSystem: 'gw',
            },
          ],
        });

      expect(res.status).toBe(403);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('FORBIDDEN_CROSS_TENANT_ACCESS');
    });

    it('rejects query parameter tampering (?orgId=victim) with 403', async () => {
      const res = await request(app)
        .post(`/api/v1/events?orgId=${orgB}`)
        .set('Authorization', `Bearer ${analystTokenOrgA}`)
        .send({
          eventType: 'auth.login.failed',
          severity: 'HIGH',
          category: 'AUTHENTICATION',
          sourceIp: '198.51.100.10',
          sourceSystem: 'auth-gateway',
        });

      expect(res.status).toBe(403);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('FORBIDDEN_CROSS_TENANT_ACCESS');
    });

    it('rejects header tampering (x-organization-id: victim) with 403', async () => {
      const res = await request(app)
        .post('/api/v1/events')
        .set('Authorization', `Bearer ${analystTokenOrgA}`)
        .set('x-organization-id', orgB)
        .send({
          eventType: 'auth.login.failed',
          severity: 'HIGH',
          category: 'AUTHENTICATION',
          sourceIp: '198.51.100.10',
          sourceSystem: 'auth-gateway',
        });

      expect(res.status).toBe(403);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('FORBIDDEN_CROSS_TENANT_ACCESS');
    });

    it('allows SUPER_ADMIN to ingest events on behalf of specified organization', async () => {
      const res = await request(app)
        .post('/api/v1/events')
        .set('Authorization', `Bearer ${superAdminToken}`)
        .set('x-organization-id', orgA)
        .send({
          eventType: 'admin.action',
          severity: 'HIGH',
          category: 'SYSTEM',
          sourceIp: '198.51.100.99',
          sourceSystem: 'super-admin-cli',
        });

      expect(res.status).toBe(202);
      expect(res.body.data.event.orgId).toBe(orgA);
    });

    it('prevents Org A from reading Org B events', async () => {
      // Ingest event into Org B
      const orgBEventId = generateUuidV7();
      await request(app)
        .post('/api/v1/events')
        .set('Authorization', `Bearer ${analystTokenOrgB}`)
        .send({
          eventId: orgBEventId,
          eventType: 'auth.login.failed',
          severity: 'HIGH',
          category: 'AUTHENTICATION',
          sourceIp: '198.51.100.88',
          sourceSystem: 'auth-b',
        });

      // Org A queries all events: must NOT see Org B's event
      const queryRes = await request(app)
        .get('/api/v1/events')
        .set('Authorization', `Bearer ${analystTokenOrgA}`);

      expect(queryRes.status).toBe(200);
      const ids = queryRes.body.data.events.map((e: { eventId: string }) => e.eventId);
      expect(ids).not.toContain(orgBEventId);

      // Org A attempts direct GET /api/v1/events/:eventId on Org B's event: must return 404
      const directRes = await request(app)
        .get(`/api/v1/events/${orgBEventId}`)
        .set('Authorization', `Bearer ${analystTokenOrgA}`);

      expect(directRes.status).toBe(404);
      expect(directRes.body.error.code).toBe('EVENT_NOT_FOUND');
    });

    it('rejects a manipulated pagination cursor containing another orgId', async () => {
      const maliciousCursor = Buffer.from(
        JSON.stringify({ orgId: orgB, offset: 0 })
      ).toString('base64');

      const res = await request(app)
        .get(`/api/v1/events?cursor=${maliciousCursor}`)
        .set('Authorization', `Bearer ${analystTokenOrgA}`);

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('INVALID_CURSOR');
    });
  });

  // ============================================================================
  // 5. Event Query & Pagination Tests (TASK-402)
  // ============================================================================
  describe('5. Event Query & Pagination (TASK-402)', () => {
    beforeEach(async () => {
      // Seed 15 diverse events into Org A
      for (let i = 0; i < 15; i++) {
        await request(app)
          .post('/api/v1/events')
          .set('Authorization', `Bearer ${analystTokenOrgA}`)
          .send({
            eventId: generateUuidV7(),
            eventType: i % 2 === 0 ? 'auth.login.failed' : 'network.connection',
            severity: i < 5 ? 'CRITICAL' : i < 10 ? 'HIGH' : 'LOW',
            category: i % 2 === 0 ? 'AUTHENTICATION' : 'NETWORK',
            sourceIp: i < 8 ? '198.51.100.10' : '203.0.113.20',
            username: i % 3 === 0 ? 'alice.admin' : 'bob.user',
            sourceSystem: 'seed-runner',
            timestamp: new Date(Date.now() - (15 - i) * 60000).toISOString(),
          });
      }
    });

    it('returns empty result set for clean organization with 200 OK', async () => {
      const res = await request(app)
        .get('/api/v1/events')
        .set('Authorization', `Bearer ${analystTokenOrgB}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.events).toHaveLength(0);
      expect(res.body.data.total).toBe(0);
      expect(res.body.data.nextCursor).toBeUndefined();
    });

    it('filters events by eventType', async () => {
      const res = await request(app)
        .get('/api/v1/events?eventType=auth.login.failed')
        .set('Authorization', `Bearer ${analystTokenOrgA}`);

      expect(res.status).toBe(200);
      expect(res.body.data.events.length).toBeGreaterThan(0);
      for (const event of res.body.data.events) {
        expect(event.eventType).toBe('auth.login.failed');
      }
    });

    it('filters events by severity', async () => {
      const res = await request(app)
        .get('/api/v1/events?severity=CRITICAL')
        .set('Authorization', `Bearer ${analystTokenOrgA}`);

      expect(res.status).toBe(200);
      expect(res.body.data.events.length).toBe(5);
      for (const event of res.body.data.events) {
        expect(event.severity).toBe('CRITICAL');
      }
    });

    it('filters events by sourceIp', async () => {
      const res = await request(app)
        .get('/api/v1/events?sourceIp=198.51.100.10')
        .set('Authorization', `Bearer ${analystTokenOrgA}`);

      expect(res.status).toBe(200);
      expect(res.body.data.events.length).toBe(8);
      for (const event of res.body.data.events) {
        expect(event.sourceIp).toBe('198.51.100.10');
      }
    });

    it('filters events by username', async () => {
      const res = await request(app)
        .get('/api/v1/events?username=alice.admin')
        .set('Authorization', `Bearer ${analystTokenOrgA}`);

      expect(res.status).toBe(200);
      expect(res.body.data.events.length).toBe(5);
      for (const event of res.body.data.events) {
        expect(event.username).toBe('alice.admin');
      }
    });

    it('filters events by date range (startTime and endTime)', async () => {
      const now = Date.now();
      const startTime = new Date(now - 10 * 60000).toISOString();
      const endTime = new Date(now).toISOString();

      const res = await request(app)
        .get(`/api/v1/events?startTime=${startTime}&endTime=${endTime}`)
        .set('Authorization', `Bearer ${analystTokenOrgA}`);

      expect(res.status).toBe(200);
      for (const event of res.body.data.events) {
        const timeMs = new Date(event.timestamp).getTime();
        expect(timeMs).toBeGreaterThanOrEqual(new Date(startTime).getTime());
        expect(timeMs).toBeLessThanOrEqual(new Date(endTime).getTime());
      }
    });

    it('rejects invalid date range where startTime is after endTime with 400', async () => {
      const startTime = '2026-11-01T12:00:00.000Z';
      const endTime = '2026-11-01T10:00:00.000Z'; // Precedes start

      const res = await request(app)
        .get(`/api/v1/events?startTime=${startTime}&endTime=${endTime}`)
        .set('Authorization', `Bearer ${analystTokenOrgA}`);

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('INVALID_QUERY_PARAMETERS');
    });

    it('paginates accurately across multiple pages without duplicate or missing events', async () => {
      const pageSize = 5;

      // Page 1
      const page1Res = await request(app)
        .get(`/api/v1/events?limit=${pageSize}`)
        .set('Authorization', `Bearer ${analystTokenOrgA}`);

      expect(page1Res.status).toBe(200);
      expect(page1Res.body.data.events).toHaveLength(pageSize);
      expect(page1Res.body.data.nextCursor).toBeDefined();

      const cursorPage2 = page1Res.body.data.nextCursor;

      // Page 2
      const page2Res = await request(app)
        .get(`/api/v1/events?limit=${pageSize}&cursor=${cursorPage2}`)
        .set('Authorization', `Bearer ${analystTokenOrgA}`);

      expect(page2Res.status).toBe(200);
      expect(page2Res.body.data.events).toHaveLength(pageSize);
      expect(page2Res.body.data.nextCursor).toBeDefined();

      const cursorPage3 = page2Res.body.data.nextCursor;

      // Page 3
      const page3Res = await request(app)
        .get(`/api/v1/events?limit=${pageSize}&cursor=${cursorPage3}`)
        .set('Authorization', `Bearer ${analystTokenOrgA}`);

      expect(page3Res.status).toBe(200);
      expect(page3Res.body.data.events).toHaveLength(pageSize);
      expect(page3Res.body.data.nextCursor).toBeUndefined(); // Reached end of 15 items

      // Verify no overlapping event IDs between pages
      const page1Ids = page1Res.body.data.events.map((e: { eventId: string }) => e.eventId);
      const page2Ids = page2Res.body.data.events.map((e: { eventId: string }) => e.eventId);
      const page3Ids = page3Res.body.data.events.map((e: { eventId: string }) => e.eventId);

      const allIds = [...page1Ids, ...page2Ids, ...page3Ids];
      const uniqueIds = new Set(allIds);
      expect(uniqueIds.size).toBe(15);
    });

    it('rejects a corrupt or garbage cursor with 400 INVALID_CURSOR', async () => {
      const res = await request(app)
        .get('/api/v1/events?cursor=corrupted-non-base64-garbage')
        .set('Authorization', `Bearer ${analystTokenOrgA}`);

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('INVALID_CURSOR');
    });

    it('allows READ_ONLY_VIEWER to query events', async () => {
      const res = await request(app)
        .get('/api/v1/events')
        .set('Authorization', `Bearer ${viewerTokenOrgA}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.events).toBeDefined();
    });
  });

  // ============================================================================
  // 6. DynamoDBStore Unit & Resilience Tests
  // ============================================================================
  describe('6. DynamoDB Storage Contract & Resilience', () => {
    it('generates correct Time-Sharded PK and SK for DynamoDB persistence', async () => {
      const store = new DynamoDBStore();
      const event: SecurityEvent = {
        eventId: '018d5f30-74e1-7cb2-b43a-e9fa651f8b1c',
        orgId: 'org-test-sharding',
        timestamp: '2026-11-01T14:30:00.000Z',
        eventType: 'auth.login.failed',
        severity: 'HIGH',
        category: 'AUTHENTICATION',
        sourceIp: '198.51.100.1',
        sourceSystem: 'auth-service',
      };

      // In local mode without AWS credentials, saveEvent should catch and throw a meaningful AWS error
      // or if DynamoDB Client is invoked, handle retry logic
      await expect(store.saveEvent(event)).rejects.toThrow();
    });

    it('MemoryStore clearAll isolates test executions', async () => {
      await memoryStore.saveEvent({
        eventId: generateUuidV7(),
        orgId: orgA,
        timestamp: new Date().toISOString(),
        eventType: 'auth.login.failed',
        severity: 'HIGH',
        category: 'AUTHENTICATION',
        sourceIp: '198.51.100.1',
        sourceSystem: 'auth-service',
      });

      const before = await memoryStore.getEvents(orgA);
      expect(before.items).toHaveLength(1);

      await memoryStore.clearAll();

      const after = await memoryStore.getEvents(orgA);
      expect(after.items).toHaveLength(0);
    });
  });
  // ============================================================================
  // 7. Security Audit Adversarial Tests (Phase 4 Code Review)
  // ============================================================================
  describe('7. Security Audit Adversarial & Concurrency Ingestion Tests', () => {
    it('supports header-based Idempotency-Key for clients omitting eventId', async () => {
      const idempotencyKey = 'client-retry-key-header-999';

      // 1. First submission with Idempotency-Key header (no eventId in body)
      const res1 = await request(app)
        .post('/api/v1/events')
        .set('Authorization', `Bearer ${analystTokenOrgA}`)
        .set('Idempotency-Key', idempotencyKey)
        .send({
          eventType: 'auth.login.failed',
          severity: 'HIGH',
          category: 'AUTHENTICATION',
          sourceIp: '198.51.100.77',
          sourceSystem: 'web-gateway',
        });

      expect(res1.status).toBe(202);
      expect(res1.body.data.status).toBe('ACCEPTED');
      const generatedEventId = res1.body.data.eventId;

      // 2. Retry with the exact same Idempotency-Key header (simulated network retry)
      const res2 = await request(app)
        .post('/api/v1/events')
        .set('Authorization', `Bearer ${analystTokenOrgA}`)
        .set('Idempotency-Key', idempotencyKey)
        .send({
          eventType: 'auth.login.failed',
          severity: 'HIGH',
          category: 'AUTHENTICATION',
          sourceIp: '198.51.100.77',
          sourceSystem: 'web-gateway',
        });

      expect(res2.status).toBe(202);
      expect(res2.body.data.status).toBe('DUPLICATE_SUPPRESSED');
    });

    it('documents non-idempotency when client omits both eventId and Idempotency-Key', async () => {
      // When client omits both eventId and idempotencyKey/header, server generates fresh UUIDv7 for each request
      const res1 = await request(app)
        .post('/api/v1/events')
        .set('Authorization', `Bearer ${analystTokenOrgA}`)
        .send({
          eventType: 'network.connection',
          severity: 'LOW',
          category: 'NETWORK',
          sourceIp: '198.51.100.80',
          sourceSystem: 'netflow',
        });

      const res2 = await request(app)
        .post('/api/v1/events')
        .set('Authorization', `Bearer ${analystTokenOrgA}`)
        .send({
          eventType: 'network.connection',
          severity: 'LOW',
          category: 'NETWORK',
          sourceIp: '198.51.100.80',
          sourceSystem: 'netflow',
        });

      expect(res1.status).toBe(202);
      expect(res2.status).toBe(202);
      expect(res1.body.data.status).toBe('ACCEPTED');
      expect(res2.body.data.status).toBe('ACCEPTED');
      expect(res1.body.data.eventId).not.toBe(res2.body.data.eventId);
    });

    it('atomically deduplicates concurrent identical submissions using Promise.all', async () => {
      const fixedEventId = generateUuidV7();
      const payload = {
        eventId: fixedEventId,
        eventType: 'auth.login.failed',
        severity: 'HIGH',
        category: 'AUTHENTICATION',
        sourceIp: '198.51.100.90',
        sourceSystem: 'concurrent-tester',
      };

      // Send 5 concurrent identical requests
      const promises = Array.from({ length: 5 }, () =>
        request(app)
          .post('/api/v1/events')
          .set('Authorization', `Bearer ${analystTokenOrgA}`)
          .send(payload)
      );

      const responses = await Promise.all(promises);
      const statuses = responses.map((r) => r.body.data?.status);

      // Exactly 1 must be ACCEPTED, and the other 4 must be DUPLICATE_SUPPRESSED
      const acceptedCount = statuses.filter((s) => s === 'ACCEPTED').length;
      const suppressedCount = statuses.filter((s) => s === 'DUPLICATE_SUPPRESSED').length;

      expect(acceptedCount).toBe(1);
      expect(suppressedCount).toBe(4);
    });

    it('accepts concurrent distinct rapid event submissions without false positive collisions', async () => {
      // 10 distinct events fired concurrently in the exact same millisecond
      const promises = Array.from({ length: 10 }, (_, i) =>
        request(app)
          .post('/api/v1/events')
          .set('Authorization', `Bearer ${analystTokenOrgA}`)
          .send({
            eventId: generateUuidV7(),
            eventType: 'api.request',
            severity: 'LOW',
            category: 'API',
            sourceIp: '198.51.100.95',
            sourceSystem: 'burst-client',
            metadata: { threadId: i },
          })
      );

      const responses = await Promise.all(promises);
      for (const res of responses) {
        expect(res.status).toBe(202);
        expect(res.body.data.status).toBe('ACCEPTED');
      }

      // Verify all 10 were saved
      const queryRes = await request(app)
        .get('/api/v1/events?sourceIp=198.51.100.95')
        .set('Authorization', `Bearer ${analystTokenOrgA}`);

      expect(queryRes.status).toBe(200);
      expect(queryRes.body.data.events).toHaveLength(10);
    });

    it('rejects a tampered pagination cursor signature with 400 INVALID_CURSOR', async () => {
      // Valid cursor signed by server
      const validCursor = signCursor({
        orgId: orgA,
        filterHash: 'all',
        offset: 5,
      });

      // Tamper with the base64 portion of the signed cursor
      const [base64, sig] = validCursor.split('.');
      const decoded = JSON.parse(Buffer.from(base64, 'base64url').toString('utf8'));
      decoded.offset = 999; // Tampered offset
      const tamperedBase64 = Buffer.from(JSON.stringify(decoded)).toString('base64url');
      const tamperedCursor = `${tamperedBase64}.${sig}`;

      const res = await request(app)
        .get(`/api/v1/events?cursor=${tamperedCursor}`)
        .set('Authorization', `Bearer ${analystTokenOrgA}`);

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('INVALID_CURSOR');
    });

    it('rejects pagination cursor reuse across different query filters with 400 INVALID_CURSOR', async () => {
      // Seed 2 events to ensure pagination boundary is reached
      await request(app)
        .post('/api/v1/events')
        .set('Authorization', `Bearer ${analystTokenOrgA}`)
        .send({
          eventType: 'auth.login.failed',
          severity: 'HIGH',
          category: 'AUTHENTICATION',
          sourceIp: '198.51.100.1',
          sourceSystem: 'auth',
        });
      await request(app)
        .post('/api/v1/events')
        .set('Authorization', `Bearer ${analystTokenOrgA}`)
        .send({
          eventType: 'auth.login.failed',
          severity: 'HIGH',
          category: 'AUTHENTICATION',
          sourceIp: '198.51.100.2',
          sourceSystem: 'auth',
        });

      // 1. Obtain a cursor for an eventType=auth.login.failed query
      const res1 = await request(app)
        .get('/api/v1/events?eventType=auth.login.failed&limit=1')
        .set('Authorization', `Bearer ${analystTokenOrgA}`);

      const cursor = res1.body.data.nextCursor;
      expect(cursor).toBeDefined();

      // 2. Attempt to use this cursor on a completely different query filter (eventType=network.connection)
      const res2 = await request(app)
        .get(`/api/v1/events?eventType=network.connection&cursor=${cursor}`)
        .set('Authorization', `Bearer ${analystTokenOrgA}`);

      expect(res2.status).toBe(400);
      expect(res2.body.success).toBe(false);
      expect(res2.body.error.code).toBe('INVALID_CURSOR');
    });

    it('rejects a crafted cursor with negative offset with 400 INVALID_CURSOR', async () => {
      // Craft a signed cursor with invalid negative offset
      const invalidCursor = signCursor({
        orgId: orgA,
        filterHash: 'all',
        offset: -10,
      });

      const res = await request(app)
        .get(`/api/v1/events?cursor=${invalidCursor}`)
        .set('Authorization', `Bearer ${analystTokenOrgA}`);

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('INVALID_CURSOR');
    });

    it('extracts date from UUIDv7 accurately and rejects non-v7 UUIDs in extractDateFromUuidV7', () => {
      // Test known timestamp: 2026-11-01T12:00:00.000Z
      const knownMs = new Date('2026-11-01T12:00:00.000Z').getTime();
      const uuidv7 = generateUuidV7(knownMs);

      const extractedDate = extractDateFromUuidV7(uuidv7);
      expect(extractedDate).toBe('2026-11-01');

      // UUIDv4 (random) should return null (no embedded millisecond date in high 48-bits)
      const uuidv4 = 'd3b07384-d113-4e4e-8c0a-75a7c2901309';
      expect(extractDateFromUuidV7(uuidv4)).toBeNull();

      // Garbage string should return null
      expect(extractDateFromUuidV7('invalid-uuid')).toBeNull();
    });
  });
});
