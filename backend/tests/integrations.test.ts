import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import { createApp } from '../src/app.js';
import { getStorage } from '../src/storage/index.js';
import { JwtService } from '../src/auth/jwt-service.js';
import { LocalAuthProvider } from '../src/auth/local-auth-provider.js';
import { resetAuthProviderForTesting } from '../src/auth/index.js';
import { MemoryStore } from '../src/storage/memory-store.js';
import { resetStorageForTesting } from '../src/storage/index.js';
import { NginxLogParser } from '../src/services/log-parsers/nginx-parser.js';
import { ApacheLogParser } from '../src/services/log-parsers/apache-parser.js';
import { LogCollectorService } from '../src/services/log-parsers/log-collector.js';

describe('Phase 6: Integration Management, API Key Auth & Log Collectors (TASK-603, TASK-605, TASK-606)', () => {
  let app: any;
  let storage: any;
  let authProvider: any;

  let orgAdminTokenA: string;
  let orgAdminTokenB: string;

  let jwtService: JwtService;

  beforeEach(async () => {
    jwtService = new JwtService('test-secret-phase-6-jwt-key-32chars');
    const localProvider = new LocalAuthProvider(jwtService);
    resetAuthProviderForTesting(localProvider);

    storage = new MemoryStore();
    resetStorageForTesting(storage);

    app = createApp();

    orgAdminTokenA = jwtService.signAccessToken({
      userId: 'usr-admin-a',
      username: 'admin.alpha',
      email: 'admin@alpha.org',
      role: 'ORG_ADMIN',
      orgId: 'org-alpha',
    });

    orgAdminTokenB = jwtService.signAccessToken({
      userId: 'usr-admin-b',
      username: 'admin.beta',
      email: 'admin@beta.org',
      role: 'ORG_ADMIN',
      orgId: 'org-beta',
    });
  });

  describe('1. Integration Registration & Secure Credential Generation (TASK-603)', () => {
    it('creates an integration, returns secretKey once, and stores only apiKeyHash', async () => {
      const res = await request(app)
        .post('/api/v1/integrations')
        .set('Authorization', `Bearer ${orgAdminTokenA}`)
        .send({
          name: 'Production Express API',
          type: 'EXPRESS',
          description: 'Main production API telemetry stream',
        });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);

      const integration = res.body.integration;
      expect(integration.integrationId).toMatch(/^int-/);
      expect(integration.name).toBe('Production Express API');
      expect(integration.type).toBe('EXPRESS');
      expect(integration.status).toBe('ACTIVE');
      expect(integration.secretKey).toMatch(/^vltx_live_/); // Returned once
      expect(integration.apiKeyPrefix).toBe(integration.secretKey.slice(0, 18));

      // Verify that database does NOT store secretKey in plaintext
      const stored = await storage.getIntegrationById('org-alpha', integration.integrationId);
      expect(stored?.secretKey).toBeUndefined();
      expect(stored?.apiKeyHash).toBeDefined();

      // Verify that listing integrations omits secretKey
      const listRes = await request(app)
        .get('/api/v1/integrations')
        .set('Authorization', `Bearer ${orgAdminTokenA}`);

      expect(listRes.status).toBe(200);
      expect(listRes.body.integrations.length).toBe(1);
      expect(listRes.body.integrations[0].secretKey).toBeUndefined();
    });

    it('validates associated siteId belongs to the same organization', async () => {
      const res = await request(app)
        .post('/api/v1/integrations')
        .set('Authorization', `Bearer ${orgAdminTokenA}`)
        .send({
          name: 'Invalid Site Binding',
          type: 'SDK_NODE',
          siteId: 'site-non-existent',
        });

      expect(res.status).toBe(404);
      expect(res.body.error.code).toBe('WEBSITE_NOT_FOUND');
    });
  });

  describe('2. Telemetry Authentication via x-api-key (TASK-603 / Module B)', () => {
    it('authenticates event ingestion using valid x-api-key header', async () => {
      // 1. Create integration to obtain secret key
      const createRes = await request(app)
        .post('/api/v1/integrations')
        .set('Authorization', `Bearer ${orgAdminTokenA}`)
        .send({
          name: 'Telemetry Ingestion Client',
          type: 'GENERIC_HTTP',
        });

      const secretKey = createRes.body.integration.secretKey;

      // 2. Ingest telemetry event using x-api-key
      const eventPayload = {
        eventType: 'web.request.normal',
        severity: 'LOW',
        category: 'NETWORK',
        sourceIp: '198.51.100.55',
        sourceSystem: 'sdk:nodejs:express',
        metadata: {
          requestUri: '/api/v1/users',
          httpStatus: 200,
        },
      };

      const ingestRes = await request(app)
        .post('/api/v1/events')
        .set('x-api-key', secretKey)
        .set('x-organization-id', 'org-alpha')
        .send(eventPayload);

      expect(ingestRes.status).toBe(202);
      expect(ingestRes.body.success).toBe(true);

      // Verify integration lastSeenAt was updated
      const intDetails = await storage.getIntegrationById(
        'org-alpha',
        createRes.body.integration.integrationId
      );
      expect(intDetails?.lastSeenAt).toBeDefined();
    });

    it('rejects event ingestion with invalid or tampered x-api-key', async () => {
      const res = await request(app)
        .post('/api/v1/events')
        .set('x-api-key', 'vltx_live_invalid_tampered_key')
        .set('x-organization-id', 'org-alpha')
        .send({
          eventType: 'web.request.normal',
          severity: 'LOW',
          category: 'NETWORK',
          sourceIp: '1.2.3.4',
          sourceSystem: 'test',
        });

      expect(res.status).toBe(401);
      expect(res.body.error.code).toBe('UNAUTHORIZED_INVALID_API_KEY');
    });

    it('rejects cross-tenant telemetry ingestion when x-organization-id does not match API key tenant', async () => {
      // Create integration for Org A
      const createRes = await request(app)
        .post('/api/v1/integrations')
        .set('Authorization', `Bearer ${orgAdminTokenA}`)
        .send({
          name: 'Org A Ingestion Key',
          type: 'GENERIC_HTTP',
        });

      const secretKey = createRes.body.integration.secretKey;

      // Submit with Org B organization header
      const res = await request(app)
        .post('/api/v1/events')
        .set('x-api-key', secretKey)
        .set('x-organization-id', 'org-beta')
        .send({
          eventType: 'web.request.normal',
          severity: 'LOW',
          category: 'NETWORK',
          sourceIp: '1.2.3.4',
          sourceSystem: 'test',
        });

      // enforceTenantIsolation rejects cross-tenant header mismatch
      expect(res.status).toBe(403);
      expect(res.body.error.code).toBe('FORBIDDEN_CROSS_TENANT_ACCESS');
    });
  });

  describe('3. API Key Rotation and Revocation (TASK-603)', () => {
    it('rotates API key, invalidates old key immediately, and accepts new key', async () => {
      // 1. Create integration
      const createRes = await request(app)
        .post('/api/v1/integrations')
        .set('Authorization', `Bearer ${orgAdminTokenA}`)
        .send({ name: 'Rotation Target', type: 'SDK_NODE' });

      const integrationId = createRes.body.integration.integrationId;
      const oldKey = createRes.body.integration.secretKey;

      // 2. Rotate key
      const rotateRes = await request(app)
        .post(`/api/v1/integrations/${integrationId}/rotate-key`)
        .set('Authorization', `Bearer ${orgAdminTokenA}`);

      expect(rotateRes.status).toBe(200);
      expect(rotateRes.body.success).toBe(true);
      const newKey = rotateRes.body.secretKey;
      expect(newKey).toBeDefined();
      expect(newKey).not.toBe(oldKey);

      // 3. Test old key -> 401 Unauthorized
      const oldRes = await request(app)
        .post('/api/v1/events')
        .set('x-api-key', oldKey)
        .send({
          eventType: 'web.request.normal',
          severity: 'LOW',
          category: 'NETWORK',
          sourceIp: '1.1.1.1',
          sourceSystem: 'test',
        });
      expect(oldRes.status).toBe(401);

      // 4. Test new key -> 202 Accepted
      const newRes = await request(app)
        .post('/api/v1/events')
        .set('x-api-key', newKey)
        .send({
          eventType: 'web.request.normal',
          severity: 'LOW',
          category: 'NETWORK',
          sourceIp: '1.1.1.1',
          sourceSystem: 'test',
        });
      expect(newRes.status).toBe(202);
    });

    it('revoking an integration immediately rejects further requests', async () => {
      const createRes = await request(app)
        .post('/api/v1/integrations')
        .set('Authorization', `Bearer ${orgAdminTokenA}`)
        .send({ name: 'Revocation Target', type: 'APACHE' });

      const integrationId = createRes.body.integration.integrationId;
      const secretKey = createRes.body.integration.secretKey;

      // Revoke integration
      const revokeRes = await request(app)
        .post(`/api/v1/integrations/${integrationId}/revoke`)
        .set('Authorization', `Bearer ${orgAdminTokenA}`);

      expect(revokeRes.status).toBe(200);
      expect(revokeRes.body.integration.status).toBe('REVOKED');

      // Attempt ingestion with revoked key -> 401
      const ingestRes = await request(app)
        .post('/api/v1/events')
        .set('x-api-key', secretKey)
        .send({
          eventType: 'web.request.normal',
          severity: 'LOW',
          category: 'NETWORK',
          sourceIp: '1.1.1.1',
          sourceSystem: 'test',
        });

      expect(ingestRes.status).toBe(401);
      expect(ingestRes.body.error.code).toBe('UNAUTHORIZED_REVOKED_API_KEY');
    });
  });

  describe('4. Server Log Collectors: Nginx & Apache (TASK-605)', () => {
    it('NginxLogParser parses veltrix_json access logs and detects attacks', () => {
      const parser = new NginxLogParser();
      const context = { orgId: 'org-alpha', siteId: 'site-prod-01' };

      const jsonLog = JSON.stringify({
        timestamp: '2026-11-01T14:00:00Z',
        sourceIp: '203.0.113.195',
        httpMethod: 'GET',
        requestUri: "/search?q=1' UNION SELECT username,password FROM users--",
        httpStatus: 403,
        responseTimeMs: 15,
        userAgent: 'sqlmap/1.5',
        host: 'app.alpha.org',
      });

      const event = parser.parseLine(jsonLog, context);
      expect(event).toBeDefined();
      expect(event?.eventType).toBe('web.attack.sqli');
      expect(event?.severity).toBe('HIGH');
      expect(event?.sourceIp).toBe('203.0.113.195');
      expect(event?.metadata?.httpStatus).toBe(403);
      expect(event?.metadata?.confidenceLevel).toBe('BLOCKED_ATTEMPT');
    });

    it('NginxLogParser parses standard combined access logs', () => {
      const parser = new NginxLogParser();
      const context = { orgId: 'org-alpha' };

      const combinedLine =
        '198.51.100.42 - sarah [01/Nov/2026:12:34:56 +0000] "GET /catalog/products?id=1 HTTP/1.1" 200 1024 "https://google.com" "Mozilla/5.0"';

      const event = parser.parseLine(combinedLine, context);
      expect(event).toBeDefined();
      expect(event?.eventType).toBe('web.request.normal');
      expect(event?.severity).toBe('LOW');
      expect(event?.sourceIp).toBe('198.51.100.42');
      expect(event?.username).toBe('sarah');
      expect(event?.metadata?.httpStatus).toBe(200);
      expect(event?.metadata?.httpMethod).toBe('GET');
    });

    it('ApacheLogParser parses combined log format and detects path traversal', () => {
      const parser = new ApacheLogParser();
      const context = { orgId: 'org-alpha' };

      const apacheLine =
        '198.51.100.88 - - [01/Nov/2026:14:10:00 +0000] "GET /images/../../etc/passwd HTTP/1.1" 403 245 "-" "curl/7.88.1"';

      const event = parser.parseLine(apacheLine, context);
      expect(event).toBeDefined();
      expect(event?.eventType).toBe('web.attack.traversal');
      expect(event?.severity).toBe('HIGH');
      expect(event?.sourceIp).toBe('198.51.100.88');
      expect(event?.metadata?.httpStatus).toBe(403);
    });

    it('LogCollectorService safely handles malformed log records without crashing', async () => {
      const collector = new LogCollectorService(storage);

      const rawLogs = [
        '{"timestamp":"2026-11-01T10:00:00Z","sourceIp":"1.2.3.4","httpMethod":"GET","requestUri":"/home","httpStatus":200}',
        'MALFORMED LINE: THIS IS NOT A VALID LOG RECORD 12345',
        'ANOTHER MALFORMED LINE [[[GARBAGE]]]',
        '198.51.100.1 - - [01/Nov/2026:12:00:00 +0000] "GET /api/status HTTP/1.1" 200 500 "-" "Mozilla/5.0"',
      ];

      const result = await collector.processLogStream('NGINX', rawLogs, {
        orgId: 'org-alpha',
        siteId: 'site-logs-01',
      });

      expect(result.validCount).toBe(2);
      expect(result.malformedCount).toBe(2);
      expect(result.ingestedCount).toBe(2);
      expect(result.errors.length).toBe(2);
      expect(result.errors[0]?.error).toBe('Malformed or unrecognized Nginx log format');
    });
  });

  describe('5. Integration Health Tracking & Statistics (TASK-606)', () => {
    it('tracks ingestion counts and updates health stats on collector dispatch', async () => {
      // 1. Create integration
      const createRes = await request(app)
        .post('/api/v1/integrations')
        .set('Authorization', `Bearer ${orgAdminTokenA}`)
        .send({ name: 'Health Monitored Collector', type: 'NGINX' });

      const integrationId = createRes.body.integration.integrationId;

      // 2. Dispatch logs via collector service
      const collector = new LogCollectorService(storage);
      const rawLogs = [
        '{"timestamp":"2026-11-01T10:00:00Z","sourceIp":"10.0.0.1","httpMethod":"GET","requestUri":"/api","httpStatus":200}',
        '{"timestamp":"2026-11-01T10:00:01Z","sourceIp":"10.0.0.2","httpMethod":"GET","requestUri":"/docs","httpStatus":200}',
      ];

      await collector.processLogStream('NGINX', rawLogs, {
        orgId: 'org-alpha',
        integrationId,
      });

      // 3. Query health endpoint
      const healthRes = await request(app)
        .get(`/api/v1/integrations/${integrationId}/health`)
        .set('Authorization', `Bearer ${orgAdminTokenA}`);

      expect(healthRes.status).toBe(200);
      expect(healthRes.body.health.status).toBe('HEALTHY');
      expect(healthRes.body.health.eventsReceived).toBe(2);
      expect(healthRes.body.health.lastSuccessAt).toBeDefined();
    });
  });
});
