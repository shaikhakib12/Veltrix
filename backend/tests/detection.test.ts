import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import { createApp } from '../src/app.js';
import { JwtService } from '../src/auth/jwt-service.js';
import { LocalAuthProvider } from '../src/auth/local-auth-provider.js';
import { resetAuthProviderForTesting } from '../src/auth/index.js';
import { MemoryStore } from '../src/storage/memory-store.js';
import { resetStorageForTesting } from '../src/storage/index.js';
import { DetectionEngine } from '../src/detection/engine.js';
import {
  Rule001BruteForce,
  Rule002PasswordSpray,
  Rule003CredentialStuffingSuccess,
  Rule004ImpossibleTravel,
  Rule005SuspiciousIp,
  Rule006PrivilegeEscalation,
  Rule007UnusualDataAccess,
  Rule008ExcessiveApiRequests,
  Rule009MultiAccountRecon,
  Rule010OffHoursAnomaly,
} from '../src/detection/rules/index.js';
import type { SecurityEvent } from '@veltrix/shared';

describe('Phase 5: Threat Detection Engine (TASK-501 through TASK-505)', () => {
  let app: ReturnType<typeof createApp>;
  let jwtService: JwtService;
  let memoryStore: MemoryStore;
  let engine: DetectionEngine;

  const testSecret = 'veltrix-phase-5-test-jwt-secret-key-32chars';
  const orgA = 'org-cyber-shield';
  const orgB = 'org-defense-matrix';

  let analystTokenOrgA: string;
  let orgAdminTokenOrgA: string;
  let viewerTokenOrgA: string;
  let analystTokenOrgB: string;

  beforeEach(() => {
    jwtService = new JwtService(testSecret);
    const localProvider = new LocalAuthProvider(jwtService);
    resetAuthProviderForTesting(localProvider);

    memoryStore = new MemoryStore();
    resetStorageForTesting(memoryStore);

    engine = new DetectionEngine(memoryStore);
    app = createApp();

    analystTokenOrgA = jwtService.signAccessToken({
      userId: 'user-analyst-a',
      email: 'analyst@shield.corp',
      username: 'analyst.shield',
      role: 'SECURITY_ANALYST',
      orgId: orgA,
    });

    orgAdminTokenOrgA = jwtService.signAccessToken({
      userId: 'user-admin-a',
      email: 'admin@shield.corp',
      username: 'admin.shield',
      role: 'ORG_ADMIN',
      orgId: orgA,
    });

    viewerTokenOrgA = jwtService.signAccessToken({
      userId: 'user-viewer-a',
      email: 'viewer@shield.corp',
      username: 'viewer.shield',
      role: 'READ_ONLY_VIEWER',
      orgId: orgA,
    });

    analystTokenOrgB = jwtService.signAccessToken({
      userId: 'user-analyst-b',
      email: 'analyst@matrix.corp',
      username: 'analyst.matrix',
      role: 'SECURITY_ANALYST',
      orgId: orgB,
    });
  });

  // ==========================================================================
  // 1. Detection Rule Evaluation Logic (RULE-001 through RULE-010)
  // ==========================================================================
  describe('Detection Rules Unit Verification', () => {
    it('RULE-001: triggers on >= 5 failed logins within 120s from same IP, correctly handling out-of-order events', async () => {
      const rule = new Rule001BruteForce();
      const baseTime = new Date('2026-11-01T12:00:00Z').getTime();

      // Create 5 failed logins arriving out-of-order
      const events: SecurityEvent[] = [
        {
          eventId: 'ev-1',
          orgId: orgA,
          category: 'AUTHENTICATION',
          eventType: 'auth.login.failed',
          severity: 'LOW',
          timestamp: new Date(baseTime + 50000).toISOString(),
          sourceIp: '198.51.100.10',
          username: 'user1',
          sourceSystem: 'auth-gateway',
        },
        {
          eventId: 'ev-2',
          orgId: orgA,
          category: 'AUTHENTICATION',
          eventType: 'auth.login.failed',
          severity: 'LOW',
          timestamp: new Date(baseTime).toISOString(),
          sourceIp: '198.51.100.10',
          username: 'user1',
          sourceSystem: 'auth-gateway',
        },
        {
          eventId: 'ev-3',
          orgId: orgA,
          category: 'AUTHENTICATION',
          eventType: 'auth.login.failed',
          severity: 'LOW',
          timestamp: new Date(baseTime + 20000).toISOString(),
          sourceIp: '198.51.100.10',
          username: 'user1',
          sourceSystem: 'auth-gateway',
        },
        {
          eventId: 'ev-4',
          orgId: orgA,
          category: 'AUTHENTICATION',
          eventType: 'auth.login.failed',
          severity: 'LOW',
          timestamp: new Date(baseTime + 30000).toISOString(),
          sourceIp: '198.51.100.10',
          username: 'user1',
          sourceSystem: 'auth-gateway',
        },
        {
          eventId: 'ev-5',
          orgId: orgA,
          category: 'AUTHENTICATION',
          eventType: 'auth.login.failed',
          severity: 'LOW',
          timestamp: new Date(baseTime + 40000).toISOString(),
          sourceIp: '198.51.100.10',
          username: 'user1',
          sourceSystem: 'auth-gateway',
        },
      ];

      const detections = await rule.evaluate({
        organizationId: orgA,
        events,
        currentTime: new Date(),
      });

      expect(detections.length).toBe(1);
      expect(detections[0].ruleId).toBe('RULE-001');
      expect(detections[0].severity).toBe('HIGH');
      expect(detections[0].mitreAttack?.techniqueId).toBe('T1110.001');
      expect(detections[0].evidence.actualCount).toBe(5);
      expect(detections[0].evidence.targetEntity?.value).toBe('198.51.100.10');
    });

    it('RULE-001: does not trigger when failed logins are below threshold (< 5)', async () => {
      const rule = new Rule001BruteForce();
      const baseTime = Date.now();

      const events: SecurityEvent[] = [1, 2, 3, 4].map((i) => ({
        eventId: `ev-${i}`,
        orgId: orgA,
        category: 'AUTHENTICATION',
        eventType: 'auth.login.failed',
        severity: 'LOW',
        timestamp: new Date(baseTime + i * 5000).toISOString(),
        sourceIp: '198.51.100.20',
        username: 'alice',
        sourceSystem: 'auth-gateway',
      }));

      const detections = await rule.evaluate({
        organizationId: orgA,
        events,
        currentTime: new Date(),
      });

      expect(detections.length).toBe(0);
    });

    it('RULE-002: triggers on password spraying across >= 3 distinct accounts from same IP', async () => {
      const rule = new Rule002PasswordSpray();
      const baseTime = Date.now();

      const events: SecurityEvent[] = ['alice', 'bob', 'charlie'].map((user, i) => ({
        eventId: `spray-${i}`,
        orgId: orgA,
        category: 'AUTHENTICATION',
        eventType: 'auth.login.failed',
        severity: 'LOW',
        timestamp: new Date(baseTime + i * 10000).toISOString(),
        sourceIp: '203.0.113.50',
        username: user,
        sourceSystem: 'vpn-gateway',
      }));

      const detections = await rule.evaluate({
        organizationId: orgA,
        events,
        currentTime: new Date(),
      });

      expect(detections.length).toBe(1);
      expect(detections[0].ruleId).toBe('RULE-002');
      expect(detections[0].mitreAttack?.techniqueId).toBe('T1110.003');
      expect(detections[0].evidence.actualCount).toBe(3);
    });

    it('RULE-003: triggers on successful login following >= 2 failed attempts within 600s', async () => {
      const rule = new Rule003CredentialStuffingSuccess();
      const baseTime = Date.now();

      const events: SecurityEvent[] = [
        {
          eventId: 'fail-1',
          orgId: orgA,
          category: 'AUTHENTICATION',
          eventType: 'auth.login.failed',
          severity: 'LOW',
          timestamp: new Date(baseTime - 30000).toISOString(),
          sourceIp: '192.0.2.1',
          username: 'victor',
          sourceSystem: 'auth',
        },
        {
          eventId: 'fail-2',
          orgId: orgA,
          category: 'AUTHENTICATION',
          eventType: 'auth.login.failed',
          severity: 'LOW',
          timestamp: new Date(baseTime - 15000).toISOString(),
          sourceIp: '192.0.2.2',
          username: 'victor',
          sourceSystem: 'auth',
        },
        {
          eventId: 'succ-1',
          orgId: orgA,
          category: 'AUTHENTICATION',
          eventType: 'auth.login.success',
          severity: 'LOW',
          timestamp: new Date(baseTime).toISOString(),
          sourceIp: '192.0.2.3',
          username: 'victor',
          sourceSystem: 'auth',
        },
      ];

      const detections = await rule.evaluate({
        organizationId: orgA,
        events,
        currentTime: new Date(),
      });

      expect(detections.length).toBe(1);
      expect(detections[0].ruleId).toBe('RULE-003');
      expect(detections[0].severity).toBe('CRITICAL');
      expect(detections[0].evidence.targetEntity?.value).toBe('victor');
      // Passwords are never logged or stored
      expect(JSON.stringify(detections[0])).not.toContain('password');
    });

    it('RULE-004: triggers on impossible travel between distant countries in < 30m, but never solely on IP change', async () => {
      const rule = new Rule004ImpossibleTravel();
      const baseTime = Date.now();

      // 1. IP change only (same country/city or missing enrichment): should NOT trigger
      const ipOnlyEvents: SecurityEvent[] = [
        {
          eventId: 'ip-1',
          orgId: orgA,
          category: 'AUTHENTICATION',
          eventType: 'auth.login.success',
          severity: 'LOW',
          timestamp: new Date(baseTime - 10000).toISOString(),
          sourceIp: '10.0.0.1',
          username: 'traveler',
          sourceSystem: 'auth',
          metadata: { country: 'US', city: 'New York' },
        },
        {
          eventId: 'ip-2',
          orgId: orgA,
          category: 'AUTHENTICATION',
          eventType: 'auth.login.success',
          severity: 'LOW',
          timestamp: new Date(baseTime).toISOString(),
          sourceIp: '10.0.0.2',
          username: 'traveler',
          sourceSystem: 'auth',
          metadata: { country: 'US', city: 'New York' },
        },
      ];

      const noDetection = await rule.evaluate({
        organizationId: orgA,
        events: ipOnlyEvents,
        currentTime: new Date(),
      });
      expect(noDetection.length).toBe(0);

      // 2. Geographic impossible travel: US then DE within 10 minutes: MUST trigger
      const geoEvents: SecurityEvent[] = [
        {
          eventId: 'geo-1',
          orgId: orgA,
          category: 'AUTHENTICATION',
          eventType: 'auth.login.success',
          severity: 'LOW',
          timestamp: new Date(baseTime - 600000).toISOString(),
          sourceIp: '198.51.100.1',
          username: 'traveler',
          sourceSystem: 'auth',
          metadata: { country: 'US', city: 'New York' },
        },
        {
          eventId: 'geo-2',
          orgId: orgA,
          category: 'AUTHENTICATION',
          eventType: 'auth.login.success',
          severity: 'LOW',
          timestamp: new Date(baseTime).toISOString(),
          sourceIp: '203.0.113.1',
          username: 'traveler',
          sourceSystem: 'auth',
          metadata: { country: 'DE', city: 'Frankfurt' },
        },
      ];

      const geoDetection = await rule.evaluate({
        organizationId: orgA,
        events: geoEvents,
        currentTime: new Date(),
      });
      expect(geoDetection.length).toBe(1);
      expect(geoDetection[0].ruleId).toBe('RULE-004');
    });

    it('RULE-005: triggers on activity from confirmed suspicious IP / Tor exit node', async () => {
      const rule = new Rule005SuspiciousIp();

      const events: SecurityEvent[] = [
        {
          eventId: 'tor-1',
          orgId: orgA,
          category: 'NETWORK',
          eventType: 'network.connection',
          severity: 'MEDIUM',
          timestamp: new Date().toISOString(),
          sourceIp: '185.220.101.5', // Known Tor exit node
          username: 'anon',
          sourceSystem: 'firewall',
          metadata: { isTorExitNode: true },
        },
      ];

      const detections = await rule.evaluate({
        organizationId: orgA,
        events,
        currentTime: new Date(),
      });

      expect(detections.length).toBe(1);
      expect(detections[0].ruleId).toBe('RULE-005');
      expect(detections[0].severity).toBe('CRITICAL');
    });

    it('RULE-006: triggers on privilege escalation / administrator role assumption', async () => {
      const rule = new Rule006PrivilegeEscalation();

      const events: SecurityEvent[] = [
        {
          eventId: 'priv-1',
          orgId: orgA,
          category: 'PRIVILEGE',
          eventType: 'privilege.escalation',
          severity: 'CRITICAL',
          timestamp: new Date().toISOString(),
          sourceIp: '10.0.1.5',
          username: 'contractor',
          sourceSystem: 'iam-service',
          metadata: { role: 'Administrator', action: 'AssumeRole' },
        },
      ];

      const detections = await rule.evaluate({
        organizationId: orgA,
        events,
        currentTime: new Date(),
      });

      expect(detections.length).toBe(1);
      expect(detections[0].ruleId).toBe('RULE-006');
      expect(detections[0].severity).toBe('CRITICAL');
    });

    it('RULE-007: triggers on bulk data access >= 10,000 records or exfiltration', async () => {
      const rule = new Rule007UnusualDataAccess();

      const events: SecurityEvent[] = [
        {
          eventId: 'data-1',
          orgId: orgA,
          category: 'DATA_ACCESS',
          eventType: 'data.access.bulk',
          severity: 'HIGH',
          timestamp: new Date().toISOString(),
          sourceIp: '10.0.2.10',
          username: 'analyst',
          sourceSystem: 'customer-db',
          metadata: { recordCount: 15000, database: 'production-pii' },
        },
      ];

      const detections = await rule.evaluate({
        organizationId: orgA,
        events,
        currentTime: new Date(),
      });

      expect(detections.length).toBe(1);
      expect(detections[0].ruleId).toBe('RULE-007');
      expect(detections[0].evidence.actualCount).toBe(15000);
    });

    it('RULE-008: triggers on excessive API burst >= 100 req/min', async () => {
      const rule = new Rule008ExcessiveApiRequests();

      const events: SecurityEvent[] = [
        {
          eventId: 'api-1',
          orgId: orgA,
          category: 'API',
          eventType: 'api.request.burst',
          severity: 'HIGH',
          timestamp: new Date().toISOString(),
          sourceIp: '198.51.100.99',
          username: 'api-client',
          sourceSystem: 'api-gateway',
          metadata: { requestCount: 250 },
        },
      ];

      const detections = await rule.evaluate({
        organizationId: orgA,
        events,
        currentTime: new Date(),
      });

      expect(detections.length).toBe(1);
      expect(detections[0].ruleId).toBe('RULE-008');
      expect(detections[0].evidence.actualCount).toBe(250);
    });

    it('RULE-009: triggers on multi-account enumeration probing >= 4 user handles in 180s', async () => {
      const rule = new Rule009MultiAccountRecon();
      const baseTime = Date.now();

      const events: SecurityEvent[] = ['u1', 'u2', 'u3', 'u4'].map((user, i) => ({
        eventId: `recon-${i}`,
        orgId: orgA,
        category: 'AUTHENTICATION',
        eventType: 'auth.login.failed',
        severity: 'LOW',
        timestamp: new Date(baseTime + i * 10000).toISOString(),
        sourceIp: '203.0.113.77',
        username: user,
        sourceSystem: 'auth-portal',
      }));

      const detections = await rule.evaluate({
        organizationId: orgA,
        events,
        currentTime: new Date(),
      });

      expect(detections.length).toBe(1);
      expect(detections[0].ruleId).toBe('RULE-009');
      expect(detections[0].evidence.actualCount).toBe(4);
    });

    it('RULE-010: triggers on administrative actions outside business hours (06:00-22:00 UTC)', async () => {
      const rule = new Rule010OffHoursAnomaly();

      // Action at 03:30 UTC (off-hours)
      const offHoursEvent: SecurityEvent = {
        eventId: 'off-1',
        orgId: orgA,
        category: 'SYSTEM',
        eventType: 'admin.action',
        severity: 'MEDIUM',
        timestamp: '2026-11-03T03:30:00Z', // Tuesday 03:30 UTC
        sourceIp: '10.0.0.50',
        username: 'sysadmin',
        sourceSystem: 'k8s-control-plane',
        metadata: { action: 'cluster.drain' },
      };

      const detections = await rule.evaluate({
        organizationId: orgA,
        events: [offHoursEvent],
        currentTime: new Date(),
      });

      expect(detections.length).toBe(1);
      expect(detections[0].ruleId).toBe('RULE-010');

      // Action at 14:00 UTC (normal business hours): does NOT trigger
      const normalHourEvent: SecurityEvent = {
        eventId: 'norm-1',
        orgId: orgA,
        category: 'SYSTEM',
        eventType: 'admin.action',
        severity: 'MEDIUM',
        timestamp: '2026-11-03T14:00:00Z', // Tuesday 14:00 UTC
        sourceIp: '10.0.0.50',
        username: 'sysadmin',
        sourceSystem: 'k8s-control-plane',
        metadata: { action: 'cluster.drain' },
      };

      const normalDetections = await rule.evaluate({
        organizationId: orgA,
        events: [normalHourEvent],
        currentTime: new Date(),
      });
      expect(normalDetections.length).toBe(0);
    });
  });

  // ==========================================================================
  // 2. Detection Engine Deduplication, Multi-Tenancy & Rule Customization
  // ==========================================================================
  describe('Detection Engine Core Guarantees', () => {
    it('suppresses duplicate detections when evaluating identical event batches repeatedly', async () => {
      const baseTime = Date.now();
      const events: SecurityEvent[] = [1, 2, 3, 4, 5].map((i) => ({
        eventId: `ev-dedup-${i}`,
        orgId: orgA,
        category: 'AUTHENTICATION',
        eventType: 'auth.login.failed',
        severity: 'LOW',
        timestamp: new Date(baseTime + i * 1000).toISOString(),
        sourceIp: '198.51.100.33',
        username: 'victim',
        sourceSystem: 'auth',
      }));

      // First run: creates detection and persists
      const run1 = await engine.evaluate(
        { organizationId: orgA, events, currentTime: new Date() },
        { persistDetections: true }
      );
      expect(run1.matchedDetectionsCount).toBe(1);

      // Second run on same events: storage deduplication suppresses duplicate
      const run2 = await engine.evaluate(
        { organizationId: orgA, events, currentTime: new Date() },
        { persistDetections: true }
      );
      expect(run2.matchedDetectionsCount).toBe(0);

      // Storage only contains 1 detection
      const stored = await memoryStore.getDetections(orgA);
      expect(stored.items.length).toBe(1);
    });

    it('enforces organization isolation: Tenant A events and detections are never accessible to Tenant B', async () => {
      // Create Tenant A detection
      await memoryStore.saveDetection({
        detectionId: 'det-org-a',
        ruleId: 'RULE-001',
        ruleName: 'Brute Force',
        orgId: orgA,
        severity: 'HIGH',
        confidence: 85,
        category: 'AUTHENTICATION',
        title: 'Tenant A Finding',
        description: 'Test finding for Org A',
        detectedAt: new Date().toISOString(),
        relatedEventIds: ['ev-a'],
        evidence: { matchedRuleId: 'RULE-001', matchedThreshold: 5 },
      });

      // Query as Tenant B
      const orgBResult = await memoryStore.getDetections(orgB);
      expect(orgBResult.items.length).toBe(0);

      // Single item retrieval as Tenant B
      const orgBSingle = await memoryStore.getDetectionById(orgB, 'det-org-a');
      expect(orgBSingle).toBeNull();
    });

    it('respects tenant-specific disabled rules', async () => {
      // Disable RULE-001 for Org A
      await memoryStore.saveDetectionRule({
        ruleId: 'RULE-001',
        orgId: orgA,
        name: 'Brute Force Authentication',
        description: 'Disabled for this tenant',
        category: 'AUTHENTICATION',
        severity: 'HIGH',
        threshold: 5,
        slidingWindowSeconds: 120,
        isEnabled: false,
        condition: {},
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      });

      const baseTime = Date.now();
      const events: SecurityEvent[] = [1, 2, 3, 4, 5].map((i) => ({
        eventId: `ev-dis-${i}`,
        orgId: orgA,
        category: 'AUTHENTICATION',
        eventType: 'auth.login.failed',
        severity: 'LOW',
        timestamp: new Date(baseTime + i * 1000).toISOString(),
        sourceIp: '198.51.100.44',
        username: 'user',
        sourceSystem: 'auth',
      }));

      const res = await engine.evaluate({
        organizationId: orgA,
        events,
        currentTime: new Date(),
      });

      // RULE-001 was skipped because isEnabled === false
      expect(res.matchedDetectionsCount).toBe(0);
      expect(res.evaluatedRuleIds).not.toContain('RULE-001');
    });
  });

  // ==========================================================================
  // 3. Detection REST API Endpoints (TASK-504)
  // ==========================================================================
  describe('Detection REST API Endpoints', () => {
    it('POST /api/v1/detections/run triggers on-demand evaluation and returns findings', async () => {
      const baseTime = Date.now();
      for (let i = 1; i <= 5; i++) {
        await memoryStore.saveEvent({
          eventId: `run-ev-${i}`,
          orgId: orgA,
          category: 'AUTHENTICATION',
          eventType: 'auth.login.failed',
          severity: 'LOW',
          timestamp: new Date(baseTime + i * 1000).toISOString(),
          sourceIp: '198.51.100.88',
          username: 'target',
          sourceSystem: 'auth-gateway',
        });
      }

      const res = await request(app)
        .post('/api/v1/detections/run')
        .set('Authorization', `Bearer ${analystTokenOrgA}`)
        .send({
          ruleIds: ['RULE-001'],
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.matchedDetectionsCount).toBe(1);
      expect(res.body.data.detections[0].ruleId).toBe('RULE-001');
    });

    it('POST /api/v1/detections/run rejects READ_ONLY_VIEWER with 403 Forbidden', async () => {
      const res = await request(app)
        .post('/api/v1/detections/run')
        .set('Authorization', `Bearer ${viewerTokenOrgA}`)
        .send({});

      expect(res.status).toBe(403);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('FORBIDDEN_INSUFFICIENT_PERMISSIONS');
    });

    it('GET /api/v1/detections queries detections with severity filtering and cursor pagination', async () => {
      // Seed 3 detections with distinct timestamps
      for (let i = 1; i <= 3; i++) {
        await memoryStore.saveDetection({
          detectionId: `det-query-${i}`,
          ruleId: `RULE-00${i}`,
          ruleName: `Rule ${i}`,
          orgId: orgA,
          severity: i === 1 ? 'CRITICAL' : 'HIGH',
          confidence: 90,
          category: 'AUTHENTICATION',
          title: `Detection ${i}`,
          description: `Description ${i}`,
          detectedAt: new Date(Date.now() - (4 - i) * 10000).toISOString(),
          relatedEventIds: [`ev-${i}`],
          evidence: { matchedRuleId: `RULE-00${i}`, matchedThreshold: 1 },
        });
      }

      // Query with severity=CRITICAL
      const filterRes = await request(app)
        .get('/api/v1/detections?severity=CRITICAL')
        .set('Authorization', `Bearer ${analystTokenOrgA}`);

      expect(filterRes.status).toBe(200);
      expect(filterRes.body.data.items.length).toBe(1);
      expect(filterRes.body.data.items[0].detectionId).toBe('det-query-1');

      // Query with limit=2 for cursor pagination
      const page1Res = await request(app)
        .get('/api/v1/detections?limit=2')
        .set('Authorization', `Bearer ${analystTokenOrgA}`);

      expect(page1Res.status).toBe(200);
      expect(page1Res.body.data.items.length).toBe(2);
      expect(page1Res.body.data.nextCursor).toBeDefined();

      // Query page 2 with cursor
      const cursor = page1Res.body.data.nextCursor;
      const page2Res = await request(app)
        .get(`/api/v1/detections?limit=2&cursor=${encodeURIComponent(cursor)}`)
        .set('Authorization', `Bearer ${analystTokenOrgA}`);

      expect(page2Res.status).toBe(200);
      expect(page2Res.body.data.items.length).toBe(1);
    });

    it('GET /api/v1/detections/:detectionId returns 404 for nonexistent or cross-tenant detections', async () => {
      // Save detection under Org A
      await memoryStore.saveDetection({
        detectionId: 'det-isolated',
        ruleId: 'RULE-001',
        ruleName: 'Brute Force',
        orgId: orgA,
        severity: 'HIGH',
        confidence: 85,
        category: 'AUTHENTICATION',
        title: 'Org A Finding',
        description: 'Isolated test finding',
        detectedAt: new Date().toISOString(),
        relatedEventIds: ['ev-iso'],
        evidence: { matchedRuleId: 'RULE-001', matchedThreshold: 5 },
      });

      // Tenant A can retrieve it
      const successRes = await request(app)
        .get('/api/v1/detections/det-isolated')
        .set('Authorization', `Bearer ${analystTokenOrgA}`);
      expect(successRes.status).toBe(200);
      expect(successRes.body.data.detectionId).toBe('det-isolated');

      // Tenant B gets 404 NOT_FOUND
      const crossTenantRes = await request(app)
        .get('/api/v1/detections/det-isolated')
        .set('Authorization', `Bearer ${analystTokenOrgB}`);
      expect(crossTenantRes.status).toBe(404);
      expect(crossTenantRes.body.error.code).toBe('NOT_FOUND');
    });

    it('GET /api/v1/detection-rules lists all 10 registered rules', async () => {
      const res = await request(app)
        .get('/api/v1/detection-rules')
        .set('Authorization', `Bearer ${analystTokenOrgA}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.rules.length).toBe(10);
      const ruleIds = res.body.data.rules.map((r: { ruleId: string }) => r.ruleId);
      expect(ruleIds).toContain('RULE-001');
      expect(ruleIds).toContain('RULE-010');
    });

    it('PATCH /api/v1/detection-rules/:ruleId allows ORG_ADMIN to tune threshold, but rejects SECURITY_ANALYST', async () => {
      // SECURITY_ANALYST is rejected with 403
      const analystRes = await request(app)
        .patch('/api/v1/detection-rules/RULE-001')
        .set('Authorization', `Bearer ${analystTokenOrgA}`)
        .send({ threshold: 10 });
      expect(analystRes.status).toBe(403);

      // ORG_ADMIN succeeds
      const adminRes = await request(app)
        .patch('/api/v1/detection-rules/RULE-001')
        .set('Authorization', `Bearer ${orgAdminTokenOrgA}`)
        .send({ threshold: 10, slidingWindowSeconds: 240 });
      expect(adminRes.status).toBe(200);
      expect(adminRes.body.data.threshold).toBe(10);
      expect(adminRes.body.data.slidingWindowSeconds).toBe(240);

      // Verify override is active for Org A
      const listRes = await request(app)
        .get('/api/v1/detection-rules')
        .set('Authorization', `Bearer ${analystTokenOrgA}`);
      const rule1 = listRes.body.data.rules.find((r: { ruleId: string }) => r.ruleId === 'RULE-001');
      expect(rule1.threshold).toBe(10);
    });

    it('POST /api/v1/detection-rules/test dry-runs rules on sample events without persistent side-effects', async () => {
      const sampleEvents = [1, 2, 3, 4, 5].map((i) => ({
        category: 'AUTHENTICATION' as const,
        eventType: 'auth.login.failed' as const,
        severity: 'LOW' as const,
        sourceIp: '198.51.100.5',
        username: 'analyst',
        sourceSystem: 'test-runner',
        timestamp: new Date(Date.now() + i * 1000).toISOString(),
      }));

      const res = await request(app)
        .post('/api/v1/detection-rules/test')
        .set('Authorization', `Bearer ${analystTokenOrgA}`)
        .send({
          ruleId: 'RULE-001',
          threshold: 5,
          sampleEvents,
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.matched).toBe(true);
      expect(res.body.data.matchedCount).toBe(1);

      // Verify nothing was persisted into storage
      const stored = await memoryStore.getDetections(orgA);
      expect(stored.items.length).toBe(0);
    });
  });
});
