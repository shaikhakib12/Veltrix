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
import type { SecurityEvent, Detection } from '@veltrix/shared';
import { generateUuidV7 } from '../src/utils/uuid.js';

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

  // ==========================================================================
  // 4. Advanced Boundary, Enrichment & Context Tests
  // ==========================================================================
  describe('Rule Advanced Boundary & Enrichment Auditing', () => {
    it('RULE-001: strictly respects sliding window boundary (5 failures across 121s does NOT trigger)', async () => {
      const rule = new Rule001BruteForce();
      const baseTime = Date.now();

      // 5 failed logins spread across 121s (> 120s default window)
      const events: SecurityEvent[] = [
        {
          eventId: 'b-1',
          orgId: orgA,
          category: 'AUTHENTICATION',
          eventType: 'auth.login.failed',
          severity: 'LOW',
          timestamp: new Date(baseTime).toISOString(),
          sourceIp: '198.51.100.111',
          username: 'victim',
          sourceSystem: 'auth',
        },
        {
          eventId: 'b-2',
          orgId: orgA,
          category: 'AUTHENTICATION',
          eventType: 'auth.login.failed',
          severity: 'LOW',
          timestamp: new Date(baseTime + 30000).toISOString(),
          sourceIp: '198.51.100.111',
          username: 'victim',
          sourceSystem: 'auth',
        },
        {
          eventId: 'b-3',
          orgId: orgA,
          category: 'AUTHENTICATION',
          eventType: 'auth.login.failed',
          severity: 'LOW',
          timestamp: new Date(baseTime + 60000).toISOString(),
          sourceIp: '198.51.100.111',
          username: 'victim',
          sourceSystem: 'auth',
        },
        {
          eventId: 'b-4',
          orgId: orgA,
          category: 'AUTHENTICATION',
          eventType: 'auth.login.failed',
          severity: 'LOW',
          timestamp: new Date(baseTime + 90000).toISOString(),
          sourceIp: '198.51.100.111',
          username: 'victim',
          sourceSystem: 'auth',
        },
        {
          eventId: 'b-5',
          orgId: orgA,
          category: 'AUTHENTICATION',
          eventType: 'auth.login.failed',
          severity: 'LOW',
          timestamp: new Date(baseTime + 121000).toISOString(), // 121 seconds later
          sourceIp: '198.51.100.111',
          username: 'victim',
          sourceSystem: 'auth',
        },
      ];

      const detections = await rule.evaluate({
        organizationId: orgA,
        events,
        currentTime: new Date(),
      });

      expect(detections.length).toBe(0);
    });

    it('RULE-004: suppresses false positives when corporate VPN or proxy metadata is present', async () => {
      const rule = new Rule004ImpossibleTravel();
      const baseTime = Date.now();

      // Logins from different countries, but event has isVpn: true (VPN toggling)
      const vpnEvents: SecurityEvent[] = [
        {
          eventId: 'vpn-1',
          orgId: orgA,
          category: 'AUTHENTICATION',
          eventType: 'auth.login.success',
          severity: 'LOW',
          timestamp: new Date(baseTime - 300000).toISOString(),
          sourceIp: '198.51.100.1',
          username: 'remote-worker',
          sourceSystem: 'okta',
          metadata: { country: 'US', city: 'Dallas' },
        },
        {
          eventId: 'vpn-2',
          orgId: orgA,
          category: 'AUTHENTICATION',
          eventType: 'auth.login.success',
          severity: 'LOW',
          timestamp: new Date(baseTime).toISOString(),
          sourceIp: '203.0.113.1',
          username: 'remote-worker',
          sourceSystem: 'okta',
          metadata: { country: 'JP', city: 'Tokyo', isVpn: true, enrichmentSource: 'INTERNAL_VPN_REGISTRY' },
        },
      ];

      const detections = await rule.evaluate({
        organizationId: orgA,
        events: vpnEvents,
        currentTime: new Date(),
      });

      expect(detections.length).toBe(0);
    });

    it('RULE-005: ignores expired threat indicators', async () => {
      const rule = new Rule005SuspiciousIp();

      const events: SecurityEvent[] = [
        {
          eventId: 'exp-1',
          orgId: orgA,
          category: 'NETWORK',
          eventType: 'network.connection',
          severity: 'MEDIUM',
          timestamp: new Date().toISOString(),
          sourceIp: '198.51.100.250',
          username: 'tester',
          sourceSystem: 'fw',
        },
      ];

      // Expired threat indicator
      const expiredIndicator = {
        indicatorId: 'ind-exp',
        type: 'IP' as const,
        value: '198.51.100.250',
        severity: 'HIGH' as const,
        confidence: 85,
        source: 'AlienVault',
        description: 'Expired test indicator',
        createdAt: new Date(Date.now() - 86400000).toISOString(),
        expiresAt: new Date(Date.now() - 3600000).toISOString(), // expired 1 hour ago
      };

      const detections = await rule.evaluate({
        organizationId: orgA,
        events,
        currentTime: new Date(),
        threatIndicators: [expiredIndicator],
      });

      expect(detections.length).toBe(0);
    });

    it('RULE-010: respects organization-configurable timezone offsets', async () => {
      const rule = new Rule010OffHoursAnomaly();

      // Action executed at 23:30 UTC on Tuesday
      // For a tenant in US Eastern (UTC-5), local time is 18:30 (during 06:00-22:00 business hours)
      const event: SecurityEvent = {
        eventId: 'tz-1',
        orgId: orgA,
        category: 'SYSTEM',
        eventType: 'admin.action',
        severity: 'MEDIUM',
        timestamp: '2026-11-03T23:30:00Z', // Tuesday 23:30 UTC = 18:30 EST
        sourceIp: '10.0.0.10',
        username: 'est-admin',
        sourceSystem: 'control-plane',
      };

      // With EST timezone offset (-5 hours): should NOT trigger
      const estDetections = await rule.evaluate(
        { organizationId: orgA, events: [event], currentTime: new Date() },
        { condition: { startHour: 6, endHour: 22, timezoneOffsetHours: -5 } }
      );
      expect(estDetections.length).toBe(0);

      // In UTC (offset 0): 23:30 is outside 06:00-22:00, so it DOES trigger
      const utcDetections = await rule.evaluate(
        { organizationId: orgA, events: [event], currentTime: new Date() },
        { condition: { startHour: 6, endHour: 22, timezoneOffsetHours: 0 } }
      );
      expect(utcDetections.length).toBe(1);
    });

    it('RULE-010: supports IANA timezone identifiers (e.g. America/New_York) with automatic DST calculation', async () => {
      const rule = new Rule010OffHoursAnomaly();

      // Action at 23:30 UTC on Tuesday (November 3, 2026) -> 18:30 EST in America/New_York (within 06:00-22:00 business hours)
      const event: SecurityEvent = {
        eventId: 'tz-iana-1',
        orgId: orgA,
        category: 'SYSTEM',
        eventType: 'admin.action',
        severity: 'MEDIUM',
        timestamp: '2026-11-03T23:30:00Z',
        sourceIp: '10.0.0.10',
        username: 'ny-admin',
        sourceSystem: 'control-plane',
      };

      const detections = await rule.evaluate(
        { organizationId: orgA, events: [event], currentTime: new Date() },
        { condition: { startHour: 6, endHour: 22, timezone: 'America/New_York' } }
      );
      expect(detections.length).toBe(0);

      // Early morning action at 08:30 UTC (03:30 AM EST in America/New_York): outside business hours, MUST trigger
      const earlyEvent: SecurityEvent = {
        eventId: 'tz-iana-2',
        orgId: orgA,
        category: 'SYSTEM',
        eventType: 'admin.action',
        severity: 'MEDIUM',
        timestamp: '2026-11-03T08:30:00Z',
        sourceIp: '10.0.0.10',
        username: 'ny-admin',
        sourceSystem: 'control-plane',
      };

      const earlyDetections = await rule.evaluate(
        { organizationId: orgA, events: [earlyEvent], currentTime: new Date() },
        { condition: { startHour: 6, endHour: 22, timezone: 'America/New_York' } }
      );
      expect(earlyDetections.length).toBe(1);
      expect(earlyDetections[0].evidence.details.effectiveTz).toBe('America/New_York');
      expect(earlyDetections[0].evidence.details.localHour).toBe(3);
    });

    it('gracefully handles events with completely missing metadata without throwing', async () => {
      const baseTime = Date.now();
      const events: SecurityEvent[] = [
        {
          eventId: 'null-meta-1',
          orgId: orgA,
          category: 'AUTHENTICATION',
          eventType: 'auth.login.failed',
          severity: 'LOW',
          timestamp: new Date(baseTime).toISOString(),
          sourceIp: '198.51.100.9',
          username: 'user',
          sourceSystem: 'sys',
        },
      ];

      const rules = engine.getRegisteredRules();
      for (const r of rules) {
        await expect(
          r.evaluate({ organizationId: orgA, events, currentTime: new Date() })
        ).resolves.toBeDefined();
      }
    });
  });

  // ==========================================================================
  // 5. Security & RBAC Adversarial Tests
  // ==========================================================================
  describe('Security & RBAC Adversarial Verification', () => {
    it('rejects unauthenticated requests to detection endpoints with 401 Unauthorized', async () => {
      const runRes = await request(app).post('/api/v1/detections/run').send({});
      expect(runRes.status).toBe(401);

      const listRes = await request(app).get('/api/v1/detections');
      expect(listRes.status).toBe(401);

      const rulesRes = await request(app).get('/api/v1/detection-rules');
      expect(rulesRes.status).toBe(401);
    });

    it('rejects expired JWT tokens with 401 Unauthorized', async () => {
      const expiredToken = jwtService.signAccessToken({
        userId: 'expired-user',
        email: 'expired@shield.corp',
        username: 'expired.user',
        role: 'SECURITY_ANALYST',
        orgId: orgA,
      }, { expiresInSeconds: -10 }); // Expired 10 seconds ago

      const res = await request(app)
        .get('/api/v1/detections')
        .set('Authorization', `Bearer ${expiredToken}`);

      expect(res.status).toBe(401);
      expect(res.body.error.code).toBe('UNAUTHORIZED_EXPIRED_TOKEN');
    });

    it('rejects tampered or forged JWT tokens with 401 Unauthorized', async () => {
      const forgedToken = analystTokenOrgA.slice(0, -6) + 'forged';
      const res = await request(app)
        .get('/api/v1/detections')
        .set('Authorization', `Bearer ${forgedToken}`);

      expect(res.status).toBe(401);
      expect(res.body.error.code).toBe('UNAUTHORIZED_INVALID_TOKEN');
    });

    it('rejects cross-tenant parameter tampering via x-organization-id with 403 Forbidden', async () => {
      // User is authenticated for orgA, but passes x-organization-id: orgB
      const res = await request(app)
        .get('/api/v1/detections')
        .set('Authorization', `Bearer ${analystTokenOrgA}`)
        .set('x-organization-id', orgB);

      expect(res.status).toBe(403);
      expect(res.body.error.code).toBe('FORBIDDEN_CROSS_TENANT_ACCESS');
    });

    it('rejects READ_ONLY_VIEWER on PATCH /api/v1/detection-rules/:ruleId with 403 Forbidden', async () => {
      const res = await request(app)
        .patch('/api/v1/detection-rules/RULE-001')
        .set('Authorization', `Bearer ${viewerTokenOrgA}`)
        .send({ threshold: 8 });

      expect(res.status).toBe(403);
      expect(res.body.error.code).toBe('FORBIDDEN_INSUFFICIENT_PERMISSIONS');
    });

    it('rejects tampered pagination cursor with 400 Bad Request (INVALID_CURSOR)', async () => {
      const tamperedCursor = 'eyJvcmdJZCI6Im9yZy1jeWJlci1zaGllbGQiLCJvZmZzZXQiOjEwfQ.invalidhmacsignature';

      const res = await request(app)
        .get(`/api/v1/detections?cursor=${tamperedCursor}`)
        .set('Authorization', `Bearer ${analystTokenOrgA}`);

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('INVALID_CURSOR');
    });
  });

  // ==========================================================================
  // 6. Phase 5 Final Merge Readiness Gate: Deduplication, Enrichment, Timezone
  // ==========================================================================
  describe('Phase 5 Final Merge Readiness Gate Verification', () => {
    // --- Section 2: Detection Deduplication Verification ---
    describe('Detection Deduplication Fingerprinting & Window Semantics', () => {
      it('duplicate events in the same fixed window produce identical dedupKey and are deduplicated in storage', async () => {
        const rule = new Rule001BruteForce();
        const baseEpoch = 1700000000000;
        const windowSec = 300;
        const bucket = Math.floor(baseEpoch / (windowSec * 1000));

        const key1 = rule.computeDedupKey(orgA, rule.id, '198.51.100.1', bucket);
        const key2 = rule.computeDedupKey(orgA, rule.id, '198.51.100.1', bucket);
        expect(key1).toBe(key2);

        const store = new MemoryStore();
        const detection1: Detection = {
          detectionId: generateUuidV7(baseEpoch),
          ruleId: rule.id,
          ruleName: rule.name,
          orgId: orgA,
          severity: 'HIGH',
          confidence: 85,
          category: 'AUTHENTICATION',
          title: 'Brute Force Alert',
          description: '5 failed logins',
          detectedAt: new Date(baseEpoch).toISOString(),
          relatedEventIds: ['ev-1', 'ev-2'],
          evidence: {
            matchedRuleId: rule.id,
            matchedThreshold: 5,
            actualCount: 5,
            timeWindowSeconds: windowSec,
          },
          status: 'ACTIVE',
          dedupKey: key1,
        };

        const res1 = await store.saveDetection(detection1);
        expect(res1.saved).toBe(true);
        expect(res1.isDuplicate).toBe(false);

        // Second detection with same dedupKey is marked duplicate and suppressed
        const detection2 = { ...detection1, detectionId: generateUuidV7(baseEpoch + 1000) };
        const res2 = await store.saveDetection(detection2);
        expect(res2.saved).toBe(false);
        expect(res2.isDuplicate).toBe(true);
      });

      it('distinct attacks against different entities in the same window produce distinct dedupKeys and both save', async () => {
        const rule = new Rule001BruteForce();
        const baseEpoch = 1700000000000;
        const bucket = Math.floor(baseEpoch / (300 * 1000));

        const keyEntity1 = rule.computeDedupKey(orgA, rule.id, '198.51.100.1', bucket);
        const keyEntity2 = rule.computeDedupKey(orgA, rule.id, '198.51.100.2', bucket);
        expect(keyEntity1).not.toBe(keyEntity2);

        const store = new MemoryStore();
        const d1: Detection = {
          detectionId: generateUuidV7(baseEpoch),
          ruleId: rule.id,
          ruleName: rule.name,
          orgId: orgA,
          severity: 'HIGH',
          confidence: 85,
          category: 'AUTHENTICATION',
          title: 'Attack 1',
          description: 'Entity 1',
          detectedAt: new Date(baseEpoch).toISOString(),
          relatedEventIds: ['ev-1'],
          evidence: { matchedRuleId: rule.id, matchedThreshold: 5, actualCount: 5, timeWindowSeconds: 300 },
          status: 'ACTIVE',
          dedupKey: keyEntity1,
        };
        const d2: Detection = {
          ...d1,
          detectionId: generateUuidV7(baseEpoch + 100),
          title: 'Attack 2',
          dedupKey: keyEntity2,
        };

        const r1 = await store.saveDetection(d1);
        const r2 = await store.saveDetection(d2);
        expect(r1.saved).toBe(true);
        expect(r2.saved).toBe(true);
      });

      it('events immediately before and after bucket boundary produce distinct dedupKeys without silent suppression', () => {
        const rule = new Rule001BruteForce();
        const windowSec = 300;
        const windowMs = windowSec * 1000;

        // Bucket boundary: T_boundary is a multiple of windowMs
        const bucketIndex = 500000;
        const boundaryMs = bucketIndex * windowMs;

        const justBeforeMs = boundaryMs - 1; // 1 ms before boundary -> bucketIndex - 1
        const atBoundaryMs = boundaryMs;     // exactly at boundary -> bucketIndex

        const bucketBefore = Math.floor(justBeforeMs / windowMs);
        const bucketAt = Math.floor(atBoundaryMs / windowMs);
        expect(bucketAt).toBe(bucketBefore + 1);

        const keyBefore = rule.computeDedupKey(orgA, rule.id, '198.51.100.1', bucketBefore);
        const keyAt = rule.computeDedupKey(orgA, rule.id, '198.51.100.1', bucketAt);
        expect(keyBefore).not.toBe(keyAt);
      });

      it('different organizations produce isolated dedupKeys and do not collide', async () => {
        const rule = new Rule001BruteForce();
        const baseEpoch = 1700000000000;
        const bucket = Math.floor(baseEpoch / (300 * 1000));

        const keyOrgA = rule.computeDedupKey(orgA, rule.id, '198.51.100.1', bucket);
        const keyOrgB = rule.computeDedupKey(orgB, rule.id, '198.51.100.1', bucket);
        expect(keyOrgA).not.toBe(keyOrgB);

        const store = new MemoryStore();
        const dOrgA: Detection = {
          detectionId: generateUuidV7(baseEpoch),
          ruleId: rule.id,
          ruleName: rule.name,
          orgId: orgA,
          severity: 'HIGH',
          confidence: 85,
          category: 'AUTHENTICATION',
          title: 'Org A Attack',
          description: 'Attack against Org A',
          detectedAt: new Date(baseEpoch).toISOString(),
          relatedEventIds: ['ev-a'],
          evidence: { matchedRuleId: rule.id, matchedThreshold: 5, actualCount: 5, timeWindowSeconds: 300 },
          status: 'ACTIVE',
          dedupKey: keyOrgA,
        };
        const dOrgB: Detection = {
          ...dOrgA,
          detectionId: generateUuidV7(baseEpoch + 50),
          orgId: orgB,
          title: 'Org B Attack',
          description: 'Attack against Org B',
          dedupKey: keyOrgB,
        };

        const resA = await store.saveDetection(dOrgA);
        const resB = await store.saveDetection(dOrgB);
        expect(resA.saved).toBe(true);
        expect(resB.saved).toBe(true);

        const listA = await store.getDetections(orgA);
        const listB = await store.getDetections(orgB);
        expect(listA.items.length).toBe(1);
        expect(listB.items.length).toBe(1);
        expect(listA.items[0].orgId).toBe(orgA);
        expect(listB.items[0].orgId).toBe(orgB);
      });

      it('concurrent saves of identical detection result in exactly one successful save and one duplicate', async () => {
        const store = new MemoryStore();
        const dedupKey = 'concurrent-test-dedup-hash-12345';
        const d1: Detection = {
          detectionId: generateUuidV7(),
          ruleId: 'RULE-001',
          ruleName: 'Brute Force',
          orgId: orgA,
          severity: 'HIGH',
          confidence: 85,
          category: 'AUTHENTICATION',
          title: 'Concurrent 1',
          description: 'Test concurrent write',
          detectedAt: new Date().toISOString(),
          relatedEventIds: ['ev-c1'],
          evidence: { matchedRuleId: 'RULE-001', matchedThreshold: 5, actualCount: 5, timeWindowSeconds: 300 },
          status: 'ACTIVE',
          dedupKey,
        };
        const d2 = { ...d1, detectionId: generateUuidV7() };

        const [r1, r2] = await Promise.all([store.saveDetection(d1), store.saveDetection(d2)]);
        const savedCount = (r1.saved ? 1 : 0) + (r2.saved ? 1 : 0);
        const dupCount = (r1.isDuplicate ? 1 : 0) + (r2.isDuplicate ? 1 : 0);
        expect(savedCount).toBe(1);
        expect(dupCount).toBe(1);
      });
    });

    // --- Section 3: Trusted Enrichment Verification ---
    describe('Trusted Enrichment & Provenance Invariants', () => {
      it('RULE-004: client-provided metadata.isVpn: true without trusted enrichment source does NOT suppress impossible travel', async () => {
        const rule = new Rule004ImpossibleTravel();
        const baseTime = Date.now();

        // Two logins from US and JP within 5 minutes, but untrusted client sent isVpn: true
        const untrustedEvents: SecurityEvent[] = [
          {
            eventId: generateUuidV7(baseTime - 300000),
            orgId: orgA,
            category: 'AUTHENTICATION',
            eventType: 'auth.login.success',
            severity: 'LOW',
            timestamp: new Date(baseTime - 300000).toISOString(),
            sourceIp: '198.51.100.1',
            username: 'alice',
            sourceSystem: 'client-app',
            metadata: { country: 'US', city: 'New York' },
          },
          {
            eventId: generateUuidV7(baseTime),
            orgId: orgA,
            category: 'AUTHENTICATION',
            eventType: 'auth.login.success',
            severity: 'LOW',
            timestamp: new Date(baseTime).toISOString(),
            sourceIp: '203.0.113.1',
            username: 'alice',
            sourceSystem: 'client-app',
            metadata: { country: 'JP', city: 'Tokyo', isVpn: true }, // Untrusted! No enrichmentSource!
          },
        ];

        const detections = await rule.evaluate({
          organizationId: orgA,
          events: untrustedEvents,
          currentTime: new Date(),
        });

        // The attack is NOT suppressed because isVpn lacked trusted enrichment provenance!
        expect(detections.length).toBe(1);
        expect(detections[0].ruleId).toBe('RULE-004');
      });

      it('RULE-004: missing location enrichment does not create unsupported conclusions', async () => {
        const rule = new Rule004ImpossibleTravel();
        const baseTime = Date.now();

        // Two logins with different IPs but NO location metadata (enrichment missing)
        const noGeoEvents: SecurityEvent[] = [
          {
            eventId: generateUuidV7(baseTime - 10000),
            orgId: orgA,
            category: 'AUTHENTICATION',
            eventType: 'auth.login.success',
            severity: 'LOW',
            timestamp: new Date(baseTime - 10000).toISOString(),
            sourceIp: '10.0.0.1',
            username: 'bob',
            sourceSystem: 'internal-portal',
          },
          {
            eventId: generateUuidV7(baseTime),
            orgId: orgA,
            category: 'AUTHENTICATION',
            eventType: 'auth.login.success',
            severity: 'LOW',
            timestamp: new Date(baseTime).toISOString(),
            sourceIp: '10.0.0.2',
            username: 'bob',
            sourceSystem: 'internal-portal',
          },
        ];

        const detections = await rule.evaluate({
          organizationId: orgA,
          events: noGeoEvents,
          currentTime: new Date(),
        });

        // Does NOT fire because missing enrichment prevents jumping to unsupported conclusions
        expect(detections.length).toBe(0);
      });

      it('RULE-005: rejects threat intelligence indicators lacking source provenance', async () => {
        const rule = new Rule005SuspiciousIp();
        const event: SecurityEvent = {
          eventId: generateUuidV7(),
          orgId: orgA,
          category: 'NETWORK',
          eventType: 'network.connection',
          severity: 'MEDIUM',
          timestamp: new Date().toISOString(),
          sourceIp: '198.51.100.222',
          username: 'charlie',
          sourceSystem: 'edge-gw',
        };

        // Indicator lacking source provenance (empty source)
        const unprovenancedIndicator = {
          indicatorId: 'ind-no-source',
          type: 'IP' as const,
          value: '198.51.100.222',
          severity: 'HIGH' as const,
          confidence: 90,
          source: '', // Empty source!
          description: 'Untrusted indicator',
          firstSeen: new Date().toISOString(),
          lastSeen: new Date().toISOString(),
          isFlagged: true,
          threatType: 'BOTNET',
        };

        const detections = await rule.evaluate({
          organizationId: orgA,
          events: [event],
          currentTime: new Date(),
          threatIndicators: [unprovenancedIndicator],
        });

        expect(detections.length).toBe(0);
      });

      it('RULE-005: client-provided isTorExitNode without trusted enrichment provenance does not trigger alert', async () => {
        const rule = new Rule005SuspiciousIp();
        const event: SecurityEvent = {
          eventId: generateUuidV7(),
          orgId: orgA,
          category: 'NETWORK',
          eventType: 'network.connection',
          severity: 'MEDIUM',
          timestamp: new Date().toISOString(),
          sourceIp: '198.51.100.223', // Not in known list
          username: 'charlie',
          sourceSystem: 'untrusted-client',
          metadata: { isTorExitNode: true }, // Client claimed Tor without enrichment source
        };

        const detections = await rule.evaluate({
          organizationId: orgA,
          events: [event],
          currentTime: new Date(),
        });

        // Untrusted client claim ignored
        expect(detections.length).toBe(0);
      });

      it('EventService sanitizes client-provided isVpn and isTorExitNode to client_declared_* at ingestion', async () => {
        const res = await request(app)
          .post('/api/v1/events')
          .set('Authorization', `Bearer ${analystTokenOrgA}`)
          .send({
            eventType: 'auth.login.success',
            severity: 'LOW',
            category: 'AUTHENTICATION',
            sourceIp: '198.51.100.55',
            username: 'sanitized-user',
            sourceSystem: 'public-api',
            metadata: {
              isVpn: true,
              isTorExitNode: true,
              legitimateField: 'user-session-123',
            },
          });

        expect(res.status).toBe(202);
        const eventId = res.body.data.eventId;

        const getRes = await request(app)
          .get(`/api/v1/events/${eventId}`)
          .set('Authorization', `Bearer ${analystTokenOrgA}`);

        expect(getRes.status).toBe(200);
        const storedEvent = getRes.body.data;
        expect(storedEvent.metadata.isVpn).toBeUndefined();
        expect(storedEvent.metadata.isTorExitNode).toBeUndefined();
        expect(storedEvent.metadata.client_declared_isVpn).toBe(true);
        expect(storedEvent.metadata.client_declared_isTorExitNode).toBe(true);
        expect(storedEvent.metadata.legitimateField).toBe('user-session-123');
      });
    });

    // --- Section 4: Timezone Tests (RULE-010) ---
    describe('RULE-010 Timezone, DST, Weekend, and Boundary Verification', () => {
      const rule = new Rule010OffHoursAnomaly();

      it('correctly handles DST transitions in America/New_York (winter EST vs summer EDT)', async () => {
        // Winter: Jan 14, 2026 at 23:30 UTC -> EST is UTC-5 -> 18:30 local (during 06:00-22:00 business hours)
        const winterEvent: SecurityEvent = {
          eventId: generateUuidV7(),
          orgId: orgA,
          category: 'SYSTEM',
          eventType: 'admin.action',
          severity: 'MEDIUM',
          timestamp: '2026-01-14T23:30:00Z',
          sourceIp: '10.0.0.1',
          username: 'winter-admin',
          sourceSystem: 'k8s',
        };
        const winterDetections = await rule.evaluate(
          { organizationId: orgA, events: [winterEvent], currentTime: new Date() },
          { condition: { startHour: 6, endHour: 22, timezone: 'America/New_York' } }
        );
        expect(winterDetections.length).toBe(0);

        // Summer: Jul 15, 2026 at 01:30 UTC -> EDT is UTC-4 -> 21:30 local (during 06:00-22:00 business hours)
        const summerEvent1: SecurityEvent = {
          eventId: generateUuidV7(),
          orgId: orgA,
          category: 'SYSTEM',
          eventType: 'admin.action',
          severity: 'MEDIUM',
          timestamp: '2026-07-15T01:30:00Z',
          sourceIp: '10.0.0.1',
          username: 'summer-admin',
          sourceSystem: 'k8s',
        };
        const summerDetections1 = await rule.evaluate(
          { organizationId: orgA, events: [summerEvent1], currentTime: new Date() },
          { condition: { startHour: 6, endHour: 22, timezone: 'America/New_York' } }
        );
        expect(summerDetections1.length).toBe(0);

        // Summer: Jul 15, 2026 at 02:30 UTC -> EDT is UTC-4 -> 22:30 local (OUTSIDE 06:00-22:00 business hours!)
        const summerEvent2: SecurityEvent = {
          eventId: generateUuidV7(),
          orgId: orgA,
          category: 'SYSTEM',
          eventType: 'admin.action',
          severity: 'MEDIUM',
          timestamp: '2026-07-15T02:30:00Z',
          sourceIp: '10.0.0.1',
          username: 'summer-admin',
          sourceSystem: 'k8s',
        };
        const summerDetections2 = await rule.evaluate(
          { organizationId: orgA, events: [summerEvent2], currentTime: new Date() },
          { condition: { startHour: 6, endHour: 22, timezone: 'America/New_York' } }
        );
        expect(summerDetections2.length).toBe(1);
      });

      it('supports configurable weekend schedules (e.g. Middle East Friday/Saturday weekend)', async () => {
        // Nov 6, 2026 is a Friday. Nov 8, 2026 is a Sunday.
        // In Middle East config, weekendDays = [5, 6] (Friday=5, Saturday=6). Sunday=0 is a normal workday.
        const fridayEvent: SecurityEvent = {
          eventId: generateUuidV7(),
          orgId: orgA,
          category: 'SYSTEM',
          eventType: 'admin.action',
          severity: 'MEDIUM',
          timestamp: '2026-11-06T10:00:00Z', // Friday 10:00 UTC
          sourceIp: '10.0.0.1',
          username: 'dubai-admin',
          sourceSystem: 'k8s',
        };
        const sundayEvent: SecurityEvent = {
          eventId: generateUuidV7(),
          orgId: orgA,
          category: 'SYSTEM',
          eventType: 'admin.action',
          severity: 'MEDIUM',
          timestamp: '2026-11-08T10:00:00Z', // Sunday 10:00 UTC
          sourceIp: '10.0.0.1',
          username: 'dubai-admin',
          sourceSystem: 'k8s',
        };

        const config = {
          condition: {
            startHour: 6,
            endHour: 22,
            timezone: 'Asia/Dubai', // UTC+4
            weekendDays: [5, 6], // Friday & Saturday are weekend
          },
        };

        // Friday is weekend -> triggers detection
        const fridayDetections = await rule.evaluate(
          { organizationId: orgA, events: [fridayEvent], currentTime: new Date() },
          config
        );
        expect(fridayDetections.length).toBe(1);

        // Sunday is normal business day -> 0 detections
        const sundayDetections = await rule.evaluate(
          { organizationId: orgA, events: [sundayEvent], currentTime: new Date() },
          config
        );
        expect(sundayDetections.length).toBe(0);
      });

      it('handles exact business hour boundary times with precision', async () => {
        // Business hours: 09:00 to 17:00 UTC
        const config = { condition: { startHour: 9, endHour: 17, timezone: 'UTC' } };

        // 08:59:59 UTC -> off-hours (triggers)
        const justBeforeStart: SecurityEvent = {
          eventId: generateUuidV7(),
          orgId: orgA,
          category: 'SYSTEM',
          eventType: 'admin.action',
          severity: 'MEDIUM',
          timestamp: '2026-11-03T08:59:59Z',
          sourceIp: '10.0.0.1',
          username: 'boundary-admin',
          sourceSystem: 'k8s',
        };
        const d1 = await rule.evaluate({ organizationId: orgA, events: [justBeforeStart], currentTime: new Date() }, config);
        expect(d1.length).toBe(1);

        // 09:00:00 UTC -> business hours (does not trigger)
        const exactStart: SecurityEvent = {
          ...justBeforeStart,
          eventId: generateUuidV7(),
          timestamp: '2026-11-03T09:00:00Z',
        };
        const d2 = await rule.evaluate({ organizationId: orgA, events: [exactStart], currentTime: new Date() }, config);
        expect(d2.length).toBe(0);

        // 16:59:59 UTC -> business hours (does not trigger)
        const justBeforeEnd: SecurityEvent = {
          ...justBeforeStart,
          eventId: generateUuidV7(),
          timestamp: '2026-11-03T16:59:59Z',
        };
        const d3 = await rule.evaluate({ organizationId: orgA, events: [justBeforeEnd], currentTime: new Date() }, config);
        expect(d3.length).toBe(0);

        // 17:00:00 UTC -> off-hours (triggers)
        const exactEnd: SecurityEvent = {
          ...justBeforeStart,
          eventId: generateUuidV7(),
          timestamp: '2026-11-03T17:00:00Z',
        };
        const d4 = await rule.evaluate({ organizationId: orgA, events: [exactEnd], currentTime: new Date() }, config);
        expect(d4.length).toBe(1);
      });

      it('safely skips evaluation without producing misleading results if invalid timezone reaches engine', async () => {
        // Event at 03:00 UTC (would be off-hours in UTC)
        const event: SecurityEvent = {
          eventId: generateUuidV7(),
          orgId: orgA,
          category: 'SYSTEM',
          eventType: 'admin.action',
          severity: 'MEDIUM',
          timestamp: '2026-11-03T03:00:00Z',
          sourceIp: '10.0.0.1',
          username: 'safe-admin',
          sourceSystem: 'k8s',
        };

        // Pass invalid timezone string
        const detections = await rule.evaluate(
          { organizationId: orgA, events: [event], currentTime: new Date() },
          { condition: { startHour: 6, endHour: 22, timezone: 'Invalid/NonExistent_Zone' } }
        );

        // Does not silently evaluate against UTC (which would have produced a false alert); safely skips evaluation
        expect(Array.isArray(detections)).toBe(true);
        expect(detections.length).toBe(0);
      });
    });

    // --- Final Security Sign-off Gate ---
    describe('Final Security Sign-off: Corporate VPN, Timezone Settings & Threat Intel Provenance', () => {
      it('RULE-004: client-supplied sourceSystem: corporate-vpn CANNOT suppress impossible travel without authorized gateway IP or trusted enrichment', async () => {
        const rule = new Rule004ImpossibleTravel();
        const baseTime = Date.now();

        // Adversary supplies sourceSystem: 'corporate-vpn' and metadata: { isVpn: true }
        const spoofedVpnEvents: SecurityEvent[] = [
          {
            eventId: generateUuidV7(baseTime - 300000),
            orgId: orgA,
            category: 'AUTHENTICATION',
            eventType: 'auth.login.success',
            severity: 'LOW',
            timestamp: new Date(baseTime - 300000).toISOString(),
            sourceIp: '198.51.100.1',
            username: 'alice',
            sourceSystem: 'okta',
            metadata: { country: 'US', city: 'New York' },
          },
          {
            eventId: generateUuidV7(baseTime),
            orgId: orgA,
            category: 'AUTHENTICATION',
            eventType: 'auth.login.success',
            severity: 'LOW',
            timestamp: new Date(baseTime).toISOString(),
            sourceIp: '203.0.113.1',
            username: 'alice',
            sourceSystem: 'corporate-vpn', // Spoofed client claim!
            metadata: { country: 'JP', city: 'Tokyo', isVpn: true }, // Spoofed client claim!
          },
        ];

        // Without verified authorizedGatewayIps, detection triggers (attack is NOT suppressed)
        const unverifiedDetections = await rule.evaluate({
          organizationId: orgA,
          events: spoofedVpnEvents,
          currentTime: new Date(),
        });
        expect(unverifiedDetections.length).toBe(1);
        expect(unverifiedDetections[0].ruleId).toBe('RULE-004');

        // When sourceIp matches an authorized corporate gateway registry IP, suppression is granted
        const verifiedDetections = await rule.evaluate(
          { organizationId: orgA, events: spoofedVpnEvents, currentTime: new Date() },
          { condition: { authorizedGatewayIps: ['203.0.113.1'] } }
        );
        expect(verifiedDetections.length).toBe(0);
      });

      it('PATCH /api/v1/detection-rules/:ruleId validates IANA timezone and rejects invalid timezones with 400 Bad Request', async () => {
        const res = await request(app)
          .patch('/api/v1/detection-rules/RULE-010')
          .set('Authorization', `Bearer ${orgAdminTokenOrgA}`)
          .send({
            condition: {
              timezone: 'Mars/Olympus_Mons', // Invalid IANA timezone
              startHour: 8,
              endHour: 18,
            },
          });

        expect(res.status).toBe(400);
        expect(res.body.error.code).toBe('INVALID_TIMEZONE');
        expect(res.body.error.message).toContain('Invalid IANA timezone identifier');

        // Valid IANA timezone succeeds
        const validRes = await request(app)
          .patch('/api/v1/detection-rules/RULE-010')
          .set('Authorization', `Bearer ${orgAdminTokenOrgA}`)
          .send({
            condition: {
              timezone: 'Europe/London',
              startHour: 8,
              endHour: 18,
            },
          });

        expect(validRes.status).toBe(200);
        expect(validRes.body.data.condition.timezone).toBe('Europe/London');
      });

      it('RULE-005: rejects threat intelligence indicators from unauthorized or unverified sources', async () => {
        const rule = new Rule005SuspiciousIp();
        const event: SecurityEvent = {
          eventId: generateUuidV7(),
          orgId: orgA,
          category: 'NETWORK',
          eventType: 'network.connection',
          severity: 'HIGH',
          timestamp: new Date().toISOString(),
          sourceIp: '198.51.100.240',
          username: 'test-user',
          sourceSystem: 'firewall',
        };

        // Indicator from unauthorized source
        const unauthorizedIndicator = {
          indicatorId: generateUuidV7(),
          type: 'IP' as const,
          value: '198.51.100.240',
          severity: 'HIGH' as const,
          confidence: 90,
          source: 'UNVERIFIED_BLOG_FEED', // Unauthorized!
          firstSeen: new Date().toISOString(),
          lastSeen: new Date().toISOString(),
          isFlagged: true,
          threatType: 'C2',
        };

        const res1 = await rule.evaluate({
          organizationId: orgA,
          events: [event],
          currentTime: new Date(),
          threatIndicators: [unauthorizedIndicator],
        });
        expect(res1.length).toBe(0);

        // Indicator from authorized source (ABUSE_CH)
        const authorizedIndicator = {
          ...unauthorizedIndicator,
          source: 'ABUSE_CH',
        };

        const res2 = await rule.evaluate({
          organizationId: orgA,
          events: [event],
          currentTime: new Date(),
          threatIndicators: [authorizedIndicator],
        });
        expect(res2.length).toBe(1);
        expect(res2[0].ruleId).toBe('RULE-005');
      });

      it('POST /api/v1/threat-indicators enforces RBAC, validates sources, and prevents unauthorized modification', async () => {
        const newIndicator = {
          type: 'IP',
          value: '198.51.100.199',
          threatType: 'BOTNET',
          severity: 'HIGH',
          confidence: 90,
          source: 'ABUSE_CH',
          description: 'Malicious scanner IP',
        };

        // 1. Unauthenticated request -> 401
        const unauthRes = await request(app)
          .post('/api/v1/threat-indicators')
          .send(newIndicator);
        expect(unauthRes.status).toBe(401);

        // 2. VIEWER role -> 403 Forbidden
        const viewerRes = await request(app)
          .post('/api/v1/threat-indicators')
          .set('Authorization', `Bearer ${viewerTokenOrgA}`)
          .send(newIndicator);
        expect(viewerRes.status).toBe(403);
        expect(viewerRes.body.error.code).toBe('FORBIDDEN_INSUFFICIENT_PERMISSIONS');

        // 3. Unauthorized source provider -> 400 Bad Request
        const badSourceRes = await request(app)
          .post('/api/v1/threat-indicators')
          .set('Authorization', `Bearer ${analystTokenOrgA}`)
          .send({ ...newIndicator, source: 'RANDOM_SCRAPER' });
        expect(badSourceRes.status).toBe(400);
        expect(badSourceRes.body.error.code).toBe('UNAUTHORIZED_INDICATOR_SOURCE');

        // 4. Authorized SECURITY_ANALYST with valid provider -> 201 Created
        const successRes = await request(app)
          .post('/api/v1/threat-indicators')
          .set('Authorization', `Bearer ${analystTokenOrgA}`)
          .send(newIndicator);
        expect(successRes.status).toBe(201);
        expect(successRes.body.data.value).toBe('198.51.100.199');
        expect(successRes.body.data.source).toBe('ABUSE_CH');

        // 5. GET /api/v1/threat-indicators is readable by authenticated users
        const getRes = await request(app)
          .get('/api/v1/threat-indicators')
          .set('Authorization', `Bearer ${viewerTokenOrgA}`);
        expect(getRes.status).toBe(200);
        expect(getRes.body.data.indicators.length).toBeGreaterThanOrEqual(1);
      });
    });
  });
});
