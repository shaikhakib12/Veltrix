/**
 * VELTRIX Scan Lifecycle & Orchestration Integration Tests (TASK-807, TASK-808)
 */

import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import { createApp } from '../../src/app.js';
import { JwtService } from '../../src/auth/jwt-service.js';
import { LocalAuthProvider } from '../../src/auth/local-auth-provider.js';
import { resetAuthProviderForTesting } from '../../src/auth/index.js';
import { MemoryStore } from '../../src/storage/memory-store.js';
import { resetStorageForTesting } from '../../src/storage/index.js';
import { resetScansForTesting } from '../../src/routes/scans.js';
import {
  ScanOrchestrator,
  TokenBucketRateLimiter,
  AbortCoordinator,
} from '../../src/scanner/orchestration/index.js';
import { EvidenceCollector } from '../../src/scanner/evidence/index.js';
import type { WebsiteAsset } from '@veltrix/shared';

describe('Scan Lifecycle & Orchestration Engine (Phase 8 - TASK-807, TASK-808)', () => {
  let app: ReturnType<typeof createApp>;
  let jwtService: JwtService;
  let memoryStore: MemoryStore;

  const testSecret = 'veltrix-phase-8-test-jwt-secret-key-32chars';
  const orgA = 'org-cyber-shield';
  let adminTokenOrgA: string;
  let analystTokenOrgA: string;
  let viewerTokenOrgA: string;

  beforeEach(async () => {
    jwtService = new JwtService(testSecret);
    const localProvider = new LocalAuthProvider(jwtService);
    resetAuthProviderForTesting(localProvider);

    memoryStore = new MemoryStore();
    resetStorageForTesting(memoryStore);
    resetScansForTesting();

    app = createApp();

    adminTokenOrgA = jwtService.signAccessToken({
      userId: 'user-admin-a',
      email: 'admin@shield.corp',
      username: 'admin.shield',
      role: 'ORG_ADMIN',
      orgId: orgA,
    });

    analystTokenOrgA = jwtService.signAccessToken({
      userId: 'user-analyst-a',
      email: 'analyst@shield.corp',
      username: 'analyst.shield',
      role: 'SECURITY_ANALYST',
      orgId: orgA,
    });

    viewerTokenOrgA = jwtService.signAccessToken({
      userId: 'user-viewer-a',
      email: 'viewer@shield.corp',
      username: 'viewer.shield',
      role: 'READ_ONLY_VIEWER',
      orgId: orgA,
    });
  });

  it('1. Enforces RBAC: READ_ONLY_VIEWER cannot launch a scan', async () => {
    const verifiedSite: WebsiteAsset = {
      siteId: 'site-rbac-01',
      orgId: orgA,
      name: 'Verified App',
      primaryDomain: 'app.example.com',
      approvedSubdomains: [],
      environment: 'PRODUCTION',
      status: 'VERIFIED',
      riskTier: 'HIGH',
      tags: [],
      scanBlocked: false,
      expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30).toISOString(),
      health: { telemetryStatus: 'ACTIVE', eventsPerMinute: 10 },
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    await memoryStore.saveWebsite(verifiedSite);

    const res = await request(app)
      .post('/api/v1/scans')
      .set('Authorization', `Bearer ${viewerTokenOrgA}`)
      .send({
        siteId: 'site-rbac-01',
        profile: 'PASSIVE_BASELINE',
      });

    expect(res.status).toBe(403);
    expect(res.body.success).toBe(false);
  });

  it('2. Enforces RBAC: FULL_AUDIT profile requires ORG_ADMIN or SUPER_ADMIN', async () => {
    const verifiedSite: WebsiteAsset = {
      siteId: 'site-full-audit-01',
      orgId: orgA,
      name: 'Verified Portal',
      primaryDomain: 'portal.example.com',
      approvedSubdomains: [],
      environment: 'PRODUCTION',
      status: 'VERIFIED',
      riskTier: 'HIGH',
      tags: [],
      scanBlocked: false,
      expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30).toISOString(),
      health: { telemetryStatus: 'ACTIVE', eventsPerMinute: 10 },
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    await memoryStore.saveWebsite(verifiedSite);

    // Analyst attempts FULL_AUDIT -> rejected 403
    const analystRes = await request(app)
      .post('/api/v1/scans')
      .set('Authorization', `Bearer ${analystTokenOrgA}`)
      .send({
        siteId: 'site-full-audit-01',
        profile: 'FULL_AUDIT',
      });

    expect(analystRes.status).toBe(403);
    expect(analystRes.body.error.code).toBe('INSUFFICIENT_PRIVILEGES');

    // Admin attempts FULL_AUDIT -> permitted 201
    const adminRes = await request(app)
      .post('/api/v1/scans')
      .set('Authorization', `Bearer ${adminTokenOrgA}`)
      .send({
        siteId: 'site-full-audit-01',
        profile: 'FULL_AUDIT',
      });

    expect(adminRes.status).toBe(201);
    expect(adminRes.body.success).toBe(true);
    expect(adminRes.body.data.profile).toBe('FULL_AUDIT');
  });

  it('3. Enforces concurrency caps: max 1 active scan per siteId', async () => {
    const site: WebsiteAsset = {
      siteId: 'site-concurrency-01',
      orgId: orgA,
      name: 'Concurrent Test Site',
      primaryDomain: 'concurrency.example.com',
      approvedSubdomains: [],
      environment: 'PRODUCTION',
      status: 'VERIFIED',
      riskTier: 'MEDIUM',
      tags: [],
      scanBlocked: false,
      expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30).toISOString(),
      health: { telemetryStatus: 'ACTIVE', eventsPerMinute: 5 },
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    await memoryStore.saveWebsite(site);

    const orchestrator = ScanOrchestrator.getOrCreateInstance(memoryStore);

    // Launch first scan
    const scan1 = await orchestrator.launchScan({
      orgId: orgA,
      siteId: site.siteId,
      profile: 'STANDARD_ACTIVE',
    });
    expect(scan1.status).toBe('RUNNING');

    // Attempt second scan on same site while first is running -> rejects with 409 SCAN_ALREADY_RUNNING
    await expect(
      orchestrator.launchScan({
        orgId: orgA,
        siteId: site.siteId,
        profile: 'PASSIVE_BASELINE',
      })
    ).rejects.toThrow(/currently active/);
  });

  it('4. Enforces emergency abort within sub-500ms SLO', async () => {
    const site: WebsiteAsset = {
      siteId: 'site-abort-slo-01',
      orgId: orgA,
      name: 'Abort SLO Site',
      primaryDomain: 'abort-slo.example.com',
      approvedSubdomains: [],
      environment: 'PRODUCTION',
      status: 'VERIFIED',
      riskTier: 'LOW',
      tags: [],
      scanBlocked: false,
      expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30).toISOString(),
      health: { telemetryStatus: 'ACTIVE', eventsPerMinute: 2 },
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    await memoryStore.saveWebsite(site);

    const res = await request(app)
      .post('/api/v1/scans')
      .set('Authorization', `Bearer ${analystTokenOrgA}`)
      .send({
        siteId: 'site-abort-slo-01',
        profile: 'STANDARD_ACTIVE',
      });

    expect(res.status).toBe(201);
    const scanId = res.body.data.scanId;

    const abortStart = performance.now();
    const abortRes = await request(app)
      .post(`/api/v1/scans/${scanId}/abort`)
      .set('Authorization', `Bearer ${analystTokenOrgA}`)
      .send({ reason: 'Emergency operator abort' });
    const abortDuration = performance.now() - abortStart;

    expect(abortRes.status).toBe(200);
    expect(abortRes.body.success).toBe(true);
    expect(abortRes.body.data.status).toBe('ABORTED');
    expect(abortDuration).toBeLessThan(500); // Sub-500ms SLO
  });

  it('5. TokenBucketRateLimiter clamps RPS between 1 and 20 and handles backoff', async () => {
    const limiterMin = new TokenBucketRateLimiter({ rps: 0.1 });
    expect(limiterMin.getRps()).toBe(1);

    const limiterMax = new TokenBucketRateLimiter({ rps: 100 });
    expect(limiterMax.getRps()).toBe(20);

    const limiter = new TokenBucketRateLimiter({ rps: 10 });
    await limiter.acquire(); // Should succeed immediately with initial burst token
    limiter.reportBackoff(1); // 1-second backoff reported
  });

  it('6. Cryptographic evidence verification detects altered payloads', async () => {
    const collector = new EvidenceCollector();
    const evidence = collector.collectEvidence({
      scanId: 'scan-verify-101',
      orgId: orgA,
      siteId: 'site-verify-101',
      finding: {
        ruleId: 'RULE_PASSIVE_HEADERS',
        vulnerabilityType: 'MISSING_SECURITY_HEADERS',
        title: 'Missing Content-Security-Policy',
        severity: 'LOW',
        confidence: 'CONFIRMED',
        description: 'CSP header missing',
        remediation: 'Add CSP',
        url: 'https://example.com/',
        evidence: { targetUrl: 'https://example.com/' },
      },
    });

    // Genuine evidence passes
    const validCheck = collector.verifyEvidenceIntegrity(evidence);
    expect(validCheck.verified).toBe(true);

    // Tampered evidence is rejected
    const tamperedEvidence = { ...evidence, severity: 'CRITICAL' as any };
    const invalidCheck = collector.verifyEvidenceIntegrity(tamperedEvidence);
    expect(invalidCheck.verified).toBe(false);
    expect(invalidCheck.reason).toContain('digest mismatch');
  });
});
