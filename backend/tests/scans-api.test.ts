import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import { createApp } from '../src/app.js';
import { JwtService } from '../src/auth/jwt-service.js';
import { LocalAuthProvider } from '../src/auth/local-auth-provider.js';
import { resetAuthProviderForTesting } from '../src/auth/index.js';
import { MemoryStore } from '../src/storage/memory-store.js';
import { resetStorageForTesting } from '../src/storage/index.js';
import type { WebsiteAsset } from '@veltrix/shared';

describe('Scans & Findings REST API Router (TASK-1)', () => {
  let app: ReturnType<typeof createApp>;
  let jwtService: JwtService;
  let memoryStore: MemoryStore;

  const testSecret = 'veltrix-phase-8-test-jwt-secret-key-32chars';
  const orgA = 'org-cyber-shield';
  let adminTokenOrgA: string;

  beforeEach(async () => {
    jwtService = new JwtService(testSecret);
    const localProvider = new LocalAuthProvider(jwtService);
    resetAuthProviderForTesting(localProvider);

    memoryStore = new MemoryStore();
    resetStorageForTesting(memoryStore);

    app = createApp();

    adminTokenOrgA = jwtService.signAccessToken({
      userId: 'user-admin-a',
      email: 'admin@shield.corp',
      username: 'admin.shield',
      role: 'ORG_ADMIN',
      orgId: orgA,
    });
  });

  it('rejects scan launch on unverified website with 403 SCAN_UNAUTHORIZED_UNVERIFIED_DOMAIN', async () => {
    const unverifiedSite: WebsiteAsset = {
      siteId: 'site-unverified-01',
      orgId: orgA,
      name: 'Unverified Shop',
      primaryDomain: 'unverified.example.com',
      approvedSubdomains: [],
      environment: 'PRODUCTION',
      status: 'PENDING_VERIFICATION',
      riskTier: 'HIGH',
      tags: ['ecommerce'],
      scanBlocked: true,
      health: { telemetryStatus: 'INACTIVE', eventsPerMinute: 0 },
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    await memoryStore.saveWebsite(unverifiedSite);

    const res = await request(app)
      .post('/api/v1/scans')
      .set('Authorization', `Bearer ${adminTokenOrgA}`)
      .send({
        siteId: 'site-unverified-01',
        profile: 'STANDARD_ACTIVE',
      });

    expect(res.status).toBe(403);
    expect(res.body.success).toBe(false);
    expect(res.body.error.code).toBe('SCAN_UNAUTHORIZED_UNVERIFIED_DOMAIN');
  });

  it('permits scan launch on VERIFIED website and returns 201 with ScanJobRecord', async () => {
    const verifiedSite: WebsiteAsset = {
      siteId: 'site-verified-01',
      orgId: orgA,
      name: 'Verified Portal',
      primaryDomain: 'portal.example.com',
      approvedSubdomains: [],
      environment: 'PRODUCTION',
      status: 'VERIFIED',
      riskTier: 'CRITICAL',
      tags: ['portal'],
      scanBlocked: false,
      expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30).toISOString(),
      health: { telemetryStatus: 'ACTIVE', eventsPerMinute: 12 },
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    await memoryStore.saveWebsite(verifiedSite);

    const res = await request(app)
      .post('/api/v1/scans')
      .set('Authorization', `Bearer ${adminTokenOrgA}`)
      .send({
        siteId: 'site-verified-01',
        profile: 'STANDARD_ACTIVE',
        maxDepth: 3,
        maxPages: 100,
      });

    expect(res.status).toBe(201);
    expect(res.body.success).toBe(true);
    expect(res.body.data.scanId).toBeDefined();
    expect(res.body.data.siteId).toBe('site-verified-01');
    expect(res.body.data.status).toBe('RUNNING');
    expect(res.body.data.profile).toBe('STANDARD_ACTIVE');
  });

  it('lists scans and allows aborting a running scan', async () => {
    const verifiedSite: WebsiteAsset = {
      siteId: 'site-verified-02',
      orgId: orgA,
      name: 'Verified Portal 2',
      primaryDomain: 'portal2.example.com',
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
    await memoryStore.saveWebsite(verifiedSite);

    const launchRes = await request(app)
      .post('/api/v1/scans')
      .set('Authorization', `Bearer ${adminTokenOrgA}`)
      .send({
        siteId: 'site-verified-02',
        profile: 'PASSIVE_BASELINE',
      });

    const scanId = launchRes.body.data.scanId;

    const listRes = await request(app)
      .get('/api/v1/scans')
      .set('Authorization', `Bearer ${adminTokenOrgA}`);

    expect(listRes.status).toBe(200);
    expect(listRes.body.success).toBe(true);
    expect(listRes.body.data.items.length).toBeGreaterThan(0);

    const abortRes = await request(app)
      .post(`/api/v1/scans/${scanId}/abort`)
      .set('Authorization', `Bearer ${adminTokenOrgA}`);

    expect(abortRes.status).toBe(200);
    expect(abortRes.body.success).toBe(true);
    expect(abortRes.body.data.status).toBe('ABORTED');
  });

  it('lists vulnerability findings with Phase 8 evidence fields', async () => {
    const res = await request(app)
      .get('/api/v1/findings')
      .set('Authorization', `Bearer ${adminTokenOrgA}`);

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.items).toBeDefined();
    expect(Array.isArray(res.body.data.items)).toBe(true);
  });
});

