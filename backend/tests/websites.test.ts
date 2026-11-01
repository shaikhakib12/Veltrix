import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import { createApp } from '../src/app.js';
import { getStorage } from '../src/storage/index.js';
import { JwtService } from '../src/auth/jwt-service.js';
import { LocalAuthProvider } from '../src/auth/local-auth-provider.js';
import { resetAuthProviderForTesting } from '../src/auth/index.js';
import { MemoryStore } from '../src/storage/memory-store.js';
import { resetStorageForTesting } from '../src/storage/index.js';
import type { DnsResolverInterface, HttpFetcherInterface } from '../src/services/domain-verification.js';

describe('Phase 6: Website Asset Inventory & Domain Ownership Verification (TASK-601 to TASK-603)', () => {
  let app: any;
  let storage: any;
  let authProvider: any;

  let orgAdminTokenA: string;
  let orgAnalystTokenA: string;
  let orgAdminTokenB: string;

  // Mock DNS Resolver and HTTP Fetcher
  const mockDnsRecords = new Map<string, string[][]>();
  const mockHttpResponses = new Map<string, { status: number; data: unknown }>();

  const testDnsResolver: DnsResolverInterface = {
    async resolveTxt(host: string): Promise<string[][]> {
      const records = mockDnsRecords.get(host.toLowerCase());
      if (!records) {
        throw new Error(`ENOTFOUND: Mock DNS record for '${host}' not found.`);
      }
      return records;
    },
  };

  const testHttpFetcher: HttpFetcherInterface = {
    async fetch(url: string): Promise<{ status: number; data: unknown }> {
      const resp = mockHttpResponses.get(url);
      if (!resp) {
        return { status: 404, data: null };
      }
      return resp;
    },
  };

  let jwtService: JwtService;

  beforeEach(async () => {
    jwtService = new JwtService('test-secret-phase-6-jwt-key-32chars');
    const localProvider = new LocalAuthProvider(jwtService);
    resetAuthProviderForTesting(localProvider);

    storage = new MemoryStore();
    resetStorageForTesting(storage);

    mockDnsRecords.clear();
    mockHttpResponses.clear();

    app = createApp();

    orgAdminTokenA = jwtService.signAccessToken({
      userId: 'usr-admin-a',
      username: 'admin.alpha',
      email: 'admin@alpha.org',
      role: 'ORG_ADMIN',
      orgId: 'org-alpha',
    });

    orgAnalystTokenA = jwtService.signAccessToken({
      userId: 'usr-analyst-a',
      username: 'analyst.alpha',
      email: 'analyst@alpha.org',
      role: 'SECURITY_ANALYST',
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

  describe('1. Website Registration & Validation (TASK-601)', () => {
    it('successfully registers website and generates cryptographic verification challenge', async () => {
      const res = await request(app)
        .post('/api/v1/websites')
        .set('Authorization', `Bearer ${orgAdminTokenA}`)
        .send({
          name: 'Alpha Portal',
          primaryDomain: 'portal.alpha.org',
          approvedSubdomains: ['api.alpha.org', 'auth.alpha.org'],
          environment: 'PRODUCTION',
          riskTier: 'CRITICAL',
          tags: ['ecommerce', 'pci-dss'],
        });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.site).toBeDefined();

      const site = res.body.site;
      expect(site.siteId).toMatch(/^site-/);
      expect(site.orgId).toBe('org-alpha');
      expect(site.primaryDomain).toBe('portal.alpha.org');
      expect(site.approvedSubdomains).toEqual(['api.alpha.org', 'auth.alpha.org']);
      expect(site.status).toBe('PENDING_VERIFICATION');
      expect(site.scanBlocked).toBe(true); // Unverified websites cannot be scanned

      // Verification challenge fields
      expect(site.verificationToken).toMatch(/^vltx_tok_/);
      expect(site.dnsTxtRecord.host).toBe('_veltrix-challenge.portal.alpha.org');
      expect(site.dnsTxtRecord.value).toBe(`veltrix-verify=org-alpha.${site.verificationToken}`);
      expect(site.httpChallenge.url).toBe(`https://portal.alpha.org/.well-known/veltrix-challenge/${site.verificationToken}`);
      expect(site.httpChallenge.expectedBody.veltrixChallengeToken).toBe(site.verificationToken);
      expect(site.httpChallenge.expectedBody.orgId).toBe('org-alpha');
    });

    it('rejects invalid FQDNs with protocols, paths, or illegal characters', async () => {
      const res = await request(app)
        .post('/api/v1/websites')
        .set('Authorization', `Bearer ${orgAdminTokenA}`)
        .send({
          name: 'Bad Site',
          primaryDomain: 'https://bad.portal.org/path', // Illegal URL format
        });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('enforces RBAC: SECURITY_ANALYST cannot register websites', async () => {
      const res = await request(app)
        .post('/api/v1/websites')
        .set('Authorization', `Bearer ${orgAnalystTokenA}`)
        .send({
          name: 'Unauthorized Site',
          primaryDomain: 'unauthorized.alpha.org',
        });

      expect(res.status).toBe(403);
      expect(res.body.success).toBe(false);
    });
  });

  describe('2. Domain Ownership Verification via DNS TXT & HTTP Challenge (TASK-602)', () => {
    it('verifies ownership via DNS TXT record and transitions to VERIFIED with 90-day validity', async () => {
      // 1. Register website
      const regRes = await request(app)
        .post('/api/v1/websites')
        .set('Authorization', `Bearer ${orgAdminTokenA}`)
        .send({
          name: 'Alpha DNS Test',
          primaryDomain: 'dns.alpha.org',
        });

      const siteId = regRes.body.site.siteId;
      const expectedHost = regRes.body.site.dnsTxtRecord.host;
      const expectedValue = regRes.body.site.dnsTxtRecord.value;

      // Mount custom mock resolver in test
      const { DomainVerificationService } = await import('../src/services/domain-verification.js');
      const verifier = new DomainVerificationService(storage, testDnsResolver, testHttpFetcher);

      // Pre-verification: simulate missing DNS record
      const failResult = await verifier.verifyDomain('org-alpha', siteId, 'DNS_TXT');
      expect(failResult.verified).toBe(false);
      expect(failResult.status).toBe('FAILED');

      // Now publish matching DNS TXT record
      mockDnsRecords.set(expectedHost.toLowerCase(), [[expectedValue]]);

      // Verify domain
      const successResult = await verifier.verifyDomain('org-alpha', siteId, 'DNS_TXT');
      expect(successResult.verified).toBe(true);
      expect(successResult.status).toBe('VERIFIED');
      expect(successResult.expiresAt).toBeDefined();

      // Check updated asset in storage
      const updatedSite = await storage.getWebsiteById('org-alpha', siteId);
      expect(updatedSite?.status).toBe('VERIFIED');
      expect(updatedSite?.scanBlocked).toBe(false); // Scan permissions unlocked
    });

    it('verifies ownership via HTTP challenge endpoint', async () => {
      // 1. Register website
      const regRes = await request(app)
        .post('/api/v1/websites')
        .set('Authorization', `Bearer ${orgAdminTokenA}`)
        .send({
          name: 'Alpha HTTP Test',
          primaryDomain: 'http.alpha.org',
        });

      const siteId = regRes.body.site.siteId;
      const challengeUrl = regRes.body.site.httpChallenge.url;
      const token = regRes.body.site.verificationToken;

      const { DomainVerificationService } = await import('../src/services/domain-verification.js');
      const verifier = new DomainVerificationService(storage, testDnsResolver, testHttpFetcher);

      // Configure mock HTTP response matching expected challenge JSON
      mockHttpResponses.set(challengeUrl, {
        status: 200,
        data: {
          veltrixChallengeToken: token,
          orgId: 'org-alpha',
        },
      });

      const result = await verifier.verifyDomain('org-alpha', siteId, 'HTTP_CHALLENGE');
      expect(result.verified).toBe(true);
      expect(result.status).toBe('VERIFIED');
    });

    it('rate-limits verification attempts to 5 per 15-minute window', async () => {
      const regRes = await request(app)
        .post('/api/v1/websites')
        .set('Authorization', `Bearer ${orgAdminTokenA}`)
        .send({
          name: 'Rate Limit Test',
          primaryDomain: 'ratelimit.alpha.org',
        });

      const siteId = regRes.body.site.siteId;
      const { DomainVerificationService } = await import('../src/services/domain-verification.js');
      const verifier = new DomainVerificationService(storage, testDnsResolver, testHttpFetcher);

      // First 5 attempts fail gracefully
      for (let i = 0; i < 5; i++) {
        const res = await verifier.verifyDomain('org-alpha', siteId, 'DNS_TXT');
        expect(res.status).toBe('FAILED');
      }

      // 6th attempt is rate-limited
      const rateLimitedRes = await verifier.verifyDomain('org-alpha', siteId, 'DNS_TXT');
      expect(rateLimitedRes.status).toBe('RATE_LIMITED');
      expect(rateLimitedRes.error?.code).toBe('VERIFICATION_RATE_LIMITED');
    });
  });

  describe('3. Domain Revocation & Grace Period Freeze (Safety Mandate)', () => {
    it('revoking verification sets GRACE_PERIOD and immediately freezes scanning (scanBlocked: true)', async () => {
      // 1. Register and verify website
      const regRes = await request(app)
        .post('/api/v1/websites')
        .set('Authorization', `Bearer ${orgAdminTokenA}`)
        .send({
          name: 'Revocation Test Site',
          primaryDomain: 'revocation.alpha.org',
        });

      const siteId = regRes.body.site.siteId;

      // Mark verified
      await storage.updateWebsite('org-alpha', siteId, {
        status: 'VERIFIED',
        scanBlocked: false,
      });

      // 2. Revoke verification
      const revokeRes = await request(app)
        .post(`/api/v1/websites/${siteId}/revoke`)
        .set('Authorization', `Bearer ${orgAdminTokenA}`)
        .send({ reason: 'TLS certificate mismatch detected' });

      expect(revokeRes.status).toBe(200);
      expect(revokeRes.body.success).toBe(true);
      expect(revokeRes.body.site.status).toBe('GRACE_PERIOD');
      expect(revokeRes.body.site.scanBlocked).toBe(true); // Scanning immediately frozen!
      expect(revokeRes.body.site.gracePeriodEndsAt).toBeDefined();

      // Check stored audit log
      const logs = await storage.getAuditLogs('org-alpha');
      const revokeLog = logs.find((l: any) => l.action === 'WEBSITE_REVOKED');
      expect(revokeLog).toBeDefined();
      expect(revokeLog.details.scanBlocked).toBe(true);
    });
  });

  describe('4. Tenant Isolation & Cross-Tenant Domain Claim Prevention', () => {
    it('prevents cross-tenant viewing or tampering of websites', async () => {
      // Org A creates a website
      const regRes = await request(app)
        .post('/api/v1/websites')
        .set('Authorization', `Bearer ${orgAdminTokenA}`)
        .send({
          name: 'Alpha Secret Site',
          primaryDomain: 'secret.alpha.org',
        });

      const siteId = regRes.body.site.siteId;

      // Org B attempts to read Org A's website -> 404 Not Found
      const getRes = await request(app)
        .get(`/api/v1/websites/${siteId}`)
        .set('Authorization', `Bearer ${orgAdminTokenB}`);

      expect(getRes.status).toBe(404);

      // Org B attempts to delete Org A's website -> 404 Not Found
      const delRes = await request(app)
        .delete(`/api/v1/websites/${siteId}`)
        .set('Authorization', `Bearer ${orgAdminTokenB}`);

      expect(delRes.status).toBe(404);
    });

    it('prevents cross-tenant takeover when domain is already claimed and verified', async () => {
      // 1. Org A registers and verifies "claimed.company.com"
      const regRes = await request(app)
        .post('/api/v1/websites')
        .set('Authorization', `Bearer ${orgAdminTokenA}`)
        .send({
          name: 'Legitimate Site',
          primaryDomain: 'claimed.company.com',
        });

      const siteIdA = regRes.body.site.siteId;
      await storage.updateWebsite('org-alpha', siteIdA, {
        status: 'VERIFIED',
        scanBlocked: false,
      });

      // 2. Org B attempts to register the exact same domain
      const hostileRes = await request(app)
        .post('/api/v1/websites')
        .set('Authorization', `Bearer ${orgAdminTokenB}`)
        .send({
          name: 'Hostile Takeover Attempt',
          primaryDomain: 'claimed.company.com',
        });

      expect(hostileRes.status).toBe(409);
      expect(hostileRes.body.success).toBe(false);
      expect(hostileRes.body.error.code).toBe('DOMAIN_ALREADY_CLAIMED');
    });
  });

  describe('5. Website Query & Pagination (TASK-603)', () => {
    it('lists websites with status filtering and pagination', async () => {
      // Create 3 sites for Org A
      await request(app)
        .post('/api/v1/websites')
        .set('Authorization', `Bearer ${orgAdminTokenA}`)
        .send({ name: 'Site 1', primaryDomain: 'site1.alpha.org' });

      await request(app)
        .post('/api/v1/websites')
        .set('Authorization', `Bearer ${orgAdminTokenA}`)
        .send({ name: 'Site 2', primaryDomain: 'site2.alpha.org' });

      await request(app)
        .post('/api/v1/websites')
        .set('Authorization', `Bearer ${orgAdminTokenA}`)
        .send({ name: 'Site 3', primaryDomain: 'site3.alpha.org' });

      const listRes = await request(app)
        .get('/api/v1/websites?limit=2')
        .set('Authorization', `Bearer ${orgAdminTokenA}`);

      expect(listRes.status).toBe(200);
      expect(listRes.body.total).toBe(3);
      expect(listRes.body.sites.length).toBe(2);
      expect(listRes.body.meta.hasMore).toBe(true);
      expect(listRes.body.meta.cursor).toBeDefined();

      // Query next page
      const nextRes = await request(app)
        .get(`/api/v1/websites?cursor=${listRes.body.meta.cursor}&limit=2`)
        .set('Authorization', `Bearer ${orgAdminTokenA}`);

      expect(nextRes.status).toBe(200);
      expect(nextRes.body.sites.length).toBe(1);
    });
  });
});
