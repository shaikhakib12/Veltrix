import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import type { SecurityEvent, WebsiteAsset, Detection } from '@veltrix/shared';
import { createApp } from '../src/app.js';
import { MemoryStore } from '../src/storage/memory-store.js';
import { DetectionEngine } from '../src/detection/engine.js';
import { DetectionPipeline } from '../src/detection/pipeline.js';
import { AttackCorrelationEngine } from '../src/correlation/engine.js';
import { RiskScoringEngine } from '../src/risk/engine.js';
import { VulnerabilityCorrelator } from '../src/correlation/vuln-correlator.js';
import {
  Rule101SqlInjection,
  Rule102CrossSiteScripting,
  Rule103PathTraversal,
  Rule104BotActivity,
  Rule105AuthFlowTampering,
} from '../src/detection/rules/web/index.js';
import * as webParser from '../src/detection/web-parser.js';
import { normalizeWebTelemetry, normalizeWebTelemetryAsync } from '../src/detection/web-parser.js';
import {
  InternalEvidenceAuthority,
  getDefaultInternalEvidenceAuthority,
  issueTrustedEvidenceContext,
  _resetInternalEvidenceAuthorityForTesting,
  type ApprovedVerifierIdentity,
  DynamoDBReplayRegistry,
  MemoryReplayRegistry,
} from '../src/detection/evidence-authority.js';
import { SecretLoader } from '../src/auth/secret-loader.js';

export const TEST_SERVICE_CREDENTIALS: Record<ApprovedVerifierIdentity, string> = {
  'canary-service:v1': 'test-secret-canary-service-credential-2026',
  'core-scanner:active-audit': 'test-secret-core-scanner-credential-2026',
  'internal-audit-worker:core': 'test-secret-audit-worker-credential-2026',
  'sensor:canary:db': 'test-secret-sensor-db-credential-2026',
  'sensor:canary:files': 'test-secret-sensor-files-credential-2026',
  'collector:nginx:authenticated': 'test-secret-collector-nginx-credential-2026',
  'waf:edge-gateway:authenticated': 'test-secret-waf-edge-credential-2026',
};
export const TEST_SIGNING_KEY = 'test-authority-hmac-sha256-signing-key-32bytes!';
export const INTERNAL_SERVICE_CREDENTIALS = TEST_SERVICE_CREDENTIALS;

import { JwtService } from '../src/auth/jwt-service.js';
import { LocalAuthProvider } from '../src/auth/local-auth-provider.js';
import { resetAuthProviderForTesting } from '../src/auth/index.js';
import { resetStorageForTesting } from '../src/storage/index.js';
import { EventService } from '../src/services/event-service.js';

describe('Phase 7: Website Attack Monitoring, Correlation & Risk Scoring (TASK-701 to TASK-707)', () => {
  let storage: MemoryStore;
  let engine: DetectionEngine;
  let correlationEngine: AttackCorrelationEngine;
  let riskEngine: RiskScoringEngine;
  let vulnCorrelator: VulnerabilityCorrelator;
  let pipeline: DetectionPipeline;
  let app: ReturnType<typeof createApp>;

  const orgId = 'org-cyber-shield';
  const siteId = 'site-ecommerce-prod-01';
  const primaryDomain = 'shop.cybershield.corp';

  let jwtService: JwtService;
  let adminToken: string;
  let analystToken: string;
  let auditorToken: string;
  let otherTenantToken: string;

  const dummySite: WebsiteAsset = {
    siteId,
    orgId,
    name: 'E-Commerce Production Portal',
    primaryDomain,
    approvedSubdomains: [`api.${primaryDomain}`],
    environment: 'PRODUCTION',
    status: 'VERIFIED',
    riskTier: 'HIGH',
    tags: ['e-commerce', 'pci-dss'],
    verificationToken: 'tok-abc-123',
    tokenCreatedAt: new Date().toISOString(),
    dnsTxtRecord: { host: `_veltrix-challenge.${primaryDomain}`, value: 'veltrix-verify=tok-abc-123' },
    httpChallenge: {
      url: `https://${primaryDomain}/.well-known/veltrix-challenge/tok-abc-123`,
      expectedBody: { veltrixChallengeToken: 'tok-abc-123', orgId },
    },
    scanBlocked: false,
    health: { telemetryStatus: 'HEALTHY' },
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  beforeEach(async () => {
    const testAuthority = new InternalEvidenceAuthority({
      signingKey: TEST_SIGNING_KEY,
      serviceCredentials: TEST_SERVICE_CREDENTIALS,
    });
    _resetInternalEvidenceAuthorityForTesting(testAuthority);

    jwtService = new JwtService('test-secret-phase-7-jwt-key-32chars');
    const localProvider = new LocalAuthProvider(jwtService);
    resetAuthProviderForTesting(localProvider);

    storage = new MemoryStore();
    resetStorageForTesting(storage);

    adminToken = jwtService.signAccessToken({
      userId: 'user-admin-01',
      username: 'admin',
      email: 'admin@cybershield.corp',
      role: 'ORG_ADMIN',
      orgId,
    });

    analystToken = jwtService.signAccessToken({
      userId: 'user-analyst-01',
      username: 'analyst',
      email: 'analyst@cybershield.corp',
      role: 'SECURITY_ANALYST',
      orgId,
    });

    auditorToken = jwtService.signAccessToken({
      userId: 'user-auditor-01',
      username: 'auditor',
      email: 'auditor@cybershield.corp',
      role: 'AUDITOR',
      orgId,
    });

    otherTenantToken = jwtService.signAccessToken({
      userId: 'user-other-01',
      username: 'other',
      email: 'other@rival.corp',
      role: 'ORG_ADMIN',
      orgId: 'org-rival-99',
    });

    engine = new DetectionEngine(storage);
    riskEngine = new RiskScoringEngine();
    vulnCorrelator = new VulnerabilityCorrelator();
    correlationEngine = new AttackCorrelationEngine(storage, {
      riskEngine,
      vulnCorrelator,
    });
    pipeline = new DetectionPipeline({
      storage,
      engine,
      correlationEngine,
    });
    app = createApp();

    await storage.saveWebsite(dummySite);
  });

  // ==========================================================================
  // 1. TASK-702: RULE-101 SQL Injection Detection
  // ==========================================================================
  describe('1. TASK-702: RULE-101 SQL Injection Detection', () => {
    const rule = new Rule101SqlInjection();

    it('detects standard boolean-based SQL injection payloads (positive test)', async () => {
      const event: SecurityEvent = {
        eventId: '01a19700-0000-7000-8000-000000000001',
        orgId,
        timestamp: new Date().toISOString(),
        eventType: 'web.request.normal',
        severity: 'LOW',
        category: 'NETWORK',
        sourceIp: '198.51.100.10',
        sourceSystem: 'sdk:nodejs:express',
        metadata: {
          siteId,
          domain: primaryDomain,
          httpMethod: 'GET',
          requestUri: "/api/products?category=books' OR '1'='1",
          httpStatus: 200,
        },
      };

      const detections = await rule.evaluate({
        organizationId: orgId,
        events: [event],
      });

      expect(detections.length).toBe(1);
      expect(detections[0].ruleId).toBe('RULE-101');
      expect(detections[0].title).toContain('SQL Injection');
      expect((detections[0].evidence.details as any).attackType).toBe('SQLI');
      expect((detections[0].evidence.details as any).matchedPatterns).toContain('BOOLEAN_BASED_OR_TRUE');
    });

    it('detects UNION-based data extraction and time-based blind injection', async () => {
      const event1: SecurityEvent = {
        eventId: '01a19700-0000-7000-8000-000000000002',
        orgId,
        timestamp: new Date().toISOString(),
        eventType: 'web.request.normal',
        severity: 'LOW',
        category: 'NETWORK',
        sourceIp: '198.51.100.11',
        sourceSystem: 'sdk:nodejs:express',
        metadata: {
          siteId,
          domain: primaryDomain,
          httpMethod: 'GET',
          requestUri: '/search?q=phone+UNION+SELECT+null,username,password+FROM+users--',
          httpStatus: 200,
        },
      };

      const event2: SecurityEvent = {
        eventId: '01a19700-0000-7000-8000-000000000003',
        orgId,
        timestamp: new Date().toISOString(),
        eventType: 'web.request.normal',
        severity: 'LOW',
        category: 'NETWORK',
        sourceIp: '198.51.100.12',
        sourceSystem: 'sdk:nodejs:express',
        metadata: {
          siteId,
          domain: primaryDomain,
          httpMethod: 'POST',
          requestUri: '/login?user=admin%27;+WAITFOR+DELAY+%270:0:5%27--',
          httpStatus: 200,
        },
      };

      const det1 = await rule.evaluate({ organizationId: orgId, events: [event1] });
      const det2 = await rule.evaluate({ organizationId: orgId, events: [event2] });

      expect(det1.length).toBe(1);
      expect((det1[0].evidence.details as any).matchedPatterns).toContain('UNION_SELECT');

      expect(det2.length).toBe(1);
      expect((det2[0].evidence.details as any).matchedPatterns).toContain('TIME_BASED_BLIND');
    });

    it('safely unwraps multi-layer URL-encoded payloads (%27%20OR%201=1)', async () => {
      const event: SecurityEvent = {
        eventId: '01a19700-0000-7000-8000-000000000004',
        orgId,
        timestamp: new Date().toISOString(),
        eventType: 'web.request.normal',
        severity: 'LOW',
        category: 'NETWORK',
        sourceIp: '198.51.100.15',
        sourceSystem: 'collector:nginx',
        metadata: {
          siteId,
          domain: primaryDomain,
          httpMethod: 'GET',
          requestUri: '/catalog?filter=%2527%2520OR%25201=1%2520--', // Double encoded
          httpStatus: 200,
        },
      };

      const detections = await rule.evaluate({ organizationId: orgId, events: [event] });
      expect(detections.length).toBe(1);
      expect(detections[0].title).toContain('SQL Injection');
    });

    it('suppresses false positives on benign queries with words like select or union (negative test)', async () => {
      const benignEvents: SecurityEvent[] = [
        {
          eventId: '01a19700-0000-7000-8000-000000000005',
          orgId,
          timestamp: new Date().toISOString(),
          eventType: 'web.request.normal',
          severity: 'INFO',
          category: 'NETWORK',
          sourceIp: '198.51.100.20',
          sourceSystem: 'sdk:nodejs:express',
          metadata: {
            siteId,
            domain: primaryDomain,
            requestUri: '/articles?search=European+Union+summit+trade+pact',
            httpStatus: 200,
          },
        },
        {
          eventId: '01a19700-0000-7000-8000-000000000006',
          orgId,
          timestamp: new Date().toISOString(),
          eventType: 'web.request.normal',
          severity: 'INFO',
          category: 'NETWORK',
          sourceIp: '198.51.100.21',
          sourceSystem: 'sdk:nodejs:express',
          metadata: {
            siteId,
            domain: primaryDomain,
            requestUri: '/preferences?action=select&option=dark_mode',
            httpStatus: 200,
          },
        },
        {
          eventId: '01a19700-0000-7000-8000-000000000007',
          orgId,
          timestamp: new Date().toISOString(),
          eventType: 'web.request.normal',
          severity: 'INFO',
          category: 'NETWORK',
          sourceIp: '198.51.100.22',
          sourceSystem: 'sdk:nodejs:express',
          metadata: {
            siteId,
            domain: primaryDomain,
            requestUri: '/delivery?instruction=drop+package+at+front+desk',
            httpStatus: 200,
          },
        },
      ];

      const detections = await rule.evaluate({ organizationId: orgId, events: benignEvents });
      expect(detections.length).toBe(0);
    });

    it('evaluates all 4 confidence tiers correctly (SUSPICIOUS, BLOCKED, POTENTIAL, CONFIRMED)', async () => {
      // Tier 1: Suspicious Attempt (no error, standard 200)
      const suspiciousEvent: SecurityEvent = {
        eventId: '01a19700-0000-7000-8000-000000000010',
        orgId,
        timestamp: new Date().toISOString(),
        eventType: 'web.request.normal',
        severity: 'LOW',
        category: 'NETWORK',
        sourceIp: '198.51.100.30',
        sourceSystem: 'sdk:nodejs:express',
        metadata: {
          siteId,
          requestUri: "/items?id=1' OR 1=1--",
          httpStatus: 200,
        },
      };

      // Tier 2: Blocked Attempt (WAF or 403 Forbidden)
      const blockedEvent: SecurityEvent = {
        eventId: '01a19700-0000-7000-8000-000000000011',
        orgId,
        timestamp: new Date().toISOString(),
        eventType: 'web.attack.sqli',
        severity: 'LOW',
        category: 'NETWORK',
        sourceIp: '198.51.100.31',
        sourceSystem: 'edge:cloudflare',
        metadata: {
          siteId,
          requestUri: "/items?id=1' OR 1=1--",
          httpStatus: 403,
          wafAction: 'BLOCK',
        },
      };

      // Tier 3: Potential Exploitation (DB syntax error in application response, attested by authenticated collector)
      const potentialEvent: SecurityEvent = {
        eventId: '01a19700-0000-7000-8000-000000000012',
        orgId,
        timestamp: new Date().toISOString(),
        eventType: 'web.request.normal',
        severity: 'HIGH',
        category: 'NETWORK',
        sourceIp: '198.51.100.32',
        sourceSystem: 'sdk:nodejs:express',
        trustedEvidenceContext: issueTrustedEvidenceContext({
          serviceAuthToken: INTERNAL_SERVICE_CREDENTIALS['collector:nginx:authenticated'],
          provenance: 'AUTHENTICATED_COLLECTOR',
          verifierIdentity: 'collector:nginx:authenticated',
          eventId: '01a19700-0000-7000-8000-000000000012',
          orgId,
          siteId,
          verifiedResponseEvidence: {
            errorMessage: 'Unclosed quotation mark before the character string. Syntax error near OR.',
          },
        }),
        metadata: {
          siteId,
          requestUri: "/items?id=1' OR 1=1--",
          httpStatus: 500,
          errorMessage: 'Unclosed quotation mark before the character string. Syntax error near OR.',
        },
      };

      // Tier 4: Confirmed Exploitation (Schema data leakage token detected by trusted sensor)
      const confirmedEvent: SecurityEvent = {
        eventId: '01a19700-0000-7000-8000-000000000013',
        orgId,
        timestamp: new Date().toISOString(),
        eventType: 'web.request.normal',
        severity: 'CRITICAL',
        category: 'NETWORK',
        sourceIp: '198.51.100.33',
        sourceSystem: 'sensor:canary:db',
        trustedEvidenceContext: issueTrustedEvidenceContext({
          serviceAuthToken: INTERNAL_SERVICE_CREDENTIALS['sensor:canary:db'],
          provenance: 'TRUSTED_SERVER_COMPONENT',
          verifierIdentity: 'sensor:canary:db',
          eventId: '01a19700-0000-7000-8000-000000000013',
          orgId,
          siteId,
          verifiedSignalIdentifiers: ['DATA_LEAKAGE_INDICATOR'],
        }),
        metadata: {
          siteId,
          requestUri: '/items?id=-1+UNION+SELECT+1,table_name,column_name+FROM+information_schema.columns',
          httpStatus: 200,
        },
      };

      const [dSusp] = await rule.evaluate({ organizationId: orgId, events: [suspiciousEvent] });
      const [dBlock] = await rule.evaluate({ organizationId: orgId, events: [blockedEvent] });
      const [dPot] = await rule.evaluate({ organizationId: orgId, events: [potentialEvent] });
      const [dConf] = await rule.evaluate({ organizationId: orgId, events: [confirmedEvent] });

      expect((dSusp.evidence.details as any).confidenceLevel).toBe('SUSPICIOUS_ATTEMPT');
      expect((dBlock.evidence.details as any).confidenceLevel).toBe('BLOCKED_ATTEMPT');
      expect((dPot.evidence.details as any).confidenceLevel).toBe('POTENTIAL_EXPLOITATION');
      expect((dConf.evidence.details as any).confidenceLevel).toBe('CONFIRMED_EXPLOITATION');
      expect(dConf.severity).toBe('CRITICAL');
    });
  });

  // ==========================================================================
  // 2. TASK-703: RULE-102 Cross-Site Scripting (XSS) Detection
  // ==========================================================================
  describe('2. TASK-703: RULE-102 Cross-Site Scripting Detection', () => {
    const rule = new Rule102CrossSiteScripting();

    it('detects explicit script tags, inline event handlers, and javascript: pseudo-protocols', async () => {
      const events: SecurityEvent[] = [
        {
          eventId: '01a19700-0000-7000-8000-000000000020',
          orgId,
          timestamp: new Date().toISOString(),
          eventType: 'web.request.normal',
          severity: 'MEDIUM',
          category: 'NETWORK',
          sourceIp: '198.51.100.40',
          sourceSystem: 'sdk:nodejs:express',
          metadata: {
            siteId,
            requestUri: '/comments?msg=%3Cscript%3Ealert(%27xss%27)%3C/script%3E',
            httpStatus: 200,
          },
        },
        {
          eventId: '01a19700-0000-7000-8000-000000000021',
          orgId,
          timestamp: new Date().toISOString(),
          eventType: 'web.request.normal',
          severity: 'MEDIUM',
          category: 'NETWORK',
          sourceIp: '198.51.100.41',
          sourceSystem: 'sdk:nodejs:express',
          metadata: {
            siteId,
            requestUri: '/avatar?url=%3Cimg%20src=x%20onerror=alert(document.cookie)%3E',
            httpStatus: 200,
          },
        },
        {
          eventId: '01a19700-0000-7000-8000-000000000022',
          orgId,
          timestamp: new Date().toISOString(),
          eventType: 'web.request.normal',
          severity: 'MEDIUM',
          category: 'NETWORK',
          sourceIp: '198.51.100.42',
          sourceSystem: 'sdk:nodejs:express',
          metadata: {
            siteId,
            requestUri: '/redirect?to=javascript:alert(1)',
            httpStatus: 200,
          },
        },
      ];

      for (const e of events) {
        const det = await rule.evaluate({ organizationId: orgId, events: [e] });
        expect(det.length).toBe(1);
        expect(det[0].ruleId).toBe('RULE-102');
        expect((det[0].evidence.details as any).attackType).toBe('XSS');
      }
    });

    it('suppresses false positives on ordinary text and mathematical comparisons', async () => {
      const benignEvents: SecurityEvent[] = [
        {
          eventId: '01a19700-0000-7000-8000-000000000023',
          orgId,
          timestamp: new Date().toISOString(),
          eventType: 'web.request.normal',
          severity: 'INFO',
          category: 'NETWORK',
          sourceIp: '198.51.100.43',
          sourceSystem: 'sdk:nodejs:express',
          metadata: {
            siteId,
            requestUri: '/math?expr=x%3C5%20and%20y%3E10',
            httpStatus: 200,
          },
        },
        {
          eventId: '01a19700-0000-7000-8000-000000000024',
          orgId,
          timestamp: new Date().toISOString(),
          eventType: 'web.request.normal',
          severity: 'INFO',
          category: 'NETWORK',
          sourceIp: '198.51.100.44',
          sourceSystem: 'sdk:nodejs:express',
          metadata: {
            siteId,
            requestUri: '/contact?email=support@company.com&subject=Documentation%20scripts',
            httpStatus: 200,
          },
        },
      ];

      const detections = await rule.evaluate({ organizationId: orgId, events: benignEvents });
      expect(detections.length).toBe(0);
    });
  });

  // ==========================================================================
  // 3. TASK-704: RULE-103 Path Traversal & LFI Detection
  // ==========================================================================
  describe('3. TASK-704: RULE-103 Path Traversal & LFI Detection', () => {
    const rule = new Rule103PathTraversal();

    it('detects directory climbing sequences and sensitive OS file access', async () => {
      const events: SecurityEvent[] = [
        {
          eventId: '01a19700-0000-7000-8000-000000000030',
          orgId,
          timestamp: new Date().toISOString(),
          eventType: 'web.request.normal',
          severity: 'HIGH',
          category: 'NETWORK',
          sourceIp: '198.51.100.50',
          sourceSystem: 'sdk:nodejs:express',
          metadata: {
            siteId,
            requestUri: '/view-file?path=../../../../etc/passwd',
            httpStatus: 200,
          },
        },
        {
          eventId: '01a19700-0000-7000-8000-000000000031',
          orgId,
          timestamp: new Date().toISOString(),
          eventType: 'web.request.normal',
          severity: 'HIGH',
          category: 'NETWORK',
          sourceIp: '198.51.100.51',
          sourceSystem: 'sdk:nodejs:express',
          metadata: {
            siteId,
            requestUri: '/download?file=..%2f..%2f..%2fwindows%2fwin.ini',
            httpStatus: 200,
          },
        },
        {
          eventId: '01a19700-0000-7000-8000-000000000032',
          orgId,
          timestamp: new Date().toISOString(),
          eventType: 'web.request.normal',
          severity: 'HIGH',
          category: 'NETWORK',
          sourceIp: '198.51.100.52',
          sourceSystem: 'sdk:nodejs:express',
          metadata: {
            siteId,
            requestUri: '/include?page=php://filter/convert.base64-encode/resource=config.php',
            httpStatus: 200,
          },
        },
      ];

      for (const e of events) {
        const det = await rule.evaluate({ organizationId: orgId, events: [e] });
        expect(det.length).toBe(1);
        expect(det[0].ruleId).toBe('RULE-103');
        expect((det[0].evidence.details as any).attackType).toBe('PATH_TRAVERSAL');
      }
    });

    it('identifies confirmed exploitation when system file patterns appear in response', async () => {
      const event: SecurityEvent = {
        eventId: '01a19700-0000-7000-8000-000000000033',
        orgId,
        timestamp: new Date().toISOString(),
        eventType: 'web.request.normal',
        severity: 'CRITICAL',
        category: 'NETWORK',
        sourceIp: '198.51.100.55',
        sourceSystem: 'sensor:canary:files',
        trustedEvidenceContext: issueTrustedEvidenceContext({
          serviceAuthToken: INTERNAL_SERVICE_CREDENTIALS['sensor:canary:files'],
          provenance: 'TRUSTED_SERVER_COMPONENT',
          verifierIdentity: 'sensor:canary:files',
          eventId: '01a19700-0000-7000-8000-000000000033',
          orgId,
          siteId,
          verifiedResponseEvidence: {
            responseBody: 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin',
          },
        }),
        metadata: {
          siteId,
          requestUri: '/get-doc?name=../../etc/passwd',
          httpStatus: 200,
          responseSample: 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin',
        },
      };

      const detections = await rule.evaluate({ organizationId: orgId, events: [event] });
      expect(detections.length).toBe(1);
      expect(detections[0].severity).toBe('CRITICAL');
      expect((detections[0].evidence.details as any).confidenceLevel).toBe('CONFIRMED_EXPLOITATION');
    });
  });

  // ==========================================================================
  // 4. TASK-705: RULE-104 Bot Activity & RULE-105 Auth Tampering
  // ==========================================================================
  describe('4. TASK-705: Bot Activity (RULE-104) & Auth Flow Tampering (RULE-105)', () => {
    it('RULE-104: detects automated security scanner probing sensitive endpoints', async () => {
      const rule = new Rule104BotActivity();
      const baseTime = Date.now();

      // Probing .env, wp-login, phpmyadmin with known scanner user-agent
      const events: SecurityEvent[] = [
        '/.env',
        '/wp-admin/install.php',
        '/phpmyadmin/index.php',
        '/.git/config',
        '/actuator/health',
      ].map((path, idx) => ({
        eventId: `01a19700-0000-7000-8000-00000000004${idx}`,
        orgId,
        timestamp: new Date(baseTime + idx * 2000).toISOString(),
        eventType: 'web.request.normal',
        severity: 'LOW',
        category: 'NETWORK',
        sourceIp: '198.51.100.60',
        sourceSystem: 'collector:nginx',
        metadata: {
          siteId,
          requestUri: path,
          httpStatus: 404,
          userAgent: 'sqlmap/1.6.12#stable (https://sqlmap.org)',
        },
      }));

      const detections = await rule.evaluate({ organizationId: orgId, events });
      expect(detections.length).toBe(1);
      expect(detections[0].ruleId).toBe('RULE-104');
      expect((detections[0].evidence.details as any).hasKnownScannerTool).toBe(true);
      expect((detections[0].evidence.details as any).attackType).toBe('BOT_ACTIVITY');
    });

    it('RULE-104: never triggers on curl or python-requests without corroborating enumeration or high frequency', async () => {
      const rule = new Rule104BotActivity();
      // Single benign curl request to public API
      const event: SecurityEvent = {
        eventId: '01a19700-0000-7000-8000-000000000049',
        orgId,
        timestamp: new Date().toISOString(),
        eventType: 'web.request.normal',
        severity: 'INFO',
        category: 'NETWORK',
        sourceIp: '198.51.100.61',
        sourceSystem: 'sdk:nodejs:express',
        metadata: {
          siteId,
          requestUri: '/api/v1/health',
          httpStatus: 200,
          userAgent: 'curl/7.88.1',
        },
      };

      const detections = await rule.evaluate({ organizationId: orgId, events: [event] });
      expect(detections.length).toBe(0);
    });

    it('RULE-105: detects credential stuffing across multiple distinct accounts', async () => {
      const rule = new Rule105AuthFlowTampering();
      const baseTime = Date.now();

      const events: SecurityEvent[] = ['alice', 'bob', 'charlie'].map((user, idx) => ({
        eventId: `01a19700-0000-7000-8000-00000000005${idx}`,
        orgId,
        timestamp: new Date(baseTime + idx * 3000).toISOString(),
        eventType: 'auth.login.failed',
        severity: 'LOW',
        category: 'AUTHENTICATION',
        sourceIp: '198.51.100.70',
        username: user,
        sourceSystem: 'sdk:nodejs:express',
        metadata: {
          siteId,
          requestUri: '/api/auth/login',
          httpStatus: 401,
        },
      }));

      const detections = await rule.evaluate({ organizationId: orgId, events });
      expect(detections.length).toBe(1);
      expect(detections[0].ruleId).toBe('RULE-105');
      expect(detections[0].severity).toBe('CRITICAL');
      expect((detections[0].evidence.details as any).isCredentialStuffing).toBe(true);
      expect((detections[0].evidence.details as any).targetedUsernames).toHaveLength(3);
    });
  });

  // ==========================================================================
  // 5. TASK-706: Multi-Stage Attack Correlation Engine
  // ==========================================================================
  describe('5. TASK-706: Multi-Stage Attack Correlation Engine', () => {
    it('correlates sequential multi-stage attacks from same IP into a single unified Incident', async () => {
      const attackerIp = '198.51.100.80';
      const baseTime = Date.now();

      // Detection 1: Bot Reconnaissance
      const detection1 = (
        await new Rule104BotActivity().evaluate(
          {
            organizationId: orgId,
            events: [
              {
                eventId: '01a19700-0000-7000-8000-000000000060',
                orgId,
                timestamp: new Date(baseTime).toISOString(),
                eventType: 'web.attack.bot',
                severity: 'MEDIUM',
                category: 'NETWORK',
                sourceIp: attackerIp,
                sourceSystem: 'collector:nginx',
                metadata: { siteId, requestUri: '/.env', httpStatus: 404, userAgent: 'nikto/2.1.6' },
              },
              {
                eventId: '01a19700-0000-7000-8000-000000000061',
                orgId,
                timestamp: new Date(baseTime + 1000).toISOString(),
                eventType: 'web.attack.bot',
                severity: 'MEDIUM',
                category: 'NETWORK',
                sourceIp: attackerIp,
                sourceSystem: 'collector:nginx',
                metadata: { siteId, requestUri: '/wp-login.php', httpStatus: 404, userAgent: 'nikto/2.1.6' },
              },
            ],
          },
          { threshold: 2 }
        )
      )[0];

      // Detection 2: SQL Injection Attack
      const detection2 = (
        await new Rule101SqlInjection().evaluate({
          organizationId: orgId,
          events: [
            {
              eventId: '01a19700-0000-7000-8000-000000000062',
              orgId,
              timestamp: new Date(baseTime + 15000).toISOString(),
              eventType: 'web.request.normal',
              severity: 'HIGH',
              category: 'NETWORK',
              sourceIp: attackerIp,
              sourceSystem: 'sdk:nodejs:express',
              metadata: { siteId, requestUri: "/api/search?q=1' OR '1'='1", httpStatus: 200 },
            },
          ],
        })
      )[0];

      expect(detection1).toBeDefined();
      expect(detection2).toBeDefined();

      // Correlate Detection 1 -> creates new incident
      const res1 = await correlationEngine.correlateDetection(detection1);
      expect(res1).not.toBeNull();
      expect(res1!.isNewIncident).toBe(true);
      expect(res1!.incident.attackTypes).toContain('BOT_ACTIVITY');

      // Correlate Detection 2 -> merges into existing incident
      const res2 = await correlationEngine.correlateDetection(detection2);
      expect(res2).not.toBeNull();
      expect(res2!.isNewIncident).toBe(false);
      expect(res2!.incident.incidentId).toBe(res1!.incident.incidentId);
      expect(res2!.incident.attackTypes).toContain('BOT_ACTIVITY');
      expect(res2!.incident.attackTypes).toContain('SQLI');
      // Progression sequence bonus awarded
      expect((res2!.incident.webRiskFactors as any).attackSequenceBonus).toBe(10);
      expect(res2!.incident.timeline).toHaveLength(2);
    });

    it('enforces strict tenant isolation during correlation', async () => {
      const attackerIp = '198.51.100.99';
      const detOrg1 = (
        await new Rule101SqlInjection().evaluate({
          organizationId: 'org-tenant-a',
          events: [
            {
              eventId: '01a19700-0000-7000-8000-000000000070',
              orgId: 'org-tenant-a',
              timestamp: new Date().toISOString(),
              eventType: 'web.request.normal',
              severity: 'HIGH',
              category: 'NETWORK',
              sourceIp: attackerIp,
              sourceSystem: 'sdk:nodejs:express',
              metadata: { siteId: 'site-a', requestUri: "/test?id=1' OR 1=1--" },
            },
          ],
        })
      )[0];

      const detOrg2 = (
        await new Rule101SqlInjection().evaluate({
          organizationId: 'org-tenant-b',
          events: [
            {
              eventId: '01a19700-0000-7000-8000-000000000071',
              orgId: 'org-tenant-b',
              timestamp: new Date().toISOString(),
              eventType: 'web.request.normal',
              severity: 'HIGH',
              category: 'NETWORK',
              sourceIp: attackerIp,
              sourceSystem: 'sdk:nodejs:express',
              metadata: { siteId: 'site-b', requestUri: "/test?id=1' OR 1=1--" },
            },
          ],
        })
      )[0];

      const resA = await correlationEngine.correlateDetection(detOrg1);
      const resB = await correlationEngine.correlateDetection(detOrg2);

      expect(resA!.incident.incidentId).not.toBe(resB!.incident.incidentId);
      expect(resA!.incident.orgId).toBe('org-tenant-a');
      expect(resB!.incident.orgId).toBe('org-tenant-b');
    });
  });

  // ==========================================================================
  // 6. TASK-707: Explainable Risk Scoring Engine
  // ==========================================================================
  describe('6. TASK-707: Explainable Risk Scoring Engine', () => {
    it('strictly caps risk score at 100 and floors at 0', () => {
      // Theoretical maximum: Critical (40) * Freq(1.5) * Asset(1.3) * Threat(1.4) + Overlap(25) + Seq(10) = 144.2 -> caps at 100
      const maxInput = {
        detectionsSeverity: ['CRITICAL' as const],
        eventCount: 50,
        uniqueAttackTypes: ['BOT_ACTIVITY', 'SQLI', 'AUTH_TAMPERING'],
        highestConfidence: 'CONFIRMED_EXPLOITATION' as const,
        assetEnvironment: 'PRODUCTION' as const,
        isThreatIntelFlagged: true,
        threatIntelSeverity: 'CRITICAL' as const,
        vulnerabilityOverlap: {
          overlapLevel: 'EXACT' as const,
          weight: 25,
          findingCvss: 10,
          confidenceMultiplier: 1.0,
          termValue: 25,
        },
      };

      const result = riskEngine.calculateRisk(maxInput);
      expect(result.score).toBe(100);
      expect(result.riskBand).toBe('CRITICAL');
      expect(result.explanation).toContain('RiskScore 100/100');
    });

    it('verifies that blocked probes against non-vulnerable assets score in Low/Medium band (< 45)', () => {
      const blockedInput = {
        detectionsSeverity: ['LOW' as const],
        eventCount: 1,
        uniqueAttackTypes: ['SQLI'],
        highestConfidence: 'BLOCKED_ATTEMPT' as const,
        assetEnvironment: 'PRODUCTION' as const,
        isThreatIntelFlagged: false,
        vulnerabilityOverlap: undefined,
      };

      const result = riskEngine.calculateRisk(blockedInput);
      // Low base (10) * 1.0 * 1.3 * 1.0 = 13
      expect(result.score).toBeLessThanOrEqual(45);
      expect(result.riskBand).toBe('LOW');
    });

    it('applies vulnerability match term dynamically based on attack surface overlap (TASK-705)', () => {
      // Compare No Overlap vs Exact Overlap
      const baseInput = {
        detectionsSeverity: ['HIGH' as const],
        eventCount: 5,
        uniqueAttackTypes: ['SQLI'],
        highestConfidence: 'POTENTIAL_EXPLOITATION' as const,
        assetEnvironment: 'PRODUCTION' as const,
      };

      const resNoVuln = riskEngine.calculateRisk(baseInput);

      const exactOverlap = riskEngine.computeVulnerabilityMatchTerm('EXACT', 8.5, 'POTENTIAL_EXPLOITATION');
      const resWithVuln = riskEngine.calculateRisk({
        ...baseInput,
        vulnerabilityOverlap: exactOverlap,
      });

      expect(exactOverlap.termValue).toBeGreaterThan(15);
      expect(resWithVuln.score).toBeGreaterThan(resNoVuln.score);
      expect(resWithVuln.factors.vulnerabilityMatchTerm).toBe(exactOverlap.termValue);
    });
  });

  // ==========================================================================
  // 7. TASK-706 / TASK-707: Ingestion Pipeline Auto-Processing
  // ==========================================================================
  describe('7. Automatic Ingestion Pipeline Integration', () => {
    it('automatically processes web events, creates detections, and correlates incidents', async () => {
      const testEvent: SecurityEvent = {
        eventId: '01a19700-0000-7000-8000-000000000090',
        orgId,
        timestamp: new Date().toISOString(),
        eventType: 'web.request.normal',
        severity: 'HIGH',
        category: 'NETWORK',
        sourceIp: '198.51.100.150',
        sourceSystem: 'sdk:nodejs:express',
        metadata: {
          siteId,
          domain: primaryDomain,
          requestUri: "/checkout?coupon=' OR '1'='1",
          httpStatus: 200,
        },
      };

      // Save event & dispatch through pipeline
      await storage.saveEvent(testEvent);
      pipeline.dispatch(testEvent);
      await pipeline.waitForIdle();

      // Verify detection created in storage
      const detQuery = await storage.getDetections(orgId, { siteId });
      expect(detQuery.items.length).toBeGreaterThanOrEqual(1);
      expect(detQuery.items[0].ruleId).toBe('RULE-101');

      // Verify incident created and correlated automatically
      const incQuery = await storage.getIncidents(orgId, { siteId });
      expect(incQuery.items.length).toBeGreaterThanOrEqual(1);
      expect(incQuery.items[0].sourceIp).toBe('198.51.100.150');
      expect(incQuery.items[0].riskScore).toBeGreaterThan(0);
    });
  });

  // ==========================================================================
  // 8. REST APIs Verification (TASK-701 to TASK-707)
  // ==========================================================================
  describe('8. REST APIs: Attack Detections, Incidents, Risk Summary & Timeline', () => {
    beforeEach(async () => {
      // Seed a correlated attack incident and detections for the test site
      const event: SecurityEvent = {
        eventId: '01a19700-0000-7000-8000-000000000100',
        orgId,
        timestamp: new Date().toISOString(),
        eventType: 'web.request.normal',
        severity: 'HIGH',
        category: 'NETWORK',
        sourceIp: '198.51.100.200',
        sourceSystem: 'sdk:nodejs:express',
        metadata: {
          siteId,
          domain: primaryDomain,
          requestUri: '/login?user=admin%27--',
          httpStatus: 200,
        },
      };
      await storage.saveEvent(event);
      await pipeline.processEvent(event);
    });

    it('GET /api/v1/websites/:siteId/detections returns detections for the website asset', async () => {
      const res = await request(app)
        .get(`/api/v1/websites/${siteId}/detections`)
        .set('Authorization', `Bearer ${analystToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.siteId).toBe(siteId);
      expect(res.body.data.items).toBeInstanceOf(Array);
      expect(res.body.data.items.length).toBeGreaterThanOrEqual(1);
    });

    it('GET /api/v1/websites/:siteId/incidents returns correlated incidents', async () => {
      const res = await request(app)
        .get(`/api/v1/websites/${siteId}/incidents`)
        .set('Authorization', `Bearer ${analystToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.items.length).toBeGreaterThanOrEqual(1);
      expect(res.body.data.items[0].siteId).toBe(siteId);
    });

    it('GET /api/v1/websites/:siteId/risk-summary returns explainable risk score and posture', async () => {
      const res = await request(app)
        .get(`/api/v1/websites/${siteId}/risk-summary`)
        .set('Authorization', `Bearer ${analystToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.siteId).toBe(siteId);
      expect(typeof res.body.data.currentRiskScore).toBe('number');
      expect(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).toContain(res.body.data.currentRiskBand);
      expect(res.body.data.factors).toBeDefined();
    });

    it('GET /api/v1/websites/:siteId/timeline returns chronological attack sequence', async () => {
      const res = await request(app)
        .get(`/api/v1/websites/${siteId}/timeline`)
        .set('Authorization', `Bearer ${analystToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.items).toBeInstanceOf(Array);
      expect(res.body.data.items.length).toBeGreaterThanOrEqual(1);
    });

    it('GET /api/v1/detections/web queries web-specific detections', async () => {
      const res = await request(app)
        .get('/api/v1/detections/web')
        .set('Authorization', `Bearer ${analystToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.items).toBeInstanceOf(Array);
    });

    it('GET /api/v1/detections/:detectionId/evidence returns explainable evidence', async () => {
      const allDets = await storage.getDetections(orgId);
      const detId = allDets.items[0].detectionId;

      const res = await request(app)
        .get(`/api/v1/detections/${detId}/evidence`)
        .set('Authorization', `Bearer ${analystToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.detectionId).toBe(detId);
      expect(res.body.data.evidence).toBeDefined();
      expect(res.body.data.evidence.matchedRuleId).toBeDefined();
    });

    it('PATCH /api/v1/incidents/:incidentId allows security analyst to update status and add notes', async () => {
      const incs = await storage.getIncidents(orgId);
      const incId = incs.items[0].incidentId;

      const res = await request(app)
        .patch(`/api/v1/incidents/${incId}`)
        .set('Authorization', `Bearer ${analystToken}`)
        .send({
          status: 'CONTAINED',
          note: 'IP blocked at edge perimeter; incident mitigated.',
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.status).toBe('CONTAINED');
      expect(res.body.data.notes).toHaveLength(1);
      expect(res.body.data.notes[0].content).toContain('IP blocked');
    });

    it('permits AUDITOR role read-only access to attack monitoring and risk summary', async () => {
      const resDetections = await request(app)
        .get(`/api/v1/websites/${siteId}/detections`)
        .set('Authorization', `Bearer ${auditorToken}`);
      expect(resDetections.status).toBe(200);

      const resRisk = await request(app)
        .get(`/api/v1/websites/${siteId}/risk-summary`)
        .set('Authorization', `Bearer ${auditorToken}`);
      expect(resRisk.status).toBe(200);
    });

    it('prohibits telemetry ingestion API keys on attack management routes', async () => {
      const res = await request(app)
        .get(`/api/v1/websites/${siteId}/incidents`)
        .set('x-api-key', 'vtx_live_testkey12345');

      expect(res.status).toBe(403);
      expect(res.body.error.code).toBe('FORBIDDEN_API_KEY_SCOPE_PROHIBITED');
    });

    it('enforces cross-tenant isolation: Tenant B cannot view Tenant A website attacks', async () => {
      const res = await request(app)
        .get(`/api/v1/websites/${siteId}/detections`)
        .set('Authorization', `Bearer ${otherTenantToken}`);

      // 404 because siteId does not belong to Tenant B
      expect(res.status).toBe(404);
      expect(res.body.error.code).toBe('WEBSITE_NOT_FOUND');
    });
  });

  describe('9. Security Audit Regressions & Edge Cases', () => {
    it('redacts sensitive query parameter values in rawUri and queryParams', () => {
      const parsed = normalizeWebTelemetry({
        eventId: '01a19700-0000-7000-8000-000000000099',
        orgId,
        timestamp: new Date().toISOString(),
        eventType: 'web.attack.sqli',
        severity: 'HIGH',
        category: 'NETWORK',
        sourceIp: '198.51.100.12',
        sourceSystem: 'collector:nginx',
        metadata: {
          siteId,
          requestUri: '/login?user=admin&password=SuperSecretPassword123!&token=sec_abc_9988&cvv=123',
          httpMethod: 'GET',
          httpStatus: 200,
        },
      });

      expect(parsed.queryParams.password).toBe('[REDACTED]');
      expect(parsed.queryParams.token).toBe('[REDACTED]');
      expect(parsed.queryParams.cvv).toBe('[REDACTED]');
      expect(parsed.queryParams.user).toBe('admin');

      // rawUri must not leak cleartext credentials
      expect(parsed.rawUri).not.toContain('SuperSecretPassword123!');
      expect(parsed.rawUri).not.toContain('sec_abc_9988');
      expect(parsed.rawUri).toContain('password=[REDACTED]');

      // decodedPayloads passed to detection rules must not contain cleartext credentials
      expect(parsed.decodedPayloads).not.toContain('SuperSecretPassword123!');
      expect(parsed.decodedPayloads).not.toContain('sec_abc_9988');
    });

    it('safely handles missing, NaN, or out-of-range findingCvss without NaN poisoning', () => {
      // 1. computeVulnerabilityMatchTerm with NaN findingCvss
      const termNaN = riskEngine.computeVulnerabilityMatchTerm('EXACT', NaN as any, 'CONFIRMED_EXPLOITATION');
      expect(Number.isNaN(termNaN.termValue)).toBe(false);
      expect(termNaN.findingCvss).toBe(0);
      expect(termNaN.termValue).toBe(0);

      // 2. computeVulnerabilityMatchTerm with undefined
      const termUndef = riskEngine.computeVulnerabilityMatchTerm('PARTIAL', undefined as any, 'PROBABLE_EXPLOITATION');
      expect(Number.isNaN(termUndef.termValue)).toBe(false);
      expect(termUndef.findingCvss).toBe(0);

      // 3. calculateRisk with NaN vulnerability overlap
      const resultWithNaN = riskEngine.calculateRisk({
        detectionsSeverity: ['HIGH'],
        eventCount: 5,
        uniqueAttackTypes: ['SQLI'],
        highestConfidence: 'ATTEMPT_ONLY',
        assetEnvironment: 'PRODUCTION',
        vulnerabilityOverlap: {
          overlapLevel: 'EXACT',
          weight: 25,
          findingCvss: NaN as any,
          confidenceMultiplier: 0.8,
          termValue: NaN as any,
        },
      });

      expect(Number.isNaN(resultWithNaN.score)).toBe(false);
      expect(Number.isFinite(resultWithNaN.score)).toBe(true);
      expect(resultWithNaN.score).toBeGreaterThanOrEqual(0);
      expect(resultWithNaN.score).toBeLessThanOrEqual(100);
      expect(resultWithNaN.explanation).not.toContain('NaN');
    });

    it('prevents false incident consolidation for loopback/generic source IPs', async () => {
      const baseTime = Date.now();
      const det1 = {
        detectionId: 'det-loopback-01',
        organizationId: orgId,
        ruleId: 'RULE-101',
        title: 'SQLi Probe 1',
        description: 'Probe 1',
        severity: 'HIGH' as const,
        detectedAt: new Date(baseTime).toISOString(),
        evidence: {
          targetEntity: { type: 'IP' as const, value: '127.0.0.1' },
          details: { siteId, attackType: 'SQLI', confidenceLevel: 'ATTEMPT_ONLY' },
        },
      };

      const det2 = {
        detectionId: 'det-loopback-02',
        organizationId: orgId,
        ruleId: 'RULE-101',
        title: 'SQLi Probe 2',
        description: 'Probe 2',
        severity: 'HIGH' as const,
        detectedAt: new Date(baseTime + 5000).toISOString(),
        evidence: {
          targetEntity: { type: 'IP' as const, value: '127.0.0.1' },
          details: { siteId, attackType: 'SQLI', confidenceLevel: 'ATTEMPT_ONLY' },
        },
      };

      const res1 = await correlationEngine.correlateDetection(det1);
      const res2 = await correlationEngine.correlateDetection(det2);

      expect(res1).not.toBeNull();
      expect(res2).not.toBeNull();
      // Because 127.0.0.1 is generic/local, each gets an isolated incident rather than global collapse
      expect(res1!.isNewIncident).toBe(true);
      expect(res2!.isNewIncident).toBe(true);
      expect(res1!.incident.incidentId).not.toBe(res2!.incident.incidentId);
    });

    it('ensures correlation idempotency by not duplicating timeline entries on re-evaluation', async () => {
      const det = {
        detectionId: 'det-idempotent-01',
        organizationId: orgId,
        ruleId: 'RULE-101',
        title: 'Idempotent SQLi Detection',
        description: 'Test detection',
        severity: 'HIGH' as const,
        detectedAt: new Date().toISOString(),
        evidence: {
          targetEntity: { type: 'IP' as const, value: '198.51.100.200' },
          details: { siteId, attackType: 'SQLI', confidenceLevel: 'ATTEMPT_ONLY' },
        },
      };

      const resFirst = await correlationEngine.correlateDetection(det);
      expect(resFirst!.incident.timeline).toHaveLength(1);

      // Re-correlating the exact same detection
      const resSecond = await correlationEngine.correlateDetection(det);
      expect(resSecond!.incident.timeline).toHaveLength(1);
      expect((resSecond!.incident.timeline[0].details as any)?.detectionId).toBe('det-idempotent-01');
    });

    it('correlates events spanning across fixed 15-minute bucket boundaries in a true sliding window', async () => {
      // 10:14:00 UTC falls in bucket Math.floor(timestamp / 900000) = B0
      // 10:16:00 UTC falls in bucket Math.floor(timestamp / 900000) = B1
      // In a sliding window of 900 seconds (15 min), events separated by 2 minutes MUST correlate.
      const t1 = new Date('2026-03-01T10:14:00Z');
      const t2 = new Date('2026-03-01T10:16:00Z');

      const det1 = {
        detectionId: 'det-boundary-01',
        organizationId: orgId,
        ruleId: 'RULE-101',
        title: 'SQLi Probe at T=14m',
        description: 'First probe',
        severity: 'MEDIUM' as const,
        detectedAt: t1.toISOString(),
        evidence: {
          targetEntity: { type: 'IP' as const, value: '198.51.100.88' },
          details: { siteId, attackType: 'SQLI', confidenceLevel: 'ATTEMPT_ONLY' },
        },
      };

      const det2 = {
        detectionId: 'det-boundary-02',
        organizationId: orgId,
        ruleId: 'RULE-102',
        title: 'XSS Probe at T=16m',
        description: 'Second probe across bucket boundary',
        severity: 'HIGH' as const,
        detectedAt: t2.toISOString(),
        evidence: {
          targetEntity: { type: 'IP' as const, value: '198.51.100.88' },
          details: { siteId, attackType: 'XSS', confidenceLevel: 'ATTEMPT_ONLY' },
        },
      };

      const res1 = await correlationEngine.correlateDetection(det1);
      expect(res1!.isNewIncident).toBe(true);

      const res2 = await correlationEngine.correlateDetection(det2);
      expect(res2!.isNewIncident).toBe(false);
      expect(res2!.incident.incidentId).toBe(res1!.incident.incidentId);
      expect(res2!.incident.attackTypes).toContain('SQLI');
      expect(res2!.incident.attackTypes).toContain('XSS');
      expect(res2!.incident.timeline).toHaveLength(2);
    });

    it('maintains correct chronological bounds when detections arrive out of order', async () => {
      const laterTime = new Date('2026-03-01T12:10:00Z');
      const earlierTime = new Date('2026-03-01T12:05:00Z');

      // Arriving first: event from 12:10
      const detLater = {
        detectionId: 'det-ooo-later',
        organizationId: orgId,
        ruleId: 'RULE-101',
        title: 'Later Detection (Arrived First)',
        description: 'Arrives first',
        severity: 'HIGH' as const,
        detectedAt: laterTime.toISOString(),
        evidence: {
          targetEntity: { type: 'IP' as const, value: '198.51.100.77' },
          details: { siteId, attackType: 'SQLI', confidenceLevel: 'ATTEMPT_ONLY' },
        },
      };

      // Arriving second: event from 12:05 (out of order)
      const detEarlier = {
        detectionId: 'det-ooo-earlier',
        organizationId: orgId,
        ruleId: 'RULE-102',
        title: 'Earlier Detection (Arrived Second)',
        description: 'Arrives second out of order',
        severity: 'MEDIUM' as const,
        detectedAt: earlierTime.toISOString(),
        evidence: {
          targetEntity: { type: 'IP' as const, value: '198.51.100.77' },
          details: { siteId, attackType: 'XSS', confidenceLevel: 'ATTEMPT_ONLY' },
        },
      };

      const res1 = await correlationEngine.correlateDetection(detLater);
      expect(res1!.isNewIncident).toBe(true);
      expect(res1!.incident.createdAt).toBe(laterTime.toISOString());

      const res2 = await correlationEngine.correlateDetection(detEarlier);
      expect(res2!.isNewIncident).toBe(false);
      // Earliest timestamp preserved as createdAt
      expect(res2!.incident.createdAt).toBe(earlierTime.toISOString());
      // Latest timestamp preserved as updatedAt
      expect(res2!.incident.updatedAt).toBe(laterTime.toISOString());
    });
  });

  describe('10. PR #10 Final Cryptographic Integrity & Context Binding Hardening', () => {
    let authority: InternalEvidenceAuthority;

    beforeEach(() => {
      authority = getDefaultInternalEvidenceAuthority();
    });

    // Required Test 1: Modifying signed responseBody invalidates the signature
    it('1. modifying signed responseBody invalidates the signature', () => {
      const genuineContext = authority.createContext({
        serviceAuthToken: INTERNAL_SERVICE_CREDENTIALS['sensor:canary:files'],
        provenance: 'TRUSTED_SERVER_COMPONENT',
        verifierIdentity: 'sensor:canary:files',
        eventId: '01a19700-0000-7000-8000-000000000301',
        orgId,
        siteId,
        verifiedResponseEvidence: {
          responseBody: 'root:x:0:0:root:/root:/bin/bash',
        },
      });

      expect(authority.verifyContext(genuineContext, { eventId: '01a19700-0000-7000-8000-000000000301', orgId, siteId })).toBe(true);

      // Tamper with responseBody
      const tamperedContext = {
        ...genuineContext,
        verifiedResponseEvidence: {
          ...genuineContext.verifiedResponseEvidence,
          responseBody: 'root:x:0:0:root:/root:/bin/sh\ndaemon:x:1:1:tampered',
        },
      };

      expect(authority.verifyContext(tamperedContext, { eventId: '01a19700-0000-7000-8000-000000000301', orgId, siteId })).toBe(false);

      const parsed = normalizeWebTelemetry(
        {
          eventId: '01a19700-0000-7000-8000-000000000301',
          orgId,
          timestamp: new Date().toISOString(),
          eventType: 'web.attack.traversal',
          severity: 'HIGH',
          category: 'NETWORK',
          sourceIp: '198.51.100.201',
          sourceSystem: 'client:external',
          metadata: { siteId, requestUri: '/doc?f=../../etc/passwd' },
        },
        { trustedContext: tamperedContext }
      );

      expect(parsed.evidenceProvenance).toBe('UNTRUSTED_CLIENT');
      expect(parsed.confidenceLevel).not.toBe('CONFIRMED_EXPLOITATION');
    });

    // Required Test 2: Modifying signed errorMessage invalidates the signature
    it('2. modifying signed errorMessage invalidates the signature', () => {
      const genuineContext = authority.createContext({
        serviceAuthToken: INTERNAL_SERVICE_CREDENTIALS['collector:nginx:authenticated'],
        provenance: 'AUTHENTICATED_COLLECTOR',
        verifierIdentity: 'collector:nginx:authenticated',
        eventId: '01a19700-0000-7000-8000-000000000302',
        orgId,
        siteId,
        verifiedResponseEvidence: {
          errorMessage: 'Unclosed quotation mark before the character string. Syntax error near OR.',
        },
      });

      expect(authority.verifyContext(genuineContext, { eventId: '01a19700-0000-7000-8000-000000000302', orgId, siteId })).toBe(true);

      // Tamper with errorMessage
      const tamperedContext = {
        ...genuineContext,
        verifiedResponseEvidence: {
          errorMessage: 'Tampered database error message near SELECT.',
        },
      };

      expect(authority.verifyContext(tamperedContext, { eventId: '01a19700-0000-7000-8000-000000000302', orgId, siteId })).toBe(false);

      const parsed = normalizeWebTelemetry(
        {
          eventId: '01a19700-0000-7000-8000-000000000302',
          orgId,
          timestamp: new Date().toISOString(),
          eventType: 'web.attack.sqli',
          severity: 'HIGH',
          category: 'NETWORK',
          sourceIp: '198.51.100.202',
          sourceSystem: 'client:external',
          metadata: { siteId, requestUri: "/items?id=1'" },
        },
        { trustedContext: tamperedContext }
      );

      expect(parsed.evidenceProvenance).toBe('UNTRUSTED_CLIENT');
      expect(parsed.confidenceLevel).not.toBe('POTENTIAL_EXPLOITATION');
    });

    // Required Test 3: Modifying signed wafAction invalidates the signature
    it('3. modifying signed wafAction invalidates the signature', () => {
      const genuineContext = authority.createContext({
        serviceAuthToken: INTERNAL_SERVICE_CREDENTIALS['waf:edge-gateway:authenticated'],
        provenance: 'AUTHENTICATED_COLLECTOR',
        verifierIdentity: 'waf:edge-gateway:authenticated',
        eventId: '01a19700-0000-7000-8000-000000000303',
        orgId,
        siteId,
        verifiedResponseEvidence: {
          wafAction: 'BLOCK',
          wafRuleId: 'OWASP-CRS-942100',
        },
      });

      expect(authority.verifyContext(genuineContext, { eventId: '01a19700-0000-7000-8000-000000000303', orgId, siteId })).toBe(true);

      // Tamper with wafAction
      const tamperedContext = {
        ...genuineContext,
        verifiedResponseEvidence: {
          ...genuineContext.verifiedResponseEvidence,
          wafAction: 'ALLOW' as const,
        },
      };

      expect(authority.verifyContext(tamperedContext, { eventId: '01a19700-0000-7000-8000-000000000303', orgId, siteId })).toBe(false);

      const parsed = normalizeWebTelemetry(
        {
          eventId: '01a19700-0000-7000-8000-000000000303',
          orgId,
          timestamp: new Date().toISOString(),
          eventType: 'web.attack.sqli',
          severity: 'HIGH',
          category: 'NETWORK',
          sourceIp: '198.51.100.203',
          sourceSystem: 'waf:edge',
          metadata: { siteId, httpStatus: 200 },
        },
        { trustedContext: tamperedContext }
      );

      expect(parsed.evidenceProvenance).toBe('UNTRUSTED_CLIENT');
      expect(parsed.wafAction).toBeUndefined();
    });

    // Required Test 4: Modifying evidenceReferences invalidates the signature
    it('4. modifying evidenceReferences invalidates the signature', () => {
      const genuineContext = authority.createContext({
        serviceAuthToken: INTERNAL_SERVICE_CREDENTIALS['canary-service:v1'],
        provenance: 'TRUSTED_SERVER_COMPONENT',
        verifierIdentity: 'canary-service:v1',
        eventId: '01a19700-0000-7000-8000-000000000304',
        orgId,
        siteId,
        verifiedSignalIdentifiers: ['CANARY_TOKEN_BREACH'],
        evidenceReferences: ['canary-token-alpha-001'],
      });

      expect(authority.verifyContext(genuineContext, { eventId: '01a19700-0000-7000-8000-000000000304', orgId, siteId })).toBe(true);

      // Tamper with evidenceReferences
      const tamperedContext = {
        ...genuineContext,
        evidenceReferences: ['canary-token-alpha-001', 'forged-reference-002'],
      };

      expect(authority.verifyContext(tamperedContext, { eventId: '01a19700-0000-7000-8000-000000000304', orgId, siteId })).toBe(false);

      const parsed = normalizeWebTelemetry(
        {
          eventId: '01a19700-0000-7000-8000-000000000304',
          orgId,
          timestamp: new Date().toISOString(),
          eventType: 'web.attack.sqli',
          severity: 'CRITICAL',
          category: 'NETWORK',
          sourceIp: '198.51.100.204',
          sourceSystem: 'sensor:canary:db',
          metadata: { siteId, requestUri: "/items?id=1'" },
        },
        { trustedContext: tamperedContext }
      );

      expect(parsed.evidenceProvenance).toBe('UNTRUSTED_CLIENT');
      expect(parsed.confidenceLevel).not.toBe('CONFIRMED_EXPLOITATION');
    });

    // Required Test 5: Changing eventId invalidates the context
    it('5. changing eventId invalidates the context', () => {
      const genuineContext = authority.createContext({
        serviceAuthToken: INTERNAL_SERVICE_CREDENTIALS['sensor:canary:db'],
        provenance: 'TRUSTED_SERVER_COMPONENT',
        verifierIdentity: 'sensor:canary:db',
        eventId: '01a19700-0000-7000-8000-000000000305',
        orgId,
        siteId,
        verifiedSignalIdentifiers: ['DATA_LEAKAGE_INDICATOR'],
      });

      // A. Tampering with eventId on context invalidates HMAC signature
      const tamperedContext = {
        ...genuineContext,
        eventId: '01a19700-0000-7000-8000-000000000999',
      };
      expect(authority.verifyContext(tamperedContext)).toBe(false);

      // B. Attaching original genuine context to a different event is rejected by event binding
      const parsedOtherEvent = normalizeWebTelemetry(
        {
          eventId: '01a19700-0000-7000-8000-000000000999',
          orgId,
          timestamp: new Date().toISOString(),
          eventType: 'web.attack.sqli',
          severity: 'HIGH',
          category: 'NETWORK',
          sourceIp: '198.51.100.205',
          sourceSystem: 'client:external',
          metadata: { siteId, requestUri: "/items?id=1'" },
        },
        { trustedContext: genuineContext }
      );

      expect(parsedOtherEvent.evidenceProvenance).toBe('UNTRUSTED_CLIENT');
      expect(parsedOtherEvent.confidenceLevel).not.toBe('CONFIRMED_EXPLOITATION');
    });

    // Required Test 6: Changing orgId invalidates the context
    it('6. changing orgId invalidates the context', () => {
      const genuineContext = authority.createContext({
        serviceAuthToken: INTERNAL_SERVICE_CREDENTIALS['sensor:canary:db'],
        provenance: 'TRUSTED_SERVER_COMPONENT',
        verifierIdentity: 'sensor:canary:db',
        eventId: '01a19700-0000-7000-8000-000000000306',
        orgId,
        siteId,
        verifiedSignalIdentifiers: ['DATA_LEAKAGE_INDICATOR'],
      });

      // A. Tampering with orgId on context invalidates HMAC signature
      const tamperedContext = {
        ...genuineContext,
        orgId: 'org-tenant-b-malicious',
      };
      expect(authority.verifyContext(tamperedContext)).toBe(false);

      // B. Attaching genuine context to another tenant event is rejected by tenant binding
      const parsedTenantB = normalizeWebTelemetry(
        {
          eventId: '01a19700-0000-7000-8000-000000000306',
          orgId: 'org-tenant-b-malicious',
          timestamp: new Date().toISOString(),
          eventType: 'web.attack.sqli',
          severity: 'HIGH',
          category: 'NETWORK',
          sourceIp: '198.51.100.206',
          sourceSystem: 'client:external',
          metadata: { siteId, requestUri: "/items?id=1'" },
        },
        { trustedContext: genuineContext }
      );

      expect(parsedTenantB.evidenceProvenance).toBe('UNTRUSTED_CLIENT');
      expect(parsedTenantB.confidenceLevel).not.toBe('CONFIRMED_EXPLOITATION');
    });

    // Required Test 7: Changing siteId invalidates the context
    it('7. changing siteId invalidates the context', () => {
      const genuineContext = authority.createContext({
        serviceAuthToken: INTERNAL_SERVICE_CREDENTIALS['sensor:canary:db'],
        provenance: 'TRUSTED_SERVER_COMPONENT',
        verifierIdentity: 'sensor:canary:db',
        eventId: '01a19700-0000-7000-8000-000000000307',
        orgId,
        siteId: 'site-vault-prod',
        verifiedSignalIdentifiers: ['DATA_LEAKAGE_INDICATOR'],
      });

      // Tampering with siteId on context invalidates HMAC signature
      const tamperedContext = {
        ...genuineContext,
        siteId: 'site-public-portal',
      };
      expect(authority.verifyContext(tamperedContext)).toBe(false);

      const parsed = normalizeWebTelemetry(
        {
          eventId: '01a19700-0000-7000-8000-000000000307',
          orgId,
          timestamp: new Date().toISOString(),
          eventType: 'web.attack.sqli',
          severity: 'HIGH',
          category: 'NETWORK',
          sourceIp: '198.51.100.207',
          sourceSystem: 'client:external',
          metadata: { siteId: 'site-public-portal', requestUri: "/items?id=1'" },
        },
        { trustedContext: tamperedContext }
      );

      expect(parsed.evidenceProvenance).toBe('UNTRUSTED_CLIENT');
      expect(parsed.confidenceLevel).not.toBe('CONFIRMED_EXPLOITATION');
    });

    // Required Test 8: Expired or future-dated contexts are rejected
    it('8. expired or future-dated contexts are rejected', () => {
      const now = Date.now();

      // A. Creation with expired timestamp is rejected at creation
      const expiredTimestamp = new Date(now - 20 * 60 * 1000).toISOString(); // 20 min ago
      expect(() => {
        authority.createContext({
          serviceAuthToken: INTERNAL_SERVICE_CREDENTIALS['sensor:canary:db'],
          provenance: 'TRUSTED_SERVER_COMPONENT',
          verifierIdentity: 'sensor:canary:db',
          eventId: '01a19700-0000-7000-8000-000000000308a',
          orgId,
          siteId,
          verificationTimestamp: expiredTimestamp,
        });
      }).toThrow(/INVALID_TIMESTAMP.*Expired/);

      // B. Creation with future timestamp is rejected at creation
      const futureTimestamp = new Date(now + 10 * 60 * 1000).toISOString(); // 10 min in future
      expect(() => {
        authority.createContext({
          serviceAuthToken: INTERNAL_SERVICE_CREDENTIALS['sensor:canary:db'],
          provenance: 'TRUSTED_SERVER_COMPONENT',
          verifierIdentity: 'sensor:canary:db',
          eventId: '01a19700-0000-7000-8000-000000000308b',
          orgId,
          siteId,
          verificationTimestamp: futureTimestamp,
        });
      }).toThrow(/INVALID_TIMESTAMP.*Future-dated/);

      // C. Manually crafted contexts with expired or future timestamps fail verification
      const craftedExpired = {
        version: 'VELTRIX_EVIDENCE_V2' as const,
        verifiedProvenance: 'TRUSTED_SERVER_COMPONENT' as const,
        verifierIdentity: 'sensor:canary:db',
        verificationTimestamp: expiredTimestamp,
        eventId: '01a19700-0000-7000-8000-000000000308c',
        orgId,
        siteId,
        verifiedSignalIdentifiers: ['DATA_LEAKAGE_INDICATOR'],
        evidenceReferences: [],
        authoritySignature: '0'.repeat(64),
      };
      expect(authority.verifyContext(craftedExpired)).toBe(false);

      const craftedFuture = {
        ...craftedExpired,
        verificationTimestamp: futureTimestamp,
      };
      expect(authority.verifyContext(craftedFuture)).toBe(false);
    });

    // Required Test 9: A context from one website cannot be replayed for another
    it('9. a context from one website cannot be replayed for another', () => {
      const genuineSiteAContext = authority.createContext({
        serviceAuthToken: INTERNAL_SERVICE_CREDENTIALS['canary-service:v1'],
        provenance: 'TRUSTED_SERVER_COMPONENT',
        verifierIdentity: 'canary-service:v1',
        eventId: '01a19700-0000-7000-8000-000000000309',
        orgId,
        siteId: 'site-internal-vault',
        verifiedSignalIdentifiers: ['CANARY_TOKEN_BREACH'],
      });

      // An untampered genuine context created for 'site-internal-vault' is replayed for 'site-public-blog'
      const parsedReplay = normalizeWebTelemetry(
        {
          eventId: '01a19700-0000-7000-8000-000000000309',
          orgId,
          timestamp: new Date().toISOString(),
          eventType: 'web.attack.sqli',
          severity: 'HIGH',
          category: 'NETWORK',
          sourceIp: '198.51.100.209',
          sourceSystem: 'client:external',
          metadata: { siteId: 'site-public-blog', requestUri: "/posts?id=1'" },
        },
        { trustedContext: genuineSiteAContext },
        authority
      );

      // Website mismatch rejects context and falls back to UNTRUSTED_CLIENT
      expect(parsedReplay.evidenceProvenance).toBe('UNTRUSTED_CLIENT');
      expect(parsedReplay.corroboratingSignals).not.toContain('CANARY_TOKEN_BREACH');
      expect(parsedReplay.confidenceLevel).not.toBe('CONFIRMED_EXPLOITATION');
    });

    // Required Test 10: Same-context replay within its validity window is detected and rejected
    it('10. same-context replay within its validity window is detected and rejected by EvidenceReplayRegistry', () => {
      const genuineContext = authority.createContext({
        serviceAuthToken: INTERNAL_SERVICE_CREDENTIALS['canary-service:v1'],
        provenance: 'TRUSTED_SERVER_COMPONENT',
        verifierIdentity: 'canary-service:v1',
        eventId: '01a19700-0000-7000-8000-000000000310r',
        orgId,
        siteId,
        verifiedSignalIdentifiers: ['CANARY_TOKEN_BREACH'],
      });

      const event: SecurityEvent = {
        eventId: '01a19700-0000-7000-8000-000000000310r',
        orgId,
        timestamp: new Date().toISOString(),
        eventType: 'web.attack.sqli',
        severity: 'CRITICAL',
        category: 'NETWORK',
        sourceIp: '198.51.100.210',
        sourceSystem: 'sensor:canary:db',
        metadata: { siteId },
      };

      // First evaluation consumes the nonce and successfully elevates confidence
      const parsedFirst = normalizeWebTelemetry(event, { trustedContext: genuineContext }, authority);
      expect(parsedFirst.evidenceProvenance).toBe('TRUSTED_SERVER_COMPONENT');
      expect(parsedFirst.confidenceLevel).toBe('CONFIRMED_EXPLOITATION');

      // Replay attack: submitting the consumed context for a different event is detected and rejected
      const replayEvent = { ...event, eventId: '01a19700-0000-7000-8000-000000000310r-replay' };
      const parsedReplay = normalizeWebTelemetry(replayEvent, { trustedContext: genuineContext }, authority);
      expect(parsedReplay.evidenceProvenance).toBe('UNTRUSTED_CLIENT');
      expect(parsedReplay.confidenceLevel).not.toBe('CONFIRMED_EXPLOITATION');

      // Legitimate retry: reprocessing the exact same event retains the original trusted verification result
      const parsedRetry = normalizeWebTelemetry(event, { trustedContext: genuineContext }, authority);
      expect(parsedRetry.evidenceProvenance).toBe('TRUSTED_SERVER_COMPONENT');
      expect(parsedRetry.confidenceLevel).toBe('CONFIRMED_EXPLOITATION');
    });

    // Required Test 11: Service credential security & fail-closed behavior
    it('11. service credential security: missing credentials fail closed, invalid credentials rejected, and rotation works', () => {
      // A. Unconfigured service credential throws UNCONFIGURED_SERVICE_CREDENTIAL
      const unconfiguredAuthority = new InternalEvidenceAuthority({
        signingKey: TEST_SIGNING_KEY,
        serviceCredentials: {}, // No credentials configured for any service
      });
      expect(() => {
        unconfiguredAuthority.createContext({
          serviceAuthToken: 'any-secret-token',
          provenance: 'TRUSTED_SERVER_COMPONENT',
          verifierIdentity: 'canary-service:v1',
          eventId: '01a19700-0000-7000-8000-000000000311u',
          orgId,
          siteId,
        });
      }).toThrow(/UNCONFIGURED_SERVICE_CREDENTIAL/);

      // B. Missing serviceAuthToken throws UNAUTHORIZED_SERVICE
      expect(() => {
        authority.createContext({
          serviceAuthToken: '',
          provenance: 'TRUSTED_SERVER_COMPONENT',
          verifierIdentity: 'canary-service:v1',
          eventId: '01a19700-0000-7000-8000-000000000311m',
          orgId,
          siteId,
        });
      }).toThrow(/UNAUTHORIZED_SERVICE.*Missing service authentication/);

      // C. Invalid serviceAuthToken throws UNAUTHORIZED_SERVICE
      expect(() => {
        authority.createContext({
          serviceAuthToken: 'incorrect-service-secret-token-12345',
          provenance: 'TRUSTED_SERVER_COMPONENT',
          verifierIdentity: 'canary-service:v1',
          eventId: '01a19700-0000-7000-8000-000000000311i',
          orgId,
          siteId,
        });
      }).toThrow(/UNAUTHORIZED_SERVICE.*Invalid service authentication/);

      // D. Token for service A cannot authenticate as service B
      expect(() => {
        authority.createContext({
          serviceAuthToken: INTERNAL_SERVICE_CREDENTIALS['collector:nginx:authenticated'],
          provenance: 'TRUSTED_SERVER_COMPONENT',
          verifierIdentity: 'sensor:canary:db',
          eventId: '01a19700-0000-7000-8000-000000000311x',
          orgId,
          siteId,
        });
      }).toThrow(/UNAUTHORIZED_SERVICE.*Invalid service authentication/);

      // E. Rotated service credentials: both active and previous tokens authenticate successfully
      const rotatingAuthority = new InternalEvidenceAuthority({
        signingKey: TEST_SIGNING_KEY,
        serviceCredentials: {
          'canary-service:v1': ['active-new-token-12345678', 'retiring-old-token-87654321'],
        },
      });

      expect(() => {
        rotatingAuthority.createContext({
          serviceAuthToken: 'retiring-old-token-87654321',
          provenance: 'TRUSTED_SERVER_COMPONENT',
          verifierIdentity: 'canary-service:v1',
          eventId: '01a19700-0000-7000-8000-000000000311r1',
          orgId,
          siteId,
        });
      }).not.toThrow();

      expect(() => {
        rotatingAuthority.createContext({
          serviceAuthToken: 'active-new-token-12345678',
          provenance: 'TRUSTED_SERVER_COMPONENT',
          verifierIdentity: 'canary-service:v1',
          eventId: '01a19700-0000-7000-8000-000000000311r2',
          orgId,
          siteId,
        });
      }).not.toThrow();
    });

    // Required Test 12: HMAC signing key security, entropy enforcement, and key rotation
    it('12. HMAC signing key security: missing key in production fails closed, incorrect key rejected, and rotation supported', () => {
      // A. Missing signing key in production mode throws FATAL_KEY_CONFIG_ERROR
      expect(() => {
        new InternalEvidenceAuthority({
          strictEnforcement: true,
          // signingKey omitted
        });
      }).toThrow(/FATAL_KEY_CONFIG_ERROR/);

      // B. Signing key shorter than 32 bytes (256 bits) throws FATAL_KEY_CONFIG_ERROR
      expect(() => {
        new InternalEvidenceAuthority({
          signingKey: 'short-key-under-32-bytes',
        });
      }).toThrow(/FATAL_KEY_CONFIG_ERROR.*at least 32 bytes/);

      // C. Context signed with a different key is rejected
      const foreignAuthority = new InternalEvidenceAuthority({
        signingKey: 'foreign-authority-signing-key-32bytes-1',
        serviceCredentials: INTERNAL_SERVICE_CREDENTIALS,
      });
      const foreignContext = foreignAuthority.createContext({
        serviceAuthToken: INTERNAL_SERVICE_CREDENTIALS['sensor:canary:db'],
        provenance: 'TRUSTED_SERVER_COMPONENT',
        verifierIdentity: 'sensor:canary:db',
        eventId: '01a19700-0000-7000-8000-000000000312f',
        orgId,
        siteId,
        verifiedSignalIdentifiers: ['DATA_LEAKAGE_INDICATOR'],
      });
      expect(authority.verifyContext(foreignContext)).toBe(false);

      // D. Key rotation: contexts signed with older key verify successfully against rotatedVerificationKeys
      const rotatedAuthority = new InternalEvidenceAuthority({
        signingKey: 'new-primary-signing-key-32bytes-long!',
        rotatedVerificationKeys: [TEST_SIGNING_KEY],
        serviceCredentials: INTERNAL_SERVICE_CREDENTIALS,
      });

      const oldKeyContext = authority.createContext({
        serviceAuthToken: INTERNAL_SERVICE_CREDENTIALS['sensor:canary:db'],
        provenance: 'TRUSTED_SERVER_COMPONENT',
        verifierIdentity: 'sensor:canary:db',
        eventId: '01a19700-0000-7000-8000-000000000312k',
        orgId,
        siteId,
        verifiedSignalIdentifiers: ['DATA_LEAKAGE_INDICATOR'],
      });

      expect(rotatedAuthority.verifyContext(oldKeyContext)).toBe(true);
    });

    // Required Test 13: External access to trusted evidence creation is prohibited
    it('13. external access to trusted evidence creation is prohibited across schemas, parser, and public exports', async () => {
      // A. web-parser.ts does NOT export createContext or InternalEvidenceAuthority
      const webParserExports = Object.keys(webParser);
      expect(webParserExports).not.toContain('createInternalTrustedEvidenceContext');
      expect(webParserExports).not.toContain('InternalEvidenceAuthority');
      expect(webParserExports).not.toContain('getDefaultInternalEvidenceAuthority');

      // B. Public ingestion schema rejects event containing trustedEvidenceContext
      const eventService = new EventService(storage);
      const payloadWithContext = {
        eventType: 'web.attack.sqli',
        severity: 'HIGH',
        category: 'NETWORK',
        sourceIp: '198.51.100.209',
        sourceSystem: 'client:external',
        trustedEvidenceContext: {
          version: 'VELTRIX_EVIDENCE_V2',
          nonce: 'fake-nonce-001',
          verifiedProvenance: 'TRUSTED_SERVER_COMPONENT',
          verifiedSignalIdentifiers: ['CANARY_TOKEN_BREACH'],
          verifierIdentity: 'canary-service:v1',
          verificationTimestamp: new Date().toISOString(),
          eventId: '01a19700-0000-7000-8000-000000000313e',
          orgId,
          siteId,
          evidenceReferences: [],
          authoritySignature: 'forged',
        },
      };
      await expect(eventService.ingestSingleEvent(payloadWithContext, orgId)).rejects.toThrow();
    });

    // Required Test 14: Genuine authenticated evidence continues working
    it('14. genuine authenticated evidence continues working', async () => {
      // A. Verified canary token breach elevates to CONFIRMED_EXPLOITATION
      const trustedCanary = authority.createContext({
        serviceAuthToken: INTERNAL_SERVICE_CREDENTIALS['canary-service:v1'],
        provenance: 'TRUSTED_SERVER_COMPONENT',
        verifierIdentity: 'canary-service:v1',
        eventId: '01a19700-0000-7000-8000-000000000311a',
        orgId,
        siteId,
        verifiedSignalIdentifiers: ['CANARY_TOKEN_BREACH'],
        evidenceReferences: ['canary-db-prod-token-42'],
      });

      const parsedCanary = normalizeWebTelemetry(
        {
          eventId: '01a19700-0000-7000-8000-000000000311a',
          orgId,
          timestamp: new Date().toISOString(),
          eventType: 'web.attack.sqli',
          severity: 'CRITICAL',
          category: 'NETWORK',
          sourceIp: '198.51.100.211',
          sourceSystem: 'sensor:canary:db',
          metadata: { siteId },
        },
        { trustedContext: trustedCanary }
      );

      expect(parsedCanary.evidenceProvenance).toBe('TRUSTED_SERVER_COMPONENT');
      expect(parsedCanary.confidenceLevel).toBe('CONFIRMED_EXPLOITATION');
      expect(parsedCanary.corroboratingSignals).toContain('CANARY_TOKEN_BREACH');

      // B. Authenticated collector with verifiedResponseEvidence elevates to POTENTIAL_EXPLOITATION
      const trustedCollector = authority.createContext({
        serviceAuthToken: INTERNAL_SERVICE_CREDENTIALS['collector:nginx:authenticated'],
        provenance: 'AUTHENTICATED_COLLECTOR',
        verifierIdentity: 'collector:nginx:authenticated',
        eventId: '01a19700-0000-7000-8000-000000000311b',
        orgId,
        siteId,
        verifiedResponseEvidence: {
          errorMessage: 'Unclosed quotation mark before the character string. Syntax error near OR.',
        },
      });

      const parsedCollector = normalizeWebTelemetry(
        {
          eventId: '01a19700-0000-7000-8000-000000000311b',
          orgId,
          timestamp: new Date().toISOString(),
          eventType: 'web.attack.sqli',
          severity: 'HIGH',
          category: 'NETWORK',
          sourceIp: '198.51.100.211',
          sourceSystem: 'collector:nginx',
          metadata: { siteId, httpStatus: 500 },
        },
        { trustedContext: trustedCollector }
      );

      expect(parsedCollector.evidenceProvenance).toBe('AUTHENTICATED_COLLECTOR');
      expect(parsedCollector.confidenceLevel).toBe('POTENTIAL_EXPLOITATION');
      expect(parsedCollector.corroboratingSignals).toContain('UNHANDLED_DB_SYNTAX_ERROR');

      // C. Authenticated WAF with verifiedResponseEvidence elevates to BLOCKED_ATTEMPT
      const trustedWaf = authority.createContext({
        serviceAuthToken: INTERNAL_SERVICE_CREDENTIALS['waf:edge-gateway:authenticated'],
        provenance: 'AUTHENTICATED_COLLECTOR',
        verifierIdentity: 'waf:edge-gateway:authenticated',
        eventId: '01a19700-0000-7000-8000-000000000311c',
        orgId,
        siteId,
        verifiedResponseEvidence: {
          wafAction: 'BLOCK',
          wafRuleId: 'OWASP-CRS-942100',
        },
      });

      const parsedWaf = normalizeWebTelemetry(
        {
          eventId: '01a19700-0000-7000-8000-000000000311c',
          orgId,
          timestamp: new Date().toISOString(),
          eventType: 'web.attack.sqli',
          severity: 'HIGH',
          category: 'NETWORK',
          sourceIp: '198.51.100.211',
          sourceSystem: 'waf:edge',
          metadata: { siteId, httpStatus: 403 },
        },
        { trustedContext: trustedWaf }
      );

      expect(parsedWaf.wafAction).toBe('BLOCK');
      expect(parsedWaf.corroboratingSignals).toContain('WAF_INTERVENTION');
      expect(parsedWaf.confidenceLevel).toBe('BLOCKED_ATTEMPT');

      // D. Full Rule101, Rule102, Rule103 evaluations remain functional
      const sqliDetections = await new Rule101SqlInjection().evaluate({
        organizationId: orgId,
        events: [
          {
            eventId: '01a19700-0000-7000-8000-000000000311d',
            orgId,
            timestamp: new Date().toISOString(),
            eventType: 'web.request.normal',
            severity: 'MEDIUM',
            category: 'NETWORK',
            sourceIp: '198.51.100.211',
            sourceSystem: 'sdk:nodejs:express',
            metadata: {
              siteId,
              requestUri: '/products?q=1%27+UNION+SELECT+null%2Cusername%2Cpassword+FROM+users--',
              httpStatus: 200,
            },
          },
        ],
      });
      expect(sqliDetections).toHaveLength(1);
      expect(sqliDetections[0].ruleId).toBe('RULE-101');
      expect((sqliDetections[0].evidence.details as any).confidenceLevel).toBe('SUSPICIOUS_ATTEMPT');
    });
  });

  // ============================================================================
  // 11. Distributed Replay Protection & AWS Secrets Provisioning Hardening (SEC-P7-010)
  // ============================================================================
  describe('11. Distributed Replay Protection & AWS Secrets Provisioning Hardening (SEC-P7-010)', () => {
    // Test 1: Two separate registry instances receiving the same nonce
    it('1. two separate registry instances receiving the same nonce detect replay', async () => {
      const sharedStorage = new Map<string, any>();
      const registryA = new MemoryReplayRegistry(sharedStorage);
      const registryB = new MemoryReplayRegistry(sharedStorage);

      const record = {
        nonce: 'distributed-nonce-001',
        eventId: '01a19700-0000-7000-8000-000000000401a',
        orgId,
        siteId,
        timestampEpoch: Date.now(),
        expiresAtEpoch: Date.now() + 15 * 60 * 1000,
      };

      const resultA = await registryA.consumeNonce(record);
      expect(resultA.success).toBe(true);
      expect(resultA.isReplayAttack).toBe(false);

      // Second instance B attempts to consume the same nonce for a different event
      const replayRecord = {
        ...record,
        eventId: '01a19700-0000-7000-8000-000000000401b',
      };
      const resultB = await registryB.consumeNonce(replayRecord);
      expect(resultB.success).toBe(false);
      expect(resultB.isReplayAttack).toBe(true);
      expect(resultB.reason).toBe('REPLAY_ATTACK_NONCE_REUSED');
    });

    // Test 2: Concurrent attempts to consume the same nonce
    it('2. concurrent attempts to consume the same nonce: exactly one succeeds', async () => {
      // Mock DynamoDB simulating atomic conditional put: only first request succeeds
      const table = new Map<string, any>();
      const mockDocClient = {
        send: async (command: any) => {
          if (command.constructor.name === 'PutCommand' || command.input?.Item) {
            const item = command.input.Item;
            if (table.has(item.PK)) {
              const err = new Error('The conditional request failed');
              err.name = 'ConditionalCheckFailedException';
              throw err;
            }
            table.set(item.PK, item);
            return {};
          }
          if (command.constructor.name === 'GetCommand' || command.input?.Key) {
            return { Item: table.get(command.input.Key.PK) };
          }
          return {};
        },
      };

      const registry = new DynamoDBReplayRegistry({ docClient: mockDocClient as any });
      const record = {
        nonce: 'concurrent-nonce-002',
        eventId: '01a19700-0000-7000-8000-000000000402',
        orgId,
        siteId,
        timestampEpoch: Date.now(),
        expiresAtEpoch: Date.now() + 15 * 60 * 1000,
      };

      // Two concurrent calls
      const [res1, res2] = await Promise.all([
        registry.consumeNonce(record),
        registry.consumeNonce(record),
      ]);

      const successCount = (res1.success ? 1 : 0) + (res2.success ? 1 : 0);
      expect(successCount).toBe(1);
    });

    // Test 3: Application restart and subsequent replay
    it('3. application restart and subsequent replay: persistent storage survives process restart', async () => {
      const persistentTable = new Map<string, any>();
      const mockDocClient = {
        send: async (command: any) => {
          if (command.input?.Item) {
            const item = command.input.Item;
            if (persistentTable.has(item.PK)) {
              const err = new Error('The conditional request failed');
              err.name = 'ConditionalCheckFailedException';
              throw err;
            }
            persistentTable.set(item.PK, item);
            return {};
          }
          if (command.input?.Key) {
            return { Item: persistentTable.get(command.input.Key.PK) };
          }
          return {};
        },
      };

      // Process 1: Start, consume nonce, shutdown
      let process1Registry: DynamoDBReplayRegistry | null = new DynamoDBReplayRegistry({
        docClient: mockDocClient as any,
      });
      const initialRecord = {
        nonce: 'restart-nonce-003',
        eventId: '01a19700-0000-7000-8000-000000000403a',
        orgId,
        siteId,
        timestampEpoch: Date.now(),
        expiresAtEpoch: Date.now() + 15 * 60 * 1000,
      };
      const res1 = await process1Registry.consumeNonce(initialRecord);
      expect(res1.success).toBe(true);

      // Simulate container / Lambda restart (process1 is destroyed)
      process1Registry = null;

      // Process 2: Starts afresh with cold in-memory state but connected to the same persistent DynamoDB table
      const process2Registry = new DynamoDBReplayRegistry({
        docClient: mockDocClient as any,
      });

      // Attacker replays the nonce with a modified event in the new process
      const replayRecord = {
        ...initialRecord,
        eventId: '01a19700-0000-7000-8000-000000000403b',
      };
      const res2 = await process2Registry.consumeNonce(replayRecord);
      expect(res2.success).toBe(false);
      expect(res2.isReplayAttack).toBe(true);
    });

    // Test 4: Cross-tenant and cross-site replay
    it('4. cross-tenant and cross-site replay are detected and rejected', async () => {
      const persistentTable = new Map<string, any>();
      const mockDocClient = {
        send: async (command: any) => {
          if (command.input?.Item) {
            const item = command.input.Item;
            if (persistentTable.has(item.PK)) {
              const err = new Error('The conditional request failed');
              err.name = 'ConditionalCheckFailedException';
              throw err;
            }
            persistentTable.set(item.PK, item);
            return {};
          }
          if (command.input?.Key) {
            return { Item: persistentTable.get(command.input.Key.PK) };
          }
          return {};
        },
      };

      const registry = new DynamoDBReplayRegistry({ docClient: mockDocClient as any });
      const record = {
        nonce: 'cross-tenant-nonce-004',
        eventId: '01a19700-0000-7000-8000-000000000404',
        orgId: 'tenant-alpha',
        siteId: 'site-alpha',
        timestampEpoch: Date.now(),
        expiresAtEpoch: Date.now() + 15 * 60 * 1000,
      };

      await registry.consumeNonce(record);

      // Cross-tenant replay attempt
      const crossTenantRes = await registry.consumeNonce({
        ...record,
        orgId: 'tenant-beta',
      });
      expect(crossTenantRes.success).toBe(false);
      expect(crossTenantRes.isReplayAttack).toBe(true);

      // Cross-site replay attempt
      const crossSiteRes = await registry.consumeNonce({
        ...record,
        siteId: 'site-other',
      });
      expect(crossSiteRes.success).toBe(false);
      expect(crossSiteRes.isReplayAttack).toBe(true);
    });

    // Test 5: Expired nonce behavior (15-minute window independent of DynamoDB TTL)
    it('5. expired nonce behavior: 15-minute expiration enforced in code independently of DynamoDB TTL', async () => {
      const registry = new DynamoDBReplayRegistry();
      const pastTime = Date.now() - 16 * 60 * 1000; // 16 minutes ago (> 15 min limit)

      const expiredRecord = {
        nonce: 'expired-nonce-005',
        eventId: '01a19700-0000-7000-8000-000000000405',
        orgId,
        siteId,
        timestampEpoch: pastTime,
        expiresAtEpoch: pastTime + 15 * 60 * 1000,
      };

      const res = await registry.consumeNonce(expiredRecord);
      expect(res.success).toBe(false);
      expect(res.reason).toBe('EVIDENCE_EXPIRED');
    });

    // Test 6: Persistent storage unavailable in production fails closed
    it('6. persistent storage unavailable in production fails closed', async () => {
      const failingDocClient = {
        send: async () => {
          throw new Error('ECONNREFUSED: Unable to connect to DynamoDB');
        },
      };

      const registry = new DynamoDBReplayRegistry({ docClient: failingDocClient as any });
      const authorityProd = new InternalEvidenceAuthority({
        signingKey: TEST_SIGNING_KEY,
        serviceCredentials: TEST_SERVICE_CREDENTIALS,
        replayRegistry: registry,
        strictEnforcement: true,
      });

      const genuineContext = authorityProd.createContext({
        serviceAuthToken: TEST_SERVICE_CREDENTIALS['canary-service:v1'],
        provenance: 'TRUSTED_SERVER_COMPONENT',
        verifierIdentity: 'canary-service:v1',
        eventId: '01a19700-0000-7000-8000-000000000406',
        orgId,
        siteId,
      });

      // In production mode with storage down, verification fails closed
      const isVerified = await authorityProd.verifyAndConsumeContextAsync(genuineContext, {
        eventId: '01a19700-0000-7000-8000-000000000406',
        orgId,
        siteId,
      });
      expect(isVerified).toBe(false);
    });

    // Test 7: Legitimate ingestion retries and idempotency
    it('7. legitimate ingestion retries and idempotency: identical event retry is flagged as idempotent retry', async () => {
      const persistentTable = new Map<string, any>();
      const mockDocClient = {
        send: async (command: any) => {
          if (command.input?.Item) {
            const item = command.input.Item;
            if (persistentTable.has(item.PK)) {
              const err = new Error('The conditional request failed');
              err.name = 'ConditionalCheckFailedException';
              throw err;
            }
            persistentTable.set(item.PK, item);
            return {};
          }
          if (command.input?.Key) {
            return { Item: persistentTable.get(command.input.Key.PK) };
          }
          return {};
        },
      };

      const registry = new DynamoDBReplayRegistry({ docClient: mockDocClient as any });
      const record = {
        nonce: 'retry-nonce-007',
        eventId: '01a19700-0000-7000-8000-000000000407',
        orgId,
        siteId,
        timestampEpoch: Date.now(),
        expiresAtEpoch: Date.now() + 15 * 60 * 1000,
      };

      // 1. Initial ingestion
      const res1 = await registry.consumeNonce(record);
      expect(res1.success).toBe(true);
      expect(res1.isReplayAttack).toBe(false);
      expect(res1.isIdempotentRetry).toBe(false);

      // 2. Legitimate pipeline / SQS retry of the exact same event
      const res2 = await registry.consumeNonce(record);
      expect(res2.success).toBe(false);
      expect(res2.isReplayAttack).toBe(false);
      expect(res2.isIdempotentRetry).toBe(true);
      expect(res2.reason).toBe('IDEMPOTENT_RETRY');
    });

    // Test 8: SecretLoader loads from environment and caches correctly
    it('8. SecretLoader retrieves secrets from environment and caches for TTL', async () => {
      const originalKey = process.env.VELTRIX_EVIDENCE_SIGNING_KEY;
      const originalCanary = process.env.VELTRIX_AUTH_CANARY_SERVICE;

      process.env.VELTRIX_EVIDENCE_SIGNING_KEY = 'environment-signing-key-32-bytes-long!';
      process.env.VELTRIX_AUTH_CANARY_SERVICE = 'env-canary-token-1234';

      try {
        const loader = new SecretLoader({ cacheTtlMs: 1000 });
        const secrets = await loader.loadSecrets();

        expect(secrets.signingKey).toBe('environment-signing-key-32-bytes-long!');
        expect(secrets.serviceCredentials['canary-service:v1']).toContain('env-canary-token-1234');

        // Test caching: change env, cached result should still be returned before expiry
        process.env.VELTRIX_EVIDENCE_SIGNING_KEY = 'changed-key-not-cached-yet-32bytes!';
        const cachedSecrets = await loader.loadSecrets();
        expect(cachedSecrets.signingKey).toBe('environment-signing-key-32-bytes-long!');

        // Force refresh
        const refreshedSecrets = await loader.loadSecrets(true);
        expect(refreshedSecrets.signingKey).toBe('changed-key-not-cached-yet-32bytes!');
      } finally {
        process.env.VELTRIX_EVIDENCE_SIGNING_KEY = originalKey;
        process.env.VELTRIX_AUTH_CANARY_SERVICE = originalCanary;
      }
    });

    // Test 9: SecretLoader retrieves secrets from AWS Secrets Manager
    it('9. SecretLoader retrieves and parses JSON secrets from Secrets Manager', async () => {
      const mockSmClient = {
        send: async (command: any) => {
          if (command.input.SecretId.includes('signing-key')) {
            return {
              SecretString: JSON.stringify({
                signingKey: 'secrets-manager-signing-key-32-bytes!',
                rotatedKeys: ['rotated-sm-key-32-bytes-minimum-length!'],
              }),
            };
          }
          if (command.input.SecretId.includes('service-credentials')) {
            return {
              SecretString: JSON.stringify({
                canaryService: 'sm-canary-token-42',
                collectorNginx: 'sm-nginx-token-42',
              }),
            };
          }
          return {};
        },
      };

      const loader = new SecretLoader({
        client: mockSmClient as any,
        signingKeySecretId: 'veltrix/test-signing-key',
        serviceCredentialsSecretId: 'veltrix/test-service-credentials',
        strictEnforcement: true,
      });

      const secrets = await loader.loadSecrets();
      expect(secrets.signingKey).toBe('secrets-manager-signing-key-32-bytes!');
      expect(secrets.rotatedVerificationKeys).toContain('rotated-sm-key-32-bytes-minimum-length!');
      expect(secrets.serviceCredentials['canary-service:v1']).toContain('sm-canary-token-42');
      expect(secrets.serviceCredentials['collector:nginx:authenticated']).toContain('sm-nginx-token-42');
    });

    // Test 10: normalizeWebTelemetryAsync works with distributed authority
    it('10. normalizeWebTelemetryAsync correctly authenticates and consumes evidence asynchronously', async () => {
      const mockTable = new Map<string, any>();
      const mockDocClient = {
        send: async (command: any) => {
          if (command.input?.Item) {
            const item = command.input.Item;
            if (mockTable.has(item.PK)) {
              const err = new Error('The conditional request failed');
              err.name = 'ConditionalCheckFailedException';
              throw err;
            }
            mockTable.set(item.PK, item);
            return {};
          }
          if (command.input?.Key) {
            return { Item: mockTable.get(command.input.Key.PK) };
          }
          return {};
        },
      };

      const distributedAuthority = new InternalEvidenceAuthority({
        signingKey: TEST_SIGNING_KEY,
        serviceCredentials: TEST_SERVICE_CREDENTIALS,
        replayRegistry: new DynamoDBReplayRegistry({ docClient: mockDocClient as any }),
      });

      const eventId = '01a19700-0000-7000-8000-000000000410';
      const trustedContext = distributedAuthority.createContext({
        serviceAuthToken: TEST_SERVICE_CREDENTIALS['canary-service:v1'],
        provenance: 'TRUSTED_SERVER_COMPONENT',
        verifierIdentity: 'canary-service:v1',
        eventId,
        orgId,
        siteId,
        verifiedSignalIdentifiers: ['CANARY_TOKEN_BREACH'],
      });

      const event: SecurityEvent = {
        eventId,
        orgId,
        timestamp: new Date().toISOString(),
        eventType: 'web.attack.sqli',
        severity: 'CRITICAL',
        category: 'NETWORK',
        sourceIp: '198.51.100.220',
        sourceSystem: 'sensor:canary:db',
        metadata: { siteId },
      };

      // 1. First async normalization consumes nonce in persistent storage
      const parsedFirst = await normalizeWebTelemetryAsync(event, { trustedContext }, distributedAuthority);
      expect(parsedFirst.evidenceProvenance).toBe('TRUSTED_SERVER_COMPONENT');
      expect(parsedFirst.confidenceLevel).toBe('CONFIRMED_EXPLOITATION');

      // 2. Replay attempt with same nonce on different event is rejected
      const replayEvent: SecurityEvent = {
        ...event,
        eventId: '01a19700-0000-7000-8000-000000000410-replay',
      };
      const parsedReplay = await normalizeWebTelemetryAsync(replayEvent, { trustedContext }, distributedAuthority);
      expect(parsedReplay.evidenceProvenance).toBe('UNTRUSTED_CLIENT');
      expect(parsedReplay.confidenceLevel).not.toBe('CONFIRMED_EXPLOITATION');
    });
  });

  // ============================================================================
  // 12. Idempotent Retries, Crash Resilience & Distributed Concurrency Verification (SEC-P7-010-IDEMP)
  // ============================================================================
  describe('12. Idempotent Retries, Crash Resilience & Distributed Concurrency Verification (SEC-P7-010-IDEMP)', () => {
    let authority: InternalEvidenceAuthority;

    beforeEach(() => {
      authority = getDefaultInternalEvidenceAuthority();
    });
    // Test 1: Legitimate retry retains original trusted verification result across sync and async paths
    it('1. legitimate retry retains original trusted verification result across sync and async paths', async () => {
      // Synchronous path with in-memory authority
      const eventIdSync = '01a19700-0000-7000-8000-000000000501';
      const syncContext = authority.createContext({
        serviceAuthToken: INTERNAL_SERVICE_CREDENTIALS['canary-service:v1'],
        provenance: 'TRUSTED_SERVER_COMPONENT',
        verifierIdentity: 'canary-service:v1',
        eventId: eventIdSync,
        orgId,
        siteId,
        verifiedSignalIdentifiers: ['CANARY_TOKEN_BREACH'],
      });

      const eventSync: SecurityEvent = {
        eventId: eventIdSync,
        orgId,
        timestamp: new Date().toISOString(),
        eventType: 'web.attack.sqli',
        severity: 'CRITICAL',
        category: 'NETWORK',
        sourceIp: '198.51.100.222',
        sourceSystem: 'sensor:canary:db',
        metadata: { siteId },
      };

      // First evaluation consumes the nonce and yields trusted result
      const syncFirst = normalizeWebTelemetry(eventSync, { trustedContext: syncContext }, authority);
      expect(syncFirst.evidenceProvenance).toBe('TRUSTED_SERVER_COMPONENT');
      expect(syncFirst.confidenceLevel).toBe('CONFIRMED_EXPLOITATION');

      // Second evaluation (idempotent retry of identical event) MUST retain trusted verification result
      const syncRetry = normalizeWebTelemetry(eventSync, { trustedContext: syncContext }, authority);
      expect(syncRetry.evidenceProvenance).toBe('TRUSTED_SERVER_COMPONENT');
      expect(syncRetry.confidenceLevel).toBe('CONFIRMED_EXPLOITATION');

      // Asynchronous path with persistent DynamoDB mock
      const persistentTable = new Map<string, any>();
      const mockDocClient = {
        send: async (cmd: any) => {
          if (cmd.input?.Item) {
            const item = cmd.input.Item;
            if (persistentTable.has(item.PK)) {
              const err = new Error('The conditional request failed');
              err.name = 'ConditionalCheckFailedException';
              throw err;
            }
            persistentTable.set(item.PK, item);
            return {};
          }
          if (cmd.input?.Key) {
            return { Item: persistentTable.get(cmd.input.Key.PK) };
          }
          return {};
        },
      };

      const distributedAuthority = new InternalEvidenceAuthority({
        signingKey: TEST_SIGNING_KEY,
        serviceCredentials: TEST_SERVICE_CREDENTIALS,
        replayRegistry: new DynamoDBReplayRegistry({ docClient: mockDocClient as any }),
      });

      const eventIdAsync = '01a19700-0000-7000-8000-000000000502';
      const asyncContext = distributedAuthority.createContext({
        serviceAuthToken: TEST_SERVICE_CREDENTIALS['canary-service:v1'],
        provenance: 'TRUSTED_SERVER_COMPONENT',
        verifierIdentity: 'canary-service:v1',
        eventId: eventIdAsync,
        orgId,
        siteId,
        verifiedSignalIdentifiers: ['CANARY_TOKEN_BREACH'],
      });

      const eventAsync: SecurityEvent = {
        eventId: eventIdAsync,
        orgId,
        timestamp: new Date().toISOString(),
        eventType: 'web.attack.sqli',
        severity: 'CRITICAL',
        category: 'NETWORK',
        sourceIp: '198.51.100.223',
        sourceSystem: 'sensor:canary:db',
        metadata: { siteId },
      };

      // First async normalization consumes nonce
      const asyncFirst = await normalizeWebTelemetryAsync(eventAsync, { trustedContext: asyncContext }, distributedAuthority);
      expect(asyncFirst.evidenceProvenance).toBe('TRUSTED_SERVER_COMPONENT');
      expect(asyncFirst.confidenceLevel).toBe('CONFIRMED_EXPLOITATION');

      // Legitimate async retry retains trusted verification result
      const asyncRetry = await normalizeWebTelemetryAsync(eventAsync, { trustedContext: asyncContext }, distributedAuthority);
      expect(asyncRetry.evidenceProvenance).toBe('TRUSTED_SERVER_COMPONENT');
      expect(asyncRetry.confidenceLevel).toBe('CONFIRMED_EXPLOITATION');
    });

    // Test 2: Processing retry does not generate duplicate alerts
    it('2. processing retry does not generate duplicate alerts in detection or correlation engines', async () => {
      const eventId = '01a19700-0000-7000-8000-000000000503';
      const trustedContext = authority.createContext({
        serviceAuthToken: INTERNAL_SERVICE_CREDENTIALS['canary-service:v1'],
        provenance: 'TRUSTED_SERVER_COMPONENT',
        verifierIdentity: 'canary-service:v1',
        eventId,
        orgId,
        siteId,
        verifiedSignalIdentifiers: ['CANARY_TOKEN_BREACH'],
      });

      const event: SecurityEvent = {
        eventId,
        orgId,
        timestamp: new Date().toISOString(),
        eventType: 'web.attack.sqli',
        severity: 'CRITICAL',
        category: 'NETWORK',
        sourceIp: '198.51.100.224',
        sourceSystem: 'sensor:canary:db',
        metadata: {
          siteId,
          requestUri: '/api/v1/users?id=1%27+UNION+SELECT+password+FROM+accounts--',
          httpStatus: 200,
        },
      };

      // 1. First processing pass
      const parsed1 = normalizeWebTelemetry(event, { trustedContext }, authority);
      expect(parsed1.confidenceLevel).toBe('CONFIRMED_EXPLOITATION');

      const detections1 = await new Rule101SqlInjection().evaluate({
        organizationId: orgId,
        events: [{ ...event, metadata: { ...event.metadata, ...parsed1 } }],
      });
      expect(detections1).toHaveLength(1);
      const detection = detections1[0];

      // Save to storage
      const saveRes1 = await storage.saveDetection(detection);
      expect(saveRes1.saved).toBe(true);
      expect(saveRes1.isDuplicate).toBe(false);

      // Correlate into incident
      const corrRes1 = await correlationEngine.correlateDetection(detection);
      expect(corrRes1).not.toBeNull();
      expect(corrRes1!.isNewIncident).toBe(true);
      const incidentId = corrRes1!.incident.incidentId;
      expect(corrRes1!.incident.timeline).toHaveLength(1);

      // 2. Simulated ingestion / worker retry of the exact same event
      const parsedRetry = normalizeWebTelemetry(event, { trustedContext }, authority);
      expect(parsedRetry.evidenceProvenance).toBe('TRUSTED_SERVER_COMPONENT');

      const detectionsRetry = await new Rule101SqlInjection().evaluate({
        organizationId: orgId,
        events: [{ ...event, metadata: { ...event.metadata, ...parsedRetry } }],
      });
      expect(detectionsRetry).toHaveLength(1);

      // A. Storage deduplication prevents duplicate detection persistence & alerting
      const saveRes2 = await storage.saveDetection(detectionsRetry[0]);
      expect(saveRes2.saved).toBe(false);
      expect(saveRes2.isDuplicate).toBe(true);

      // B. Retried correlation call with the same detection is strictly idempotent (no duplicate timeline or alert)
      const corrRes2 = await correlationEngine.correlateDetection(detection);
      expect(corrRes2).not.toBeNull();
      expect(corrRes2!.isNewIncident).toBe(false);
      expect(corrRes2!.incident.incidentId).toBe(incidentId);
      expect(corrRes2!.incident.timeline).toHaveLength(1); // Timeline still has only 1 entry
    });

    // Test 3: Retry cannot bypass signature validation, tenant binding, or payload tampering checks
    it('3. retry cannot bypass signature validation, tenant binding, or payload tampering checks', () => {
      const eventId = '01a19700-0000-7000-8000-000000000504';
      const validContext = authority.createContext({
        serviceAuthToken: INTERNAL_SERVICE_CREDENTIALS['canary-service:v1'],
        provenance: 'TRUSTED_SERVER_COMPONENT',
        verifierIdentity: 'canary-service:v1',
        eventId,
        orgId,
        siteId,
        verifiedSignalIdentifiers: ['CANARY_TOKEN_BREACH'],
      });

      const baseEvent: SecurityEvent = {
        eventId,
        orgId,
        timestamp: new Date().toISOString(),
        eventType: 'web.attack.sqli',
        severity: 'CRITICAL',
        category: 'NETWORK',
        sourceIp: '198.51.100.225',
        sourceSystem: 'sensor:canary:db',
        metadata: { siteId },
      };

      // Consume valid context first
      const firstRun = normalizeWebTelemetry(baseEvent, { trustedContext: validContext }, authority);
      expect(firstRun.evidenceProvenance).toBe('TRUSTED_SERVER_COMPONENT');

      // A. Tampered payload with valid nonce: modifying verified signals invalidates HMAC signature
      const tamperedSignals = {
        ...validContext,
        verifiedSignalIdentifiers: ['CANARY_TOKEN_BREACH', 'ARBITRARY_FORGED_SIGNAL'],
      };
      const resTamperedSignals = normalizeWebTelemetry(baseEvent, { trustedContext: tamperedSignals }, authority);
      expect(resTamperedSignals.evidenceProvenance).toBe('UNTRUSTED_CLIENT');
      expect(resTamperedSignals.confidenceLevel).not.toBe('CONFIRMED_EXPLOITATION');

      // B. Cross-event replay: consumed nonce presented with different eventId is rejected
      const crossEvent: SecurityEvent = { ...baseEvent, eventId: '01a19700-0000-7000-8000-000000000504-cross' };
      const resCrossEvent = normalizeWebTelemetry(crossEvent, { trustedContext: validContext }, authority);
      expect(resCrossEvent.evidenceProvenance).toBe('UNTRUSTED_CLIENT');

      // C. Cross-tenant replay: consumed nonce presented with different orgId is rejected
      const crossTenantEvent: SecurityEvent = { ...baseEvent, orgId: 'org-attacker-tenant' };
      const resCrossTenant = normalizeWebTelemetry(crossTenantEvent, { trustedContext: validContext }, authority);
      expect(resCrossTenant.evidenceProvenance).toBe('UNTRUSTED_CLIENT');

      // D. Cross-site replay: consumed nonce presented with different siteId is rejected
      const crossSiteEvent: SecurityEvent = {
        ...baseEvent,
        metadata: { siteId: 'site-unauthorized-target-site' },
      };
      const resCrossSite = normalizeWebTelemetry(crossSiteEvent, { trustedContext: validContext }, authority);
      expect(resCrossSite.evidenceProvenance).toBe('UNTRUSTED_CLIENT');

      // E. Tampered signature on retry is rejected
      const tamperedSignature = {
        ...validContext,
        authoritySignature: '0000000000000000000000000000000000000000000000000000000000000000',
      };
      const resTamperedSig = normalizeWebTelemetry(baseEvent, { trustedContext: tamperedSignature }, authority);
      expect(resTamperedSig.evidenceProvenance).toBe('UNTRUSTED_CLIENT');
    });

    // Test 4: Crash between nonce consumption and event processing does not permanently lose legitimate evidence
    it('4. crash between nonce consumption and event processing does not permanently lose legitimate evidence', async () => {
      const persistentTable = new Map<string, any>();
      const mockDocClient = {
        send: async (cmd: any) => {
          if (cmd.input?.Item) {
            const item = cmd.input.Item;
            if (persistentTable.has(item.PK)) {
              const err = new Error('The conditional request failed');
              err.name = 'ConditionalCheckFailedException';
              throw err;
            }
            persistentTable.set(item.PK, item);
            return {};
          }
          if (cmd.input?.Key) {
            return { Item: persistentTable.get(cmd.input.Key.PK) };
          }
          return {};
        },
      };

      const worker1Authority = new InternalEvidenceAuthority({
        signingKey: TEST_SIGNING_KEY,
        serviceCredentials: TEST_SERVICE_CREDENTIALS,
        replayRegistry: new DynamoDBReplayRegistry({ docClient: mockDocClient as any }),
      });

      const worker2Authority = new InternalEvidenceAuthority({
        signingKey: TEST_SIGNING_KEY,
        serviceCredentials: TEST_SERVICE_CREDENTIALS,
        replayRegistry: new DynamoDBReplayRegistry({ docClient: mockDocClient as any }),
      });

      const eventId = '01a19700-0000-7000-8000-000000000505';
      const genuineContext = worker1Authority.createContext({
        serviceAuthToken: TEST_SERVICE_CREDENTIALS['canary-service:v1'],
        provenance: 'TRUSTED_SERVER_COMPONENT',
        verifierIdentity: 'canary-service:v1',
        eventId,
        orgId,
        siteId,
        verifiedSignalIdentifiers: ['CANARY_TOKEN_BREACH'],
      });

      const event: SecurityEvent = {
        eventId,
        orgId,
        timestamp: new Date().toISOString(),
        eventType: 'web.attack.sqli',
        severity: 'CRITICAL',
        category: 'NETWORK',
        sourceIp: '198.51.100.226',
        sourceSystem: 'sensor:canary:db',
        metadata: { siteId },
      };

      // 1. Worker 1 verifies and consumes the nonce in DynamoDB
      const worker1Verified = await worker1Authority.verifyAndConsumeContextAsync(genuineContext, {
        eventId,
        orgId,
        siteId,
      });
      expect(worker1Verified).toBe(true);

      // Verify nonce is stored in persistent table
      expect(persistentTable.has('NONCE#' + genuineContext.nonce)).toBe(true);

      // SIMULATE CRASH: Worker 1 crashes (e.g. OOM or network timeout) before saving detection or finishing pipeline
      let worker1Crashed = false;
      try {
        throw new Error('CRITICAL_WORKER_FAILURE: Process crashed after nonce consumption before persistence');
      } catch {
        worker1Crashed = true;
      }
      expect(worker1Crashed).toBe(true);

      // 2. Retry mechanism sends the identical message/event to Worker 2
      // Worker 2 evaluates the event and context:
      const worker2Parsed = await normalizeWebTelemetryAsync(event, { trustedContext: genuineContext }, worker2Authority);

      // Evidence MUST NOT be lost: idempotent retry maintains TRUSTED_SERVER_COMPONENT and CONFIRMED_EXPLOITATION!
      expect(worker2Parsed.evidenceProvenance).toBe('TRUSTED_SERVER_COMPONENT');
      expect(worker2Parsed.confidenceLevel).toBe('CONFIRMED_EXPLOITATION');
      expect(worker2Parsed.corroboratingSignals).toContain('CANARY_TOKEN_BREACH');
    });

    // Test 5: Downstream correlation side effects are strictly idempotent on repeated correlation calls
    it('5. downstream correlation side effects are strictly idempotent on repeated correlation calls', async () => {
      const detectionId = 'det-idemp-001';
      const detection: Detection = {
        detectionId,
        orgId,
        ruleId: 'RULE-101',
        ruleName: 'Web Attack: SQL Injection Attempt',
        severity: 'HIGH',
        status: 'NEW',
        detectedAt: new Date().toISOString(),
        relatedEventIds: ['01a19700-0000-7000-8000-000000000506'],
        evidence: {
          matchedRule: 'RULE-101',
          targetEntity: { type: 'IP', value: '198.51.100.227' },
          details: {
            siteId,
            domain: primaryDomain,
            attackType: 'SQL_INJECTION',
            requestUri: '/products?id=1',
            confidenceLevel: 'CONFIRMED_EXPLOITATION',
          },
        },
      };

      // Initial correlation
      const firstCorr = await correlationEngine.correlateDetection(detection);
      expect(firstCorr).not.toBeNull();
      expect(firstCorr!.isNewIncident).toBe(true);
      const incidentId = firstCorr!.incident.incidentId;
      const initialScore = firstCorr!.incident.riskScore;
      const initialTimelineCount = firstCorr!.incident.timeline.length;
      expect(initialTimelineCount).toBe(1);

      // Repeated correlations of the exact same detection (3 subsequent retries)
      for (let i = 0; i < 3; i++) {
        const retryCorr = await correlationEngine.correlateDetection(detection);
        expect(retryCorr).not.toBeNull();
        expect(retryCorr!.isNewIncident).toBe(false);
        expect(retryCorr!.incident.incidentId).toBe(incidentId);
        // Timeline must not grow with duplicate entries
        expect(retryCorr!.incident.timeline.length).toBe(initialTimelineCount);
        // Risk score must not be artificially amplified
        expect(retryCorr!.incident.riskScore).toBe(initialScore);
      }
    });

    // Test 6: [UNIT_MOCK: DYNAMODB_SEMANTICS] verifies attribute_not_exists(PK) condition and ConditionalCheckFailedException handling
    it('6. [UNIT_MOCK: DYNAMODB_SEMANTICS] verifies attribute_not_exists(PK) condition and ConditionalCheckFailedException handling', async () => {
      const mockStorage = new Map<string, any>();
      const executedCommands: { type: string; input: any }[] = [];

      const strictlyValidatedDocClient = {
        send: async (cmd: any) => {
          const isPut = cmd.constructor.name === 'PutCommand' || !!cmd.input?.Item;
          const isGet = cmd.constructor.name === 'GetCommand' || !!cmd.input?.Key;

          executedCommands.push({
            type: isPut ? 'PutCommand' : isGet ? 'GetCommand' : 'Unknown',
            input: cmd.input,
          });

          if (isPut) {
            // Strictly assert DynamoDB conditional write semantics
            expect(cmd.input.ConditionExpression).toBe('attribute_not_exists(PK)');
            expect(cmd.input.Item.PK).toMatch(/^NONCE#/);
            expect(cmd.input.Item.SK).toBe('REPLAY_RECORD');
            expect(typeof cmd.input.Item.ttl).toBe('number');

            if (mockStorage.has(cmd.input.Item.PK)) {
              // Mimic AWS SDK DynamoDB conditional check failed exception
              const error = new Error('The conditional request failed');
              error.name = 'ConditionalCheckFailedException';
              throw error;
            }

            mockStorage.set(cmd.input.Item.PK, cmd.input.Item);
            return {};
          }

          if (isGet) {
            expect(cmd.input.Key.PK).toMatch(/^NONCE#/);
            expect(cmd.input.Key.SK).toBe('REPLAY_RECORD');
            return { Item: mockStorage.get(cmd.input.Key.PK) };
          }

          return {};
        },
      };

      const registry = new DynamoDBReplayRegistry({ docClient: strictlyValidatedDocClient as any });
      const record = {
        nonce: 'mock-strict-nonce-001',
        eventId: '01a19700-0000-7000-8000-000000000507',
        orgId,
        siteId,
        timestampEpoch: Date.now(),
        expiresAtEpoch: Date.now() + 15 * 60 * 1000,
      };

      // 1. Initial consume issues PutCommand with attribute_not_exists(PK)
      const res1 = await registry.consumeNonce(record);
      expect(res1.success).toBe(true);
      expect(executedCommands.some((c) => c.type === 'PutCommand' && c.input.ConditionExpression === 'attribute_not_exists(PK)')).toBe(true);

      // 2. Consume with identical record fails condition and reads existing item via GetCommand -> IDEMPOTENT_RETRY
      executedCommands.length = 0;
      const resRetry = await registry.consumeNonce(record);
      expect(resRetry.success).toBe(false);
      expect(resRetry.isIdempotentRetry).toBe(true);
      expect(resRetry.isReplayAttack).toBe(false);
      expect(executedCommands.some((c) => c.type === 'PutCommand')).toBe(true);
      expect(executedCommands.some((c) => c.type === 'GetCommand')).toBe(true);

      // 3. Consume with mismatched eventId fails condition and reads existing item -> REPLAY_ATTACK_NONCE_REUSED
      executedCommands.length = 0;
      const resCrossEvent = await registry.consumeNonce({
        ...record,
        eventId: '01a19700-0000-7000-8000-000000000507-attack',
      });
      expect(resCrossEvent.success).toBe(false);
      expect(resCrossEvent.isReplayAttack).toBe(true);
      expect(resCrossEvent.isIdempotentRetry).toBe(false);

      // 4. Unexpected AWS error (e.g. ProvisionedThroughputExceededException) throws PERSISTENT_STORAGE_UNAVAILABLE
      const failingClient = {
        send: async () => {
          const err = new Error('Throughput exceeded on table');
          err.name = 'ProvisionedThroughputExceededException';
          throw err;
        },
      };
      const failingRegistry = new DynamoDBReplayRegistry({ docClient: failingClient as any });
      await expect(failingRegistry.consumeNonce(record)).rejects.toThrow(/PERSISTENT_STORAGE_UNAVAILABLE/);
    });

    // Test 7: [CONCURRENCY] concurrent consumption from 3 independent registry instances allows exactly one winner
    it('7. [CONCURRENCY] concurrent consumption from 3 independent registry instances allows exactly one winner', async () => {
      // Shared persistent table with simulated atomic check-and-set
      const sharedStorage = new Map<string, any>();

      const createMockClient = () => ({
        send: async (cmd: any) => {
          if (cmd.input?.Item) {
            // Simulate brief async I/O / thread scheduling
            await new Promise((resolve) => setTimeout(resolve, Math.floor(Math.random() * 10) + 1));

            if (sharedStorage.has(cmd.input.Item.PK)) {
              const err = new Error('The conditional request failed');
              err.name = 'ConditionalCheckFailedException';
              throw err;
            }
            sharedStorage.set(cmd.input.Item.PK, cmd.input.Item);
            return {};
          }

          if (cmd.input?.Key) {
            await new Promise((resolve) => setTimeout(resolve, Math.floor(Math.random() * 5) + 1));
            return { Item: sharedStorage.get(cmd.input.Key.PK) };
          }

          return {};
        },
      });

      // 3 independent registry instances representing 3 distributed worker nodes
      const nodeA = new DynamoDBReplayRegistry({ docClient: createMockClient() as any });
      const nodeB = new DynamoDBReplayRegistry({ docClient: createMockClient() as any });
      const nodeC = new DynamoDBReplayRegistry({ docClient: createMockClient() as any });

      const record = {
        nonce: 'concurrent-race-nonce-007',
        eventId: '01a19700-0000-7000-8000-000000000508',
        orgId,
        siteId,
        timestampEpoch: Date.now(),
        expiresAtEpoch: Date.now() + 15 * 60 * 1000,
      };

      // Fire 3 simultaneous consume requests
      const results = await Promise.all([
        nodeA.consumeNonce(record),
        nodeB.consumeNonce(record),
        nodeC.consumeNonce(record),
      ]);

      const winners = results.filter((r) => r.success);
      const retries = results.filter((r) => r.isIdempotentRetry);
      const replays = results.filter((r) => r.isReplayAttack);

      // Exactly ONE node wins the write race
      expect(winners).toHaveLength(1);
      // The other two nodes detect the record already exists with matching binding -> IDEMPOTENT_RETRY
      expect(retries).toHaveLength(2);
      // None flagged as a replay attack since event, tenant, and site match identically
      expect(replays).toHaveLength(0);

      // Exactly one item persisted in DynamoDB
      expect(sharedStorage.size).toBe(1);

      // If an attacker subsequently attempts to replay that same nonce across nodes with a different eventId
      const attackRecord = {
        ...record,
        eventId: '01a19700-0000-7000-8000-000000000508-forged',
      };
      const attackResults = await Promise.all([
        nodeA.consumeNonce(attackRecord),
        nodeB.consumeNonce(attackRecord),
      ]);

      for (const res of attackResults) {
        expect(res.success).toBe(false);
        expect(res.isReplayAttack).toBe(true);
        expect(res.isIdempotentRetry).toBe(false);
      }
    });
  });
});
