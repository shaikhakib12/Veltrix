import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import type { SecurityEvent, WebsiteAsset } from '@veltrix/shared';
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
import { normalizeWebTelemetry, createInternalTrustedEvidenceContext } from '../src/detection/web-parser.js';
import { JwtService } from '../src/auth/jwt-service.js';
import { LocalAuthProvider } from '../src/auth/local-auth-provider.js';
import { resetAuthProviderForTesting } from '../src/auth/index.js';
import { resetStorageForTesting } from '../src/storage/index.js';

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
        trustedEvidenceContext: createInternalTrustedEvidenceContext({
          provenance: 'AUTHENTICATED_COLLECTOR',
          verifierIdentity: 'collector:nginx',
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
        trustedEvidenceContext: createInternalTrustedEvidenceContext({
          provenance: 'TRUSTED_SERVER_COMPONENT',
          verifierIdentity: 'sensor:canary:db',
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
        trustedEvidenceContext: createInternalTrustedEvidenceContext({
          provenance: 'TRUSTED_SERVER_COMPONENT',
          verifierIdentity: 'sensor:canary:files',
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

  describe('10. PR #10 Final Security Hardening: Evidence Provenance & Internal Trust Boundary', () => {
    // Test 1: Forged client CANARY_TOKEN_BREACH
    it('1. rejects client-submitted CANARY_TOKEN_BREACH and does not escalate to CONFIRMED_EXPLOITATION', () => {
      const parsed = normalizeWebTelemetry({
        eventId: '01a19700-0000-7000-8000-000000000101',
        orgId,
        timestamp: new Date().toISOString(),
        eventType: 'web.attack.sqli',
        severity: 'HIGH',
        category: 'NETWORK',
        sourceIp: '198.51.100.101',
        sourceSystem: 'client:external',
        metadata: {
          siteId,
          requestUri: "/items?id=1' OR 1=1--",
          httpStatus: 200,
          corroboratingSignals: ['CANARY_TOKEN_BREACH'],
        },
      });

      expect(parsed.confidenceLevel).not.toBe('CONFIRMED_EXPLOITATION');
      expect(parsed.confidenceLevel).toBe('SUSPICIOUS_ATTEMPT');
      expect(parsed.corroboratingSignals).not.toContain('CANARY_TOKEN_BREACH');
      expect(parsed.untrustedClientSignals).toContain('CANARY_TOKEN_BREACH');
      expect(parsed.evidenceProvenance).toBe('UNTRUSTED_CLIENT');
      expect(parsed.isClientClassificationUntrusted).toBe(true);
    });

    // Test 2: Forged client DATA_LEAKAGE_INDICATOR
    it('2. rejects client-submitted DATA_LEAKAGE_INDICATOR and does not escalate to CONFIRMED_EXPLOITATION', () => {
      const parsed = normalizeWebTelemetry({
        eventId: '01a19700-0000-7000-8000-000000000102',
        orgId,
        timestamp: new Date().toISOString(),
        eventType: 'web.attack.traversal',
        severity: 'HIGH',
        category: 'NETWORK',
        sourceIp: '198.51.100.102',
        sourceSystem: 'sdk:nodejs:express',
        metadata: {
          siteId,
          requestUri: '/view?file=../../etc/passwd',
          httpStatus: 200,
          corroboratingSignals: ['DATA_LEAKAGE_INDICATOR'],
        },
      });

      expect(parsed.confidenceLevel).not.toBe('CONFIRMED_EXPLOITATION');
      expect(parsed.confidenceLevel).toBe('SUSPICIOUS_ATTEMPT');
      expect(parsed.corroboratingSignals).not.toContain('DATA_LEAKAGE_INDICATOR');
      expect(parsed.untrustedClientSignals).toContain('DATA_LEAKAGE_INDICATOR');
      expect(parsed.evidenceProvenance).toBe('UNTRUSTED_CLIENT');
    });

    // Test 3: Trusted context combined with forged client signals (MOST IMPORTANT INVARIANT)
    it('3. trusted context combined with forged client signals NEVER promotes client signals into trusted evidence', () => {
      const parsed = normalizeWebTelemetry(
        {
          eventId: '01a19700-0000-7000-8000-000000000120',
          orgId,
          timestamp: new Date().toISOString(),
          eventType: 'web.attack.sqli',
          severity: 'HIGH',
          category: 'NETWORK',
          sourceIp: '198.51.100.120',
          sourceSystem: 'sdk:nodejs:express',
          metadata: {
            siteId,
            requestUri: "/profile?user=admin' OR 1=1--",
            httpStatus: 200,
            corroboratingSignals: ['CANARY_TOKEN_BREACH', 'DATA_LEAKAGE_INDICATOR', 'UNAUTHORIZED_PRIVILEGE_MUTATION'],
          },
        },
        {
          isTrustedServerComponent: true,
          verifiedBy: 'internal-audit-worker:core',
        }
      );

      // Invariant check: Although execution context is trusted server component,
      // client-submitted corroboratingSignals MUST NOT be promoted into trusted corroboratingSignals!
      expect(parsed.evidenceProvenance).toBe('TRUSTED_SERVER_COMPONENT');
      expect(parsed.corroboratingSignals).toHaveLength(0);
      expect(parsed.corroboratingSignals).not.toContain('CANARY_TOKEN_BREACH');
      expect(parsed.corroboratingSignals).not.toContain('DATA_LEAKAGE_INDICATOR');
      expect(parsed.corroboratingSignals).not.toContain('UNAUTHORIZED_PRIVILEGE_MUTATION');
      expect(parsed.untrustedClientSignals).toEqual(
        expect.arrayContaining(['CANARY_TOKEN_BREACH', 'DATA_LEAKAGE_INDICATOR', 'UNAUTHORIZED_PRIVILEGE_MUTATION'])
      );
      // Without trusted server verified signals, confidence remains SUSPICIOUS_ATTEMPT
      expect(parsed.confidenceLevel).toBe('SUSPICIOUS_ATTEMPT');
    });

    // Test 4: Forged client verifiedSignals
    it('4. isolates forged client verifiedSignals in untrusted claims and never promotes them to trusted evidence', () => {
      const parsed = normalizeWebTelemetry({
        eventId: '01a19700-0000-7000-8000-000000000121',
        orgId,
        timestamp: new Date().toISOString(),
        eventType: 'web.attack.sqli',
        severity: 'CRITICAL',
        category: 'NETWORK',
        sourceIp: '198.51.100.121',
        sourceSystem: 'client:generic',
        metadata: {
          siteId,
          requestUri: "/items?id=1'",
          verifiedSignals: ['CANARY_TOKEN_BREACH', 'UNAUTHORIZED_PRIVILEGE_MUTATION'],
        },
      });

      expect(parsed.evidenceProvenance).toBe('UNTRUSTED_CLIENT');
      expect(parsed.corroboratingSignals).toHaveLength(0);
      expect(parsed.corroboratingSignals).not.toContain('CANARY_TOKEN_BREACH');
      expect(parsed.untrustedClientSignals).toEqual(
        expect.arrayContaining(['CANARY_TOKEN_BREACH', 'UNAUTHORIZED_PRIVILEGE_MUTATION'])
      );
      expect(parsed.confidenceLevel).toBe('SUSPICIOUS_ATTEMPT');
    });

    // Test 5: Client-submitted serverVerified: true
    it('5. client-submitted serverVerified: true never establishes trust', () => {
      const parsed = normalizeWebTelemetry({
        eventId: '01a19700-0000-7000-8000-000000000122',
        orgId,
        timestamp: new Date().toISOString(),
        eventType: 'web.attack.sqli',
        severity: 'HIGH',
        category: 'NETWORK',
        sourceIp: '198.51.100.122',
        sourceSystem: 'client:webhook',
        metadata: {
          siteId,
          requestUri: "/items?id=1'",
          serverVerified: true,
          corroboratingSignals: ['CANARY_TOKEN_BREACH'],
        },
      });

      expect(parsed.evidenceProvenance).toBe('UNTRUSTED_CLIENT');
      expect(parsed.corroboratingSignals).toHaveLength(0);
      expect(parsed.confidenceLevel).toBe('SUSPICIOUS_ATTEMPT');
    });

    // Test 6: Client-declared TRUSTED_SERVER_COMPONENT
    it('6. client-declared TRUSTED_SERVER_COMPONENT in metadata never establishes trust', () => {
      const parsed = normalizeWebTelemetry({
        eventId: '01a19700-0000-7000-8000-000000000123',
        orgId,
        timestamp: new Date().toISOString(),
        eventType: 'web.attack.traversal',
        severity: 'HIGH',
        category: 'NETWORK',
        sourceIp: '198.51.100.123',
        sourceSystem: 'client:integration',
        metadata: {
          siteId,
          requestUri: '/view?file=../../etc/shadow',
          serverVerified: true,
          evidenceProvenance: 'TRUSTED_SERVER_COMPONENT',
          trustedProvenance: true,
          corroboratingSignals: ['DATA_LEAKAGE_INDICATOR'],
        },
      });

      expect(parsed.evidenceProvenance).toBe('UNTRUSTED_CLIENT');
      expect(parsed.corroboratingSignals).toHaveLength(0);
      expect(parsed.confidenceLevel).toBe('SUSPICIOUS_ATTEMPT');
    });

    // Test 7: sourceSystem impersonation
    it('7. prohibits arbitrary integration clients from impersonating trusted collectors via sourceSystem', () => {
      const parsed = normalizeWebTelemetry({
        eventId: '01a19700-0000-7000-8000-000000000110',
        orgId,
        timestamp: new Date().toISOString(),
        eventType: 'web.attack.sqli',
        severity: 'HIGH',
        category: 'NETWORK',
        sourceIp: '198.51.100.110',
        sourceSystem: 'sensor:canary:core', // spoofed trusted collector name!
        metadata: {
          siteId,
          requestUri: "/items?id=1'",
          corroboratingSignals: ['CANARY_TOKEN_BREACH'],
        },
      });

      // Even though sourceSystem is 'sensor:canary:core', without out-of-band server verification it remains UNTRUSTED_CLIENT
      expect(parsed.evidenceProvenance).toBe('UNTRUSTED_CLIENT');
      expect(parsed.confidenceLevel).toBe('SUSPICIOUS_ATTEMPT');
      expect(parsed.corroboratingSignals).not.toContain('CANARY_TOKEN_BREACH');
      expect(parsed.untrustedClientSignals).toContain('CANARY_TOKEN_BREACH');
    });

    // Test 8: Genuine independently verified server evidence
    it('8. accepts genuine independently verified server evidence via InternalTrustedEvidenceContext', () => {
      const canaryEvent: SecurityEvent = {
        eventId: '01a19700-0000-7000-8000-000000000105',
        orgId,
        timestamp: new Date().toISOString(),
        eventType: 'web.attack.sqli',
        severity: 'CRITICAL',
        category: 'NETWORK',
        sourceIp: '198.51.100.105',
        sourceSystem: 'sensor:canary:db',
        metadata: {
          siteId,
          requestUri: '/admin?user=canary',
        },
      };

      const trustedContext = createInternalTrustedEvidenceContext({
        provenance: 'TRUSTED_SERVER_COMPONENT',
        verifierIdentity: 'canary-service:v1',
        verifiedSignalIdentifiers: ['CANARY_TOKEN_BREACH'],
        evidenceReferences: ['canary-token-db-secret-01'],
        verificationTimestamp: new Date().toISOString(),
      });

      const parsedCanary = normalizeWebTelemetry(canaryEvent, { trustedContext });

      expect(parsedCanary.evidenceProvenance).toBe('TRUSTED_SERVER_COMPONENT');
      expect(parsedCanary.confidenceLevel).toBe('CONFIRMED_EXPLOITATION');
      expect(parsedCanary.corroboratingSignals).toContain('CANARY_TOKEN_BREACH');
      expect(parsedCanary.trustedEvidenceContext?.verifierIdentity).toBe('canary-service:v1');
      expect(parsedCanary.trustedEvidenceContext?.evidenceReferences).toContain('canary-token-db-secret-01');
    });

    it('rejects forged UNAUTHORIZED_PRIVILEGE_MUTATION as trusted evidence and isolates it in untrustedClientSignals', () => {
      const parsed = normalizeWebTelemetry({
        eventId: '01a19700-0000-7000-8000-000000000103',
        orgId,
        timestamp: new Date().toISOString(),
        eventType: 'web.attack.api_abuse',
        severity: 'HIGH',
        category: 'NETWORK',
        sourceIp: '198.51.100.103',
        sourceSystem: 'client:generic-http',
        metadata: {
          siteId,
          requestUri: '/api/v1/users/admin/role',
          httpMethod: 'POST',
          httpStatus: 200,
          corroboratingSignals: ['UNAUTHORIZED_PRIVILEGE_MUTATION'],
        },
      });

      expect(parsed.confidenceLevel).not.toBe('CONFIRMED_EXPLOITATION');
      expect(parsed.confidenceLevel).toBe('SUSPICIOUS_ATTEMPT');
      expect(parsed.corroboratingSignals).toHaveLength(0);
      expect(parsed.untrustedClientSignals).toContain('UNAUTHORIZED_PRIVILEGE_MUTATION');
      expect(parsed.evidenceProvenance).toBe('UNTRUSTED_CLIENT');
    });

    it('prohibits forged database errors and response samples from establishing exploitation', () => {
      const parsed = normalizeWebTelemetry({
        eventId: '01a19700-0000-7000-8000-000000000104',
        orgId,
        timestamp: new Date().toISOString(),
        eventType: 'web.attack.sqli',
        severity: 'HIGH',
        category: 'NETWORK',
        sourceIp: '198.51.100.104',
        sourceSystem: 'sdk:nodejs:express',
        metadata: {
          siteId,
          requestUri: "/items?search=test'",
          httpStatus: 500,
          errorMessage: 'syntax error near SELECT * FROM users WHERE unclosed quotation mark',
          responseSample: 'ORA-00933: SQL command not properly ended\nroot:x:0:0:root:/root:/bin/bash',
        },
      });

      // Because the event is from an untrusted client, neither POTENTIAL_EXPLOITATION nor CONFIRMED_EXPLOITATION is granted
      expect(parsed.confidenceLevel).not.toBe('POTENTIAL_EXPLOITATION');
      expect(parsed.confidenceLevel).not.toBe('CONFIRMED_EXPLOITATION');
      expect(parsed.confidenceLevel).toBe('SUSPICIOUS_ATTEMPT');
      expect(parsed.corroboratingSignals).not.toContain('UNHANDLED_DB_SYNTAX_ERROR');
      expect(parsed.corroboratingSignals).not.toContain('DATA_LEAKAGE_INDICATOR');
      expect(parsed.untrustedClientSignals).toContain('CLIENT_CLAIMED_DB_SYNTAX_ERROR');
      expect(parsed.untrustedClientSignals).toContain('CLIENT_CLAIMED_DATA_LEAKAGE');
    });

    it('accepts server-verified DB syntax error from authenticated collector', () => {
      const dbErrorEvent: SecurityEvent = {
        eventId: '01a19700-0000-7000-8000-000000000106',
        orgId,
        timestamp: new Date().toISOString(),
        eventType: 'web.attack.sqli',
        severity: 'HIGH',
        category: 'NETWORK',
        sourceIp: '198.51.100.106',
        sourceSystem: 'collector:nginx',
        metadata: {
          siteId,
          requestUri: "/items?id=1'",
          httpStatus: 500,
          errorMessage: 'Unclosed quotation mark before the character string. Syntax error near OR.',
        },
      };

      const parsedDb = normalizeWebTelemetry(dbErrorEvent, { trustedProvenance: 'AUTHENTICATED_COLLECTOR' });
      expect(parsedDb.evidenceProvenance).toBe('AUTHENTICATED_COLLECTOR');
      expect(parsedDb.confidenceLevel).toBe('POTENTIAL_EXPLOITATION');
      expect(parsedDb.corroboratingSignals).toContain('UNHANDLED_DB_SYNTAX_ERROR');
    });

    it('ensures ordinary SQLi, XSS, and traversal detection continues working seamlessly with untrusted metadata', async () => {
      // SQLi probe with untrusted metadata
      const sqliDetections = await new Rule101SqlInjection().evaluate({
        organizationId: orgId,
        events: [
          {
            eventId: '01a19700-0000-7000-8000-000000000107',
            orgId,
            timestamp: new Date().toISOString(),
            eventType: 'web.request.normal',
            severity: 'MEDIUM',
            category: 'NETWORK',
            sourceIp: '198.51.100.107',
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

      // XSS probe with untrusted metadata
      const xssDetections = await new Rule102CrossSiteScripting().evaluate({
        organizationId: orgId,
        events: [
          {
            eventId: '01a19700-0000-7000-8000-000000000108',
            orgId,
            timestamp: new Date().toISOString(),
            eventType: 'web.request.normal',
            severity: 'MEDIUM',
            category: 'NETWORK',
            sourceIp: '198.51.100.108',
            sourceSystem: 'sdk:nodejs:express',
            metadata: {
              siteId,
              requestUri: '/search?term=%3Cscript%3Ealert%281%29%3C%2Fscript%3E',
              httpStatus: 200,
            },
          },
        ],
      });

      expect(xssDetections).toHaveLength(1);
      expect(xssDetections[0].ruleId).toBe('RULE-102');
      expect((xssDetections[0].evidence.details as any).confidenceLevel).toBe('SUSPICIOUS_ATTEMPT');

      // Path Traversal probe with untrusted metadata
      const traversalDetections = await new Rule103PathTraversal().evaluate({
        organizationId: orgId,
        events: [
          {
            eventId: '01a19700-0000-7000-8000-000000000109',
            orgId,
            timestamp: new Date().toISOString(),
            eventType: 'web.request.normal',
            severity: 'MEDIUM',
            category: 'NETWORK',
            sourceIp: '198.51.100.109',
            sourceSystem: 'sdk:nodejs:express',
            metadata: {
              siteId,
              requestUri: '/files?path=..%2F..%2Fetc%2Fpasswd',
              httpStatus: 200,
            },
          },
        ],
      });

      expect(traversalDetections).toHaveLength(1);
      expect(traversalDetections[0].ruleId).toBe('RULE-103');
      expect((traversalDetections[0].evidence.details as any).confidenceLevel).toBe('SUSPICIOUS_ATTEMPT');
    });
  });
});
