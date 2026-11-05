import { Router, type Request, type Response } from 'express';
import type {
  ApiErrorResponse,
  ResponseExecution,
  SecurityEvent,
  Severity,
  ThreatIndicator,
  WebsiteAsset,
} from '@veltrix/shared';
import { authenticate } from '../middleware/auth.js';
import { enforceTenantIsolation } from '../middleware/tenant.js';
import { requireRole } from '../middleware/rbac.js';
import { getStorage } from '../storage/index.js';
import { getDetectionPipeline } from '../detection/pipeline.js';
import { DomainVerificationService } from '../services/domain-verification.js';
import { generateUuidV7 } from '../utils/uuid.js';

interface SeedSite {
  name: string;
  domain: string;
  environment: WebsiteAsset['environment'];
  riskTier: WebsiteAsset['riskTier'];
  tags: string[];
  eventsPerMinute: number;
}

const DEMO_SITES: SeedSite[] = [
  {
    name: 'Customer Portal',
    domain: 'portal.cyberdefend.corp',
    environment: 'PRODUCTION',
    riskTier: 'CRITICAL',
    tags: ['customer', 'pci', 'public'],
    eventsPerMinute: 42,
  },
  {
    name: 'Public API Gateway',
    domain: 'api.cyberdefend.corp',
    environment: 'PRODUCTION',
    riskTier: 'HIGH',
    tags: ['api', 'partner'],
    eventsPerMinute: 87,
  },
  {
    name: 'Staging Checkout',
    domain: 'staging.cyberdefend.corp',
    environment: 'STAGING',
    riskTier: 'MEDIUM',
    tags: ['staging', 'checkout'],
    eventsPerMinute: 6,
  },
];

interface AttackSpec {
  siteIndex: number;
  ip: string;
  minutesAgo: number;
  eventType: string;
  severity: Severity;
  category: SecurityEvent['category'];
  method: string;
  uri: string;
  status: number;
  userAgent?: string;
  responseSample?: string;
  errorMessage?: string;
  wafAction?: 'ALLOW' | 'BLOCK' | 'CHALLENGE' | 'LOG';
}

const DEMO_ATTACKS: AttackSpec[] = [
  // --- Attack story 1: multi-stage SQLi -> XSS -> LFI against the portal ---
  {
    siteIndex: 0,
    ip: '198.51.100.23',
    minutesAgo: 320,
    eventType: 'web.attack.sqli',
    severity: 'HIGH',
    category: 'NETWORK',
    method: 'POST',
    uri: "/account/login?username=admin'%20OR%20'1'='1'--&password=x",
    status: 500,
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    responseSample: 'You have an error in your SQL syntax near \'admin\\\' OR ...\' at line 1',
  },
  {
    siteIndex: 0,
    ip: '198.51.100.23',
    minutesAgo: 314,
    eventType: 'web.attack.xss',
    severity: 'HIGH',
    category: 'NETWORK',
    method: 'GET',
    uri: '/search?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E',
    status: 200,
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
  },
  {
    siteIndex: 0,
    ip: '198.51.100.23',
    minutesAgo: 306,
    eventType: 'web.attack.traversal',
    severity: 'CRITICAL',
    category: 'NETWORK',
    method: 'GET',
    uri: '/download?file=../../../../etc/passwd',
    status: 200,
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    responseSample: 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin',
  },
  // --- Attack story 2: automated reconnaissance against the API ---
  ...[
    '/.env',
    '/.git/config',
    '/wp-login.php',
    '/actuator/health',
    '/phpmyadmin',
    '/server-status',
    '/.aws/credentials',
  ].map((path, index) => ({
    siteIndex: 1,
    ip: '203.0.113.77',
    minutesAgo: 180 - index * 0.5,
    eventType: 'web.attack.bot',
    severity: 'MEDIUM' as Severity,
    category: 'NETWORK' as const,
    method: 'GET',
    uri: path,
    status: 404,
    userAgent: 'sqlmap/1.7.2#stable (https://sqlmap.org)',
  })),
  // --- Attack story 3: credential stuffing against staging checkout ---
  ...[0, 1, 2, 3, 4, 5].map((index) => ({
    siteIndex: 2,
    ip: '192.0.2.45',
    minutesAgo: 90 - index * 0.7,
    eventType: 'web.request.normal',
    severity: 'LOW' as Severity,
    category: 'AUTHENTICATION' as const,
    method: 'POST',
    uri: '/login',
    status: 401,
    userAgent: 'python-requests/2.31.0',
  })),
  // --- One WAF-blocked probe, to exercise BLOCKED_ATTEMPT ---
  {
    siteIndex: 0,
    ip: '198.51.100.99',
    minutesAgo: 45,
    eventType: 'web.attack.sqli',
    severity: 'MEDIUM',
    category: 'NETWORK',
    method: 'GET',
    uri: "/products?category=1'%20UNION%20SELECT%20username,password%20FROM%20users--",
    status: 403,
    userAgent: 'Mozilla/5.0',
    wafAction: 'BLOCK',
  },
];

function buildEvents(orgId: string, now: number): SecurityEvent[] {
  const events: SecurityEvent[] = [];

  // Normal baseline telemetry keeps the velocity chart realistic.
  for (let i = 0; i < 48; i++) {
    const site = DEMO_SITES[i % DEMO_SITES.length]!;
    events.push({
      eventId: generateUuidV7(now - i * 11 * 60 * 1000),
      orgId,
      timestamp: new Date(now - i * 11 * 60 * 1000).toISOString(),
      eventType: 'web.request.normal',
      severity: 'LOW',
      category: 'NETWORK',
      sourceIp: `198.51.100.${10 + (i % 40)}`,
      sourceSystem: 'veltrix-edge',
      isSimulated: true,
      metadata: {
        siteId: `site-demo-${(i % DEMO_SITES.length) + 1}`,
        domain: site.domain,
        httpMethod: 'GET',
        requestUri: ['/', '/products', '/pricing', '/docs', '/account'][i % 5],
        httpStatus: 200,
        responseTimeMs: 40 + (i % 90),
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
      },
    });
  }

  for (const spec of DEMO_ATTACKS) {
    const site = DEMO_SITES[spec.siteIndex]!;
    events.push({
      eventId: generateUuidV7(now - spec.minutesAgo * 60 * 1000),
      orgId,
      timestamp: new Date(now - spec.minutesAgo * 60 * 1000).toISOString(),
      eventType: spec.eventType,
      severity: spec.severity,
      category: spec.category,
      sourceIp: spec.ip,
      username: spec.category === 'AUTHENTICATION' ? `user${Math.floor(Math.random() * 40)}` : undefined,
      sourceSystem: 'veltrix-edge',
      isSimulated: true,
      metadata: {
        siteId: `site-demo-${spec.siteIndex + 1}`,
        domain: site.domain,
        httpMethod: spec.method,
        requestUri: spec.uri,
        httpStatus: spec.status,
        responseTimeMs: 120 + Math.floor(Math.random() * 400),
        userAgent: spec.userAgent,
        wafAction: spec.wafAction,
        responseSample: spec.responseSample,
        errorMessage: spec.errorMessage,
      },
    });
  }

  return events.sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp));
}

export async function seedDemoDataset(orgId: string = 'org-enterprise-01'): Promise<{
  alreadySeeded: boolean;
  sites: number;
  incidents: number;
  events?: number;
  detections?: number;
  topologyIncident?: string | null;
}> {
  const storage = getStorage();
  const existing = await storage.getWebsites(orgId, { limit: 1 });
  if (existing.items.length > 0) {
    const incidents = await storage.getIncidents(orgId, { limit: 200 });
    const sites = await storage.getWebsites(orgId, { limit: 50 });
    return {
      alreadySeeded: true,
      sites: sites.items.length,
      incidents: incidents.items.length,
    };
  }

  const now = Date.now();
  const nowIso = new Date(now).toISOString();

  // 1. Verified assets.
  const sites: WebsiteAsset[] = DEMO_SITES.map((seed, index) => {
    const challenge = DomainVerificationService.generateChallenge(orgId, seed.domain);
    return {
      siteId: `site-demo-${index + 1}`,
      orgId,
      name: seed.name,
      primaryDomain: seed.domain,
      approvedSubdomains: index === 0 ? ['checkout.portal.cyberdefend.corp'] : [],
      environment: seed.environment,
      status: 'VERIFIED',
      riskTier: seed.riskTier,
      tags: seed.tags,
      verificationToken: challenge.token,
      tokenHash: challenge.tokenHash,
      tokenCreatedAt: new Date(now - 10 * 24 * 60 * 60 * 1000).toISOString(),
      dnsTxtRecord: challenge.dnsTxtRecord,
      httpChallenge: challenge.httpChallenge,
      metaTag: {
        tag: 'meta',
        name: 'veltrix-site-verification',
        content: challenge.token,
      },
      verifiedMethod: 'DNS_TXT',
      verifiedAt: new Date(now - 9 * 24 * 60 * 60 * 1000).toISOString(),
      expiresAt: new Date(now + 80 * 24 * 60 * 60 * 1000).toISOString(),
      scanBlocked: false,
      health: {
        telemetryStatus: 'HEALTHY',
        lastEventReceivedAt: new Date(now - 2 * 60 * 1000).toISOString(),
        eventsPerMinute: seed.eventsPerMinute,
      },
      createdAt: new Date(now - 10 * 24 * 60 * 60 * 1000).toISOString(),
      updatedAt: nowIso,
    };
  });
  for (const site of sites) {
    await storage.saveWebsite(site);
  }

  // 2. Threat intelligence indicators.
  const indicators: ThreatIndicator[] = [
    {
      indicatorId: generateUuidV7(now - 60_000),
      type: 'IP',
      value: '198.51.100.23',
      threatType: 'Multi-stage web attack infrastructure',
      severity: 'CRITICAL',
      confidence: 94,
      source: 'TOR_PROJECT',
      provenance: 'VERIFIED_FEED',
      orgId: 'global',
      retrievedAt: nowIso,
      firstSeen: new Date(now - 30 * 24 * 60 * 60 * 1000).toISOString(),
      lastSeen: nowIso,
      isFlagged: true,
      metadata: { asn: 'AS64500', country: 'NL', notes: 'Known SQLi/LFI campaign' },
    },
    {
      indicatorId: generateUuidV7(now - 59_000),
      type: 'IP',
      value: '203.0.113.77',
      threatType: 'Automated vulnerability scanner',
      severity: 'HIGH',
      confidence: 88,
      source: 'ABUSE_CH',
      provenance: 'VERIFIED_FEED',
      orgId: 'global',
      retrievedAt: nowIso,
      firstSeen: new Date(now - 14 * 24 * 60 * 60 * 1000).toISOString(),
      lastSeen: nowIso,
      isFlagged: true,
      metadata: { asn: 'AS64501', country: 'RU', notes: 'sqlmap / gobuster traffic' },
    },
    {
      indicatorId: generateUuidV7(now - 58_000),
      type: 'USER_AGENT',
      value: 'sqlmap/1.7.2',
      threatType: 'Offensive security tooling',
      severity: 'HIGH',
      confidence: 99,
      source: 'MANDIANT',
      provenance: 'VERIFIED_FEED',
      orgId: 'global',
      retrievedAt: nowIso,
      firstSeen: new Date(now - 90 * 24 * 60 * 60 * 1000).toISOString(),
      lastSeen: nowIso,
      isFlagged: true,
    },
  ];
  for (const indicator of indicators) {
    await storage.saveIndicator(indicator);
  }

  // 3. Ingest telemetry through the real detection + correlation pipeline.
  const pipeline = getDetectionPipeline();
  const events = buildEvents(orgId, now);
  for (const event of events) {
    const result = await storage.saveEvent(event);
    if (result.saved) {
      try {
        await pipeline.processEvent(event);
      } catch (pipelineErr) {
        console.warn('[VELTRIX] Demo pipeline warning:', pipelineErr);
      }
    }
  }

  const incidents = await storage.getIncidents(orgId, { limit: 100 });
  const topIncident = incidents.items[0];

  // 4. SOAR demo records (pending approval + one executed containment).
  if (topIncident) {
    const pending: ResponseExecution = {
      executionId: generateUuidV7(now - 30_000),
      incidentId: topIncident.incidentId,
      orgId,
      actionType: 'BLOCK_IP',
      target: '198.51.100.23',
      parameters: { durationMinutes: 60, reason: 'Active multi-stage web attack' },
      status: 'PENDING_APPROVAL',
      requestedBy: 'soc.analyst',
      isSimulated: true,
      rollbackCapable: true,
    };
    const executed: ResponseExecution = {
      executionId: generateUuidV7(now - 29_000),
      incidentId: topIncident.incidentId,
      orgId,
      actionType: 'STEP_UP_AUTH',
      target: 'customer-portal-sessions',
      parameters: { scope: 'privileged-sessions' },
      status: 'EXECUTED',
      requestedBy: 'soc.analyst',
      approvedBy: 'secops.admin',
      executedAt: new Date(now - 25 * 60 * 1000).toISOString(),
      result: { success: true, message: 'Step-up authentication enforced for 12 sessions.' },
      isSimulated: true,
      rollbackCapable: true,
    };
    await storage.saveExecution(pending);
    await storage.saveExecution(executed);
  }

  // 5. Audit ledger entries so the inspector and hash-chain verification work.
  const auditActions: Array<{
    action: Parameters<typeof storage.appendAuditLog>[0]['action'];
    details: Record<string, unknown>;
    minutesAgo: number;
  }> = [
    {
      action: 'WEBSITE_REGISTERED',
      details: { domain: sites[0]?.primaryDomain, siteId: sites[0]?.siteId },
      minutesAgo: 600,
    },
    {
      action: 'WEBSITE_VERIFIED',
      details: { domain: sites[0]?.primaryDomain, method: 'DNS_TXT' },
      minutesAgo: 590,
    },
    {
      action: 'INTEGRATION_CREATED',
      details: { type: 'CLOUDFLARE', name: 'Edge WAF telemetry' },
      minutesAgo: 500,
    },
    {
      action: 'RULE_MODIFIED',
      details: { ruleId: 'RULE-101', threshold: 1, window: 300 },
      minutesAgo: 400,
    },
    {
      action: 'INCIDENT_CREATED',
      details: { incidentId: topIncident?.incidentId, riskScore: topIncident?.riskScore },
      minutesAgo: 320,
    },
    {
      action: 'RESPONSE_REQUESTED',
      details: { actionType: 'BLOCK_IP', target: '198.51.100.23' },
      minutesAgo: 60,
    },
    {
      action: 'RESPONSE_APPROVED',
      details: { actionType: 'BLOCK_IP', approvedBy: 'secops.admin' },
      minutesAgo: 58,
    },
    {
      action: 'RESPONSE_EXECUTED',
      details: { actionType: 'BLOCK_IP', target: '198.51.100.23', durationMinutes: 60 },
      minutesAgo: 57,
    },
  ];
  for (const entry of auditActions) {
    await storage.appendAuditLog({
      logId: generateUuidV7(now - entry.minutesAgo * 60 * 1000),
      orgId,
      timestamp: new Date(now - entry.minutesAgo * 60 * 1000).toISOString(),
      action: entry.action,
      actor: {
        userId: 'usr-analyst-01',
        role: 'SECURITY_ANALYST',
        ipAddress: '127.0.0.1',
      },
      details: entry.details,
    });
  }

  const seededIncidents = await storage.getIncidents(orgId, { limit: 100 });
  const seededDetections = await storage.getDetections(orgId, { limit: 500 });
  return {
    alreadySeeded: false,
    sites: sites.length,
    events: events.length,
    detections: seededDetections.items.length,
    incidents: seededIncidents.items.length,
    topologyIncident: topIncident?.incidentId ?? null,
  };
}

export function createDemoRouter(): Router {
  const router = Router();

  router.use(authenticate);
  router.use(enforceTenantIsolation);

  router.post(
    '/seed',
    requireRole('ORG_ADMIN', 'SUPER_ADMIN'),
    async (req: Request, res: Response) => {
      const hasCognito = Boolean(process.env.COGNITO_CLIENT_ID) && process.env.COGNITO_CLIENT_ID !== 'undefined';
      const isDemoDisabled = process.env.DISABLE_DEMO_SEED === 'true' || (hasCognito && process.env.ENABLE_DEMO_SEED !== 'true');
      if (isDemoDisabled) {
        res.status(404).json({
          success: false,
          error: { code: 'NOT_FOUND', message: 'Demo seeding is not available in this environment' },
        });
        return;
      }

      try {
        const orgId = req.tenantOrgId!;
        const data = await seedDemoDataset(orgId);
        res.status(data.alreadySeeded ? 200 : 201).json({
          success: true,
          data,
          meta: { timestamp: new Date().toISOString() },
        });
      } catch (err: unknown) {
        console.error('[VELTRIX] Demo seed error:', err);
        const errorResponse: ApiErrorResponse = {
          success: false,
          error: {
            code: 'DEMO_SEED_ERROR',
            message: err instanceof Error ? err.message : 'Failed to seed the demo dataset',
          },
        };
        res.status(500).json(errorResponse);
      }
    }
  );

  return router;
}
