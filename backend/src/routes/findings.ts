import { Router, type Request, type Response } from 'express';
import { authenticate, requireBearerAuth } from '../middleware/auth.js';
import { enforceTenantIsolation } from '../middleware/tenant.js';

export interface FindingRecord {
  findingId: string;
  orgId: string;
  siteId: string;
  ruleId: string;
  title: string;
  vulnType: string;
  cwe: string;
  owasp: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
  confidence: 'CONFIRMED' | 'HIGH' | 'MEDIUM' | 'LOW';
  status: 'OPEN' | 'IN_REMEDIATION' | 'RESOLVED' | 'FALSE_POSITIVE';
  targetUri: string;
  targetParameter?: string;
  cvssScore: number;
  evidenceRequest: string;
  evidenceResponse: string;
  curlReproduction: string;
  remediation: string;
  discoveredAt: string;
}

// In-memory findings registry initialized with Phase 8 findings
const INITIAL_DEMO_FINDINGS: FindingRecord[] = [
  {
    findingId: 'fnd-sqli-101',
    orgId: 'org-enterprise-01',
    siteId: 'site-shop-01',
    ruleId: 'RULE_ACTIVE_SQLI_ANOMALY',
    title: 'Unauthenticated SQL Injection in Authentication Endpoint',
    vulnType: 'SQL_INJECTION',
    cwe: 'CWE-89: SQL Injection',
    owasp: 'A03:2021-Injection',
    severity: 'CRITICAL',
    confidence: 'CONFIRMED',
    status: 'OPEN',
    targetUri: '/api/v1/auth/login',
    targetParameter: 'username',
    cvssScore: 9.8,
    evidenceRequest: `POST /api/v1/auth/login HTTP/1.1\nHost: shop.veltrix.io\nContent-Type: application/json\n\n{"username": "admin' OR 1=1 --", "password": "x"}`,
    evidenceResponse: `HTTP/1.1 200 OK\nContent-Type: application/json\n\n{"token": "eyJhbGciOi...", "role": "ADMIN", "bypassed": true}`,
    curlReproduction: `curl -s -X POST https://shop.veltrix.io/api/v1/auth/login \\\n  -H "Content-Type: application/json" \\\n  -d '{"username": "admin\\' OR 1=1 --", "password": "x"}'`,
    remediation: 'Use parameterized queries or an ORM with prepared statement bindings. Sanitize all dynamic SQL inputs.',
    discoveredAt: new Date(Date.now() - 1000 * 60 * 120).toISOString(),
  },
  {
    findingId: 'fnd-xss-102',
    orgId: 'org-enterprise-01',
    siteId: 'site-shop-01',
    ruleId: 'RULE_ACTIVE_XSS_CANARY',
    title: 'Reflected Cross-Site Scripting (XSS) via Canary Probe',
    vulnType: 'CROSS_SITE_SCRIPTING',
    cwe: 'CWE-79: Improper Neutralization of Input During Web Page Generation',
    owasp: 'A03:2021-Injection',
    severity: 'HIGH',
    confidence: 'CONFIRMED',
    status: 'IN_REMEDIATION',
    targetUri: '/products/search?q=vxcanary7a8b9c',
    targetParameter: 'q',
    cvssScore: 7.5,
    evidenceRequest: `GET /products/search?q=vxcanary7a8b9c HTTP/1.1\nHost: shop.veltrix.io`,
    evidenceResponse: `HTTP/1.1 200 OK\nContent-Type: text/html\n\n<div class="search-term"><span>vxcanary7a8b9c</span></div>`,
    curlReproduction: `curl -s "https://shop.veltrix.io/products/search?q=vxcanary7a8b9c"`,
    remediation: 'Contextually encode all user-controlled inputs with HTML entity encoding before rendering into DOM contexts.',
    discoveredAt: new Date(Date.now() - 1000 * 60 * 240).toISOString(),
  },
  {
    findingId: 'fnd-tls-103',
    orgId: 'org-enterprise-01',
    siteId: 'site-shop-01',
    ruleId: 'RULE_PASSIVE_TLS',
    title: 'TLS Certificate Expiring within 14 Days',
    vulnType: 'INSECURE_TLS',
    cwe: 'CWE-295: Improper Certificate Validation',
    owasp: 'A02:2021-Cryptographic Failures',
    severity: 'MEDIUM',
    confidence: 'HIGH',
    status: 'OPEN',
    targetUri: 'https://shop.veltrix.io',
    cvssScore: 5.3,
    evidenceRequest: `TLS Handshake ClientHello -> shop.veltrix.io:443`,
    evidenceResponse: `ServerCertificate: valid_to="2026-11-18T00:00:00Z" (Days remaining: 14)`,
    curlReproduction: `curl -Iv https://shop.veltrix.io 2>&1 | grep "expire date"`,
    remediation: 'Renew and deploy updated TLS certificate from trusted ACME / CA provider before expiration.',
    discoveredAt: new Date(Date.now() - 1000 * 60 * 360).toISOString(),
  },
  {
    findingId: 'fnd-headers-104',
    orgId: 'org-enterprise-01',
    siteId: 'site-shop-01',
    ruleId: 'RULE_PASSIVE_HEADERS',
    title: 'Missing Content-Security-Policy (CSP) and HSTS Preload',
    vulnType: 'MISSING_SECURITY_HEADERS',
    cwe: 'CWE-1021: Improper Restriction of Rendered UI Layers',
    owasp: 'A05:2021-Security Misconfiguration',
    severity: 'LOW',
    confidence: 'CONFIRMED',
    status: 'OPEN',
    targetUri: 'https://shop.veltrix.io/',
    cvssScore: 3.8,
    evidenceRequest: `GET / HTTP/1.1\nHost: shop.veltrix.io`,
    evidenceResponse: `HTTP/1.1 200 OK\nStrict-Transport-Security: missing\nContent-Security-Policy: missing`,
    curlReproduction: `curl -I https://shop.veltrix.io | grep -i -E "content-security|strict-transport"`,
    remediation: 'Configure Content-Security-Policy with default-src \'self\' and Strict-Transport-Security max-age=31536000; includeSubDomains; preload.',
    discoveredAt: new Date(Date.now() - 1000 * 60 * 480).toISOString(),
  },
];

const tenantFindings = new Map<string, FindingRecord[]>();

export function getFindingsRegistryForOrg(orgId: string): FindingRecord[] {
  let list = tenantFindings.get(orgId);
  if (!list) {
    list = INITIAL_DEMO_FINDINGS.map((f) => ({ ...f, orgId }));
    tenantFindings.set(orgId, list);
  }
  return list;
}

export function createFindingsRouter(): Router {
  const router = Router();

  router.use(requireBearerAuth);
  router.use(authenticate);
  router.use(enforceTenantIsolation);

  /**
   * GET /api/v1/findings
   */
  router.get('/', async (req: Request, res: Response) => {
    const orgId = req.tenantOrgId!;
    const siteId = req.query.siteId as string | undefined;
    const severity = req.query.severity as string | undefined;
    const confidence = req.query.confidence as string | undefined;

    let items = getFindingsRegistryForOrg(orgId);
    if (siteId) {
      items = items.filter((f) => f.siteId === siteId);
    }
    if (severity) {
      items = items.filter((f) => f.severity.toLowerCase() === severity.toLowerCase());
    }
    if (confidence) {
      items = items.filter((f) => f.confidence.toLowerCase() === confidence.toLowerCase());
    }

    return res.status(200).json({
      success: true,
      data: {
        items,
        total: items.length,
      },
      meta: {
        timestamp: new Date().toISOString(),
      },
    });
  });

  /**
   * GET /api/v1/findings/:findingId
   */
  router.get('/:findingId', async (req: Request, res: Response) => {
    const orgId = req.tenantOrgId!;
    const findingId = req.params.findingId;

    const items = getFindingsRegistryForOrg(orgId);
    const finding = items.find((f) => f.findingId === findingId);
    if (!finding) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'FINDING_NOT_FOUND',
          message: `Finding '${findingId}' was not found.`,
        },
      });
    }

    return res.status(200).json({
      success: true,
      data: finding,
    });
  });

  return router;
}

