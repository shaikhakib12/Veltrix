import { describe, it, expect } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { FindingsPage } from '../src/pages/FindingsPage';
import { AuthProvider } from '../src/features/auth/AuthProvider';

describe('FindingsPage Component (TASK-5)', () => {
  it('renders live findings from query cache with Phase 8 rule badges, confidence tags, and CWE ratings', () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });

    qc.setQueryData(['findings', 'ALL'], [
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
        evidenceRequest: 'POST /api/v1/auth/login HTTP/1.1\nHost: shop.veltrix.io',
        evidenceResponse: 'HTTP/1.1 200 OK\n{"role": "ADMIN"}',
        curlReproduction: 'curl -s -X POST https://shop.veltrix.io/api/v1/auth/login',
        remediation: 'Use parameterized queries or an ORM.',
        discoveredAt: new Date().toISOString(),
      },
      {
        findingId: 'fnd-xss-102',
        orgId: 'org-enterprise-01',
        siteId: 'site-shop-01',
        ruleId: 'RULE_ACTIVE_XSS_CANARY',
        title: 'Reflected Cross-Site Scripting (XSS) via Canary Probe',
        vulnType: 'CROSS_SITE_SCRIPTING',
        cwe: 'CWE-79: Improper Neutralization',
        owasp: 'A03:2021-Injection',
        severity: 'HIGH',
        confidence: 'CONFIRMED',
        status: 'OPEN',
        targetUri: '/products/search?q=vxcanary',
        targetParameter: 'q',
        cvssScore: 7.5,
        evidenceRequest: 'GET /products/search?q=vxcanary HTTP/1.1',
        evidenceResponse: 'HTTP/1.1 200 OK\n<span>vxcanary</span>',
        curlReproduction: 'curl -s "https://shop.veltrix.io/products/search?q=vxcanary"',
        remediation: 'HTML entity encode dynamic outputs.',
        discoveredAt: new Date().toISOString(),
      },
    ]);

    const html = renderToStaticMarkup(
      <QueryClientProvider client={qc}>
        <AuthProvider>
          <MemoryRouter>
            <FindingsPage />
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    );

    expect(html).toContain('RULE_ACTIVE_SQLI_ANOMALY');
    expect(html).toContain('RULE_ACTIVE_XSS_CANARY');
    expect(html).toContain('CONFIRMED');
    expect(html).toContain('CWE-89: SQL Injection');
    expect(html).toContain('Unauthenticated SQL Injection in Authentication Endpoint');
  });
});

