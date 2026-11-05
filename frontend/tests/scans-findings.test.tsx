import { describe, it, expect } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { ScansPage } from '../src/pages/ScansPage';
import { FindingsPage } from '../src/pages/FindingsPage';
import { AuthProvider } from '../src/features/auth/AuthProvider';

describe('ScansPage Component', () => {
  it('renders scan orchestrator view with contract-first backend status indicator and scope verification', () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });

    // Mock websites for target scope validation
    qc.setQueryData(['websites'], {
      success: true,
      sites: [
        {
          siteId: 'site-shop-01',
          name: 'Shop Core Production',
          primaryDomain: 'shop.veltrix.io',
          environment: 'PRODUCTION',
          status: 'VERIFIED',
          scanBlocked: false,
          riskTier: 'CRITICAL',
          approvedSubdomains: [],
          tags: ['ecommerce'],
          createdAt: '2026-11-01T00:00:00.000Z',
          updatedAt: '2026-11-01T00:00:00.000Z',
        },
        {
          siteId: 'site-staging-02',
          name: 'Staging Portal',
          primaryDomain: 'staging.veltrix.io',
          environment: 'STAGING',
          status: 'PENDING_VERIFICATION',
          scanBlocked: true,
          riskTier: 'MEDIUM',
          approvedSubdomains: [],
          tags: ['staging'],
          createdAt: '2026-11-02T00:00:00.000Z',
          updatedAt: '2026-11-02T00:00:00.000Z',
        },
      ],
    });

    const html = renderToStaticMarkup(
      <QueryClientProvider client={qc}>
        <AuthProvider>
          <MemoryRouter>
            <ScansPage />
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    );

    expect(html).toContain('Vulnerability Scans');
    expect(html).toContain('Phase 8 Backend Scan Engine');
    expect(html).toContain('Launch Scan');
    expect(html).toContain('Scope Verification');
    expect(html).toContain('Target Asset Scope');
    expect(html).toContain('shop.veltrix.io');
  });
});

describe('FindingsPage Component', () => {
  it('renders vulnerability findings evidence catalog with severity filters, findings list and cwe ratings', () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });

    const html = renderToStaticMarkup(
      <QueryClientProvider client={qc}>
        <AuthProvider>
          <MemoryRouter>
            <FindingsPage />
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    );

    expect(html).toContain('Vulnerability Findings');
    expect(html).toContain('Evidence Ledger');
    expect(html).toContain('CRITICAL');
    expect(html).toContain('HIGH');
    expect(html).toContain('MEDIUM');
    expect(html).toContain('Phase 8 Vulnerability Catalog Ready');
    expect(html).toContain('SQL_INJECTION');
    expect(html).toContain('9.8');
    expect(html).toContain('/api/v1/auth/login');
  });
});
