import { describe, it, expect } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { ScansPage } from '../src/pages/ScansPage';
import { AuthProvider } from '../src/features/auth/AuthProvider';

describe('ScansPage Component (TASK-4)', () => {
  it('renders live scan jobs from query cache and displays Phase 8 profiles and stages', () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });

    qc.setQueryData(['scans'], [
      {
        scanId: 'scan-live-001',
        siteId: 'site-shop-01',
        targetDomain: 'shop.veltrix.io',
        profile: 'STANDARD_ACTIVE',
        status: 'RUNNING',
        currentStage: 'ACTIVE_PROBING',
        progressPercent: 50,
        findingsCount: 2,
        startedAt: new Date().toISOString(),
      },
      {
        scanId: 'scan-live-002',
        siteId: 'site-shop-01',
        targetDomain: 'shop.veltrix.io',
        profile: 'PASSIVE_BASELINE',
        status: 'COMPLETED',
        currentStage: 'REPORT_GENERATION',
        progressPercent: 100,
        findingsCount: 4,
        startedAt: new Date().toISOString(),
      },
    ]);

    qc.setQueryData(['websites'], {
      success: true,
      sites: [
        {
          siteId: 'site-shop-01',
          name: 'Shop Core',
          primaryDomain: 'shop.veltrix.io',
          environment: 'PRODUCTION',
          status: 'VERIFIED',
          scanBlocked: false,
          riskTier: 'CRITICAL',
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

    expect(html).toContain('Vulnerability Scans &amp; Scope Verification');
    expect(html).toContain('scan-live-001');
    expect(html).toContain('Non-Destructive Active Probes');
    expect(html).toContain('STANDARD_ACTIVE');
    expect(html).toContain('Launch Scan');
  });
});
