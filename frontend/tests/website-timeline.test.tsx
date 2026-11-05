import { describe, it, expect } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { WebsiteDetailPage } from '../src/pages/WebsiteDetailPage';
import { AuthProvider } from '../src/features/auth/AuthProvider';

describe('WebsiteDetailPage Attack Timeline (TASK-6)', () => {
  it('renders chronological attack kill-chain timeline with detections, incidents, and source IPs', () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });

    qc.setQueryData(['website', 'site-shop-01'], {
      site: {
        siteId: 'site-shop-01',
        orgId: 'org-enterprise-01',
        name: 'Shop Core',
        primaryDomain: 'shop.veltrix.io',
        environment: 'PRODUCTION',
        status: 'VERIFIED',
        scanBlocked: false,
        riskTier: 'CRITICAL',
        approvedSubdomains: [],
        tags: ['prod'],
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      },
    });

    qc.setQueryData(['website', 'site-shop-01', 'scan-authorization'], {
      siteId: 'site-shop-01',
      primaryDomain: 'shop.veltrix.io',
      status: 'VERIFIED',
      scanBlocked: false,
      authorized: true,
    });

    qc.setQueryData(['website', 'site-shop-01', 'timeline'], {
      siteId: 'site-shop-01',
      domain: 'shop.veltrix.io',
      total: 2,
      items: [
        {
          timestamp: '2026-11-04T10:00:00.000Z',
          type: 'INCIDENT',
          title: 'Coordinated SQL Injection Campaign',
          description: 'Multiple automated probes targeted /api/v1/auth/login from malicious subnets',
          severity: 'CRITICAL',
          sourceIp: '198.51.100.42',
        },
        {
          timestamp: '2026-11-04T09:45:00.000Z',
          type: 'DETECTION',
          title: 'Canary Probe Reflected XSS Attempt',
          description: 'Suspicious payload injected in search parameter query',
          severity: 'HIGH',
          sourceIp: '203.0.113.19',
        },
      ],
    });

    const html = renderToStaticMarkup(
      <QueryClientProvider client={qc}>
        <AuthProvider>
          <MemoryRouter initialEntries={['/websites/site-shop-01']}>
            <Routes>
              <Route path="/websites/:siteId" element={<WebsiteDetailPage />} />
            </Routes>
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    );

    expect(html).toContain('Attack &amp; Security Timeline');
    expect(html).toContain('Coordinated SQL Injection Campaign');
    expect(html).toContain('Canary Probe Reflected XSS Attempt');
    expect(html).toContain('198.51.100.42');
    expect(html).toContain('203.0.113.19');
    expect(html).toContain('INCIDENT');
    expect(html).toContain('DETECTION');
  });
});

