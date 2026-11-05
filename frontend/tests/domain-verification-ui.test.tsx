import { describe, it, expect } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { DomainVerificationModal } from '../src/components/DomainVerificationModal';
import { WebsiteDetailPage } from '../src/pages/WebsiteDetailPage';
import { AuthProvider } from '../src/features/auth/AuthProvider';
import type { WebsiteAsset } from '@veltrix/shared';

describe('Domain Verification UI (TASK-3)', () => {
  const pendingSite: WebsiteAsset = {
    siteId: 'site-pending-01',
    orgId: 'org-test',
    name: 'Pending Site',
    primaryDomain: 'pending.example.com',
    approvedSubdomains: [],
    environment: 'PRODUCTION',
    status: 'PENDING_VERIFICATION',
    riskTier: 'HIGH',
    tags: [],
    verificationToken: 'token-abc-123',
    tokenCreatedAt: new Date().toISOString(),
    dnsTxtRecord: {
      host: '_veltrix-challenge.pending.example.com',
      value: 'veltrix-domain-verification=token-abc-123',
    },
    metaTag: {
      tag: '<meta name="veltrix-domain-verification" content="token-abc-123">',
      name: 'veltrix-domain-verification',
      content: 'token-abc-123',
    },
    httpChallenge: {
      url: 'https://pending.example.com/.well-known/veltrix-challenge.txt',
      expectedBody: {
        veltrixChallengeToken: 'token-abc-123',
        orgId: 'org-test',
      },
    },
    scanBlocked: true,
    health: { telemetryStatus: 'INACTIVE', eventsPerMinute: 0 },
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  it('renders DomainVerificationModal with DNS TXT, HTTP Challenge, and Meta Tag tabs', () => {
    const html = renderToStaticMarkup(
      <DomainVerificationModal
        isOpen={true}
        onClose={() => {}}
        site={pendingSite}
      />
    );

    expect(html).toContain('Verify Domain Ownership');
    expect(html).toContain('pending.example.com');
    expect(html).toContain('DNS TXT Record');
    expect(html).toContain('HTTP Challenge');
    expect(html).toContain('HTML Meta Tag');
    expect(html).toContain('veltrix-domain-verification=token-abc-123');
    expect(html).toContain('Verify Ownership Now');
  });

  it('renders Verify Domain Ownership trigger in WebsiteDetailPage when site is pending', () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    qc.setQueryData(['website', 'site-pending-01'], {
      success: true,
      site: pendingSite,
    });
    qc.setQueryData(['website', 'site-pending-01', 'scan-authorization'], {
      siteId: 'site-pending-01',
      primaryDomain: 'pending.example.com',
      authorized: false,
      status: 'PENDING_VERIFICATION',
      scanBlocked: true,
    });

    const html = renderToStaticMarkup(
      <QueryClientProvider client={qc}>
        <AuthProvider>
          <MemoryRouter initialEntries={['/websites/site-pending-01']}>
            <Routes>
              <Route path="/websites/:siteId" element={<WebsiteDetailPage />} />
            </Routes>
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    );

    expect(html).toContain('Verify Domain');
    expect(html).toContain('Scans Blocked');
  });
});
