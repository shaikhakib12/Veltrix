import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as endpoints from '../src/lib/api/endpoints';

describe('Scans, Findings, and Verification API Adapters (TASK-2)', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('verifyDomain issues POST /websites/:siteId/verify with method payload', async () => {
    const mockFetch = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          success: true,
          verified: true,
          status: 'VERIFIED',
          message: 'Domain ownership verified.',
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      )
    );

    const result = await endpoints.verifyDomain('site-123', 'DNS_TXT');

    expect(mockFetch).toHaveBeenCalledTimes(1);
    const [url, init] = mockFetch.mock.calls[0];
    expect(url).toContain('/websites/site-123/verify');
    expect(init?.method).toBe('POST');
    expect(JSON.parse(init?.body as string)).toEqual({ method: 'DNS_TXT' });
    expect(result.verified).toBe(true);
    expect(result.status).toBe('VERIFIED');
  });

  it('fetchScanAuthorization issues GET /websites/:siteId/scan-authorization', async () => {
    const mockFetch = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          success: true,
          data: {
            siteId: 'site-123',
            primaryDomain: 'shop.veltrix.io',
            authorized: true,
            status: 'VERIFIED',
            scanBlocked: false,
          },
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      )
    );

    const result = await endpoints.fetchScanAuthorization('site-123');
    expect(mockFetch).toHaveBeenCalled();
    expect(result.authorized).toBe(true);
    expect(result.primaryDomain).toBe('shop.veltrix.io');
  });

  it('createScan issues POST /scans with profile and siteId', async () => {
    const mockFetch = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          success: true,
          data: {
            scanId: 'scan-999',
            siteId: 'site-123',
            profile: 'STANDARD_ACTIVE',
            status: 'RUNNING',
            progressPercent: 25,
            startedAt: new Date().toISOString(),
          },
        }),
        { status: 201, headers: { 'Content-Type': 'application/json' } }
      )
    );

    const result = await endpoints.createScan({
      siteId: 'site-123',
      profile: 'STANDARD_ACTIVE',
      maxDepth: 3,
    });

    expect(mockFetch).toHaveBeenCalled();
    expect(result.scanId).toBe('scan-999');
    expect(result.status).toBe('RUNNING');
  });

  it('fetchScans issues GET /scans and returns list', async () => {
    const mockFetch = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          success: true,
          data: {
            items: [
              {
                scanId: 'scan-1',
                siteId: 'site-123',
                profile: 'PASSIVE_BASELINE',
                status: 'COMPLETED',
                progressPercent: 100,
                startedAt: new Date().toISOString(),
              },
            ],
            total: 1,
          },
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      )
    );

    const result = await endpoints.fetchScans({ siteId: 'site-123' });
    expect(mockFetch).toHaveBeenCalled();
    expect(result.length).toBe(1);
    expect(result[0].scanId).toBe('scan-1');
  });

  it('fetchFindings issues GET /findings and returns items', async () => {
    const mockFetch = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          success: true,
          data: {
            items: [
              {
                findingId: 'fnd-1',
                title: 'SQL Injection',
                severity: 'CRITICAL',
                confidence: 'CONFIRMED',
                ruleId: 'RULE_ACTIVE_SQLI_ANOMALY',
              },
            ],
            total: 1,
          },
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      )
    );

    const result = await endpoints.fetchFindings();
    expect(mockFetch).toHaveBeenCalled();
    expect(result.length).toBe(1);
    expect(result[0].findingId).toBe('fnd-1');
  });

  it('fetchWebsiteTimeline issues GET /websites/:siteId/timeline', async () => {
    const mockFetch = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          success: true,
          data: {
            siteId: 'site-123',
            domain: 'shop.veltrix.io',
            items: [
              {
                timestamp: new Date().toISOString(),
                type: 'DETECTION',
                title: 'Web Attack Probe',
                severity: 'HIGH',
              },
            ],
          },
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      )
    );

    const result = await endpoints.fetchWebsiteTimeline('site-123');
    expect(mockFetch).toHaveBeenCalled();
    expect(result.items.length).toBe(1);
    expect(result.items[0].title).toBe('Web Attack Probe');
  });
});

