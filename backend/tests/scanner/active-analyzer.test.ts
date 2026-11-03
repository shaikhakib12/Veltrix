/**
 * VELTRIX Active Security Assessment Pipeline - Test Suite (TASK-805)
 *
 * Verifies all requirements from Phase 8 specification:
 * 1. Central ActiveSafetyGate (authorization, scope, method, budget, abort).
 * 2. Reflected XSS Canary Rule (alphanumeric canaries, context analysis, entity-encoding suppression).
 * 3. SQL Syntax Anomaly Rule (benign disruptors, RDBMS error signatures, differential comparison).
 * 4. Open Redirect Canary Rule (canary target, 3xx Location evaluation, maxRedirects=0).
 * 5. Path Traversal Canary Rule (non-existent canary, path normalization error signatures).
 * 6. Non-Destructive Invariant, Negative Boundary Verification & Zero Requests When Blocked.
 */

import http from 'node:http';
import net from 'node:net';
import tls from 'node:tls';
import { describe, it, expect, vi, beforeAll, afterAll } from 'vitest';
import type { CrawledPage } from '../../src/scanner/crawler/types.js';
import {
  ActiveAnalyzer,
  ActiveSafetyGate,
  XssCanaryRule,
  SqliAnomalyRule,
  OpenRedirectRule,
  PathTraversalRule,
  PassiveAnalyzer,
  RULE_ACTIVE_XSS_CANARY,
  RULE_ACTIVE_SQLI_ANOMALY,
  RULE_ACTIVE_OPEN_REDIRECT,
  RULE_ACTIVE_PATH_TRAVERSAL,
  SafeHttpClient,
  SafeTransportError,
  sanitizeHeaders,
  type ActiveRuleExecutionContext,
} from '../../src/scanner/index.js';
import { createTestScanContext } from './helpers/test-context-helper.js';

function createMockCrawledPage(overrides?: Partial<CrawledPage>): CrawledPage {
  return {
    url: 'https://example.com/search?q=test',
    depth: 1,
    parentUrl: 'https://example.com/',
    source: 'a',
    status: 200,
    statusText: 'OK',
    contentType: 'text/html; charset=utf-8',
    title: 'Search Page',
    discoveredEndpoints: [],
    durationMs: 40,
    wireBytesReceived: 1024,
    headers: {
      'content-type': 'text/html; charset=utf-8',
    },
    bodyText: '<html><body>Search results for test</body></html>',
    ...overrides,
  };
}

describe('Phase 8: Controlled Non-Destructive Active Security Probes (TASK-805)', () => {
  // =========================================================================
  // SECTION 1: Central Active Safety Gate Tests
  // =========================================================================
  describe('1. Central Active Safety Gate (active-safety-gate.ts)', () => {
    it('is disabled by default and rejects probes with zero network requests', async () => {
      const gate = new ActiveSafetyGate(); // enabled is undefined / false
      expect(gate.isEnabled()).toBe(false);

      const context = await createTestScanContext({ primaryDomain: 'example.com' });

      expect(() => {
        gate.checkAndAcquireProbeSlot('https://example.com/test', context, 'GET');
      }).toThrowError(/Active security probing is disabled by default/i);

      expect(gate.getTotalRequestsDispatched()).toBe(0);
    });

    it('rejects forged or untrusted RequestAuthorizationContext', () => {
      const gate = new ActiveSafetyGate({ enabled: true });
      const fakeContext: any = {
        purpose: 'AUTHORIZED_SCAN',
        status: 'VERIFIED',
        primaryDomain: 'example.com',
        scanBlocked: false,
        expiresAt: Date.now() + 86400000,
      };

      expect(() => {
        gate.checkAndAcquireProbeSlot('https://example.com/test', fakeContext, 'GET');
      }).toThrowError(/Untrusted or forged RequestAuthorizationContext/i);
    });

    it('rejects targets when domain verification has expired', async () => {
      const gate = new ActiveSafetyGate({ enabled: true });
      const context = await createTestScanContext({
        primaryDomain: 'example.com',
        expiresAt: Date.now() + 50,
      });

      await new Promise((resolve) => setTimeout(resolve, 60));

      expect(() => {
        gate.checkAndAcquireProbeSlot('https://example.com/test', context, 'GET');
      }).toThrowError(/expired/i);
    });

    it('rejects targets when site is administratively scan-blocked', async () => {
      await expect(
        createTestScanContext({
          primaryDomain: 'example.com',
          scanBlocked: true,
        })
      ).rejects.toThrowError(/scanBlocked set to true/i);
    });

    it('rejects probe target URLs outside authorized host scope', async () => {
      const gate = new ActiveSafetyGate({ enabled: true });
      const context = await createTestScanContext({
        primaryDomain: 'authorized.example.com',
        approvedSubdomains: ['sub.authorized.example.com'],
      });

      // Target different domain
      expect(() => {
        gate.checkAndAcquireProbeSlot('https://attacker.com/test', context, 'GET');
      }).toThrowError(/outside the authorized scan scope/i);

      // Target unapproved subdomain
      expect(() => {
        gate.checkAndAcquireProbeSlot('https://evil.authorized.example.com/test', context, 'GET');
      }).toThrowError(/outside the authorized scan scope/i);
    });

    it('rejects non-standard destination ports without explicit authorization', async () => {
      const gate = new ActiveSafetyGate({ enabled: true });
      const context = await createTestScanContext({
        primaryDomain: 'example.com',
      });

      expect(() => {
        gate.checkAndAcquireProbeSlot('https://example.com:8443/test', context, 'GET');
      }).toThrowError(/Non-standard port 8443 is not allowed/i);
    });

    it('categorically blocks prohibited internal infrastructure ports', async () => {
      const gate = new ActiveSafetyGate({ enabled: true });
      const context = await createTestScanContext({
        primaryDomain: 'example.com',
      });

      expect(() => {
        gate.checkAndAcquireProbeSlot('https://example.com:22/test', context, 'GET');
      }).toThrowError(/prohibited internal infrastructure port/i);
    });

    it('strictly prohibits mutating HTTP methods (POST, PUT, DELETE, PATCH)', async () => {
      const gate = new ActiveSafetyGate({ enabled: true });
      const context = await createTestScanContext({ primaryDomain: 'example.com' });

      for (const method of ['POST', 'PUT', 'DELETE', 'PATCH']) {
        expect(() => {
          gate.checkAndAcquireProbeSlot('https://example.com/test', context, method);
        }).toThrowError(/strictly prohibited for active security probes/i);
      }
    });

    it('strictly blocks mandatory server excluded paths', async () => {
      const gate = new ActiveSafetyGate({ enabled: true });
      const context = await createTestScanContext({ primaryDomain: 'example.com' });

      expect(() => {
        gate.checkAndAcquireProbeSlot('https://example.com/.env', context, 'GET');
      }).toThrowError(/matches excluded security prefix/i);

      expect(() => {
        gate.checkAndAcquireProbeSlot('https://example.com/.git/config', context, 'GET');
      }).toThrowError(/matches excluded security prefix/i);
    });

    it('strictly blocks active probes against potentially state-altering GET endpoints', async () => {
      const gate = new ActiveSafetyGate({ enabled: true });
      const context = await createTestScanContext({ primaryDomain: 'example.com' });

      const dangerousPaths = [
        'https://example.com/logout',
        'https://example.com/auth/signout',
        'https://example.com/user/sign-out',
        'https://example.com/items/123/delete',
        'https://example.com/account/destroy',
        'https://example.com/auth/reset-password',
        'https://example.com/api/cart/checkout',
        'https://example.com/subscription/cancel',
        'https://example.com/posts/delete/456',
      ];

      for (const url of dangerousPaths) {
        expect(() => {
          gate.checkAndAcquireProbeSlot(url, context, 'GET');
        }).toThrowError(/potentially state-altering or mutating GET route/i);
      }

      // Safe endpoints should pass through
      expect(() => {
        gate.checkAndAcquireProbeSlot('https://example.com/search?q=test', context, 'GET');
      }).not.toThrow();
    });

    it('enforces aggregate session request budget limit', async () => {
      const maxTotal = 3;
      const gate = new ActiveSafetyGate({ enabled: true, maxTotalRequests: maxTotal });
      const context = await createTestScanContext({ primaryDomain: 'example.com' });

      gate.checkAndAcquireProbeSlot('https://example.com/1', context, 'GET');
      gate.checkAndAcquireProbeSlot('https://example.com/2', context, 'GET');
      gate.checkAndAcquireProbeSlot('https://example.com/3', context, 'GET');

      expect(() => {
        gate.checkAndAcquireProbeSlot('https://example.com/4', context, 'GET');
      }).toThrowError(/aggregate request budget exhausted/i);

      expect(gate.getTotalRequestsDispatched()).toBe(3);
    });

    it('enforces per-endpoint probe request ceiling', async () => {
      const maxPerEndpoint = 2;
      const gate = new ActiveSafetyGate({
        enabled: true,
        maxRequestsPerEndpoint: maxPerEndpoint,
      });
      const context = await createTestScanContext({ primaryDomain: 'example.com' });

      gate.checkAndAcquireProbeSlot('https://example.com/search?q=1', context, 'GET');
      gate.checkAndAcquireProbeSlot('https://example.com/search?q=2', context, 'GET');

      expect(() => {
        gate.checkAndAcquireProbeSlot('https://example.com/search?q=3', context, 'GET');
      }).toThrowError(/Per-endpoint probe request ceiling reached/i);
    });

    it('fails closed when AbortSignal is already cancelled', async () => {
      const gate = new ActiveSafetyGate({ enabled: true });
      const context = await createTestScanContext({ primaryDomain: 'example.com' });
      const controller = new AbortController();
      controller.abort();

      expect(() => {
        gate.checkAndAcquireProbeSlot('https://example.com/test', context, 'GET', controller.signal);
      }).toThrowError(/cancelled by caller AbortSignal/i);
    });
  });

  // =========================================================================
  // SECTION 2: Reflected XSS Canary Rule Tests
  // =========================================================================
  describe('2. Reflected XSS Canary Rule (xss-canary-rule.ts)', () => {
    it('detects unencoded alphanumeric canary reflection in HTML text', async () => {
      const rule = new XssCanaryRule();
      const page = createMockCrawledPage({
        url: 'https://example.com/search?q=hello',
        bodyText: '<html><body>No canary here</body></html>',
      });

      let dispatchedUrl = '';
      const mockContext = {
        timeoutMs: 5000,
        dispatchProbe: async (url: string) => {
          dispatchedUrl = url;
          const u = new URL(url);
          const canary = u.searchParams.get('q') || '';
          return {
            status: 200,
            statusText: 'OK',
            headers: { 'content-type': 'text/html' },
            text: `<html><body>Search results for: <div>${canary}</div></body></html>`,
            wireBytesReceived: 200,
            decompressedBytes: 200,
            redirectHops: 0,
          };
        },
      };

      const findings = await rule.evaluate(page, mockContext);
      expect(findings.length).toBe(1);
      const f = findings[0]!;
      expect(f.ruleId).toBe(RULE_ACTIVE_XSS_CANARY);
      expect(f.vulnerabilityType).toBe('CROSS_SITE_SCRIPTING_REFLECTED');
      expect(f.severity).toBe('INFORMATIONAL');
      expect(f.confidence).toBe('LOW');
      expect(f.title).toContain('Reflected Parameter Value in HTML Text');
      expect(f.evidence.parameter).toBe('q');
      expect(f.evidence.reflectionContext).toBe('HTML_TEXT');
      expect(dispatchedUrl).toContain('vltxcanary_');
    });

    it('identifies reflection inside HTML attribute context with LOW severity and LOW confidence', async () => {
      const rule = new XssCanaryRule();
      const page = createMockCrawledPage({
        url: 'https://example.com/profile?name=alice',
      });

      const mockContext = {
        timeoutMs: 5000,
        dispatchProbe: async (url: string) => {
          const u = new URL(url);
          const canary = u.searchParams.get('name') || '';
          return {
            status: 200,
            statusText: 'OK',
            headers: { 'content-type': 'text/html' },
            text: `<html><body><input type="text" name="name" value="${canary}"></body></html>`,
            wireBytesReceived: 200,
            decompressedBytes: 200,
            redirectHops: 0,
          };
        },
      };

      const findings = await rule.evaluate(page, mockContext);
      expect(findings.length).toBe(1);
      expect(findings[0]?.evidence.reflectionContext).toBe('HTML_ATTRIBUTE');
      expect(findings[0]?.severity).toBe('LOW');
      expect(findings[0]?.confidence).toBe('LOW');
      expect(findings[0]?.title).toContain('HTML Attribute');
    });

    it('identifies reflection inside script block context with MEDIUM severity and MEDIUM confidence', async () => {
      const rule = new XssCanaryRule();
      const page = createMockCrawledPage({
        url: 'https://example.com/app?user=test',
      });

      const mockContext = {
        timeoutMs: 5000,
        dispatchProbe: async (url: string) => {
          const u = new URL(url);
          const canary = u.searchParams.get('user') || '';
          return {
            status: 200,
            statusText: 'OK',
            headers: { 'content-type': 'text/html' },
            text: `<html><head><script>var currentUser = "${canary}";</script></head></html>`,
            wireBytesReceived: 200,
            decompressedBytes: 200,
            redirectHops: 0,
          };
        },
      };

      const findings = await rule.evaluate(page, mockContext);
      expect(findings.length).toBe(1);
      expect(findings[0]?.evidence.reflectionContext).toBe('SCRIPT_BLOCK');
      expect(findings[0]?.severity).toBe('MEDIUM');
      expect(findings[0]?.confidence).toBe('MEDIUM');
      expect(findings[0]?.title).toContain('Script Context');
    });

    it('proves ordinary search-term text reflection does NOT generate a CONFIRMED or HIGH XSS finding', async () => {
      const rule = new XssCanaryRule();
      const page = createMockCrawledPage({
        url: 'https://example.com/search?q=normal_search_term',
      });

      const mockContext = {
        timeoutMs: 5000,
        dispatchProbe: async (url: string) => {
          const u = new URL(url);
          const canary = u.searchParams.get('q') || '';
          return {
            status: 200,
            statusText: 'OK',
            headers: { 'content-type': 'text/html' },
            text: `<p>Your search returned 0 results for: ${canary}</p>`,
            wireBytesReceived: 200,
            decompressedBytes: 200,
            redirectHops: 0,
          };
        },
      };

      const findings = await rule.evaluate(page, mockContext);
      expect(findings.length).toBe(1);
      expect(findings[0]?.confidence).not.toBe('CONFIRMED');
      expect(findings[0]?.severity).not.toBe('HIGH');
      expect(findings[0]?.confidence).toBe('LOW');
      expect(findings[0]?.severity).toBe('INFORMATIONAL');
    });

    it('does NOT flag when canary reflection is properly entity-encoded (&lt;canary&gt;)', async () => {
      const rule = new XssCanaryRule();
      const page = createMockCrawledPage({
        url: 'https://example.com/safe?q=test',
      });

      const mockContext = {
        timeoutMs: 5000,
        dispatchProbe: async (url: string) => {
          const u = new URL(url);
          const canary = u.searchParams.get('q') || '';
          // Server properly encodes the reflection
          return {
            status: 200,
            statusText: 'OK',
            headers: { 'content-type': 'text/html' },
            text: `<html><body>Results for &lt;${canary}&gt;</body></html>`,
            wireBytesReceived: 200,
            decompressedBytes: 200,
            redirectHops: 0,
          };
        },
      };

      const findings = await rule.evaluate(page, mockContext);
      expect(findings.length).toBe(0);
    });

    it('proves only non-executable alphanumeric canaries are dispatched (never <script>)', async () => {
      const rule = new XssCanaryRule();
      const page = createMockCrawledPage({ url: 'https://example.com/check?term=val' });

      let capturedProbeUrl = '';
      const mockContext = {
        timeoutMs: 5000,
        dispatchProbe: async (url: string) => {
          capturedProbeUrl = url;
          return null;
        },
      };

      await rule.evaluate(page, mockContext);
      expect(capturedProbeUrl).toBeDefined();
      expect(capturedProbeUrl).not.toContain('<script');
      expect(capturedProbeUrl).not.toContain('alert(');
      expect(capturedProbeUrl).toMatch(/term=vltxcanary_[0-9a-f]{16}/i);
    });
  });

  // =========================================================================
  // SECTION 3: SQL Syntax Anomaly Rule Tests
  // =========================================================================
  describe('3. SQL Syntax Anomaly Rule (sqli-anomaly-rule.ts)', () => {
    it('detects explicit MySQL syntax error signature and flags with HIGH confidence', async () => {
      const rule = new SqliAnomalyRule();
      const page = createMockCrawledPage({
        url: 'https://example.com/items?id=10',
        bodyText: '<html>Item details for #10</html>',
      });

      const mockContext = {
        timeoutMs: 5000,
        dispatchProbe: async (url: string) => {
          return {
            status: 500,
            statusText: 'Internal Server Error',
            headers: { 'content-type': 'text/html' },
            text: '<html><body>Database error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version near \'10\'\'</body></html>',
            wireBytesReceived: 300,
            decompressedBytes: 300,
            redirectHops: 0,
          };
        },
      };

      const findings = await rule.evaluate(page, mockContext);
      expect(findings.length).toBe(1);
      const f = findings[0]!;
      expect(f.ruleId).toBe(RULE_ACTIVE_SQLI_ANOMALY);
      expect(f.vulnerabilityType).toBe('SQL_INJECTION_SYNTAX_ANOMALY');
      expect(f.severity).toBe('HIGH');
      expect(f.confidence).toBe('HIGH');
      expect(f.evidence.rdbms).toBe('MySQL / MariaDB');
    });

    it('detects explicit Microsoft Access / ODBC SQL error signature', async () => {
      const rule = new SqliAnomalyRule();
      const page = createMockCrawledPage({
        url: 'https://example.com/view?cat=books',
        bodyText: '<html>Category: Books</html>',
      });

      const mockContext = {
        timeoutMs: 5000,
        dispatchProbe: async () => {
          return {
            status: 500,
            statusText: 'Server Error',
            headers: { 'content-type': 'text/html' },
            text: 'Microsoft OLE DB Provider for ODBC Drivers error: ODBC Microsoft Access Driver Syntax error in string in query expression',
            wireBytesReceived: 250,
            decompressedBytes: 250,
            redirectHops: 0,
          };
        },
      };

      const findings = await rule.evaluate(page, mockContext);
      expect(findings.length).toBe(1);
      expect(findings[0]?.evidence.rdbms).toContain('Microsoft');
    });

    it('detects explicit PostgreSQL syntax error signature', async () => {
      const rule = new SqliAnomalyRule();
      const page = createMockCrawledPage({ url: 'https://example.com/users?id=5' });

      const mockContext = {
        timeoutMs: 5000,
        dispatchProbe: async () => {
          return {
            status: 500,
            statusText: 'Error',
            headers: { 'content-type': 'text/html' },
            text: 'org.postgresql.util.PSQLException: ERROR: syntax error at or near "\'"',
            wireBytesReceived: 200,
            decompressedBytes: 200,
            redirectHops: 0,
          };
        },
      };

      const findings = await rule.evaluate(page, mockContext);
      expect(findings.length).toBe(1);
      expect(findings[0]?.evidence.rdbms).toBe('PostgreSQL');
    });

    it('flags HTTP 500 status anomaly without explicit error text with LOW confidence', async () => {
      const rule = new SqliAnomalyRule();
      const page = createMockCrawledPage({
        url: 'https://example.com/api?id=1',
        status: 200,
        bodyText: '{"status":"ok"}',
      });

      const mockContext = {
        timeoutMs: 5000,
        dispatchProbe: async () => {
          return {
            status: 500,
            statusText: 'Internal Error',
            headers: { 'content-type': 'application/json' },
            text: '{"error":"An unexpected error occurred"}',
            wireBytesReceived: 100,
            decompressedBytes: 100,
            redirectHops: 0,
          };
        },
      };

      const findings = await rule.evaluate(page, mockContext);
      expect(findings.length).toBe(1);
      expect(findings[0]?.severity).toBe('MEDIUM');
      expect(findings[0]?.confidence).toBe('LOW');
    });

    it('suppresses finding when error was already present in baseline response (differential check)', async () => {
      const rule = new SqliAnomalyRule();
      const existingError = 'You have an error in your SQL syntax; pre-existing database error';
      const page = createMockCrawledPage({
        url: 'https://example.com/broken?id=1',
        status: 500,
        bodyText: existingError,
      });

      const mockContext = {
        timeoutMs: 5000,
        dispatchProbe: async () => {
          return {
            status: 500,
            statusText: 'Error',
            headers: { 'content-type': 'text/html' },
            text: existingError,
            wireBytesReceived: 200,
            decompressedBytes: 200,
            redirectHops: 0,
          };
        },
      };

      const findings = await rule.evaluate(page, mockContext);
      expect(findings.length).toBe(0);
    });

    it('proves zero destructive SQL commands (DROP, DELETE, UPDATE) are ever dispatched', async () => {
      const rule = new SqliAnomalyRule();
      const page = createMockCrawledPage({ url: 'https://example.com/test?id=42' });

      const dispatchedUrls: string[] = [];
      const mockContext = {
        timeoutMs: 5000,
        dispatchProbe: async (url: string) => {
          dispatchedUrls.push(url);
          return null;
        },
      };

      await rule.evaluate(page, mockContext);
      expect(dispatchedUrls.length).toBeGreaterThan(0);
      for (const url of dispatchedUrls) {
        expect(url).not.toMatch(/drop|delete|update|insert|sleep|benchmark/i);
      }
    });
  });

  // =========================================================================
  // SECTION 4: Open Redirect Canary Rule Tests
  // =========================================================================
  describe('4. Open Redirect Canary Rule (open-redirect-rule.ts)', () => {
    it('detects unvalidated external redirection to canary target on 302 response', async () => {
      const rule = new OpenRedirectRule();
      const page = createMockCrawledPage({
        url: 'https://example.com/login?redirect=/dashboard',
      });

      let requestedUrl = '';
      const mockContext = {
        timeoutMs: 5000,
        dispatchProbe: async (url: string) => {
          requestedUrl = url;
          const u = new URL(url);
          const redir = u.searchParams.get('redirect') || '';
          return {
            status: 302,
            statusText: 'Found',
            headers: {
              'location': redir,
              'content-type': 'text/html',
            },
            text: '',
            wireBytesReceived: 100,
            decompressedBytes: 100,
            redirectHops: 0,
          };
        },
      };

      const findings = await rule.evaluate(page, mockContext);
      expect(findings.length).toBe(1);
      const f = findings[0]!;
      expect(f.ruleId).toBe(RULE_ACTIVE_OPEN_REDIRECT);
      expect(f.vulnerabilityType).toBe('OPEN_REDIRECT_UNVALIDATED');
      expect(f.severity).toBe('MEDIUM');
      expect(f.confidence).toBe('CONFIRMED');
      expect(f.evidence.locationHeader).toContain('vltx_canary_');
      expect(requestedUrl).toContain('redirect=');
    });

    it('does NOT flag safe relative redirection (e.g. /home)', async () => {
      const rule = new OpenRedirectRule();
      const page = createMockCrawledPage({ url: 'https://example.com/auth?redirect=/home' });

      const mockContext = {
        timeoutMs: 5000,
        dispatchProbe: async () => {
          return {
            status: 302,
            statusText: 'Found',
            headers: { 'location': '/home' },
            text: '',
            wireBytesReceived: 100,
            decompressedBytes: 100,
            redirectHops: 0,
          };
        },
      };

      const findings = await rule.evaluate(page, mockContext);
      expect(findings.length).toBe(0);
    });

    it('does NOT flag same-origin redirection', async () => {
      const rule = new OpenRedirectRule();
      const page = createMockCrawledPage({ url: 'https://example.com/auth-return' });

      const mockContext = {
        timeoutMs: 5000,
        dispatchProbe: async () => {
          return {
            status: 302,
            statusText: 'Found',
            headers: { 'location': 'https://example.com/login' },
            text: '',
            wireBytesReceived: 100,
            decompressedBytes: 100,
            redirectHops: 0,
          };
        },
      };

      const findings = await rule.evaluate(page, mockContext);
      expect(findings.length).toBe(0);
    });

    it('rejects lookalike hostnames (e.g. vltx-canary.invalid.attacker.com)', async () => {
      const rule = new OpenRedirectRule();
      const page = createMockCrawledPage({ url: 'https://example.com/redir?redirect=val' });

      const mockContext = {
        timeoutMs: 5000,
        dispatchProbe: async (url: string) => {
          const u = new URL(url);
          const canaryTarget = u.searchParams.get('redirect') || '';
          const canaryPath = new URL(canaryTarget).pathname;
          // Lookalike attacker domain
          return {
            status: 302,
            statusText: 'Found',
            headers: { 'location': `https://vltx-canary.invalid.attacker.com${canaryPath}` },
            text: '',
            wireBytesReceived: 100,
            decompressedBytes: 100,
            redirectHops: 0,
          };
        },
      };

      const findings = await rule.evaluate(page, mockContext);
      expect(findings.length).toBe(0);
    });

    it('rejects canary destination embedded in another URL query parameter', async () => {
      const rule = new OpenRedirectRule();
      const page = createMockCrawledPage({ url: 'https://example.com/redir?redirect=val' });

      const mockContext = {
        timeoutMs: 5000,
        dispatchProbe: async (url: string) => {
          const u = new URL(url);
          const canaryTarget = u.searchParams.get('redirect') || '';
          // Canary is only a parameter value to a safe third party
          return {
            status: 302,
            statusText: 'Found',
            headers: { 'location': `https://safe-oauth-provider.com/login?returnUrl=${encodeURIComponent(canaryTarget)}` },
            text: '',
            wireBytesReceived: 100,
            decompressedBytes: 100,
            redirectHops: 0,
          };
        },
      };

      const findings = await rule.evaluate(page, mockContext);
      expect(findings.length).toBe(0);
    });

    it('rejects redirects with different scheme or port from the canary destination', async () => {
      const rule = new OpenRedirectRule();
      const page = createMockCrawledPage({ url: 'https://example.com/redir?redirect=val' });

      const mockContextScheme = {
        timeoutMs: 5000,
        dispatchProbe: async (url: string) => {
          const u = new URL(url);
          const canaryTarget = u.searchParams.get('redirect') || '';
          const p = new URL(canaryTarget);
          return {
            status: 302,
            statusText: 'Found',
            headers: { 'location': `http://${p.hostname}${p.pathname}` }, // Insecure HTTP scheme
            text: '',
            wireBytesReceived: 100,
            decompressedBytes: 100,
            redirectHops: 0,
          };
        },
      };

      expect((await rule.evaluate(page, mockContextScheme)).length).toBe(0);

      const mockContextPort = {
        timeoutMs: 5000,
        dispatchProbe: async (url: string) => {
          const u = new URL(url);
          const canaryTarget = u.searchParams.get('redirect') || '';
          const p = new URL(canaryTarget);
          return {
            status: 302,
            statusText: 'Found',
            headers: { 'location': `https://${p.hostname}:8443${p.pathname}` }, // Different port
            text: '',
            wireBytesReceived: 100,
            decompressedBytes: 100,
            redirectHops: 0,
          };
        },
      };

      expect((await rule.evaluate(page, mockContextPort)).length).toBe(0);
    });

    it('rejects external redirects that do not contain the canary destination', async () => {
      const rule = new OpenRedirectRule();
      const page = createMockCrawledPage({ url: 'https://example.com/redir?redirect=val' });

      const mockContext = {
        timeoutMs: 5000,
        dispatchProbe: async () => {
          return {
            status: 302,
            statusText: 'Found',
            headers: { 'location': 'https://google.com/' },
            text: '',
            wireBytesReceived: 100,
            decompressedBytes: 100,
            redirectHops: 0,
          };
        },
      };

      const findings = await rule.evaluate(page, mockContext);
      expect(findings.length).toBe(0);
    });
  });

  // =========================================================================
  // SECTION 5: Path Traversal Canary Rule Tests
  // =========================================================================
  describe('5. Path Traversal Canary Rule (path-traversal-rule.ts)', () => {
    it('detects unhandled path traversal error signatures', async () => {
      const rule = new PathTraversalRule();
      const page = createMockCrawledPage({
        url: 'https://example.com/download?file=report.pdf',
        bodyText: 'Download page',
      });

      const mockContext = {
        timeoutMs: 5000,
        dispatchProbe: async (url: string) => {
          return {
            status: 500,
            statusText: 'Server Error',
            headers: { 'content-type': 'text/html' },
            text: 'Warning: open_basedir restriction in effect. File(/etc/nonexistent_canary_probe) is not within allowed path',
            wireBytesReceived: 200,
            decompressedBytes: 200,
            redirectHops: 0,
          };
        },
      };

      const findings = await rule.evaluate(page, mockContext);
      expect(findings.length).toBe(1);
      const f = findings[0]!;
      expect(f.ruleId).toBe(RULE_ACTIVE_PATH_TRAVERSAL);
      expect(f.vulnerabilityType).toBe('PATH_TRAVERSAL_ANOMALY');
      expect(f.severity).toBe('HIGH');
      expect(f.confidence).toBe('HIGH');
      expect(f.evidence.detectedPlatform).toBe('PHP');
    });

    it('detects Java FileNotFoundException traversal signature', async () => {
      const rule = new PathTraversalRule();
      const page = createMockCrawledPage({ url: 'https://example.com/docs?path=intro' });

      const mockContext = {
        timeoutMs: 5000,
        dispatchProbe: async () => {
          return {
            status: 500,
            statusText: 'Error',
            headers: { 'content-type': 'text/plain' },
            text: 'java.io.FileNotFoundException: /var/app/../../../../etc/nonexistent_canary_probe',
            wireBytesReceived: 200,
            decompressedBytes: 200,
            redirectHops: 0,
          };
        },
      };

      const findings = await rule.evaluate(page, mockContext);
      expect(findings.length).toBe(1);
      expect(findings[0]?.evidence.detectedPlatform).toBe('Java');
    });

    it('proves only non-existent canary paths are probed', async () => {
      const rule = new PathTraversalRule();
      const page = createMockCrawledPage({ url: 'https://example.com/view?doc=readme' });

      const dispatchedUrls: string[] = [];
      const mockContext = {
        timeoutMs: 5000,
        dispatchProbe: async (url: string) => {
          dispatchedUrls.push(url);
          return null;
        },
      };

      await rule.evaluate(page, mockContext);
      expect(dispatchedUrls.length).toBeGreaterThan(0);
      for (const url of dispatchedUrls) {
        expect(url).toContain('nonexistent_canary_probe');
      }
    });
  });

  // =========================================================================
  // SECTION 6: ActiveAnalyzer End-to-End Orchestration & Integration Tests
  // =========================================================================
  describe('6. ActiveAnalyzer Integration with Real Local HTTP Server', () => {
    let testServer: http.Server;
    let testPort: number;

    beforeAll(async () => {
      testServer = http.createServer((req, res) => {
        const reqUrl = req.url || '/';
        const parsed = new URL(reqUrl, 'http://127.0.0.1');

        if (parsed.pathname === '/search') {
          const q = parsed.searchParams.get('q') || '';
          if (q.includes('vltxcanary_')) {
            // Reflect canary unencoded
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
            res.end(`<html><body>Results for: ${q}</body></html>`);
            return;
          }
        }

        if (parsed.pathname === '/items') {
          const id = parsed.searchParams.get('id') || '';
          if (id.includes("'")) {
            // Trigger SQL error
            res.writeHead(500, { 'Content-Type': 'text/html; charset=utf-8' });
            res.end('<html>You have an error in your SQL syntax near id</html>');
            return;
          }
        }

        if (parsed.pathname === '/redirect') {
          const target = parsed.searchParams.get('redirect');
          if (target && target.startsWith('https://example.com/vltx_canary_')) {
            res.writeHead(302, { Location: target });
            res.end();
            return;
          }
        }

        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end('<html><body>Default test response</body></html>');
      });

      await new Promise<void>((resolve) => {
        testServer.listen(0, '127.0.0.1', () => {
          const addr = testServer.address() as net.AddressInfo;
          testPort = addr.port;
          resolve();
        });
      });
    });

    afterAll(async () => {
      await new Promise<void>((resolve) => testServer.close(() => resolve()));
    });

    it('executes active security probes through SafeHttpClient when explicitly enabled', async () => {
      const client = new SafeHttpClient({ allowLoopbackForTesting: true });
      const context = await createTestScanContext({
        primaryDomain: '127.0.0.1',
        allowedPorts: [testPort],
        allowedMethods: ['GET', 'HEAD'],
      });

      const analyzer = new ActiveAnalyzer({
        client,
        context,
        enabled: true, // Explicitly opted in
      });

      expect(analyzer.isEnabled()).toBe(true);
      expect(analyzer.getActiveRuleIds()).toEqual([
        RULE_ACTIVE_XSS_CANARY,
        RULE_ACTIVE_SQLI_ANOMALY,
        RULE_ACTIVE_OPEN_REDIRECT,
        RULE_ACTIVE_PATH_TRAVERSAL,
      ]);

      const pages: CrawledPage[] = [
        createMockCrawledPage({
          url: `http://127.0.0.1:${testPort}/search?q=test`,
        }),
        createMockCrawledPage({
          url: `http://127.0.0.1:${testPort}/items?id=1`,
        }),
        createMockCrawledPage({
          url: `http://127.0.0.1:${testPort}/redirect?redirect=/home`,
        }),
      ];

      const findings = await analyzer.analyze(pages);
      expect(findings.length).toBeGreaterThanOrEqual(2);

      // Verify XSS finding was discovered (reported with LOW confidence since alphanumeric only)
      const xssFinding = findings.find((f) => f.vulnerabilityType === 'CROSS_SITE_SCRIPTING_REFLECTED');
      expect(xssFinding).toBeDefined();
      expect(xssFinding?.confidence).toBe('LOW');

      // Verify SQLi finding was discovered
      const sqliFinding = findings.find((f) => f.vulnerabilityType === 'SQL_INJECTION_SYNTAX_ANOMALY');
      expect(sqliFinding).toBeDefined();
      expect(sqliFinding?.confidence).toBe('HIGH');

      // Verify Open Redirect finding was discovered
      const redirectFinding = findings.find((f) => f.vulnerabilityType === 'OPEN_REDIRECT_UNVALIDATED');
      expect(redirectFinding).toBeDefined();

      expect(analyzer.getTotalRequestsDispatched()).toBeGreaterThan(0);
    });

    it('returns zero findings and makes ZERO network requests when active probing is disabled', async () => {
      const client = new SafeHttpClient({ allowLoopbackForTesting: true });
      const requestSpy = vi.spyOn(client, 'request');

      const context = await createTestScanContext({
        primaryDomain: '127.0.0.1',
        allowedPorts: [testPort],
      });

      const analyzer = new ActiveAnalyzer({
        client,
        context,
        enabled: false, // Explicitly disabled (default)
      });

      const page = createMockCrawledPage({
        url: `http://127.0.0.1:${testPort}/search?q=test`,
      });

      const findings = await analyzer.analyze(page);
      expect(findings.length).toBe(0);
      expect(requestSpy).not.toHaveBeenCalled();
      expect(analyzer.getTotalRequestsDispatched()).toBe(0);
    });

    it('aborts active probes immediately when AbortSignal is fired', async () => {
      const client = new SafeHttpClient({ allowLoopbackForTesting: true });
      const context = await createTestScanContext({
        primaryDomain: '127.0.0.1',
        allowedPorts: [testPort],
      });

      const controller = new AbortController();
      controller.abort(); // Cancelled before analysis

      const analyzer = new ActiveAnalyzer({
        client,
        context,
        enabled: true,
        signal: controller.signal,
      });

      const page = createMockCrawledPage({
        url: `http://127.0.0.1:${testPort}/search?q=test`,
      });

      const findings = await analyzer.analyze(page);
      expect(findings.length).toBe(0);
      expect(analyzer.getTotalRequestsDispatched()).toBe(0);
    });

    it('isolates rule exceptions without terminating remaining active rules', async () => {
      const client = new SafeHttpClient({ allowLoopbackForTesting: true });
      const context = await createTestScanContext({
        primaryDomain: '127.0.0.1',
        allowedPorts: [testPort],
      });

      // Custom faulty rule that throws an exception
      const faultyRule = {
        id: 'FAULTY_RULE',
        name: 'Faulty Rule',
        description: 'Throws error',
        evaluate: async () => {
          throw new Error('Database connection crashed in rule');
        },
      };

      const validRule = new XssCanaryRule();

      const analyzer = new ActiveAnalyzer({
        client,
        context,
        enabled: true,
        rules: [faultyRule as any, validRule],
      });

      const page = createMockCrawledPage({
        url: `http://127.0.0.1:${testPort}/search?q=test`,
      });

      // Does not throw, valid rule completes cleanly
      const findings = await analyzer.analyze(page);
      expect(findings.some((f) => f.ruleId === RULE_ACTIVE_XSS_CANARY)).toBe(true);
    });

    it('respects explicitly provided empty rules array (rules: []) by registering zero active rules', async () => {
      const client = new SafeHttpClient({ allowLoopbackForTesting: true });
      const context = await createTestScanContext({
        primaryDomain: '127.0.0.1',
        allowedPorts: [testPort],
      });

      const analyzer = new ActiveAnalyzer({
        client,
        context,
        enabled: true,
        rules: [],
      });

      expect(analyzer.getActiveRuleIds()).toEqual([]);
      const page = createMockCrawledPage({
        url: `http://127.0.0.1:${testPort}/search?q=test`,
      });
      const findings = await analyzer.analyze(page);
      expect(findings).toEqual([]);
      expect(analyzer.getTotalRequestsDispatched()).toBe(0);
    });

    it('respects explicitly provided empty enabledRuleIds array (enabledRuleIds: []) by running zero rules', async () => {
      const client = new SafeHttpClient({ allowLoopbackForTesting: true });
      const context = await createTestScanContext({
        primaryDomain: '127.0.0.1',
        allowedPorts: [testPort],
      });

      const analyzer = new ActiveAnalyzer({
        client,
        context,
        enabled: true,
        enabledRuleIds: [],
      });

      expect(analyzer.getActiveRuleIds()).toEqual([]);
      const page = createMockCrawledPage({
        url: `http://127.0.0.1:${testPort}/search?q=test`,
      });
      const findings = await analyzer.analyze(page);
      expect(findings).toEqual([]);
      expect(analyzer.getTotalRequestsDispatched()).toBe(0);
    });

    it('eliminates client and context capability bypass: ActiveRuleExecutionContext only provides dispatchProbe', async () => {
      const client = new SafeHttpClient({ allowLoopbackForTesting: true });
      const context = await createTestScanContext({
        primaryDomain: '127.0.0.1',
        allowedPorts: [testPort],
      });

      let observedContext: any = null;
      const probeInspectorRule = {
        id: 'RULE_PROBE_INSPECTOR',
        name: 'Probe Inspector',
        description: 'Verifies no transport capabilities are leaked',
        evaluate: async (_page: CrawledPage, ruleContext: ActiveRuleExecutionContext) => {
          observedContext = ruleContext;
          // Verify rule can dispatch probe safely through the safety gate
          await ruleContext.dispatchProbe(`http://127.0.0.1:${testPort}/search?q=safe_test`);
          return [];
        },
      };

      const analyzer = new ActiveAnalyzer({
        client,
        context,
        enabled: true,
        rules: [probeInspectorRule as any],
      });

      const page = createMockCrawledPage({
        url: `http://127.0.0.1:${testPort}/search?q=test`,
      });

      await analyzer.analyze(page);

      expect(observedContext).toBeDefined();
      expect(observedContext.client).toBeUndefined();
      expect(observedContext.context).toBeUndefined();
      expect(typeof observedContext.dispatchProbe).toBe('function');
      expect(typeof observedContext.timeoutMs).toBe('number');
    });

    it('skips active probing when page URL matches potentially mutating GET routes', async () => {
      const client = new SafeHttpClient({ allowLoopbackForTesting: true });
      const context = await createTestScanContext({
        primaryDomain: '127.0.0.1',
        allowedPorts: [testPort],
      });

      const analyzer = new ActiveAnalyzer({
        client,
        context,
        enabled: true,
      });

      const logoutPage = createMockCrawledPage({
        url: `http://127.0.0.1:${testPort}/logout?redirect=home`,
      });

      const findings = await analyzer.analyze(logoutPage);
      expect(findings.length).toBe(0);
      expect(analyzer.getTotalRequestsDispatched()).toBe(0);
    });

    it('guarantees that passive analyzer still makes ZERO network requests alongside active analyzer', async () => {
      const passiveAnalyzer = new PassiveAnalyzer();
      const page = createMockCrawledPage({
        url: 'https://example.com/secure',
        headers: {
          server: 'nginx/1.18.0',
        },
        bodyText: '<html>Some static body text</html>',
      });

      const originalFetch = globalThis.fetch;
      const fetchSpy = vi.fn();
      globalThis.fetch = fetchSpy as any;

      try {
        const passiveFindings = await passiveAnalyzer.analyze(page);
        expect(passiveFindings.length).toBeGreaterThan(0);
        expect(fetchSpy).not.toHaveBeenCalled();
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    it('strictly redacts sensitive credentials, tokens, and cookie values from headers', () => {
      const rawHeaders = {
        'authorization': 'Bearer secret-jwt-token-12345',
        'proxy-authorization': 'Basic dXNlcjpwYXNz',
        'cookie': 'session=abc123secret; tracker=xyz; user_id=42',
        'set-cookie': 'auth_token=super_secret_cookie_token; Path=/; Secure; HttpOnly',
        'content-type': 'application/json',
        'x-custom-header': 'normal-value',
      };

      const sanitized = sanitizeHeaders(rawHeaders);
      expect(sanitized['authorization']).toBe('[REDACTED]');
      expect(sanitized['proxy-authorization']).toBe('[REDACTED]');
      expect(sanitized['cookie']).toContain('session=[REDACTED]');
      expect(sanitized['cookie']).toContain('tracker=[REDACTED]');
      expect(sanitized['cookie']).not.toContain('abc123secret');
      expect(sanitized['set-cookie']).toContain('auth_token=[REDACTED]');
      expect(sanitized['set-cookie']).not.toContain('super_secret_cookie_token');
      expect(sanitized['content-type']).toBe('application/json');
      expect(sanitized['x-custom-header']).toBe('normal-value');
    });

    it('strictly proves ZERO network requests across all APIs when active probing is unauthorized or blocked', async () => {
      const client = new SafeHttpClient({ allowLoopbackForTesting: true });
      const context = await createTestScanContext({
        primaryDomain: '127.0.0.1',
        allowedPorts: [testPort],
      });

      const analyzer = new ActiveAnalyzer({
        client,
        context,
        enabled: false, // Disabled by default
      });

      const originalFetch = globalThis.fetch;
      const originalHttpRequest = http.request;
      const originalHttpGet = http.get;
      const originalNetConnect = net.connect;
      const originalSafeRequest = SafeHttpClient.prototype.request;

      const fetchSpy = vi.fn();
      const httpReqSpy = vi.fn();
      const httpGetSpy = vi.fn();
      const netConnSpy = vi.fn();
      const safeReqSpy = vi.fn();

      globalThis.fetch = fetchSpy as any;
      (http as any).request = httpReqSpy;
      (http as any).get = httpGetSpy;
      (net as any).connect = netConnSpy;
      SafeHttpClient.prototype.request = safeReqSpy as any;

      try {
        const page = createMockCrawledPage({
          url: `http://127.0.0.1:${testPort}/search?q=test`,
        });

        const findings = await analyzer.analyze(page);
        expect(findings.length).toBe(0);

        // Strict negative guarantee: Zero calls across ALL network transport layers
        expect(fetchSpy).not.toHaveBeenCalled();
        expect(httpReqSpy).not.toHaveBeenCalled();
        expect(httpGetSpy).not.toHaveBeenCalled();
        expect(netConnSpy).not.toHaveBeenCalled();
        expect(safeReqSpy).not.toHaveBeenCalled();
      } finally {
        globalThis.fetch = originalFetch;
        http.request = originalHttpRequest;
        http.get = originalHttpGet;
        net.connect = originalNetConnect;
        SafeHttpClient.prototype.request = originalSafeRequest;
      }
    });
  });
});
