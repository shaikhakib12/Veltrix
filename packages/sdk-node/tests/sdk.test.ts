import { describe, it, expect, vi } from 'vitest';
import express from 'express';
import request from 'supertest';
import { VeltrixClient, veltrixMiddleware, RingBuffer, DataSanitizer } from '../src/index.js';

describe('Veltrix Node.js SDK & Express Middleware (TASK-604)', () => {
  describe('1. RingBuffer Bounded Capacity & Drop-Oldest Policy', () => {
    it('enforces maximum item limit and drops oldest item upon overflow', () => {
      const buffer = new RingBuffer(3, 1024 * 1024);

      const event1 = {
        eventId: '00000000-0000-0000-0000-000000000001',
        orgId: 'org-test',
        timestamp: new Date().toISOString(),
        eventType: 'web.request.normal',
        severity: 'LOW' as const,
        category: 'NETWORK' as const,
        sourceIp: '1.1.1.1',
        sourceSystem: 'test',
      };
      const event2 = { ...event1, eventId: '00000000-0000-0000-0000-000000000002' };
      const event3 = { ...event1, eventId: '00000000-0000-0000-0000-000000000003' };
      const event4 = { ...event1, eventId: '00000000-0000-0000-0000-000000000004' };

      expect(buffer.push(event1)).toBe(true);
      expect(buffer.push(event2)).toBe(true);
      expect(buffer.push(event3)).toBe(true);
      expect(buffer.size()).toBe(3);
      expect(buffer.getDroppedCount()).toBe(0);

      // Pushing 4th item triggers drop-oldest policy
      expect(buffer.push(event4)).toBe(true);
      expect(buffer.size()).toBe(3);
      expect(buffer.getDroppedCount()).toBe(1);

      // Verify that event1 was dropped and event2, event3, event4 remain
      const drained = buffer.drain(10);
      expect(drained.length).toBe(3);
      expect(drained[0]!.eventId).toBe('00000000-0000-0000-0000-000000000002');
      expect(drained[1]!.eventId).toBe('00000000-0000-0000-0000-000000000003');
      expect(drained[2]!.eventId).toBe('00000000-0000-0000-0000-000000000004');
    });

    it('enforces maximum byte ceiling and tracks memory usage', () => {
      // 300 bytes max ceiling
      const buffer = new RingBuffer(100, 300);

      const event = {
        eventId: '00000000-0000-0000-0000-000000000001',
        orgId: 'org-test',
        timestamp: new Date().toISOString(),
        eventType: 'web.request.normal',
        severity: 'LOW' as const,
        category: 'NETWORK' as const,
        sourceIp: '1.1.1.1',
        sourceSystem: 'test',
        metadata: {
          hugeField: 'x'.repeat(500), // Exceeds 300 bytes limit
        },
      };

      const pushed = buffer.push(event);
      expect(pushed).toBe(false);
      expect(buffer.getDroppedCount()).toBe(1);
      expect(buffer.size()).toBe(0);
    });
  });

  describe('2. Sensitive Parameter Redaction', () => {
    it('redacts sensitive fields and bearer tokens recursively', () => {
      const sanitizer = new DataSanitizer(['customSecret']);

      const raw = {
        username: 'alice',
        password: 'SuperSecretPassword123!',
        token: 'eyJh...',
        authorization: 'Bearer secret_jwt_token',
        nested: {
          apiKey: 'live_key_99',
          creditCard: '4111222233334444',
          customSecret: 'internal_val',
          safeField: 'visible_data',
        },
      };

      const cleaned = sanitizer.sanitizeObject(raw);

      expect(cleaned.username).toBe('alice');
      expect(cleaned.password).toBe('[REDACTED]');
      expect(cleaned.token).toBe('[REDACTED]');
      expect(cleaned.authorization).toBe('[REDACTED]');
      expect(cleaned.nested.apiKey).toBe('[REDACTED]');
      expect(cleaned.nested.creditCard).toBe('[REDACTED]');
      expect(cleaned.nested.customSecret).toBe('[REDACTED]');
      expect(cleaned.nested.safeField).toBe('visible_data');
    });
  });

  describe('3. VeltrixClient Batching, Retry & Stable Idempotency', () => {
    it('batches events and dispatches to endpoint with stable idempotency keys', async () => {
      let dispatchedRequests: Array<{ url: string; headers: Record<string, string>; body: any }> = [];

      const mockFetcher = async (url: string, init?: RequestInit): Promise<Response> => {
        dispatchedRequests.push({
          url,
          headers: (init?.headers as Record<string, string>) || {},
          body: JSON.parse(init?.body as string),
        });

        return new Response(JSON.stringify({ success: true, accepted: 1 }), {
          status: 202,
          headers: { 'Content-Type': 'application/json' },
        });
      };

      const client = new VeltrixClient({
        apiKey: 'vltx_live_testkey123',
        orgId: 'org-test-enterprise',
        siteId: 'site-test-01',
        endpoint: 'https://telemetry.mock.veltrix.io',
        bufferFlushIntervalMs: 0, // Manual flush
        fetcher: mockFetcher,
      });

      client.recordEvent({
        eventType: 'web.request.normal',
        severity: 'LOW',
        category: 'NETWORK',
        sourceIp: '198.51.100.10',
        metadata: {
          requestUri: '/api/v1/health',
          httpStatus: 200,
        },
      });

      await client.flush();

      expect(dispatchedRequests.length).toBe(1);
      const req = dispatchedRequests[0]!;
      expect(req.url).toBe('https://telemetry.mock.veltrix.io/api/v1/events');
      expect(req.headers['x-api-key']).toBe('vltx_live_testkey123');
      expect(req.headers['x-organization-id']).toBe('org-test-enterprise');
      expect(req.body.events.length).toBe(1);

      const event = req.body.events[0];
      expect(event.orgId).toBe('org-test-enterprise');
      expect(event.metadata.siteId).toBe('site-test-01');
      expect(event.idempotencyKey).toBe(event.eventId); // Stable idempotency key
    });

    it('retries with exponential backoff on transient 500 error and reuses eventId', async () => {
      let callCount = 0;
      const seenEventIds: string[] = [];

      const mockFetcher = async (_url: string, init?: RequestInit): Promise<Response> => {
        callCount++;
        const parsed = JSON.parse(init?.body as string);
        seenEventIds.push(parsed.events[0].eventId);

        if (callCount === 1) {
          // First attempt fails with 500
          return new Response('Internal Server Error', { status: 500 });
        }
        // Second attempt succeeds
        return new Response(JSON.stringify({ success: true }), { status: 202 });
      };

      const client = new VeltrixClient({
        apiKey: 'vltx_live_retry_test',
        orgId: 'org-retry',
        endpoint: 'https://mock.api',
        bufferFlushIntervalMs: 0,
        maxRetries: 2,
        baseBackoffMs: 10, // Fast backoff for tests
        fetcher: mockFetcher,
      });

      client.recordEvent({
        eventType: 'web.request.normal',
        severity: 'LOW',
        category: 'NETWORK',
        sourceIp: '1.2.3.4',
      });

      await client.flush();

      expect(callCount).toBe(2);
      expect(seenEventIds.length).toBe(2);
      // Verify stable eventId across retries to prevent duplicate persistence in DynamoDB
      expect(seenEventIds[0]).toBe(seenEventIds[1]);

      const health = client.getHealth();
      expect(health.status).toBe('HEALTHY');
      expect(health.eventsSent).toBe(1);
    });
  });

  describe('4. Express Middleware Non-Blocking Lifecycle', () => {
    it('does not delay the host request pipeline and correctly records web telemetry', async () => {
      const recordedEvents: any[] = [];

      const mockFetcher = async (_url: string, init?: RequestInit): Promise<Response> => {
        const body = JSON.parse(init?.body as string);
        recordedEvents.push(...body.events);
        return new Response(JSON.stringify({ success: true }), { status: 202 });
      };

      const client = new VeltrixClient({
        apiKey: 'vltx_live_mw_test',
        orgId: 'org-middleware',
        endpoint: 'https://mock.api',
        bufferFlushIntervalMs: 0,
        fetcher: mockFetcher,
      });

      const app = express();
      app.use(express.json());
      app.use(veltrixMiddleware(client));

      app.get('/api/search', (req, res) => {
        res.status(200).json({ query: req.query.q });
      });

      app.post('/api/admin', (_req, res) => {
        res.status(403).json({ error: 'Forbidden' });
      });

      // 1. Benign request
      const res1 = await request(app).get('/api/search?q=shoes');
      expect(res1.status).toBe(200);

      // 2. SQL injection attempt
      const res2 = await request(app).get("/api/search?q=1' UNION SELECT username,password FROM users--");
      expect(res2.status).toBe(200);

      // 3. Path traversal attempt
      const res3 = await request(app).get('/api/search?q=../../etc/passwd');
      expect(res3.status).toBe(200);

      // Flush telemetry to mock collector
      await client.flush();

      expect(recordedEvents.length).toBe(3);

      // Verify classification
      const normalEvent = recordedEvents.find((e) => e.eventType === 'web.request.normal');
      expect(normalEvent).toBeDefined();
      expect(normalEvent.metadata.httpStatus).toBe(200);

      const sqliEvent = recordedEvents.find((e) => e.eventType === 'web.attack.sqli');
      expect(sqliEvent).toBeDefined();
      expect(sqliEvent.severity).toBe('HIGH');
      expect(sqliEvent.metadata.matchedPatterns).toContain('SQLI_KEYWORDS');

      const traversalEvent = recordedEvents.find((e) => e.eventType === 'web.attack.traversal');
      expect(traversalEvent).toBeDefined();
      expect(traversalEvent.severity).toBe('HIGH');
      expect(traversalEvent.metadata.matchedPatterns).toContain('PATH_TRAVERSAL');
    });
  });
});
