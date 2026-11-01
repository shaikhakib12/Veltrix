import { randomUUID } from 'node:crypto';
import type { SecurityEvent } from '@veltrix/shared';
import type { VeltrixClientConfig, ClientHealthStats, AuthEventOptions, PartialWebSecurityEvent } from './types.js';
import { RingBuffer } from './buffer.js';
import { DataSanitizer } from './sanitizer.js';

export class VeltrixClient {
  private config: Required<VeltrixClientConfig>;
  private buffer: RingBuffer;
  private sanitizer: DataSanitizer;
  private flushTimer?: NodeJS.Timeout;
  private isFlushing = false;
  private isClosed = false;

  private eventsSent = 0;
  private failedDeliveries = 0;
  private lastSuccessAt?: string;
  private lastFailureAt?: string;
  private lastError?: string;

  constructor(config: VeltrixClientConfig) {
    this.config = {
      apiKey: config.apiKey,
      orgId: config.orgId,
      siteId: config.siteId || 'default-site',
      endpoint: (config.endpoint || 'http://localhost:3000').replace(/\/+$/, ''),
      maxBufferSize: config.maxBufferSize || 500,
      maxBufferSizeBytes: config.maxBufferSizeBytes || 5 * 1024 * 1024,
      bufferFlushIntervalMs: config.bufferFlushIntervalMs || 1000,
      maxRetries: config.maxRetries ?? 3,
      baseBackoffMs: config.baseBackoffMs || 1000,
      maxBackoffMs: config.maxBackoffMs || 8000,
      sanitizeParams: config.sanitizeParams || [],
      disabled: config.disabled ?? false,
      sourceSystem: config.sourceSystem || 'sdk:nodejs:express',
      fetcher: config.fetcher || globalThis.fetch,
    };

    this.buffer = new RingBuffer(this.config.maxBufferSize, this.config.maxBufferSizeBytes);
    this.sanitizer = new DataSanitizer(this.config.sanitizeParams);

    if (!this.config.disabled && this.config.bufferFlushIntervalMs > 0) {
      this.flushTimer = setInterval(() => {
        this.flush().catch(() => {});
      }, this.config.bufferFlushIntervalMs);
      if (this.flushTimer.unref) {
        this.flushTimer.unref();
      }
    }
  }

  recordEvent(event: PartialWebSecurityEvent): void {
    if (this.config.disabled || this.isClosed) return;

    const eventId = event.eventId || randomUUID();
    const timestamp = event.timestamp || new Date().toISOString();
    const idempotencyKey = event.idempotencyKey || eventId;

    const sanitizedMetadata = event.metadata
      ? (this.sanitizer.sanitizeObject(event.metadata) as Record<string, unknown>)
      : {};

    const fullEvent: SecurityEvent = {
      eventId,
      orgId: this.config.orgId,
      timestamp,
      eventType: event.eventType,
      severity: event.severity,
      category: event.category,
      sourceIp: event.sourceIp || '127.0.0.1',
      username: event.username,
      sourceSystem: event.sourceSystem || this.config.sourceSystem,
      metadata: {
        siteId: this.config.siteId,
        ...sanitizedMetadata,
      },
      idempotencyKey,
      isSimulated: false,
    };

    this.buffer.push(fullEvent);
  }

  recordAuthEvent(
    req: { ip?: string; socket?: { remoteAddress?: string }; headers?: Record<string, string | string[] | undefined> },
    opts: AuthEventOptions
  ): void {
    const clientIp =
      opts.ipAddress ||
      req.ip ||
      req.socket?.remoteAddress ||
      (Array.isArray(req.headers?.['x-forwarded-for'])
        ? req.headers?.['x-forwarded-for'][0]
        : (req.headers?.['x-forwarded-for'] as string)?.split(',')[0]?.trim()) ||
      '127.0.0.1';

    this.recordEvent({
      eventType: opts.success ? 'auth.login.success' : 'auth.login.failed',
      severity: opts.success ? 'LOW' : 'MEDIUM',
      category: 'AUTHENTICATION',
      sourceIp: clientIp,
      username: opts.username,
      metadata: {
        reason: opts.reason,
        userId: opts.userId,
      },
    });
  }

  async flush(): Promise<void> {
    if (this.config.disabled || this.isFlushing || this.buffer.size() === 0) {
      return;
    }

    this.isFlushing = true;

    try {
      while (this.buffer.size() > 0) {
        const batch = this.buffer.drain(100);
        if (batch.length === 0) break;

        await this.dispatchBatchWithRetry(batch);
      }
    } finally {
      this.isFlushing = false;
    }
  }

  private async dispatchBatchWithRetry(batch: SecurityEvent[]): Promise<void> {
    const url = `${this.config.endpoint}/api/v1/events`;
    const payload = JSON.stringify({ events: batch });

    let attempt = 0;
    while (attempt <= this.config.maxRetries) {
      try {
        const response = await this.config.fetcher(url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-api-key': this.config.apiKey,
            'x-organization-id': this.config.orgId,
          },
          body: payload,
        });

        if (response.ok || response.status === 202) {
          this.eventsSent += batch.length;
          this.lastSuccessAt = new Date().toISOString();
          return;
        }

        // If client error (4xx) other than rate limit (429), retrying won't help
        if (response.status >= 400 && response.status < 500 && response.status !== 429) {
          this.failedDeliveries += batch.length;
          this.lastFailureAt = new Date().toISOString();
          this.lastError = `HTTP ${response.status}`;
          return;
        }

        // Handle HTTP 429 (Rate Limited) with Retry-After header support
        let retryAfterMs: number | undefined;
        if (response.status === 429 && response.headers?.get) {
          const retryHeader = response.headers.get('retry-after');
          if (retryHeader) {
            const parsedSeconds = parseInt(retryHeader, 10);
            if (!isNaN(parsedSeconds) && parsedSeconds > 0) {
              retryAfterMs = parsedSeconds * 1000;
            }
          }
        }

        // Transient error (5xx or 429), retry with backoff
        const err = new Error(`HTTP ${response.status}`);
        if (retryAfterMs !== undefined) {
          (err as any).retryAfterMs = retryAfterMs;
        }
        throw err;
      } catch (err: unknown) {
        attempt++;
        const errMsg = err instanceof Error ? err.message : String(err);
        this.lastError = errMsg;

        if (attempt > this.config.maxRetries) {
          this.failedDeliveries += batch.length;
          this.lastFailureAt = new Date().toISOString();
          // Fail open: log warning but never throw out of SDK
          return;
        }

        // Use Retry-After duration if supplied, otherwise truncated exponential backoff with jitter
        const retryAfterMs = (err as { retryAfterMs?: number })?.retryAfterMs;
        let delayMs: number;
        if (typeof retryAfterMs === 'number' && retryAfterMs > 0) {
          delayMs = Math.min(this.config.maxBackoffMs, retryAfterMs);
        } else {
          const backoff = Math.min(
            this.config.maxBackoffMs,
            this.config.baseBackoffMs * Math.pow(2, attempt - 1)
          );
          delayMs = backoff * (0.8 + Math.random() * 0.4);
        }
        await new Promise((resolve) => setTimeout(resolve, delayMs));
      }
    }
  }

  getHealth(): ClientHealthStats {
    let status: ClientHealthStats['status'] = 'HEALTHY';
    if (this.failedDeliveries > 0 && this.eventsSent === 0) {
      status = 'DISCONNECTED';
    } else if (this.buffer.getDroppedCount() > 0 || this.failedDeliveries > 0) {
      status = 'DEGRADED';
    }

    return {
      status,
      eventsQueued: this.buffer.size(),
      eventsSent: this.eventsSent,
      eventsDropped: this.buffer.getDroppedCount(),
      failedDeliveries: this.failedDeliveries,
      lastSuccessAt: this.lastSuccessAt,
      lastFailureAt: this.lastFailureAt,
      lastError: this.lastError,
    };
  }

  async close(): Promise<void> {
    this.isClosed = true;
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = undefined;
    }
    await this.flush();
  }
}
