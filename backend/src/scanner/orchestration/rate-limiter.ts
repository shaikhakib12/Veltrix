/**
 * VELTRIX Scanner Rate Limiter (Phase 8 - TASK-807)
 *
 * Implements a token-bucket rate limiter enforcing 1–20 requests per second (RPS)
 * with adaptive backoff on HTTP 429 (Too Many Requests) and 503 (Service Unavailable).
 */

export interface TokenBucketOptions {
  readonly rps: number; // 1 to 20
  readonly burstCapacity?: number;
}

export class TokenBucketRateLimiter {
  private readonly rps: number;
  private readonly capacity: number;
  private tokens: number;
  private lastRefillTimestamp: number;
  private backoffUntilMs: number = 0;

  public static readonly MIN_RPS = 1;
  public static readonly MAX_RPS = 20;
  public static readonly DEFAULT_RPS = 5;

  constructor(options?: TokenBucketOptions) {
    const rawRps = options?.rps ?? TokenBucketRateLimiter.DEFAULT_RPS;
    this.rps = Math.max(
      TokenBucketRateLimiter.MIN_RPS,
      Math.min(TokenBucketRateLimiter.MAX_RPS, Math.round(rawRps))
    );
    this.capacity = options?.burstCapacity ?? this.rps;
    this.tokens = this.capacity;
    this.lastRefillTimestamp = Date.now();
  }

  public getRps(): number {
    return this.rps;
  }

  /**
   * Refills tokens based on elapsed wall-clock time.
   */
  private refill(): void {
    const now = Date.now();
    const elapsedSeconds = (now - this.lastRefillTimestamp) / 1000;
    if (elapsedSeconds > 0) {
      this.tokens = Math.min(this.capacity, this.tokens + elapsedSeconds * this.rps);
      this.lastRefillTimestamp = now;
    }
  }

  /**
   * Acquires a token, waiting asynchronously if bucket is empty or backoff is active.
   */
  public async acquire(signal?: AbortSignal): Promise<void> {
    while (true) {
      if (signal?.aborted) {
        throw new Error('RateLimiter acquire cancelled by AbortSignal');
      }

      const now = Date.now();
      if (now < this.backoffUntilMs) {
        const waitMs = this.backoffUntilMs - now;
        await this.sleep(Math.min(waitMs, 500), signal);
        continue;
      }

      this.refill();

      if (this.tokens >= 1) {
        this.tokens -= 1;
        return;
      }

      // Calculate time needed to replenish 1 token
      const waitTimeMs = Math.ceil(((1 - this.tokens) / this.rps) * 1000);
      await this.sleep(Math.max(waitTimeMs, 50), signal);
    }
  }

  /**
   * Reports an HTTP 429 or 503 response from target to trigger temporary backoff.
   */
  public reportBackoff(retryAfterSeconds?: number): void {
    const backoffSeconds = retryAfterSeconds && retryAfterSeconds > 0 && retryAfterSeconds <= 60
      ? retryAfterSeconds
      : 2; // Default 2-second backoff
    this.backoffUntilMs = Date.now() + backoffSeconds * 1000;
  }

  private sleep(ms: number, signal?: AbortSignal): Promise<void> {
    return new Promise((resolve, reject) => {
      if (signal?.aborted) {
        return reject(new Error('RateLimiter sleep cancelled by AbortSignal'));
      }

      const timer = setTimeout(() => {
        cleanup();
        resolve();
      }, ms);

      const onAbort = () => {
        cleanup();
        reject(new Error('RateLimiter sleep cancelled by AbortSignal'));
      };

      const cleanup = () => {
        clearTimeout(timer);
        signal?.removeEventListener('abort', onAbort);
      };

      signal?.addEventListener('abort', onAbort, { once: true });
    });
  }
}
