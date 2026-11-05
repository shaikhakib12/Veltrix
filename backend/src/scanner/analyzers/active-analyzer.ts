/**
 * VELTRIX Active Security Assessment Pipeline - ActiveAnalyzer (TASK-805)
 *
 * Coordinates non-destructive, controlled active security probes against discovered
 * application endpoints.
 *
 * Invariants:
 * - Disabled by default. Active probing requires explicit opt-in (enabled: true).
 * - Central ActiveSafetyGate enforces scope, host, method, and budget validation before any request.
 * - Uses SafeHttpClient strictly; never bypasses SSRF filters, DNS pinning, or port restrictions.
 * - Strictly non-destructive: uses benign canaries only (GET/HEAD methods only; never submits forms,
 *   never issues SQL DROP/DELETE, never uploads files).
 * - Isolates rule execution: an exception in one rule does not abort remaining probes.
 * - Concurrency and request budgets are strictly enforced.
 */

import type { CrawledPage, CrawlResult } from '../crawler/types.js';
import type {
  ActiveRuleInterface,
  ActiveRuleExecutionContext,
  ScannerFinding,
} from '../types.js';
import type {
  AuthorizedScanScopeContext,
  SafeHttpResponse,
} from '../transport/types.js';
import type { SafeHttpClient } from '../transport/safe-http-client.js';
import { ActiveSafetyGate, type ActiveSafetyGateOptions } from './active-safety-gate.js';
import { XssCanaryRule } from '../rules/active/xss-canary-rule.js';
import { SqliAnomalyRule } from '../rules/active/sqli-anomaly-rule.js';
import { OpenRedirectRule } from '../rules/active/open-redirect-rule.js';
import { PathTraversalRule } from '../rules/active/path-traversal-rule.js';

export interface ActiveAnalyzerOptions extends ActiveSafetyGateOptions {
  /**
   * SafeHttpClient egress transport instance.
   */
  readonly client: SafeHttpClient;

  /**
   * Authoritative capability-backed scan scope context.
   */
  readonly context: AuthorizedScanScopeContext;

  /**
   * Custom active rule instances. If omitted, defaults to all 4 standard active rules.
   */
  readonly rules?: readonly ActiveRuleInterface[];

  /**
   * Optional allowlist of rule IDs to execute.
   */
  readonly enabledRuleIds?: readonly string[];

  /**
   * Maximum concurrent probe requests (default: 2, max: 5).
   */
  readonly maxConcurrency?: number;

  /**
   * Timeout per active probe request in milliseconds (default: 5000, max: 10000).
   */
  readonly timeoutMs?: number;

  /**
   * Emergency abort / cancellation signal.
   */
  readonly signal?: AbortSignal;
}

class AsyncSemaphore {
  private current = 0;
  private readonly queue: Array<() => void> = [];

  constructor(private readonly max: number) {}

  public async acquire(): Promise<() => void> {
    if (this.current < this.max) {
      this.current++;
      let released = false;
      return () => {
        if (!released) {
          released = true;
          this.current--;
          const next = this.queue.shift();
          if (next) {
            this.current++;
            next();
          }
        }
      };
    }

    return new Promise<() => void>((resolve) => {
      this.queue.push(() => {
        let released = false;
        resolve(() => {
          if (!released) {
            released = true;
            this.current--;
            const next = this.queue.shift();
            if (next) {
              this.current++;
              next();
            }
          }
        });
      });
    });
  }
}

export class ActiveAnalyzer {
  public static readonly DEFAULT_CONCURRENCY = 2;
  public static readonly ABSOLUTE_MAX_CONCURRENCY = 5;
  public static readonly DEFAULT_TIMEOUT_MS = 5000;
  public static readonly ABSOLUTE_MAX_TIMEOUT_MS = 10000;

  private readonly client: SafeHttpClient;
  private readonly context: AuthorizedScanScopeContext;
  private readonly safetyGate: ActiveSafetyGate;
  private readonly rules: readonly ActiveRuleInterface[];
  private readonly timeoutMs: number;
  private readonly signal?: AbortSignal;
  private readonly semaphore: AsyncSemaphore;

  constructor(options: ActiveAnalyzerOptions) {
    if (!options.client) {
      throw new TypeError('ActiveAnalyzer requires a valid SafeHttpClient instance.');
    }
    if (!options.context) {
      throw new TypeError('ActiveAnalyzer requires an AuthorizedScanScopeContext.');
    }

    this.client = options.client;
    this.context = options.context;
    this.signal = options.signal;

    // Initialize Central Safety Gate
    this.safetyGate = new ActiveSafetyGate({
      enabled: options.enabled,
      maxTotalRequests: options.maxTotalRequests,
      maxRequestsPerEndpoint: options.maxRequestsPerEndpoint,
      allowedEndpointPrefixes: options.allowedEndpointPrefixes,
    });

    // Validate concurrency
    const rawConcurrency = options.maxConcurrency ?? ActiveAnalyzer.DEFAULT_CONCURRENCY;
    if (
      !Number.isInteger(rawConcurrency) ||
      rawConcurrency < 1 ||
      rawConcurrency > ActiveAnalyzer.ABSOLUTE_MAX_CONCURRENCY
    ) {
      throw new RangeError(
        `maxConcurrency must be an integer between 1 and ${ActiveAnalyzer.ABSOLUTE_MAX_CONCURRENCY} (received ${rawConcurrency}).`
      );
    }
    this.semaphore = new AsyncSemaphore(rawConcurrency);

    // Validate timeout
    const rawTimeout = options.timeoutMs ?? ActiveAnalyzer.DEFAULT_TIMEOUT_MS;
    if (
      !Number.isInteger(rawTimeout) ||
      rawTimeout < 100 ||
      rawTimeout > ActiveAnalyzer.ABSOLUTE_MAX_TIMEOUT_MS
    ) {
      throw new RangeError(
        `timeoutMs must be an integer between 100 and ${ActiveAnalyzer.ABSOLUTE_MAX_TIMEOUT_MS} (received ${rawTimeout}).`
      );
    }
    this.timeoutMs = rawTimeout;

    // Rules initialization:
    // If options.rules is explicitly provided (including empty []), respect caller configuration.
    // If omitted (undefined), defaults to the 4 canonical active rules.
    if (options.rules !== undefined) {
      this.rules = Object.freeze([...options.rules]);
    } else {
      this.rules = Object.freeze([
        new XssCanaryRule(),
        new SqliAnomalyRule(),
        new OpenRedirectRule(),
        new PathTraversalRule(),
      ]);
    }

    // If options.enabledRuleIds is explicitly provided (including empty []), respect caller filter.
    // If omitted (undefined), all rules remain active.
    if (options.enabledRuleIds !== undefined) {
      const allowedSet = new Set(options.enabledRuleIds);
      this.rules = Object.freeze(this.rules.filter((r) => allowedSet.has(r.id)));
    }
  }

  /**
   * Returns true only if active probing is explicitly enabled.
   */
  public isEnabled(): boolean {
    return this.safetyGate.isEnabled();
  }

  /**
   * Returns all active rule identifiers.
   */
  public getActiveRuleIds(): readonly string[] {
    return Object.freeze(this.rules.map((r) => r.id));
  }

  /**
   * Returns total probe requests dispatched so far.
   */
  public getTotalRequestsDispatched(): number {
    return this.safetyGate.getTotalRequestsDispatched();
  }

  /**
   * Dispatches a single controlled active probe request through the safety gate and semaphore.
   */
  public async dispatchProbe(
    targetUrl: string,
    options?: {
      readonly method?: 'GET' | 'HEAD';
      readonly headers?: Record<string, string>;
    }
  ): Promise<SafeHttpResponse | null> {
    try {
      // 1. Safety Gate check & budget acquisition
      this.safetyGate.checkAndAcquireProbeSlot(
        targetUrl,
        this.context,
        options?.method,
        this.signal
      );

      // 2. Concurrency limiting via semaphore
      const release = await this.semaphore.acquire();
      try {
        const res = await this.client.request(targetUrl, {
          context: this.context,
          method: options?.method || 'GET',
          headers: options?.headers,
          timeoutMs: this.timeoutMs,
          signal: this.signal,
          maxRedirects: 0, // Strict non-redirecting transport for active probe canary observation
        });
        return res;
      } catch {
        return null;
      } finally {
        release();
      }
    } catch {
      return null;
    }
  }

  /**
   * Executes active security analysis across crawled pages.
   */
  public async analyze(
    input: CrawledPage | readonly CrawledPage[] | CrawlResult
  ): Promise<readonly ScannerFinding[]> {
    // If active probing is not explicitly enabled, return immediately (0 requests)
    if (!this.isEnabled()) {
      return Object.freeze([]);
    }

    const pages = this.normalizeInput(input);
    const findings: ScannerFinding[] = [];
    const seenFindingKeys = new Set<string>();

    const executionContext: ActiveRuleExecutionContext = {
      timeoutMs: this.timeoutMs,
      signal: this.signal,
      dispatchProbe: this.dispatchProbe.bind(this),
    };

    for (const page of pages) {
      if (this.signal?.aborted) break;

      for (const rule of this.rules) {
        if (this.signal?.aborted) break;

        try {
          const ruleFindings = await rule.evaluate(page, executionContext, pages);
          for (const finding of ruleFindings) {
            const dedupeKey = this.computeDeduplicationKey(finding);
            if (!seenFindingKeys.has(dedupeKey)) {
              seenFindingKeys.add(dedupeKey);
              findings.push(finding);
            }
          }
        } catch {
          // Rule fault isolation: continue other rules even if one fails
        }
      }
    }

    return Object.freeze(findings);
  }

  private normalizeInput(
    input: CrawledPage | readonly CrawledPage[] | CrawlResult
  ): readonly CrawledPage[] {
    if (Array.isArray(input)) {
      return input;
    }
    if ('pages' in input && Array.isArray(input.pages)) {
      return input.pages;
    }
    return [input as CrawledPage];
  }

  private computeDeduplicationKey(finding: ScannerFinding): string {
    const ep = finding.endpoint || '';
    return `${finding.ruleId}:${finding.vulnerabilityType}:${finding.url}:${finding.title}:${ep}`;
  }
}

/**
 * Sanitizes headers for evidence storage to ensure sensitive tokens and cookie values
 * are not leaked into vulnerability reports or telemetry.
 */
export function sanitizeHeaders(
  headers?: Record<string, string>
): Record<string, string> {
  if (!headers) return {};
  const sanitized: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    const lower = k.toLowerCase();
    if (lower === 'authorization' || lower === 'proxy-authorization') {
      sanitized[k] = '[REDACTED]';
    } else if (lower === 'cookie') {
      sanitized[k] = v.replace(/([^=;\s]+)=([^;]+)/g, '$1=[REDACTED]');
    } else if (lower === 'set-cookie') {
      sanitized[k] = v.replace(/^([^=;\s]+)=([^;]+)/, '$1=[REDACTED]');
    } else {
      sanitized[k] = v;
    }
  }
  return Object.freeze(sanitized);
}

