/**
 * VELTRIX Central Active Probing Safety Gate (TASK-805)
 *
 * Enforces mandatory authorization, strict host/scope allowlisting, non-destructive
 * method restrictions (GET/HEAD only), budget limits, and emergency abort signals
 * BEFORE any active probe network request can be dispatched.
 *
 * Invariants:
 * - Active probing is DISABLED by default. Must be explicitly opted into via enabled: true.
 * - Requires an unforgeable, server-minted AuthorizedScanScopeContext.
 * - Requires site status === 'VERIFIED', !scanBlocked, and expiresAt > Date.now().
 * - Rejects any URL outside primaryDomain or approvedSubdomains.
 * - Rejects non-standard ports not explicitly authorized in the context.
 * - Rejects mandatory server excluded paths (/.env, /.git, /proc/, etc.) and context exclusions.
 * - Strictly prohibits mutating HTTP methods (POST, PUT, DELETE, PATCH, etc.).
 * - Enforces aggregate session request budget and per-endpoint request budget.
 * - Any violation fails closed immediately with ZERO network requests.
 *
 * SECURITY ARCHITECTURE & LIMITATION DISCLOSURE:
 * - Pattern-based dangerous-route blocking is an operational defense-in-depth heuristic, NOT
 *   an absolute guarantee against state-altering or destructive GET endpoints.
 * - HTTP and REST web applications can theoretically bind arbitrary mutations, state transitions,
 *   or transactions to GET routes (e.g. /approve?id=123, /confirm, or custom API endpoints) that do
 *   not match known keyword patterns.
 * - Route pattern matching mitigates accidental triggering of conventional operational endpoints
 *   (/logout, /delete, /destroy, /reset-password, /checkout, etc.), but cannot guarantee that all
 *   unlisted GET requests are safe or idempotent.
 * - For environments where zero-risk active assessment is required, the architecture supports an
 *   explicit server-controlled endpoint allowlist (allowedEndpointPrefixes). Client inputs cannot
 *   expand or self-authorize endpoints.
 */

import path from 'node:path';
import { isTrustedScopeContext, SERVER_MANDATORY_EXCLUDED_PATHS } from '../transport/context-authority.js';
import {
  type AuthorizedScanScopeContext,
  SafeTransportError,
  isBlockedInternalPort,
} from '../transport/types.js';

/**
 * Maximum number of percent-decoding passes to address multi-encoded or double-encoded path representations.
 */
const MAX_DECODE_PASSES = 3;

/**
 * Safely canonicalizes a URL pathname for security pattern matching and route exclusion checks.
 *
 * Requirements:
 * 1. Safe Decoding: Rejects malformed percent-encoding safely (fails closed by throwing SafeTransportError).
 * 2. Multi-encoding handling: Performs bounded repeated decoding (up to MAX_DECODE_PASSES).
 * 3. Separator canonicalization: Replaces backslashes (\ and %5C) and encoded slashes (%2F) with forward slashes (/).
 * 4. Posix normalization: Resolves dot segments (., ..) and collapses consecutive slashes (//) using path.posix.normalize.
 * 5. Non-destructive: The output of this function is strictly used for security inspection; the outbound URL
 *    dispatched over the wire is NEVER modified merely for matching purposes.
 *
 * @throws SafeTransportError('MALFORMED_URL') if percent-encoding is malformed or invalid UTF-8.
 */
export function canonicalizePathForInspection(rawPath: string): string {
  if (typeof rawPath !== 'string' || rawPath.length === 0) {
    return '/';
  }

  let current = rawPath;

  // Bounded repeated decoding to address nested / double-encoded variants (e.g. /%256cogout)
  for (let pass = 0; pass < MAX_DECODE_PASSES; pass++) {
    if (!current.includes('%')) {
      break;
    }

    let next: string;
    try {
      next = decodeURIComponent(current);
    } catch {
      throw new SafeTransportError(
        'MALFORMED_URL',
        `Malformed percent-encoding detected in probe target path: '${rawPath}'.`
      );
    }

    if (next === current) {
      break;
    }
    current = next;
  }

  // Check if there is still unresolved percent-encoding that would mutate further
  if (current.includes('%')) {
    try {
      const peek = decodeURIComponent(current);
      if (peek !== current) {
        throw new SafeTransportError(
          'MALFORMED_URL',
          `Excessive nested percent-encoding detected in probe target path: '${rawPath}'.`
        );
      }
    } catch {
      throw new SafeTransportError(
        'MALFORMED_URL',
        `Malformed percent-encoding detected in probe target path: '${rawPath}'.`
      );
    }
  }

  // Canonicalize path separators: Convert backslashes (including literal and decoded %5c) to forward slashes
  current = current.replace(/\\/g, '/');

  // Normalize path segments (collapse redundant slashes, resolve . and ..)
  let normalized = path.posix.normalize(current);

  // Ensure leading slash
  if (!normalized.startsWith('/')) {
    normalized = `/${normalized}`;
  }

  return normalized;
}

/**
 * Known potentially state-altering or destructive path segments often mistakenly
 * exposed or triggered via HTTP GET requests in web applications.
 *
 * CAUTION - HEURISTIC LIMITATION:
 * This list represents common sensitive operational routes (/logout, /delete, /reset-password, etc.)
 * to prevent accidental session termination, resource deletion, or transactional side effects.
 * However, regex pattern matching is a defense-in-depth heuristic and DOES NOT guarantee that
 * unlisted GET endpoints are non-destructive. Web applications may execute arbitrary state changes
 * on custom GET routes.
 */
export const POTENTIALLY_MUTATING_GET_PATH_PATTERNS: readonly RegExp[] = Object.freeze([
  /(?:^|\/)(?:logout|signout|sign-out|log-off|logoff)(?:$|[?#\/])/i,
  /(?:^|\/)(?:delete|destroy|purge|remove|drop|erase)(?:$|[?#\/])/i,
  /(?:^|\/)(?:terminate|shutdown|reboot|restart|kill)(?:$|[?#\/])/i,
  /(?:^|\/)(?:checkout|pay|payment|purchase|transfer|order\/submit)(?:$|[?#\/])/i,
  /(?:^|\/)(?:reset-password|password-reset|change-password|revoke)(?:$|[?#\/])/i,
  /(?:^|\/)(?:cancel|unsubscribe|opt-out|optout)(?:$|[?#\/])/i,
]);

export interface ActiveSafetyGateOptions {
  readonly enabled?: boolean;
  readonly maxTotalRequests?: number;
  readonly maxRequestsPerEndpoint?: number;
  /**
   * Optional server-controlled allowlist of permitted endpoint path prefixes for active probes.
   * If provided and non-empty, only paths whose canonical representation starts with one of these prefixes
   * are permitted to receive active probes.
   *
   * Note: This allowlist CANNOT be configured or expanded by client request parameters; it must be
   * configured by server-side scan orchestrators. Even if a path is allowlisted, it MUST still pass all
   * scope, excluded-path, and non-destructive route pattern checks.
   */
  readonly allowedEndpointPrefixes?: readonly string[];
}

export class ActiveSafetyGate {
  public static readonly DEFAULT_MAX_TOTAL_REQUESTS = 50;
  public static readonly ABSOLUTE_MAX_TOTAL_REQUESTS = 200;
  public static readonly DEFAULT_MAX_REQUESTS_PER_ENDPOINT = 10;
  public static readonly ABSOLUTE_MAX_REQUESTS_PER_ENDPOINT = 20;

  private readonly enabled: boolean;
  private readonly maxTotalRequests: number;
  private readonly maxRequestsPerEndpoint: number;
  private readonly allowedEndpointPrefixes?: readonly string[];
  private totalRequestsDispatched = 0;
  private readonly endpointRequestCounts = new Map<string, number>();

  constructor(options?: ActiveSafetyGateOptions) {
    this.enabled = options?.enabled === true;

    const rawMaxTotal = options?.maxTotalRequests ?? ActiveSafetyGate.DEFAULT_MAX_TOTAL_REQUESTS;
    if (
      !Number.isInteger(rawMaxTotal) ||
      rawMaxTotal < 1 ||
      rawMaxTotal > ActiveSafetyGate.ABSOLUTE_MAX_TOTAL_REQUESTS
    ) {
      throw new RangeError(
        `maxTotalRequests must be an integer between 1 and ${ActiveSafetyGate.ABSOLUTE_MAX_TOTAL_REQUESTS} (received ${rawMaxTotal}).`
      );
    }
    this.maxTotalRequests = rawMaxTotal;

    const rawMaxEndpoint =
      options?.maxRequestsPerEndpoint ?? ActiveSafetyGate.DEFAULT_MAX_REQUESTS_PER_ENDPOINT;
    if (
      !Number.isInteger(rawMaxEndpoint) ||
      rawMaxEndpoint < 1 ||
      rawMaxEndpoint > ActiveSafetyGate.ABSOLUTE_MAX_REQUESTS_PER_ENDPOINT
    ) {
      throw new RangeError(
        `maxRequestsPerEndpoint must be an integer between 1 and ${ActiveSafetyGate.ABSOLUTE_MAX_REQUESTS_PER_ENDPOINT} (received ${rawMaxEndpoint}).`
      );
    }
    this.maxRequestsPerEndpoint = rawMaxEndpoint;

    if (options?.allowedEndpointPrefixes !== undefined) {
      if (!Array.isArray(options.allowedEndpointPrefixes)) {
        throw new TypeError('allowedEndpointPrefixes must be an array of path prefixes.');
      }
      for (const prefix of options.allowedEndpointPrefixes) {
        if (typeof prefix !== 'string' || !prefix.startsWith('/')) {
          throw new RangeError(`Allowed endpoint prefix must be a non-empty string starting with '/' (received '${prefix}').`);
        }
      }
      this.allowedEndpointPrefixes = Object.freeze([...options.allowedEndpointPrefixes]);
    }
  }

  /**
   * Returns true only if active probing was explicitly opted into.
   */
  public isEnabled(): boolean {
    return this.enabled;
  }

  /**
   * Returns the count of total requests dispatched through this gate.
   */
  public getTotalRequestsDispatched(): number {
    return this.totalRequestsDispatched;
  }

  /**
   * Validates target authorization, scope, method, and request budgets.
   * Throws SafeTransportError if any security control is violated.
   * Increments budget counters if all checks pass.
   */
  public checkAndAcquireProbeSlot(
    targetUrl: string,
    context: AuthorizedScanScopeContext,
    method?: string,
    signal?: AbortSignal
  ): { target: URL; endpointKey: string } {
    // 1. Explicit opt-in verification
    if (!this.enabled) {
      throw new SafeTransportError(
        'DOMAIN_NOT_VERIFIED',
        'Active security probing is disabled by default. Explicit authorization (enabled: true) is required before sending active probes.'
      );
    }

    // 2. Abort Signal check
    if (signal?.aborted) {
      throw new SafeTransportError(
        'ABORTED',
        'Active probe was cancelled by caller AbortSignal.'
      );
    }

    // 3. Authoritative Scope Context verification
    if (!isTrustedScopeContext(context)) {
      throw new SafeTransportError(
        'DOMAIN_NOT_VERIFIED',
        'Untrusted or forged RequestAuthorizationContext supplied to ActiveSafetyGate.'
      );
    }

    if (context.purpose !== 'AUTHORIZED_SCAN') {
      throw new SafeTransportError(
        'DOMAIN_NOT_VERIFIED',
        `Active probing requires an AUTHORIZED_SCAN context purpose (received ${context.purpose}).`
      );
    }

    if (context.status !== 'VERIFIED') {
      throw new SafeTransportError(
        'DOMAIN_NOT_VERIFIED',
        `Target domain ownership must be in VERIFIED status (current: ${context.status}).`
      );
    }

    if (context.scanBlocked) {
      throw new SafeTransportError(
        'DOMAIN_VERIFICATION_SUSPENDED',
        'Target domain is administratively blocked from scanning.'
      );
    }

    if (context.expiresAt <= Date.now()) {
      throw new SafeTransportError(
        'DOMAIN_NOT_VERIFIED',
        `Target domain verification has expired at ${new Date(context.expiresAt).toISOString()}.`
      );
    }

    // 4. Method restriction: Non-destructive GET and HEAD only
    const reqMethod = (method || 'GET').trim().toUpperCase();
    if (reqMethod !== 'GET' && reqMethod !== 'HEAD') {
      throw new SafeTransportError(
        'METHOD_NOT_PERMITTED',
        `HTTP method '${reqMethod}' is strictly prohibited for active security probes. Only non-destructive GET and HEAD requests are permitted.`
      );
    }

    // 5. URL and Scope Parsing
    let parsed: URL;
    try {
      parsed = new URL(targetUrl);
    } catch {
      throw new SafeTransportError('MALFORMED_URL', `Invalid target probe URL: '${targetUrl}'.`);
    }

    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throw new SafeTransportError(
        'MALFORMED_URL',
        `Unsupported scheme '${parsed.protocol}'. Active probes must use http: or https:.`
      );
    }

    const host = parsed.hostname.toLowerCase();
    const primary = context.primaryDomain.toLowerCase();
    const approvedSubdomains = (context.approvedSubdomains || []).map((s) => s.toLowerCase());
    const isAllowedHost = host === primary || approvedSubdomains.includes(host);

    if (!isAllowedHost) {
      throw new SafeTransportError(
        'DOMAIN_NOT_VERIFIED',
        `Probe target host '${host}' is outside the authorized scan scope (primary: '${primary}').`
      );
    }

    // 6. Port restrictions
    const defaultPort = parsed.protocol === 'https:' ? 443 : 80;
    const targetPort = parsed.port ? parseInt(parsed.port, 10) : defaultPort;

    if (isBlockedInternalPort(targetPort)) {
      throw new SafeTransportError(
        'INTERNAL_PORT_BLOCKED',
        `Port ${targetPort} is a prohibited internal infrastructure port.`
      );
    }

    if (context.allowedPorts && context.allowedPorts.length > 0) {
      if (!context.allowedPorts.includes(targetPort)) {
        throw new SafeTransportError(
          'PORT_NOT_PERMITTED',
          `Port ${targetPort} is not permitted by scan authorization policy.`
        );
      }
    } else {
      if (targetPort !== 80 && targetPort !== 443) {
        throw new SafeTransportError(
          'PORT_NOT_PERMITTED',
          `Non-standard port ${targetPort} is not allowed without explicit scan policy authorization.`
        );
      }
    }

    // 7. Canonical Path Inspection & Excluded Paths check
    const rawPathname = parsed.pathname;
    const canonicalPath = canonicalizePathForInspection(rawPathname);

    const allExclusions = [
      ...SERVER_MANDATORY_EXCLUDED_PATHS,
      ...(context.excludedPaths || []),
    ];

    for (const excluded of allExclusions) {
      if (rawPathname.startsWith(excluded) || canonicalPath.startsWith(excluded)) {
        throw new SafeTransportError(
          'MALFORMED_URL',
          `Target probe path '${rawPathname}' (canonical: '${canonicalPath}') matches excluded security prefix '${excluded}'.`
        );
      }
    }

    // 8. Server-Controlled Active Probe Endpoint Allowlist (if configured)
    if (this.allowedEndpointPrefixes && this.allowedEndpointPrefixes.length > 0) {
      const isAllowedEndpoint = this.allowedEndpointPrefixes.some((prefix) =>
        canonicalPath.startsWith(prefix)
      );
      if (!isAllowedEndpoint) {
        throw new SafeTransportError(
          'MALFORMED_URL',
          `Active probe blocked: canonical path '${canonicalPath}' is not permitted by server-controlled active probe endpoint allowlist.`
        );
      }
    }

    // 9. Conservative Non-Destructive Endpoint Safeguard
    // Blocks active probing against application routes commonly used for destructive or state-altering GET actions.
    // Evaluates both canonicalized and raw path representations to prevent encoding bypasses.
    const isPotentiallyMutatingPath =
      POTENTIALLY_MUTATING_GET_PATH_PATTERNS.some((pattern) => pattern.test(canonicalPath)) ||
      POTENTIALLY_MUTATING_GET_PATH_PATTERNS.some((pattern) => pattern.test(rawPathname));

    if (isPotentiallyMutatingPath) {
      throw new SafeTransportError(
        'MALFORMED_URL',
        `Active probe blocked for potentially state-altering or mutating GET route: '${rawPathname}' (canonical: '${canonicalPath}'). Active probing is restricted on sensitive operational routes to prevent unintended side effects.`
      );
    }

    // 10. Request Budget checks
    if (this.totalRequestsDispatched >= this.maxTotalRequests) {
      throw new SafeTransportError(
        'MAX_RESPONSE_SIZE_EXCEEDED',
        `Active scan aggregate request budget exhausted (${this.totalRequestsDispatched}/${this.maxTotalRequests} requests).`
      );
    }

    const endpointKey = `${parsed.origin}${parsed.pathname}`;
    const endpointCount = this.endpointRequestCounts.get(endpointKey) || 0;
    if (endpointCount >= this.maxRequestsPerEndpoint) {
      throw new SafeTransportError(
        'MAX_RESPONSE_SIZE_EXCEEDED',
        `Per-endpoint probe request ceiling reached for '${endpointKey}' (${endpointCount}/${this.maxRequestsPerEndpoint}).`
      );
    }

    // Acquire slot
    this.totalRequestsDispatched++;
    this.endpointRequestCounts.set(endpointKey, endpointCount + 1);

    return { target: parsed, endpointKey };
  }

  /**
   * Resets internal request budget counters (for testing or new scan sessions).
   */
  public resetBudget(): void {
    this.totalRequestsDispatched = 0;
    this.endpointRequestCounts.clear();
  }
}
