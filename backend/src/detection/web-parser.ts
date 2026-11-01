import type {
  SecurityEvent,
  WebConfidenceTier,
  WebSecurityEventMetadata,
  EvidenceProvenance,
} from '@veltrix/shared';

export { EvidenceProvenance };

export interface WebTelemetryContext {
  /**
   * Explicitly indicates caller is an authenticated, trusted internal server-side component
   * (e.g. internal canary sensor, trusted core scanner, audit engine).
   */
  isTrustedServerComponent?: boolean;
  /**
   * Explicitly sets trusted provenance tier.
   */
  trustedProvenance?: EvidenceProvenance;
  /**
   * Server-side component or verifier identifier.
   */
  verifiedBy?: string;
}

export interface NormalizedWebTelemetry {
  eventId: string;
  orgId: string;
  siteId?: string;
  domain?: string;
  timestamp: string;
  sourceIp: string;
  username?: string;
  sourceSystem: string;
  httpMethod: string;
  rawUri: string;
  normalizedPath: string;
  queryParams: Record<string, string>;
  decodedPayloads: string[];
  httpStatus?: number;
  responseTimeMs?: number;
  userAgent?: string;
  wafAction?: 'ALLOW' | 'BLOCK' | 'CHALLENGE' | 'LOG';
  isBot?: boolean;
  confidenceLevel: WebConfidenceTier;
  corroboratingSignals: string[]; // Strictly SERVER-VERIFIED signals
  untrustedClientSignals: string[]; // Client-submitted unverified signals
  evidenceProvenance: EvidenceProvenance;
  isClientClassificationUntrusted: boolean;
}

/**
 * Known database syntax error signatures indicating potential SQL injection execution.
 */
const DB_SYNTAX_ERROR_PATTERNS = [
  /syntax error near/i,
  /unclosed quotation mark/i,
  /quoted string not properly terminated/i,
  /ora-[0-9]{4,5}/i,
  /pg_query\(\)/i,
  /psqlexception/i,
  /mysql_fetch_array\(\)/i,
  /you have an error in your sql syntax/i,
  /warning: mysql_/i,
  /microsoft ole db provider for sql server/i,
  /sqlite3::sqlexception/i,
  /driver.*sql[-_ ]*server/i,
];

/**
 * Known system file leakage signatures indicating confirmed path traversal / LFI.
 */
const SYSTEM_FILE_LEAKAGE_PATTERNS = [
  /root:.*:0:0:/i,
  /\[boot loader\]/i,
  /\[fonts\]/i,
  /for 16-bit app support/i,
  /daemon:.*:1:1:/i,
];

/**
 * Safely decodes URL encoded strings iteratively (up to 3 passes to unwrap double encoding)
 * while guarding against malformed percent encodings.
 */
export function safeDecodeUriComponent(str: string): string {
  if (!str) return '';
  let current = str;
  for (let pass = 0; pass < 3; pass++) {
    try {
      const decoded = decodeURIComponent(current.replace(/\+/g, ' '));
      if (decoded === current) {
        break; // Reached stable decoded representation
      }
      current = decoded;
    } catch {
      // Malformed URI sequence, stop unrolling
      break;
    }
  }
  return current;
}

/**
 * Sensitive parameter names whose values must be redacted to prevent credential leakage.
 */
export const SENSITIVE_PARAM_PATTERN =
  /^(pass(word)?|passwd|pwd|token|access_token|refresh_token|secret|auth|authorization|bearer|cookie|session|sessionid|apikey|api_key|credit|cvv|ssn)$/i;

/**
 * Sanitizes a raw URI by replacing sensitive parameter values with '[REDACTED]'.
 */
export function sanitizeUriString(uri: string): string {
  if (!uri || !uri.includes('?')) return uri;
  const qIdx = uri.indexOf('?');
  const path = uri.slice(0, qIdx);
  const qs = uri.slice(qIdx + 1);
  const pairs = qs.split('&');
  const sanitizedPairs = pairs.map((pair) => {
    if (!pair) return pair;
    const eqIdx = pair.indexOf('=');
    if (eqIdx === -1) return pair;
    const rawKey = pair.slice(0, eqIdx);
    const decodedKey = safeDecodeUriComponent(rawKey).trim();
    if (SENSITIVE_PARAM_PATTERN.test(decodedKey)) {
      return `${rawKey}=[REDACTED]`;
    }
    return pair;
  });
  return `${path}?${sanitizedPairs.join('&')}`;
}

/**
 * Extracts query parameters into key-value map and returns all raw and decoded values.
 */
export function extractQueryParams(uri: string): {
  params: Record<string, string>;
  allValues: string[];
} {
  const params: Record<string, string> = {};
  const allValues: string[] = [];

  const qIdx = uri.indexOf('?');
  if (qIdx === -1) {
    return { params, allValues };
  }

  const queryString = uri.slice(qIdx + 1);
  const pairs = queryString.split('&');

  for (const pair of pairs) {
    if (!pair) continue;
    const eqIdx = pair.indexOf('=');
    let key = '';
    let val = '';
    if (eqIdx !== -1) {
      key = safeDecodeUriComponent(pair.slice(0, eqIdx)).trim();
      val = safeDecodeUriComponent(pair.slice(eqIdx + 1)).trim();
    } else {
      key = safeDecodeUriComponent(pair).trim();
    }

    if (key) {
      if (SENSITIVE_PARAM_PATTERN.test(key)) {
        params[key] = '[REDACTED]';
      } else {
        params[key] = val;
        if (val) {
          allValues.push(val);
        }
      }
    }
  }

  return { params, allValues };
}

/**
 * Normalizes and classifies inbound website telemetry into a standardized security model.
 * Enforces zero-trust validation of client-provided attack classifications and evaluates
 * the Four Evidence-Based Confidence Tiers based on a verified provenance model.
 *
 * PROVENANCE & TRUST BOUNDARY RULES:
 * 1. All externally submitted telemetry is UNTRUSTED_CLIENT by default.
 * 2. Client-provided corroboratingSignals are NEVER promoted directly into trusted evidence.
 * 3. Externally reported signals are separated from server-verified evidence.
 * 4. Only TRUSTED_SERVER_COMPONENT provenance can establish CONFIRMED_EXPLOITATION.
 * 5. WAF actions, response samples, and error messages from untrusted clients are unverified claims
 *    and cannot independently establish exploitation.
 * 6. Arbitrary integration clients cannot impersonate trusted collectors via sourceSystem alone.
 * 7. Ordinary suspicious-attempt attack detection is preserved even when corroborating evidence is untrusted.
 */
export function normalizeWebTelemetry(
  event: SecurityEvent,
  context?: WebTelemetryContext
): NormalizedWebTelemetry {
  const meta = (event.metadata || {}) as WebSecurityEventMetadata;

  const rawUri = typeof meta.requestUri === 'string' ? meta.requestUri : '/';
  const sanitizedRawUri = sanitizeUriString(rawUri);
  const httpMethod = (typeof meta.httpMethod === 'string' ? meta.httpMethod : 'GET').toUpperCase();
  const httpStatus = typeof meta.httpStatus === 'number' ? meta.httpStatus : undefined;
  const userAgent = typeof meta.userAgent === 'string' ? meta.userAgent : undefined;
  const wafAction = meta.wafAction;

  // Extract path without query parameters and decode safely
  const qIdx = rawUri.indexOf('?');
  const pathOnly = qIdx === -1 ? rawUri : rawUri.slice(0, qIdx);
  const normalizedPath = safeDecodeUriComponent(pathOnly);

  // Extract query parameters and payload strings (with sensitive keys sanitized)
  const { params: queryParams, allValues: queryValues } = extractQueryParams(rawUri);

  // Collect all searchable payloads (URI path, query parameters, matched patterns)
  const decodedPayloads: string[] = [normalizedPath, ...queryValues];

  if (Array.isArray(meta.matchedPatterns)) {
    for (const pat of meta.matchedPatterns) {
      if (typeof pat === 'string') {
        decodedPayloads.push(safeDecodeUriComponent(pat));
      }
    }
  }

  // 1. Establish Evidence Provenance Model
  // Zero-Trust Rule: All externally submitted telemetry is UNTRUSTED_CLIENT by default (Rule 1).
  // Rule 7: Arbitrary integration clients MUST NOT be able to impersonate trusted collectors.
  // Bare client-supplied sourceSystem or unverified metadata flags alone NEVER grant trusted provenance.
  let evidenceProvenance: EvidenceProvenance = 'UNTRUSTED_CLIENT';

  if (
    context?.isTrustedServerComponent === true ||
    context?.trustedProvenance === 'TRUSTED_SERVER_COMPONENT'
  ) {
    evidenceProvenance = 'TRUSTED_SERVER_COMPONENT';
  } else if (context?.trustedProvenance === 'AUTHENTICATED_COLLECTOR') {
    evidenceProvenance = 'AUTHENTICATED_COLLECTOR';
  } else if (
    meta.serverVerified === true &&
    (meta.evidenceProvenance === 'TRUSTED_SERVER_COMPONENT' || meta.trustedProvenance === true)
  ) {
    evidenceProvenance = 'TRUSTED_SERVER_COMPONENT';
  } else if (
    meta.serverVerified === true &&
    meta.evidenceProvenance === 'AUTHENTICATED_COLLECTOR'
  ) {
    evidenceProvenance = 'AUTHENTICATED_COLLECTOR';
  }

  // Client-supplied event classification check
  const isClientClassificationUntrusted = Boolean(
    meta.clientDeclaredAttackType ||
    event.eventType.startsWith('web.attack.') ||
    evidenceProvenance === 'UNTRUSTED_CLIENT'
  );

  // 2. Separate client-provided signals from server-verified evidence (Rules 2 & 3)
  // Rule 2: Never promote client-provided corroboratingSignals directly into trusted evidence.
  const untrustedClientSignals: string[] = Array.isArray(meta.corroboratingSignals)
    ? [...meta.corroboratingSignals]
    : [];

  // Trusted corroborating signals start EMPTY
  const trustedCorroboratingSignals: string[] = [];

  // If the event has verified TRUSTED_SERVER_COMPONENT provenance, promote verified signals
  if (evidenceProvenance === 'TRUSTED_SERVER_COMPONENT') {
    if (Array.isArray(meta.verifiedSignals)) {
      for (const s of meta.verifiedSignals) {
        if (typeof s === 'string' && !trustedCorroboratingSignals.includes(s)) {
          trustedCorroboratingSignals.push(s);
        }
      }
    }
    for (const s of untrustedClientSignals) {
      if (!trustedCorroboratingSignals.includes(s)) {
        trustedCorroboratingSignals.push(s);
      }
    }
  }

  // 3. Inspect application response and error messages with strict provenance validation (Rule 6)
  // Rule 6: Validate provenance of WAF actions, response samples, error messages before confidence escalation.
  // Forged database errors cannot independently establish exploitation.
  const responseText = typeof meta.responseSample === 'string' ? meta.responseSample : '';
  const errorText = typeof meta.errorMessage === 'string' ? meta.errorMessage : '';
  const combinedInspection = `${responseText} ${errorText}`;

  if (
    evidenceProvenance === 'TRUSTED_SERVER_COMPONENT' ||
    evidenceProvenance === 'AUTHENTICATED_COLLECTOR'
  ) {
    for (const pat of DB_SYNTAX_ERROR_PATTERNS) {
      if (pat.test(combinedInspection)) {
        if (!trustedCorroboratingSignals.includes('UNHANDLED_DB_SYNTAX_ERROR')) {
          trustedCorroboratingSignals.push('UNHANDLED_DB_SYNTAX_ERROR');
        }
        break;
      }
    }

    if (evidenceProvenance === 'TRUSTED_SERVER_COMPONENT') {
      for (const pat of SYSTEM_FILE_LEAKAGE_PATTERNS) {
        if (pat.test(combinedInspection)) {
          if (!trustedCorroboratingSignals.includes('DATA_LEAKAGE_INDICATOR')) {
            trustedCorroboratingSignals.push('DATA_LEAKAGE_INDICATOR');
          }
          break;
        }
      }
    }
  } else {
    // Untrusted client: if client sent DB error or leakage strings, record as untrusted client claims only
    for (const pat of DB_SYNTAX_ERROR_PATTERNS) {
      if (pat.test(combinedInspection)) {
        if (!untrustedClientSignals.includes('CLIENT_CLAIMED_DB_SYNTAX_ERROR')) {
          untrustedClientSignals.push('CLIENT_CLAIMED_DB_SYNTAX_ERROR');
        }
        break;
      }
    }
    for (const pat of SYSTEM_FILE_LEAKAGE_PATTERNS) {
      if (pat.test(combinedInspection)) {
        if (!untrustedClientSignals.includes('CLIENT_CLAIMED_DATA_LEAKAGE')) {
          untrustedClientSignals.push('CLIENT_CLAIMED_DATA_LEAKAGE');
        }
        break;
      }
    }
  }

  // 4. Validate WAF action provenance
  const isWafVerified =
    evidenceProvenance === 'TRUSTED_SERVER_COMPONENT' ||
    evidenceProvenance === 'AUTHENTICATED_COLLECTOR';
  const effectiveWafAction = isWafVerified ? wafAction : undefined;

  // 5. Determine Confidence Tier:
  // Rule 5: Only allow CONFIRMED_EXPLOITATION when evidence has been independently verified
  // by a trusted server-side component.
  let confidenceLevel: WebConfidenceTier = 'SUSPICIOUS_ATTEMPT';

  if (
    evidenceProvenance === 'TRUSTED_SERVER_COMPONENT' &&
    (trustedCorroboratingSignals.includes('DATA_LEAKAGE_INDICATOR') ||
      trustedCorroboratingSignals.includes('CANARY_TOKEN_BREACH') ||
      trustedCorroboratingSignals.includes('UNAUTHORIZED_PRIVILEGE_MUTATION'))
  ) {
    confidenceLevel = 'CONFIRMED_EXPLOITATION';
  } else if (
    (evidenceProvenance === 'TRUSTED_SERVER_COMPONENT' ||
      evidenceProvenance === 'AUTHENTICATED_COLLECTOR') &&
    (trustedCorroboratingSignals.includes('UNHANDLED_DB_SYNTAX_ERROR') ||
      trustedCorroboratingSignals.includes('STACK_TRACE_IN_RESPONSE') ||
      trustedCorroboratingSignals.includes('LATENCY_SPIKE_EXPLOIT'))
  ) {
    confidenceLevel = 'POTENTIAL_EXPLOITATION';
  } else if (
    effectiveWafAction === 'BLOCK' ||
    effectiveWafAction === 'CHALLENGE' ||
    httpStatus === 403 ||
    httpStatus === 406 ||
    trustedCorroboratingSignals.includes('WAF_INTERVENTION')
  ) {
    confidenceLevel = 'BLOCKED_ATTEMPT';
  } else {
    // Rule 8: Preserve useful suspicious-attempt detection even when corroborating evidence is untrusted.
    confidenceLevel = 'SUSPICIOUS_ATTEMPT';
  }

  return {
    eventId: event.eventId,
    orgId: event.orgId,
    siteId: meta.siteId,
    domain: meta.domain,
    timestamp: event.timestamp,
    sourceIp: event.sourceIp,
    username: event.username,
    sourceSystem: event.sourceSystem,
    httpMethod,
    rawUri: sanitizedRawUri,
    normalizedPath,
    queryParams,
    decodedPayloads,
    httpStatus,
    responseTimeMs: meta.responseTimeMs,
    userAgent,
    wafAction: effectiveWafAction || (wafAction && !isWafVerified ? wafAction : undefined),
    isBot: meta.isBot,
    confidenceLevel,
    corroboratingSignals: trustedCorroboratingSignals,
    untrustedClientSignals,
    evidenceProvenance,
    isClientClassificationUntrusted,
  };
}
