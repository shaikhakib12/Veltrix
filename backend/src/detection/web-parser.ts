import type {
  SecurityEvent,
  WebConfidenceTier,
  WebSecurityEventMetadata,
  EvidenceProvenance,
  InternalTrustedEvidenceContext,
  VerifiedResponseEvidence,
} from '@veltrix/shared';
import {
  InternalEvidenceAuthority,
  getDefaultInternalEvidenceAuthority,
  APPROVED_INTERNAL_VERIFIERS,
  ALLOWED_VERIFIED_SIGNALS,
  type ApprovedVerifierIdentity,
  type AllowedVerifiedSignal,
} from './evidence-authority.js';

export {
  EvidenceProvenance,
  InternalTrustedEvidenceContext,
  VerifiedResponseEvidence,
  APPROVED_INTERNAL_VERIFIERS,
  ALLOWED_VERIFIED_SIGNALS,
  ApprovedVerifierIdentity,
  AllowedVerifiedSignal,
};

export interface WebTelemetryContext {
  /**
   * Cryptographically signed, internal-only trusted evidence context issued by
   * an authorized InternalEvidenceAuthority.
   */
  trustedContext?: InternalTrustedEvidenceContext;
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
  trustedEvidenceContext?: InternalTrustedEvidenceContext;
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
  context?: WebTelemetryContext,
  authority?: InternalEvidenceAuthority
): NormalizedWebTelemetry {
  const meta = (event.metadata || {}) as WebSecurityEventMetadata;
  const auth = authority || getDefaultInternalEvidenceAuthority();

  const rawUri = typeof meta.requestUri === 'string' ? meta.requestUri : '/';
  const sanitizedRawUri = sanitizeUriString(rawUri);
  const httpMethod = (typeof meta.httpMethod === 'string' ? meta.httpMethod : 'GET').toUpperCase();
  const httpStatus = typeof meta.httpStatus === 'number' ? meta.httpStatus : undefined;
  const userAgent = typeof meta.userAgent === 'string' ? meta.userAgent : undefined;

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
  // Zero-Trust Rule: All externally submitted telemetry is UNTRUSTED_CLIENT by default.
  // Provenance can ONLY be established by a runtime-verified internal capability issued
  // by an authorized InternalEvidenceAuthority (Finding 1).
  // All legacy trust flags (isTrustedServerComponent, trustedProvenance) have been removed.
  // Client metadata (serverVerified, evidenceProvenance, trustedProvenance, verifiedSignals)
  // are untrusted client claims and must never establish trust by themselves (Finding B).
  let evidenceProvenance: EvidenceProvenance = 'UNTRUSTED_CLIENT';
  let activeTrustedContext: InternalTrustedEvidenceContext | undefined;

  const expectedBinding = {
    eventId: event.eventId,
    orgId: event.orgId,
    siteId: meta.siteId || '',
  };

  if (context?.trustedContext) {
    if (auth.verifyContext(context.trustedContext, expectedBinding)) {
      evidenceProvenance = context.trustedContext.verifiedProvenance;
      activeTrustedContext = context.trustedContext;
    } else {
      console.warn('[VELTRIX-SECURITY] Rejected forged, invalid, or replayed trustedContext in WebTelemetryContext');
    }
  } else if (event.trustedEvidenceContext) {
    if (auth.verifyContext(event.trustedEvidenceContext, expectedBinding)) {
      evidenceProvenance = event.trustedEvidenceContext.verifiedProvenance;
      activeTrustedContext = event.trustedEvidenceContext;
    } else {
      console.warn('[VELTRIX-SECURITY] Rejected forged, invalid, or replayed event.trustedEvidenceContext');
    }
  }

  // Client-supplied event classification check
  const isClientClassificationUntrusted = Boolean(
    meta.clientDeclaredAttackType ||
    event.eventType.startsWith('web.attack.') ||
    evidenceProvenance === 'UNTRUSTED_CLIENT'
  );

  // 2. Separate client-provided signals from server-verified evidence (Finding A, B & 2)
  const untrustedClientSignals: string[] = [];

  if (Array.isArray(meta.corroboratingSignals)) {
    for (const s of meta.corroboratingSignals) {
      if (typeof s === 'string' && !untrustedClientSignals.includes(s)) {
        untrustedClientSignals.push(s);
      }
    }
  }

  // Any client-submitted verifiedSignals in metadata are untrusted claims and isolated here
  if (Array.isArray(meta.verifiedSignals)) {
    for (const s of meta.verifiedSignals) {
      if (typeof s === 'string' && !untrustedClientSignals.includes(s)) {
        untrustedClientSignals.push(s);
      }
    }
  }

  // Finding 2: Client-Controlled Response Evidence
  // Invariant: Response samples and error messages submitted in client metadata are untrusted claims.
  // They must NEVER be promoted into trusted evidence, even under trusted provenance!
  const clientResponseText = typeof meta.responseSample === 'string' ? meta.responseSample : '';
  const clientErrorText = typeof meta.errorMessage === 'string' ? meta.errorMessage : '';
  const clientCombined = `${clientResponseText} ${clientErrorText}`;

  for (const pat of DB_SYNTAX_ERROR_PATTERNS) {
    if (pat.test(clientCombined)) {
      if (!untrustedClientSignals.includes('CLIENT_CLAIMED_DB_SYNTAX_ERROR')) {
        untrustedClientSignals.push('CLIENT_CLAIMED_DB_SYNTAX_ERROR');
      }
      break;
    }
  }
  for (const pat of SYSTEM_FILE_LEAKAGE_PATTERNS) {
    if (pat.test(clientCombined)) {
      if (!untrustedClientSignals.includes('CLIENT_CLAIMED_DATA_LEAKAGE')) {
        untrustedClientSignals.push('CLIENT_CLAIMED_DATA_LEAKAGE');
      }
      break;
    }
  }

  // Finding 3: WAF Action Provenance
  // Invariant: Client-submitted WAF action is an unverified claim.
  if (meta.wafAction) {
    const claimedWafSignal = `CLIENT_CLAIMED_WAF_${meta.wafAction}`;
    if (!untrustedClientSignals.includes(claimedWafSignal)) {
      untrustedClientSignals.push(claimedWafSignal);
    }
  }

  // Trusted corroborating signals start EMPTY
  const trustedCorroboratingSignals: string[] = [];
  let effectiveWafAction: 'ALLOW' | 'BLOCK' | 'CHALLENGE' | 'LOG' | undefined;

  // ONLY verified signals explicitly attested by the internal server authority are added:
  if (activeTrustedContext) {
    for (const s of activeTrustedContext.verifiedSignalIdentifiers) {
      if (typeof s === 'string' && !trustedCorroboratingSignals.includes(s)) {
        trustedCorroboratingSignals.push(s);
      }
    }

    // Inspect separate internal verified response evidence envelope (Finding 2 & 3)
    const verifiedEnv = activeTrustedContext.verifiedResponseEvidence;
    if (verifiedEnv) {
      const verifiedResponseText = typeof verifiedEnv.responseBody === 'string' ? verifiedEnv.responseBody : '';
      const verifiedErrorText = typeof verifiedEnv.errorMessage === 'string' ? verifiedEnv.errorMessage : '';
      const verifiedCombined = `${verifiedResponseText} ${verifiedErrorText}`;

      for (const pat of DB_SYNTAX_ERROR_PATTERNS) {
        if (pat.test(verifiedCombined)) {
          if (!trustedCorroboratingSignals.includes('UNHANDLED_DB_SYNTAX_ERROR')) {
            trustedCorroboratingSignals.push('UNHANDLED_DB_SYNTAX_ERROR');
          }
          break;
        }
      }

      if (evidenceProvenance === 'TRUSTED_SERVER_COMPONENT') {
        for (const pat of SYSTEM_FILE_LEAKAGE_PATTERNS) {
          if (pat.test(verifiedCombined)) {
            if (!trustedCorroboratingSignals.includes('DATA_LEAKAGE_INDICATOR')) {
              trustedCorroboratingSignals.push('DATA_LEAKAGE_INDICATOR');
            }
            break;
          }
        }
      }

      // Authenticated WAF action from verified response envelope (Finding 3)
      if (verifiedEnv.wafAction) {
        effectiveWafAction = verifiedEnv.wafAction;
        if (verifiedEnv.wafAction === 'BLOCK' || verifiedEnv.wafAction === 'CHALLENGE') {
          if (!trustedCorroboratingSignals.includes('WAF_INTERVENTION')) {
            trustedCorroboratingSignals.push('WAF_INTERVENTION');
          }
        }
      }
    }
  }

  // CRITICAL INVARIANT (Finding A): Client-provided signals (untrustedClientSignals) are NEVER copied
  // or promoted into trustedCorroboratingSignals under any circumstances, even when activeTrustedContext
  // is present!

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
    trustedCorroboratingSignals.includes('WAF_INTERVENTION') ||
    trustedCorroboratingSignals.includes('AUTHENTICATED_WAF_BLOCK') ||
    trustedCorroboratingSignals.includes('AUTHENTICATED_WAF_CHALLENGE') ||
    httpStatus === 403 ||
    httpStatus === 406
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
    wafAction: effectiveWafAction,
    isBot: meta.isBot,
    confidenceLevel,
    corroboratingSignals: trustedCorroboratingSignals,
    untrustedClientSignals,
    evidenceProvenance,
    isClientClassificationUntrusted,
    trustedEvidenceContext: activeTrustedContext,
  };
}
