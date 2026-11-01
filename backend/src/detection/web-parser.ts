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
  corroboratingSignals: string[];
  untrustedClientSignals: string[];
  evidenceProvenance: EvidenceProvenance;
  isClientClassificationUntrusted: boolean;
  trustedEvidenceContext?: InternalTrustedEvidenceContext;
}

/**
 * Standard database syntax error substrings indicating unhandled SQL injection errors.
 */
export const DB_SYNTAX_ERROR_PATTERNS = [
  /you have an error in your sql syntax/i,
  /warning:\s*mysql/i,
  /unclosed quotation mark before the character string/i,
  /quoted string not properly terminated/i,
  /pg_query\(\):\s*query failed/i,
  /sqlite3::sqlexception/i,
  /syntax error near/i,
  /ora-01756/i,
  /microsoft ole db provider for sql server/i,
];

/**
 * Standard system file patterns indicating path traversal or local file inclusion data leakage.
 */
export const SYSTEM_FILE_LEAKAGE_PATTERNS = [
  /root:.*:0:0:/i,
  /\[extensions\]/i,
  /default=multi\(0\)disk\(0\)/i,
  /<\?php/i,
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
 * Helper to parse query parameters with redaction of sensitive credentials.
 */
export function extractQueryParams(uri: string): {
  params: Record<string, string>;
  allValues: string[];
} {
  const params: Record<string, string> = {};
  const allValues: string[] = [];
  if (!uri || !uri.includes('?')) {
    return { params, allValues };
  }

  const queryString = uri.split('?')[1] || '';
  const pairs = queryString.split('&');

  for (const pair of pairs) {
    if (!pair) continue;
    const eqIdx = pair.indexOf('=');
    const rawKey = eqIdx === -1 ? pair : pair.slice(0, eqIdx);
    const rawVal = eqIdx === -1 ? '' : pair.slice(eqIdx + 1);
    const decodedKey = safeDecodeUriComponent(rawKey).trim();
    const decodedVal = safeDecodeUriComponent(rawVal);

    if (SENSITIVE_PARAM_PATTERN.test(decodedKey)) {
      params[decodedKey] = '[REDACTED]';
    } else {
      params[decodedKey] = decodedVal;
      allValues.push(decodedVal);
    }
  }

  return { params, allValues };
}

/**
 * Core telemetry normalizer enforcing strict trust boundaries and zero-trust evidence validation.
 *
 * Invariants:
 * 1. Zero-trust default: all externally submitted telemetry defaults to UNTRUSTED_CLIENT.
 * 2. External metadata cannot declare provenance or promote signals into trusted evidence.
 * 3. Client response samples and error messages are isolated in untrustedClientSignals.
 * 4. External WAF claims do not establish WAF_INTERVENTION unless signed by an authorized verifier.
 * 5. CONFIRMED_EXPLOITATION requires explicit attestation by an authorized internal verifier.
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

  const qIdx = rawUri.indexOf('?');
  const pathOnly = qIdx === -1 ? rawUri : rawUri.slice(0, qIdx);
  const normalizedPath = safeDecodeUriComponent(pathOnly);

  const { params: queryParams, allValues: queryValues } = extractQueryParams(rawUri);

  const decodedPayloads: string[] = [normalizedPath, ...queryValues];

  if (Array.isArray(meta.matchedPatterns)) {
    for (const pat of meta.matchedPatterns) {
      if (typeof pat === 'string') {
        decodedPayloads.push(safeDecodeUriComponent(pat));
      }
    }
  }

  // 1. Establish Evidence Provenance Model
  let evidenceProvenance: EvidenceProvenance = 'UNTRUSTED_CLIENT';
  let activeTrustedContext: InternalTrustedEvidenceContext | undefined;

  const expectedBinding = {
    eventId: event.eventId,
    orgId: event.orgId,
    siteId: meta.siteId || '',
  };

  if (context?.trustedContext) {
    if (auth.verifyAndConsumeContext(context.trustedContext, expectedBinding)) {
      evidenceProvenance = context.trustedContext.verifiedProvenance;
      activeTrustedContext = context.trustedContext;
    } else {
      console.warn('[VELTRIX-SECURITY] Rejected forged, invalid, or replayed trustedContext in WebTelemetryContext');
    }
  } else if (event.trustedEvidenceContext) {
    if (auth.verifyAndConsumeContext(event.trustedEvidenceContext, expectedBinding)) {
      evidenceProvenance = event.trustedEvidenceContext.verifiedProvenance;
      activeTrustedContext = event.trustedEvidenceContext;
    } else {
      console.warn('[VELTRIX-SECURITY] Rejected forged, invalid, or replayed event.trustedEvidenceContext');
    }
  }

  return finalizeWebTelemetryNormalization(
    event,
    meta,
    sanitizedRawUri,
    httpMethod,
    httpStatus,
    userAgent,
    normalizedPath,
    queryParams,
    decodedPayloads,
    evidenceProvenance,
    activeTrustedContext
  );
}

/**
 * Asynchronous version of normalizeWebTelemetry supporting distributed persistent replay verification.
 */
export async function normalizeWebTelemetryAsync(
  event: SecurityEvent,
  context?: WebTelemetryContext,
  authority?: InternalEvidenceAuthority
): Promise<NormalizedWebTelemetry> {
  const meta = (event.metadata || {}) as WebSecurityEventMetadata;
  const auth = authority || getDefaultInternalEvidenceAuthority();

  const rawUri = typeof meta.requestUri === 'string' ? meta.requestUri : '/';
  const sanitizedRawUri = sanitizeUriString(rawUri);
  const httpMethod = (typeof meta.httpMethod === 'string' ? meta.httpMethod : 'GET').toUpperCase();
  const httpStatus = typeof meta.httpStatus === 'number' ? meta.httpStatus : undefined;
  const userAgent = typeof meta.userAgent === 'string' ? meta.userAgent : undefined;

  const qIdx = rawUri.indexOf('?');
  const pathOnly = qIdx === -1 ? rawUri : rawUri.slice(0, qIdx);
  const normalizedPath = safeDecodeUriComponent(pathOnly);

  const { params: queryParams, allValues: queryValues } = extractQueryParams(rawUri);

  const decodedPayloads: string[] = [normalizedPath, ...queryValues];

  if (Array.isArray(meta.matchedPatterns)) {
    for (const pat of meta.matchedPatterns) {
      if (typeof pat === 'string') {
        decodedPayloads.push(safeDecodeUriComponent(pat));
      }
    }
  }

  let evidenceProvenance: EvidenceProvenance = 'UNTRUSTED_CLIENT';
  let activeTrustedContext: InternalTrustedEvidenceContext | undefined;

  const expectedBinding = {
    eventId: event.eventId,
    orgId: event.orgId,
    siteId: meta.siteId || '',
  };

  if (context?.trustedContext) {
    if (await auth.verifyAndConsumeContextAsync(context.trustedContext, expectedBinding)) {
      evidenceProvenance = context.trustedContext.verifiedProvenance;
      activeTrustedContext = context.trustedContext;
    } else {
      console.warn('[VELTRIX-SECURITY] Rejected forged, invalid, or replayed trustedContext in WebTelemetryContext');
    }
  } else if (event.trustedEvidenceContext) {
    if (await auth.verifyAndConsumeContextAsync(event.trustedEvidenceContext, expectedBinding)) {
      evidenceProvenance = event.trustedEvidenceContext.verifiedProvenance;
      activeTrustedContext = event.trustedEvidenceContext;
    } else {
      console.warn('[VELTRIX-SECURITY] Rejected forged, invalid, or replayed event.trustedEvidenceContext');
    }
  }

  return finalizeWebTelemetryNormalization(
    event,
    meta,
    sanitizedRawUri,
    httpMethod,
    httpStatus,
    userAgent,
    normalizedPath,
    queryParams,
    decodedPayloads,
    evidenceProvenance,
    activeTrustedContext
  );
}

function finalizeWebTelemetryNormalization(
  event: SecurityEvent,
  meta: WebSecurityEventMetadata,
  sanitizedRawUri: string,
  httpMethod: string,
  httpStatus: number | undefined,
  userAgent: string | undefined,
  normalizedPath: string,
  queryParams: Record<string, string>,
  decodedPayloads: string[],
  evidenceProvenance: EvidenceProvenance,
  activeTrustedContext: InternalTrustedEvidenceContext | undefined
): NormalizedWebTelemetry {
  const isClientClassificationUntrusted = Boolean(
    meta.clientDeclaredAttackType ||
    event.eventType.startsWith('web.attack.') ||
    evidenceProvenance === 'UNTRUSTED_CLIENT'
  );

  // 2. Separate client-provided signals from server-verified evidence
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

  // Client-Controlled Response Evidence
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

  // Client WAF Action claim
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

    // Inspect separate internal verified response evidence envelope
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

      // Authenticated WAF action from verified response envelope
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

  // 5. Determine Confidence Tier:
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
