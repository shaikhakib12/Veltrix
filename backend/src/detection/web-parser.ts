import type {
  SecurityEvent,
  WebConfidenceTier,
  WebSecurityEventMetadata,
} from '@veltrix/shared';

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
 * the Four Evidence-Based Confidence Tiers.
 */
export function normalizeWebTelemetry(event: SecurityEvent): NormalizedWebTelemetry {
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
  const decodedPayloads: string[] = [
    normalizedPath,
    ...queryValues,
  ];

  if (Array.isArray(meta.matchedPatterns)) {
    for (const pat of meta.matchedPatterns) {
      if (typeof pat === 'string') {
        decodedPayloads.push(safeDecodeUriComponent(pat));
      }
    }
  }

  // Client-supplied event classification check
  const isClientClassificationUntrusted = Boolean(
    meta.clientDeclaredAttackType ||
    event.eventType.startsWith('web.attack.')
  );

  // Assess corroborating application signals
  const corroboratingSignals: string[] = Array.isArray(meta.corroboratingSignals)
    ? [...meta.corroboratingSignals]
    : [];

  // Check for DB syntax errors or system file leakage in error/response metadata where available
  const responseText = typeof meta.responseSample === 'string' ? meta.responseSample : '';
  const errorText = typeof meta.errorMessage === 'string' ? meta.errorMessage : '';
  const combinedInspection = `${responseText} ${errorText}`;

  for (const pat of DB_SYNTAX_ERROR_PATTERNS) {
    if (pat.test(combinedInspection)) {
      if (!corroboratingSignals.includes('UNHANDLED_DB_SYNTAX_ERROR')) {
        corroboratingSignals.push('UNHANDLED_DB_SYNTAX_ERROR');
      }
      break;
    }
  }

  for (const pat of SYSTEM_FILE_LEAKAGE_PATTERNS) {
    if (pat.test(combinedInspection)) {
      if (!corroboratingSignals.includes('DATA_LEAKAGE_INDICATOR')) {
        corroboratingSignals.push('DATA_LEAKAGE_INDICATOR');
      }
      break;
    }
  }

  // Determine Confidence Tier:
  // 1. Confirmed Exploitation: Proved data leakage, canary breach, or verified privilege mutation
  // 2. Potential Exploitation: DB syntax error traceback or anomalous application execution signals
  // 3. Blocked Attempt: WAF blocked action, 403 Forbidden, 406 Not Acceptable, or middleware rejection
  // 4. Suspicious Attempt: Pattern matched without corroborating execution anomalies
  let confidenceLevel: WebConfidenceTier = 'SUSPICIOUS_ATTEMPT';

  if (
    corroboratingSignals.includes('DATA_LEAKAGE_INDICATOR') ||
    corroboratingSignals.includes('CANARY_TOKEN_BREACH') ||
    corroboratingSignals.includes('UNAUTHORIZED_PRIVILEGE_MUTATION')
  ) {
    confidenceLevel = 'CONFIRMED_EXPLOITATION';
  } else if (
    corroboratingSignals.includes('UNHANDLED_DB_SYNTAX_ERROR') ||
    corroboratingSignals.includes('STACK_TRACE_IN_RESPONSE') ||
    corroboratingSignals.includes('LATENCY_SPIKE_EXPLOIT')
  ) {
    confidenceLevel = 'POTENTIAL_EXPLOITATION';
  } else if (
    wafAction === 'BLOCK' ||
    wafAction === 'CHALLENGE' ||
    httpStatus === 403 ||
    httpStatus === 406 ||
    corroboratingSignals.includes('WAF_INTERVENTION')
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
    wafAction,
    isBot: meta.isBot,
    confidenceLevel,
    corroboratingSignals,
    isClientClassificationUntrusted,
  };
}
