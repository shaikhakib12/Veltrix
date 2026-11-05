/**
 * VELTRIX Scanner Secret Scrubber & Sanitizer (TASK-806)
 *
 * Sanitizes and redacts sensitive credentials, tokens, session IDs, and authorization
 * secrets from scanner evidence, HTTP headers, URLs, and reproduction curl commands.
 *
 * Invariants:
 * - Truncates response excerpts to a maximum ceiling of 64 KB (65,536 bytes).
 * - Redacts bearer tokens, basic auth credentials, session cookies, and private API keys.
 * - Scrubs sensitive URL query parameters (e.g. ?token=, ?secret=, ?password=).
 * - Safe for JSON, form-encoded, and plain-text snippets.
 */

export const MAX_EVIDENCE_EXCERPT_BYTES = 64 * 1024; // 64 KB

const SENSITIVE_PARAM_NAMES = new Set([
  'token',
  'access_token',
  'refresh_token',
  'id_token',
  'auth',
  'authorization',
  'api_key',
  'apikey',
  'key',
  'secret',
  'client_secret',
  'password',
  'passwd',
  'pwd',
  'session',
  'sessionid',
  'session_id',
  'sid',
  'jwt',
  'private_key',
]);

const SENSITIVE_HEADER_NAMES = new Set([
  'authorization',
  'proxy-authorization',
  'cookie',
  'set-cookie',
  'x-api-key',
  'api-key',
  'x-auth-token',
  'x-access-token',
  'x-secret-key',
]);

/**
 * Scrubs sensitive query parameters from a target URL while preserving pathname and structure.
 */
export function scrubUrl(url: string): string {
  try {
    const parsed = new URL(url);
    let modified = false;

    for (const [key] of parsed.searchParams.entries()) {
      if (SENSITIVE_PARAM_NAMES.has(key.toLowerCase())) {
        parsed.searchParams.set(key, '[REDACTED]');
        modified = true;
      }
    }

    if (parsed.password) {
      parsed.password = 'REDACTED';
      modified = true;
    }

    return modified ? parsed.toString() : url;
  } catch {
    return url;
  }
}

/**
 * Scrubs and redacts sensitive HTTP headers.
 */
export function scrubHeaders(
  headers: Record<string, string | undefined>
): Record<string, string> {
  const result: Record<string, string> = {};

  for (const [key, val] of Object.entries(headers)) {
    if (val === undefined) continue;
    const lowerKey = key.toLowerCase();

    if (SENSITIVE_HEADER_NAMES.has(lowerKey)) {
      if (lowerKey === 'cookie') {
        result[key] = val
          .split(';')
          .map((cookiePart) => {
            const eqIdx = cookiePart.indexOf('=');
            if (eqIdx === -1) return cookiePart.trim();
            const cName = cookiePart.slice(0, eqIdx).trim();
            return `${cName}=[REDACTED]`;
          })
          .join('; ');
      } else if (lowerKey === 'set-cookie') {
        const parts = val.split(';');
        const first = parts[0] || '';
        const eqIdx = first.indexOf('=');
        if (eqIdx !== -1) {
          const cName = first.slice(0, eqIdx).trim();
          parts[0] = `${cName}=[REDACTED]`;
        }
        result[key] = parts.join(';');
      } else {
        result[key] = '[REDACTED]';
      }
    } else {
      result[key] = val;
    }
  }

  return result;
}

/**
 * Truncates and sanitizes response bodies and evidence text to a maximum of 64 KB.
 */
export function scrubResponseBody(
  body: string | null | undefined,
  maxBytes = MAX_EVIDENCE_EXCERPT_BYTES
): string {
  if (!body) return '';

  let sanitized = body;

  // Basic regex pass for typical token patterns embedded in body
  sanitized = sanitized.replace(
    /(["']?(?:access_token|refresh_token|id_token|password|client_secret)["']?\s*[:=]\s*["'])([^"'\s]{4,})(["'])/gi,
    '$1[REDACTED]$3'
  );

  const buf = Buffer.from(sanitized, 'utf8');
  if (buf.length <= maxBytes) {
    return sanitized;
  }

  // Safe UTF-8 truncation
  const truncatedBuf = buf.subarray(0, maxBytes);
  return `${truncatedBuf.toString('utf8')}... [TRUNCATED at ${maxBytes} bytes]`;
}

/**
 * Generates a reproduction curl command with sensitive parameters and headers redacted.
 */
export function generateScrubbedCurl(
  method: string,
  url: string,
  headers?: Record<string, string>,
  body?: string
): string {
  const safeUrl = scrubUrl(url);
  const parts: string[] = ['curl', '-s', '-S', '-X', method.toUpperCase(), `"${safeUrl}"`];

  if (headers) {
    const safeHeaders = scrubHeaders(headers);
    for (const [k, v] of Object.entries(safeHeaders)) {
      parts.push('-H', `"${k}: ${v}"`);
    }
  }

  if (body && (method === 'POST' || method === 'PUT' || method === 'PATCH')) {
    const safeBody = scrubResponseBody(body, 4096);
    parts.push('-d', JSON.stringify(safeBody));
  }

  return parts.join(' ');
}
