import type { SecurityEvent, Severity, EventCategory } from '@veltrix/shared';

export interface LogParserContext {
  orgId: string;
  siteId?: string;
  sourceSystem?: string;
}

export interface ParseBatchResult {
  events: SecurityEvent[];
  validCount: number;
  malformedCount: number;
  errors: Array<{ lineIndex: number; error: string; rawLine: string }>;
}

export interface LogParserInterface {
  parseLine(line: string, context: LogParserContext, lineIndex?: number): SecurityEvent | null;
  parseBatch(lines: string[] | string, context: LogParserContext): ParseBatchResult;
}

export function parseApacheTimestamp(timeStr: string): string {
  // Format: "10/Nov/2026:14:32:10 +0000" or ISO 8601
  if (timeStr.includes('T')) {
    const d = new Date(timeStr);
    return !isNaN(d.getTime()) ? d.toISOString() : new Date().toISOString();
  }

  // Format: DD/Mon/YYYY:HH:MM:SS +/-ZZZZ
  const match = timeStr.match(/^(\d{2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s+([+\-]\d{4})$/);
  if (!match) {
    const d = new Date(timeStr);
    return !isNaN(d.getTime()) ? d.toISOString() : new Date().toISOString();
  }

  const [, day, mon, year, hour, min, sec, tz] = match;
  const monthMap: Record<string, string> = {
    Jan: '01', Feb: '02', Mar: '03', Apr: '04', May: '05', Jun: '06',
    Jul: '07', Aug: '08', Sep: '09', Oct: '10', Nov: '11', Dec: '12',
  };

  const month = monthMap[mon!] || '01';
  const tzFormatted = `${tz!.slice(0, 3)}:${tz!.slice(3)}`;
  const isoStr = `${year}-${month}-${day}T${hour}:${min}:${sec}${tzFormatted}`;
  const parsed = new Date(isoStr);
  return !isNaN(parsed.getTime()) ? parsed.toISOString() : new Date().toISOString();
}

export function detectWebAttackType(
  _method: string,
  uri: string,
  statusCode: number
): {
  eventType: string;
  severity: Severity;
  category: EventCategory;
  matchedPatterns?: string[];
  confidenceLevel: 'SUSPICIOUS_ATTEMPT' | 'BLOCKED_ATTEMPT' | 'POTENTIAL_EXPLOITATION' | 'CONFIRMED_EXPLOITATION';
} {
  const uriLower = uri.toLowerCase();

  // SQL Injection
  if (
    /('|\%27).*?(or|and|union|select|insert|update|delete|drop|benchmark|sleep)/i.test(uriLower) ||
    /union\s+select/i.test(uriLower) ||
    /--|#|\/\*/.test(uriLower)
  ) {
    return {
      eventType: 'web.attack.sqli',
      severity: 'HIGH',
      category: 'NETWORK',
      matchedPatterns: ['SQLI_KEYWORDS'],
      confidenceLevel: statusCode === 403 ? 'BLOCKED_ATTEMPT' : 'SUSPICIOUS_ATTEMPT',
    };
  }

  // XSS
  if (
    /<script/i.test(uriLower) ||
    /javascript:/i.test(uriLower) ||
    /onload=|onerror=|onclick=/i.test(uriLower)
  ) {
    return {
      eventType: 'web.attack.xss',
      severity: 'MEDIUM',
      category: 'NETWORK',
      matchedPatterns: ['XSS_PAYLOAD'],
      confidenceLevel: statusCode === 403 ? 'BLOCKED_ATTEMPT' : 'SUSPICIOUS_ATTEMPT',
    };
  }

  // Path Traversal
  if (
    /(\.\.\/|\.\.\\)/.test(uri) ||
    /\/etc\/passwd/.test(uriLower) ||
    /\/boot\.ini/.test(uriLower) ||
    /windows\/win\.ini/.test(uriLower)
  ) {
    return {
      eventType: 'web.attack.traversal',
      severity: 'HIGH',
      category: 'NETWORK',
      matchedPatterns: ['PATH_TRAVERSAL'],
      confidenceLevel: statusCode === 403 ? 'BLOCKED_ATTEMPT' : 'SUSPICIOUS_ATTEMPT',
    };
  }

  // Benign request
  return {
    eventType: 'web.request.normal',
    severity: 'LOW',
    category: 'NETWORK',
    confidenceLevel: 'SUSPICIOUS_ATTEMPT',
  };
}
