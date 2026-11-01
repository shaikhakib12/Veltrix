import { randomUUID } from 'node:crypto';
import type { SecurityEvent } from '@veltrix/shared';
import {
  type LogParserInterface,
  type LogParserContext,
  type ParseBatchResult,
  detectWebAttackType,
  parseApacheTimestamp,
} from './base-parser.js';

export class ApacheLogParser implements LogParserInterface {
  // Regex for Apache Common/Combined Log format:
  // %h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"
  private static readonly APACHE_REGEX =
    /^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^"]+?)(?:\s+HTTP\/[\d.]+)"\s+(\d{3})\s+(\d+|-)(?:\s+"([^"]*)"\s+"([^"]*)")?/;

  parseLine(line: string, context: LogParserContext, _lineIndex = 0): SecurityEvent | null {
    const trimmed = line.trim();
    if (!trimmed) return null;

    // Mode 1: JSON formatted log
    if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
      try {
        const obj = JSON.parse(trimmed);
        const sourceIp = obj.sourceIp || obj.ip || obj.clientIp || '127.0.0.1';
        const httpMethod = (obj.httpMethod || obj.method || 'GET').toUpperCase();
        const requestUri = obj.requestUri || obj.uri || obj.path || '/';
        const httpStatus = parseInt(obj.httpStatus || obj.status || '200', 10);
        const responseTimeMs = typeof obj.responseTimeMs === 'number' ? obj.responseTimeMs : undefined;
        const userAgent = obj.userAgent || obj['user-agent'];
        const timestamp = obj.timestamp ? parseApacheTimestamp(obj.timestamp) : new Date().toISOString();

        const attackAnalysis = detectWebAttackType(httpMethod, requestUri, httpStatus);

        return {
          eventId: randomUUID(),
          orgId: context.orgId,
          timestamp,
          eventType: attackAnalysis.eventType,
          severity: attackAnalysis.severity,
          category: attackAnalysis.category,
          sourceIp,
          username: obj.user && obj.user !== '-' ? obj.user : undefined,
          sourceSystem: context.sourceSystem || 'collector:apache',
          metadata: {
            siteId: context.siteId,
            domain: obj.host,
            httpMethod,
            requestUri,
            httpStatus,
            responseTimeMs,
            userAgent,
            matchedPatterns: attackAnalysis.matchedPatterns,
            confidenceLevel: attackAnalysis.confidenceLevel,
          },
          isSimulated: false,
        };
      } catch {
        // Fall through to regex parse
      }
    }

    // Mode 2: Apache standard common/combined log
    const match = trimmed.match(ApacheLogParser.APACHE_REGEX);
    if (!match) {
      return null;
    }

    const [, sourceIp, remoteUser, timeLocal, httpMethod, requestUri, statusStr, , , userAgent] = match;
    const httpStatus = parseInt(statusStr!, 10);
    const timestamp = parseApacheTimestamp(timeLocal!);
    const attackAnalysis = detectWebAttackType(httpMethod!, requestUri!, httpStatus);

    return {
      eventId: randomUUID(),
      orgId: context.orgId,
      timestamp,
      eventType: attackAnalysis.eventType,
      severity: attackAnalysis.severity,
      category: attackAnalysis.category,
      sourceIp: sourceIp!,
      username: remoteUser && remoteUser !== '-' ? remoteUser : undefined,
      sourceSystem: context.sourceSystem || 'collector:apache',
      metadata: {
        siteId: context.siteId,
        httpMethod: httpMethod!,
        requestUri: requestUri!,
        httpStatus,
        userAgent,
        matchedPatterns: attackAnalysis.matchedPatterns,
        confidenceLevel: attackAnalysis.confidenceLevel,
      },
      isSimulated: false,
    };
  }

  parseBatch(lines: string[] | string, context: LogParserContext): ParseBatchResult {
    const lineArray = Array.isArray(lines) ? lines : lines.split(/\r?\n/);
    const events: SecurityEvent[] = [];
    const errors: Array<{ lineIndex: number; error: string; rawLine: string }> = [];

    lineArray.forEach((line, index) => {
      const trimmed = line.trim();
      if (!trimmed) return;

      try {
        const event = this.parseLine(trimmed, context, index);
        if (event) {
          events.push(event);
        } else {
          errors.push({
            lineIndex: index,
            error: 'Malformed or unrecognized Apache log format',
            rawLine: trimmed.length > 200 ? trimmed.slice(0, 200) + '...' : trimmed,
          });
        }
      } catch (err: unknown) {
        errors.push({
          lineIndex: index,
          error: (err as Error).message || 'Parsing error',
          rawLine: trimmed.length > 200 ? trimmed.slice(0, 200) + '...' : trimmed,
        });
      }
    });

    return {
      events,
      validCount: events.length,
      malformedCount: errors.length,
      errors,
    };
  }
}
