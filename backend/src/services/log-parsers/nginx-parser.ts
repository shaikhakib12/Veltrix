import { randomUUID } from 'node:crypto';
import type { SecurityEvent } from '@veltrix/shared';
import {
  type LogParserInterface,
  type LogParserContext,
  type ParseBatchResult,
  detectWebAttackType,
  parseApacheTimestamp,
} from './base-parser.js';

export class NginxLogParser implements LogParserInterface {
  // Regex for Nginx standard combined format:
  // $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
  private static readonly COMBINED_REGEX =
    /^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^"]+?)(?:\s+HTTP\/[\d.]+)"\s+(\d{3})\s+(\d+|-)(?:\s+"([^"]*)"\s+"([^"]*)")?/;

  parseLine(line: string, context: LogParserContext, _lineIndex = 0): SecurityEvent | null {
    const trimmed = line.trim();
    if (!trimmed) return null;

    // Mode 1: JSON formatted access log (veltrix_json format)
    if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
      try {
        const obj = JSON.parse(trimmed);
        const sourceIp = obj.sourceIp || obj.remote_addr || '127.0.0.1';
        const httpMethod = (obj.httpMethod || obj.request_method || 'GET').toUpperCase();
        const requestUri = obj.requestUri || obj.request_uri || '/';
        const httpStatus = parseInt(obj.httpStatus || obj.status || '200', 10);
        const responseTimeMs = typeof obj.responseTimeMs === 'number' ? obj.responseTimeMs : undefined;
        const userAgent = obj.userAgent || obj.http_user_agent;
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
          username: obj.remote_user && obj.remote_user !== '-' ? obj.remote_user : undefined,
          sourceSystem: context.sourceSystem || 'collector:nginx',
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

    // Mode 2: Standard Nginx combined access log
    const match = trimmed.match(NginxLogParser.COMBINED_REGEX);
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
      sourceSystem: context.sourceSystem || 'collector:nginx',
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
            error: 'Malformed or unrecognized Nginx log format',
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
