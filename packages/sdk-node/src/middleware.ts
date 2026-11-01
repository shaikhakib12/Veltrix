import type { Request, Response, NextFunction } from 'express';
import type { Severity, EventCategory } from '@veltrix/shared';
import type { VeltrixClient } from './client.js';

export interface MiddlewareOptions {
  sampleRate?: number;
  captureAllRequests?: boolean;
}

export function veltrixMiddleware(client: VeltrixClient, options?: MiddlewareOptions) {
  const captureAll = options?.captureAllRequests ?? true;

  return (req: Request, res: Response, next: NextFunction): void => {
    const startTime = Date.now();

    // Strictly non-blocking: proceed immediately to business logic!
    next();

    // Asynchronous hook on response completion
    res.on('finish', () => {
      try {
        const responseTimeMs = Date.now() - startTime;
        const statusCode = res.statusCode;
        const method = req.method;
        const originalUrl = req.originalUrl || req.url;
        const userAgent = req.headers['user-agent'] as string | undefined;

        const clientIp =
          req.ip ||
          req.socket.remoteAddress ||
          (Array.isArray(req.headers['x-forwarded-for'])
            ? req.headers['x-forwarded-for'][0]
            : (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim()) ||
          '127.0.0.1';

        // Lightweight pattern analysis on URI and query (safe against malformed percent sequences)
        let uriDecoded = originalUrl;
        try {
          uriDecoded = decodeURIComponent(originalUrl);
        } catch {
          uriDecoded = originalUrl;
        }
        const attackAnalysis = analyzeRequest(method, uriDecoded, statusCode);

        if (!attackAnalysis.isAttack && !captureAll) {
          return;
        }

        client.recordEvent({
          eventType: attackAnalysis.eventType,
          severity: attackAnalysis.severity,
          category: attackAnalysis.category,
          sourceIp: clientIp,
          username: (req as { user?: { username?: string } }).user?.username,
          metadata: {
            httpMethod: method,
            requestUri: originalUrl,
            httpStatus: statusCode,
            responseTimeMs,
            userAgent,
            matchedPatterns: attackAnalysis.matchedPatterns,
            confidenceLevel: attackAnalysis.confidenceLevel,
          },
        });
      } catch {
        // Fail-open: SDK errors must never crash or impact host app
      }
    });
  };
}

function analyzeRequest(
  _method: string,
  uri: string,
  status: number
): {
  isAttack: boolean;
  eventType: string;
  severity: Severity;
  category: EventCategory;
  matchedPatterns?: string[];
  confidenceLevel: 'SUSPICIOUS_ATTEMPT' | 'BLOCKED_ATTEMPT' | 'POTENTIAL_EXPLOITATION' | 'CONFIRMED_EXPLOITATION';
} {
  const uriLower = uri.toLowerCase();

  // 1. SQL Injection Heuristics
  if (
    /('|\%27).*?(or|and|union|select|insert|update|delete|drop|benchmark|sleep)/i.test(uriLower) ||
    /union\s+select/i.test(uriLower) ||
    /--|#|\/\*/.test(uriLower)
  ) {
    return {
      isAttack: true,
      eventType: 'web.attack.sqli',
      severity: 'HIGH',
      category: 'NETWORK',
      matchedPatterns: ['SQLI_KEYWORDS'],
      confidenceLevel: status === 403 ? 'BLOCKED_ATTEMPT' : 'SUSPICIOUS_ATTEMPT',
    };
  }

  // 2. Cross-Site Scripting (XSS) Heuristics
  if (
    /<script/i.test(uriLower) ||
    /javascript:/i.test(uriLower) ||
    /onload=|onerror=|onclick=/i.test(uriLower)
  ) {
    return {
      isAttack: true,
      eventType: 'web.attack.xss',
      severity: 'MEDIUM',
      category: 'NETWORK',
      matchedPatterns: ['XSS_PAYLOAD'],
      confidenceLevel: status === 403 ? 'BLOCKED_ATTEMPT' : 'SUSPICIOUS_ATTEMPT',
    };
  }

  // 3. Path Traversal Heuristics
  if (
    /(\.\.\/|\.\.\\)/.test(uri) ||
    /\/etc\/passwd/.test(uriLower) ||
    /\/boot\.ini/.test(uriLower) ||
    /windows\/win\.ini/.test(uriLower)
  ) {
    return {
      isAttack: true,
      eventType: 'web.attack.traversal',
      severity: 'HIGH',
      category: 'NETWORK',
      matchedPatterns: ['PATH_TRAVERSAL'],
      confidenceLevel: status === 403 ? 'BLOCKED_ATTEMPT' : 'SUSPICIOUS_ATTEMPT',
    };
  }

  // Baseline normal request
  return {
    isAttack: false,
    eventType: 'web.request.normal',
    severity: 'LOW',
    category: 'NETWORK',
    confidenceLevel: 'SUSPICIOUS_ATTEMPT',
  };
}
