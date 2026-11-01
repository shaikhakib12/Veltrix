import type { Severity, EventCategory } from '@veltrix/shared';

export interface VeltrixClientConfig {
  apiKey: string;
  orgId: string;
  siteId?: string;
  endpoint?: string;
  maxBufferSize?: number;
  maxBufferSizeBytes?: number;
  bufferFlushIntervalMs?: number;
  maxRetries?: number;
  baseBackoffMs?: number;
  maxBackoffMs?: number;
  sanitizeParams?: string[];
  disabled?: boolean;
  sourceSystem?: string;
  fetcher?: (url: string, init?: RequestInit) => Promise<Response>;
}

export interface ClientHealthStats {
  status: 'HEALTHY' | 'DEGRADED' | 'DISCONNECTED';
  eventsQueued: number;
  eventsSent: number;
  eventsDropped: number;
  failedDeliveries: number;
  lastSuccessAt?: string;
  lastFailureAt?: string;
  lastError?: string;
}

export interface AuthEventOptions {
  success: boolean;
  username?: string;
  reason?: string;
  userId?: string;
  ipAddress?: string;
}

export interface PartialWebSecurityEvent {
  eventId?: string;
  timestamp?: string;
  eventType: string;
  severity: Severity;
  category: EventCategory;
  sourceIp: string;
  username?: string;
  sourceSystem?: string;
  metadata?: Record<string, unknown>;
  idempotencyKey?: string;
}
