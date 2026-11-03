/**
 * VELTRIX Scanner Domain & Finding Types (Phase 8 - TASK-804)
 *
 * Defines the canonical types for passive and active vulnerability findings,
 * rule evaluator interfaces, and security assessment contracts.
 */

import type { CrawledPage } from './crawler/types.js';
import type { SafeHttpResponse } from './transport/types.js';

export type VulnerabilitySeverity =
  | 'CRITICAL'
  | 'HIGH'
  | 'MEDIUM'
  | 'LOW'
  | 'INFORMATIONAL';

export type FindingConfidence =
  | 'CONFIRMED'
  | 'HIGH'
  | 'MEDIUM'
  | 'LOW';

export interface FindingEvidence {
  readonly targetUrl: string;
  readonly method?: string;
  readonly responseStatus?: number;
  readonly responseHeaders?: Record<string, string>;
  readonly responseBodySnippet?: string;
  readonly observation?: string;
  readonly matchedPattern?: string;
  readonly [key: string]: unknown;
}

export interface ScannerFinding {
  readonly id?: string;
  readonly ruleId: string;
  readonly vulnerabilityType: string;
  readonly title: string;
  readonly severity: VulnerabilitySeverity;
  readonly confidence: FindingConfidence;
  readonly description: string;
  readonly remediation: string;
  readonly url: string;
  readonly endpoint?: string;
  readonly evidence: FindingEvidence;
  readonly timestamp?: string;
}

export interface PassiveRuleInterface {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  evaluate(page: CrawledPage, allPages?: readonly CrawledPage[]): readonly ScannerFinding[] | Promise<readonly ScannerFinding[]>;
}

export const RULE_PASSIVE_TLS = 'RULE_PASSIVE_TLS';
export const RULE_PASSIVE_HEADERS = 'RULE_PASSIVE_HEADERS';
export const RULE_PASSIVE_COOKIES = 'RULE_PASSIVE_COOKIES';
export const RULE_PASSIVE_DISCLOSURE = 'RULE_PASSIVE_DISCLOSURE';

export interface ActiveRuleExecutionContext {
  readonly timeoutMs: number;
  readonly signal?: AbortSignal;
  dispatchProbe(
    url: string,
    options?: {
      readonly method?: 'GET' | 'HEAD';
      readonly headers?: Record<string, string>;
    }
  ): Promise<SafeHttpResponse | null>;
}

export interface ActiveRuleInterface {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  evaluate(
    page: CrawledPage,
    context: ActiveRuleExecutionContext,
    allPages?: readonly CrawledPage[]
  ): Promise<readonly ScannerFinding[]>;
}

export const RULE_ACTIVE_XSS_CANARY = 'RULE_ACTIVE_XSS_CANARY';
export const RULE_ACTIVE_SQLI_ANOMALY = 'RULE_ACTIVE_SQLI_ANOMALY';
export const RULE_ACTIVE_OPEN_REDIRECT = 'RULE_ACTIVE_OPEN_REDIRECT';
export const RULE_ACTIVE_PATH_TRAVERSAL = 'RULE_ACTIVE_PATH_TRAVERSAL';

