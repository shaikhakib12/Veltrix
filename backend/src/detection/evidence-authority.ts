import { createHmac, createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import type {
  InternalTrustedEvidenceContext,
  VerifiedResponseEvidence,
} from '@veltrix/shared';

/**
 * Server-side allowlist of explicitly approved, authenticated internal verifiers.
 * Telemetry claiming to be verified by any identity outside this allowlist is rejected.
 */
export const APPROVED_INTERNAL_VERIFIERS = [
  'canary-service:v1',
  'core-scanner:active-audit',
  'internal-audit-worker:core',
  'sensor:canary:db',
  'sensor:canary:files',
  'collector:nginx:authenticated',
  'waf:edge-gateway:authenticated',
] as const;

export type ApprovedVerifierIdentity = (typeof APPROVED_INTERNAL_VERIFIERS)[number];

/**
 * Server-side allowlist of permissible verified signal identifiers.
 * Arbitrary or unapproved strings cannot be promoted to verified evidence.
 */
export const ALLOWED_VERIFIED_SIGNALS = [
  'CANARY_TOKEN_BREACH',
  'DATA_LEAKAGE_INDICATOR',
  'UNAUTHORIZED_PRIVILEGE_MUTATION',
  'UNHANDLED_DB_SYNTAX_ERROR',
  'STACK_TRACE_IN_RESPONSE',
  'LATENCY_SPIKE_EXPLOIT',
  'WAF_INTERVENTION',
  'AUTHENTICATED_WAF_BLOCK',
  'AUTHENTICATED_WAF_CHALLENGE',
] as const;

export type AllowedVerifiedSignal = (typeof ALLOWED_VERIFIED_SIGNALS)[number];

/**
 * Pre-shared internal service authentication credentials for approved backend services.
 * In production environments, these credentials are provided via secure environment
 * variables or AWS KMS / Secrets Manager.
 */
export const INTERNAL_SERVICE_CREDENTIALS: Record<ApprovedVerifierIdentity, string> = {
  'canary-service:v1': process.env.VELTRIX_CANARY_SERVICE_KEY || 'sec-svc-canary-prod-a79f1',
  'core-scanner:active-audit': process.env.VELTRIX_CORE_SCANNER_KEY || 'sec-svc-scanner-prod-b82e2',
  'internal-audit-worker:core': process.env.VELTRIX_AUDIT_WORKER_KEY || 'sec-svc-audit-prod-c31d3',
  'sensor:canary:db': process.env.VELTRIX_SENSOR_DB_KEY || 'sec-svc-db-prod-d44c4',
  'sensor:canary:files': process.env.VELTRIX_SENSOR_FILES_KEY || 'sec-svc-files-prod-e55b5',
  'collector:nginx:authenticated': process.env.VELTRIX_COLLECTOR_NGINX_KEY || 'sec-svc-nginx-prod-f66a6',
  'waf:edge-gateway:authenticated': process.env.VELTRIX_WAF_EDGE_KEY || 'sec-svc-waf-prod-07797',
};

export interface CreateEvidenceContextParams {
  /**
   * Required internal service authorization credential proving caller identity.
   * Unauthorized callers supplying an allowlisted string without matching secret are rejected.
   */
  serviceAuthToken: string;
  provenance: 'TRUSTED_SERVER_COMPONENT' | 'AUTHENTICATED_COLLECTOR';
  verifierIdentity: string;
  eventId: string;
  orgId: string;
  siteId?: string;
  verifiedSignalIdentifiers?: string[];
  evidenceReferences?: string[];
  verifiedResponseEvidence?: VerifiedResponseEvidence;
  verificationTimestamp?: string;
}

export interface ExpectedEventBinding {
  eventId?: string;
  orgId?: string;
  siteId?: string;
}

export interface CanonicalPayloadParams {
  version: 'VELTRIX_EVIDENCE_V2';
  eventId: string;
  orgId: string;
  siteId: string;
  provenance: string;
  verifierIdentity: string;
  signals: string[];
  evidenceReferences: string[];
  verificationTimestamp: string;
  responseBody?: string;
  errorMessage?: string;
  wafAction?: string;
  wafRuleId?: string;
}

/** Maximum age allowed for trusted evidence (15 minutes). */
export const MAX_EVIDENCE_AGE_MS = 15 * 60 * 1000;

/** Allowed clock skew tolerance for future timestamps (60 seconds). */
export const ALLOWED_CLOCK_SKEW_MS = 60 * 1000;

/**
 * Runtime internal capability authority that issues and verifies cryptographic capability
 * signatures on InternalTrustedEvidenceContext objects.
 *
 * Provides unforgeable tamper protection and event/tenant/site binding:
 * - Deterministic canonical serialization covering the COMPLETE context.
 * - Anti-replay and event binding (eventId, orgId, siteId).
 * - Caller service authentication via internal service credentials.
 * - Timestamp freshness checks (rejecting expired and future-dated contexts).
 * - Constant-time signature verification.
 */
export class InternalEvidenceAuthority {
  private readonly authoritySecret: string;
  private readonly serviceCredentials: Record<ApprovedVerifierIdentity, string>;

  constructor(secret?: string, customCredentials?: Partial<Record<ApprovedVerifierIdentity, string>>) {
    this.authoritySecret = secret || randomBytes(32).toString('hex');
    this.serviceCredentials = {
      ...INTERNAL_SERVICE_CREDENTIALS,
      ...(customCredentials || {}),
    };
  }

  /**
   * Constructs an authorized, signed InternalTrustedEvidenceContext.
   * Throws if:
   * 1. Service authentication fails for caller identity.
   * 2. Verifier identity or signal identifiers are not in the approved allowlists.
   * 3. EventId or OrgId bindings are missing.
   * 4. Verification timestamp is expired or future-dated.
   */
  createContext(params: CreateEvidenceContextParams): InternalTrustedEvidenceContext {
    // 1. Service authentication verification
    if (!params.serviceAuthToken || typeof params.serviceAuthToken !== 'string') {
      throw new Error(`UNAUTHORIZED_SERVICE: Missing service authentication credential for '${params.verifierIdentity}'`);
    }

    // 2. Validate verifier identity against server-side allowlist
    if (!APPROVED_INTERNAL_VERIFIERS.includes(params.verifierIdentity as ApprovedVerifierIdentity)) {
      throw new Error(
        `UNAUTHORIZED_VERIFIER_IDENTITY: '${params.verifierIdentity}' is not an approved server-side verifier. Allowed: ${APPROVED_INTERNAL_VERIFIERS.join(', ')}`
      );
    }

    const expectedToken = this.serviceCredentials[params.verifierIdentity as ApprovedVerifierIdentity];
    const actualTokenBuf = Buffer.from(params.serviceAuthToken);
    const expectedTokenBuf = Buffer.from(expectedToken);
    if (
      actualTokenBuf.length !== expectedTokenBuf.length ||
      !timingSafeEqual(actualTokenBuf, expectedTokenBuf)
    ) {
      throw new Error(
        `UNAUTHORIZED_SERVICE: Invalid service authentication credential for verifier '${params.verifierIdentity}'`
      );
    }

    // 3. Validate provenance
    if (
      params.provenance !== 'TRUSTED_SERVER_COMPONENT' &&
      params.provenance !== 'AUTHENTICATED_COLLECTOR'
    ) {
      throw new Error(`UNAUTHORIZED_PROVENANCE: '${params.provenance}' is not a valid trusted provenance level`);
    }

    // 4. Validate verified signal identifiers against server-side allowlist
    const signals = params.verifiedSignalIdentifiers || [];
    for (const sig of signals) {
      if (!ALLOWED_VERIFIED_SIGNALS.includes(sig as AllowedVerifiedSignal)) {
        throw new Error(
          `UNAUTHORIZED_SIGNAL_IDENTIFIER: '${sig}' is not in the allowed verified signals list. Allowed: ${ALLOWED_VERIFIED_SIGNALS.join(', ')}`
        );
      }
    }

    // 5. Validate event and tenant binding
    if (!params.eventId || typeof params.eventId !== 'string') {
      throw new Error('INVALID_EVENT_BINDING: eventId is required to bind evidence to its event');
    }
    if (!params.orgId || typeof params.orgId !== 'string') {
      throw new Error('INVALID_EVENT_BINDING: orgId is required to bind evidence to its tenant');
    }
    const siteId = params.siteId || '';

    // 6. Validate timestamp freshness
    const verificationTimestamp = params.verificationTimestamp || new Date().toISOString();
    const tsEpoch = new Date(verificationTimestamp).getTime();
    if (isNaN(tsEpoch)) {
      throw new Error(`INVALID_TIMESTAMP: Invalid ISO 8601 date '${verificationTimestamp}'`);
    }
    const now = Date.now();
    if (tsEpoch > now + ALLOWED_CLOCK_SKEW_MS) {
      throw new Error('INVALID_TIMESTAMP: Future-dated verification timestamp is rejected');
    }
    if (now - tsEpoch > MAX_EVIDENCE_AGE_MS) {
      throw new Error('INVALID_TIMESTAMP: Expired verification timestamp is rejected');
    }

    const evidenceReferences = Array.isArray(params.evidenceReferences) ? [...params.evidenceReferences] : [];

    // 7. Deterministic canonical serialization and signature
    const canonicalPayload = this.computeCanonicalPayload({
      version: 'VELTRIX_EVIDENCE_V2',
      eventId: params.eventId,
      orgId: params.orgId,
      siteId,
      provenance: params.provenance,
      verifierIdentity: params.verifierIdentity,
      signals,
      evidenceReferences,
      verificationTimestamp,
      responseBody: params.verifiedResponseEvidence?.responseBody,
      errorMessage: params.verifiedResponseEvidence?.errorMessage,
      wafAction: params.verifiedResponseEvidence?.wafAction,
      wafRuleId: params.verifiedResponseEvidence?.wafRuleId,
    });

    const signature = this.computeSignature(canonicalPayload);

    return {
      version: 'VELTRIX_EVIDENCE_V2',
      verifiedProvenance: params.provenance,
      verifiedSignalIdentifiers: [...signals],
      verifierIdentity: params.verifierIdentity,
      verificationTimestamp,
      eventId: params.eventId,
      orgId: params.orgId,
      siteId,
      evidenceReferences,
      authoritySignature: signature,
      verifiedResponseEvidence: params.verifiedResponseEvidence
        ? { ...params.verifiedResponseEvidence }
        : undefined,
    };
  }

  /**
   * Validates whether an evidence context:
   * 1. Matches version 'VELTRIX_EVIDENCE_V2'.
   * 2. Matches the approved verifier and signal allowlists.
   * 3. Matches expected eventId, orgId, and siteId bindings.
   * 4. Has a fresh timestamp (not in the future and not older than 15 minutes).
   * 5. Has a valid cryptographic HMAC-SHA256 signature computed over the COMPLETE payload.
   */
  verifyContext(
    context: unknown,
    expectedBinding?: ExpectedEventBinding
  ): context is InternalTrustedEvidenceContext {
    if (!context || typeof context !== 'object') {
      return false;
    }

    const c = context as InternalTrustedEvidenceContext;

    // Must be version 2
    if (c.version !== 'VELTRIX_EVIDENCE_V2') {
      return false;
    }

    // Must have an authority signature
    if (!c.authoritySignature || typeof c.authoritySignature !== 'string') {
      return false;
    }

    // Must have a valid provenance
    if (
      c.verifiedProvenance !== 'TRUSTED_SERVER_COMPONENT' &&
      c.verifiedProvenance !== 'AUTHENTICATED_COLLECTOR'
    ) {
      return false;
    }

    // Must have an approved verifier identity
    if (!APPROVED_INTERNAL_VERIFIERS.includes(c.verifierIdentity as ApprovedVerifierIdentity)) {
      return false;
    }

    // Must have valid signal identifiers
    if (!Array.isArray(c.verifiedSignalIdentifiers)) {
      return false;
    }
    for (const sig of c.verifiedSignalIdentifiers) {
      if (!ALLOWED_VERIFIED_SIGNALS.includes(sig as AllowedVerifiedSignal)) {
        return false;
      }
    }

    // Must have valid evidence references
    if (!Array.isArray(c.evidenceReferences)) {
      return false;
    }

    // Validate event and tenant bindings
    if (typeof c.eventId !== 'string' || typeof c.orgId !== 'string') {
      return false;
    }

    // Verify expected event binding if provided
    if (expectedBinding) {
      if (expectedBinding.eventId && c.eventId !== expectedBinding.eventId) {
        return false;
      }
      if (expectedBinding.orgId && c.orgId !== expectedBinding.orgId) {
        return false;
      }
      if (expectedBinding.siteId !== undefined) {
        const normExpectedSite = expectedBinding.siteId || '';
        const normContextSite = c.siteId || '';
        if (normExpectedSite !== normContextSite) {
          return false;
        }
      }
    }

    // Validate timestamp freshness
    const tsEpoch = new Date(c.verificationTimestamp).getTime();
    if (isNaN(tsEpoch)) {
      return false;
    }
    const now = Date.now();
    if (tsEpoch > now + ALLOWED_CLOCK_SKEW_MS) {
      return false;
    }
    if (now - tsEpoch > MAX_EVIDENCE_AGE_MS) {
      return false;
    }

    // Deterministic canonical serialization and signature verification
    const canonicalPayload = this.computeCanonicalPayload({
      version: c.version,
      eventId: c.eventId,
      orgId: c.orgId,
      siteId: c.siteId || '',
      provenance: c.verifiedProvenance,
      verifierIdentity: c.verifierIdentity,
      signals: c.verifiedSignalIdentifiers,
      evidenceReferences: c.evidenceReferences,
      verificationTimestamp: c.verificationTimestamp,
      responseBody: c.verifiedResponseEvidence?.responseBody,
      errorMessage: c.verifiedResponseEvidence?.errorMessage,
      wafAction: c.verifiedResponseEvidence?.wafAction,
      wafRuleId: c.verifiedResponseEvidence?.wafRuleId,
    });

    const expectedSignature = this.computeSignature(canonicalPayload);

    try {
      const expectedBuf = Buffer.from(expectedSignature, 'hex');
      const actualBuf = Buffer.from(c.authoritySignature, 'hex');
      if (expectedBuf.length !== actualBuf.length || !timingSafeEqual(expectedBuf, actualBuf)) {
        return false;
      }
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Deterministically canonicalizes all security-relevant fields into a normalized representation.
   * Arbitrary string fields (such as response bodies and error messages) are hashed with SHA-256
   * to guarantee collision-resistant integrity protection regardless of length or formatting.
   */
  private computeCanonicalPayload(params: CanonicalPayloadParams): string {
    const sortedSignals = [...(params.signals || [])].sort().join(',');
    const sortedRefs = [...(params.evidenceReferences || [])].sort().join(',');

    const respBodyHash =
      params.responseBody !== undefined
        ? createHash('sha256').update(params.responseBody).digest('hex')
        : 'NONE';

    const errMsgHash =
      params.errorMessage !== undefined
        ? createHash('sha256').update(params.errorMessage).digest('hex')
        : 'NONE';

    const wafActionStr = params.wafAction || 'NONE';
    const wafRuleIdStr = params.wafRuleId || 'NONE';

    return [
      'VELTRIX_CANONICAL_EVIDENCE_V2',
      `v=${params.version}`,
      `eid=${params.eventId}`,
      `org=${params.orgId}`,
      `site=${params.siteId}`,
      `prov=${params.provenance}`,
      `verifier=${params.verifierIdentity}`,
      `sigs=${sortedSignals}`,
      `refs=${sortedRefs}`,
      `ts=${params.verificationTimestamp}`,
      `respHash=${respBodyHash}`,
      `errHash=${errMsgHash}`,
      `wafAction=${wafActionStr}`,
      `wafRuleId=${wafRuleIdStr}`,
    ].join('\n');
  }

  private computeSignature(canonicalPayload: string): string {
    return createHmac('sha256', this.authoritySecret).update(canonicalPayload).digest('hex');
  }
}

let defaultAuthority: InternalEvidenceAuthority | undefined;

/**
 * Returns the process-wide internal evidence authority singleton for verification.
 */
export function getDefaultInternalEvidenceAuthority(): InternalEvidenceAuthority {
  if (!defaultAuthority) {
    defaultAuthority = new InternalEvidenceAuthority();
  }
  return defaultAuthority;
}

/**
 * Authorized internal service helper to construct signed evidence contexts.
 * Requires genuine service authentication credential.
 */
export function issueTrustedEvidenceContext(
  params: CreateEvidenceContextParams
): InternalTrustedEvidenceContext {
  return getDefaultInternalEvidenceAuthority().createContext(params);
}

/**
 * Test-only utility to reset or override the default authority.
 */
export function _resetInternalEvidenceAuthorityForTesting(
  authority?: InternalEvidenceAuthority
): void {
  defaultAuthority = authority;
}
