import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import type {
  InternalTrustedEvidenceContext,
  EvidenceProvenance,
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

export interface CreateEvidenceContextParams {
  provenance: 'TRUSTED_SERVER_COMPONENT' | 'AUTHENTICATED_COLLECTOR';
  verifierIdentity: string;
  verifiedSignalIdentifiers?: string[];
  evidenceReferences?: string[];
  verifiedResponseEvidence?: VerifiedResponseEvidence;
  verificationTimestamp?: string;
}

/**
 * Runtime internal capability authority that issues and verifies cryptographic capability
 * signatures on InternalTrustedEvidenceContext objects.
 *
 * This provides an unforgeable server-side boundary: external SDK users, webhooks, API callers,
 * and generic integrations do not have access to this authority instance or its secret.
 */
export class InternalEvidenceAuthority {
  private readonly authoritySecret: string;

  constructor(secret?: string) {
    this.authoritySecret = secret || randomBytes(32).toString('hex');
  }

  /**
   * Constructs an authorized, signed InternalTrustedEvidenceContext.
   * Throws if verifier identity or signal identifiers are not in the approved server-side allowlists.
   */
  createContext(params: CreateEvidenceContextParams): InternalTrustedEvidenceContext {
    // 1. Validate provenance
    if (
      params.provenance !== 'TRUSTED_SERVER_COMPONENT' &&
      params.provenance !== 'AUTHENTICATED_COLLECTOR'
    ) {
      throw new Error(`UNAUTHORIZED_PROVENANCE: '${params.provenance}' is not a valid trusted provenance level`);
    }

    // 2. Validate verifier identity against server-side allowlist
    if (!APPROVED_INTERNAL_VERIFIERS.includes(params.verifierIdentity as ApprovedVerifierIdentity)) {
      throw new Error(
        `UNAUTHORIZED_VERIFIER_IDENTITY: '${params.verifierIdentity}' is not an approved server-side verifier. Allowed: ${APPROVED_INTERNAL_VERIFIERS.join(', ')}`
      );
    }

    // 3. Validate verified signal identifiers against server-side allowlist
    const signals = params.verifiedSignalIdentifiers || [];
    for (const sig of signals) {
      if (!ALLOWED_VERIFIED_SIGNALS.includes(sig as AllowedVerifiedSignal)) {
        throw new Error(
          `UNAUTHORIZED_SIGNAL_IDENTIFIER: '${sig}' is not in the allowed verified signals list. Allowed: ${ALLOWED_VERIFIED_SIGNALS.join(', ')}`
        );
      }
    }

    const verificationTimestamp = params.verificationTimestamp || new Date().toISOString();
    const evidenceReferences = Array.isArray(params.evidenceReferences) ? [...params.evidenceReferences] : [];

    // 4. Compute cryptographic capability signature
    const signature = this.computeSignature(
      params.provenance,
      params.verifierIdentity,
      signals,
      verificationTimestamp
    );

    return {
      verifiedProvenance: params.provenance,
      verifiedSignalIdentifiers: [...signals],
      verifierIdentity: params.verifierIdentity,
      verificationTimestamp,
      evidenceReferences,
      authoritySignature: signature,
      verifiedResponseEvidence: params.verifiedResponseEvidence
        ? { ...params.verifiedResponseEvidence }
        : undefined,
    };
  }

  /**
   * Validates whether an evidence context was issued by this authority, matches the approved allowlists,
   * and has a valid, untampered HMAC signature.
   */
  verifyContext(context: unknown): context is InternalTrustedEvidenceContext {
    if (!context || typeof context !== 'object') {
      return false;
    }

    const c = context as InternalTrustedEvidenceContext;

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

    // Verify cryptographic capability signature using constant-time comparison
    const expectedSignature = this.computeSignature(
      c.verifiedProvenance,
      c.verifierIdentity,
      c.verifiedSignalIdentifiers,
      c.verificationTimestamp
    );

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

  private computeSignature(
    provenance: EvidenceProvenance,
    verifierIdentity: string,
    signals: string[],
    timestamp: string
  ): string {
    const sortedSignals = [...signals].sort().join(',');
    const canonicalPayload = `VELTRIX_EVIDENCE_V1:${provenance}:${verifierIdentity}:${sortedSignals}:${timestamp}`;
    return createHmac('sha256', this.authoritySecret).update(canonicalPayload).digest('hex');
  }
}

let defaultAuthority: InternalEvidenceAuthority | undefined;

/**
 * Returns the process-wide internal evidence authority singleton.
 */
export function getDefaultInternalEvidenceAuthority(): InternalEvidenceAuthority {
  if (!defaultAuthority) {
    defaultAuthority = new InternalEvidenceAuthority();
  }
  return defaultAuthority;
}

/**
 * Resets or overrides the default authority (for test isolation).
 */
export function resetDefaultInternalEvidenceAuthorityForTesting(authority?: InternalEvidenceAuthority): void {
  defaultAuthority = authority;
}
