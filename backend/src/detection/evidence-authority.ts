import { createHmac, createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import type {
  InternalTrustedEvidenceContext,
  EvidenceProvenance,
  VerifiedResponseEvidence,
} from '@veltrix/shared';
import {
  type IReplayRegistry,
  type ReplayRecord,
  type ReplayConsumeResult,
  MemoryReplayRegistry,
  DynamoDBReplayRegistry,
  EvidenceReplayRegistry,
  MAX_EVIDENCE_AGE_MS,
} from './replay-registry.js';

export {
  type IReplayRegistry,
  type ReplayRecord,
  type ReplayConsumeResult,
  MemoryReplayRegistry,
  DynamoDBReplayRegistry,
  EvidenceReplayRegistry,
  MAX_EVIDENCE_AGE_MS,
};

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
  'veltrix:internal:testing',
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
  'OUT_OF_BAND_CALLBACK_CONFIRMED',
  'SYSTEM_COMMAND_EXECUTION_DETECTED',
  'CORE_FILE_INTEGRITY_COMPROMISED',
  'KNOWN_ATTACK_PATTERN_PROBE',
  'AUTHENTICATION_BYPASS_ATTEMPT',
] as const;

export type AllowedVerifiedSignal = (typeof ALLOWED_VERIFIED_SIGNALS)[number];

/**
 * Environment variable names used for service credential authentication.
 * Production and staging deployments inject unique, high-entropy secrets per service.
 */
export const SERVICE_ENV_VAR_NAMES: Record<ApprovedVerifierIdentity, string> = {
  'canary-service:v1': 'VELTRIX_AUTH_CANARY_SERVICE',
  'core-scanner:active-audit': 'VELTRIX_AUTH_CORE_SCANNER',
  'internal-audit-worker:core': 'VELTRIX_AUTH_AUDIT_WORKER',
  'sensor:canary:db': 'VELTRIX_AUTH_SENSOR_CANARY_DB',
  'sensor:canary:files': 'VELTRIX_AUTH_SENSOR_CANARY_FILES',
  'collector:nginx:authenticated': 'VELTRIX_AUTH_COLLECTOR_NGINX',
  'waf:edge-gateway:authenticated': 'VELTRIX_AUTH_WAF_EDGE',
  'veltrix:internal:testing': 'VELTRIX_AUTH_INTERNAL_TESTING',
};

export interface CreateEvidenceContextParams {
  /** Caller service authentication token for verifier identity verification. */
  serviceAuthToken: string;
  provenance: EvidenceProvenance;
  verifierIdentity: ApprovedVerifierIdentity;
  eventId: string;
  orgId: string;
  siteId?: string;
  nonce?: string;
  verifiedSignalIdentifiers?: AllowedVerifiedSignal[];
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
  nonce: string;
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

export interface AuthorityConfig {
  /** Primary HMAC signing key (minimum 32 bytes / 256 bits). */
  signingKey?: string;
  /** Rotated keys accepted for verification during key rotation windows. */
  rotatedVerificationKeys?: string[];
  /** Service credentials map (verifier -> secret token or list of valid rotated tokens). */
  serviceCredentials?: Partial<Record<ApprovedVerifierIdentity, string | string[]>>;
  /** Enforce strict fail-closed behavior on missing configuration. Defaults to true in production. */
  strictEnforcement?: boolean;
  /** Custom replay registry instance. In production defaults to DynamoDBReplayRegistry; otherwise MemoryReplayRegistry. */
  replayRegistry?: IReplayRegistry;
}

/** Allowed clock skew tolerance for future timestamps (60 seconds). */
export const ALLOWED_CLOCK_SKEW_MS = 60 * 1000;

/** Minimum byte length required for cryptographic signing keys (256 bits). */
export const MIN_KEY_BYTE_LENGTH = 32;

/**
 * Runtime internal capability authority that issues and verifies cryptographic capability
 * signatures on InternalTrustedEvidenceContext objects.
 *
 * Implements:
 * 1. Fail-closed service credential management (no hardcoded credentials).
 * 2. Key lifecycle management with minimum 256-bit entropy and key rotation support.
 * 3. Separation of caller credentials from HMAC signing keys.
 * 4. Deterministic canonical serialization covering the COMPLETE context (including nonce).
 * 5. Single-use replay protection via persistent atomic DynamoDB conditional writes or in-memory fallback.
 * 6. Strict event, tenant, and website binding.
 */
export class InternalEvidenceAuthority {
  private readonly signingKey: string;
  private readonly rotatedVerificationKeys: string[];
  private readonly serviceCredentials = new Map<ApprovedVerifierIdentity, string[]>();
  private readonly replayRegistry: IReplayRegistry;
  private readonly isProduction: boolean;

  constructor(config?: AuthorityConfig) {
    this.isProduction = process.env.NODE_ENV === 'production' || config?.strictEnforcement === true;

    // Initialize replay registry: custom, DynamoDB in AWS/prod, or MemoryReplayRegistry
    if (config?.replayRegistry) {
      this.replayRegistry = config.replayRegistry;
    } else if (
      this.isProduction &&
      (process.env.STORAGE_MODE === 'aws' || Boolean(process.env.DYNAMODB_REPLAY_TABLE))
    ) {
      this.replayRegistry = new DynamoDBReplayRegistry();
    } else {
      this.replayRegistry = new MemoryReplayRegistry();
    }

    // 1. Resolve and validate HMAC signing key
    const envSigningKey = process.env.VELTRIX_EVIDENCE_SIGNING_KEY;
    const resolvedKey = config?.signingKey || envSigningKey;

    if (!resolvedKey) {
      if (this.isProduction) {
        throw new Error(
          'FATAL_KEY_CONFIG_ERROR: VELTRIX_EVIDENCE_SIGNING_KEY must be securely configured with at least 32 bytes in production.'
        );
      }
      // In development/test mode without an explicit key, generate an ephemeral 256-bit key
      this.signingKey = randomBytes(MIN_KEY_BYTE_LENGTH).toString('hex');
    } else {
      if (Buffer.from(resolvedKey).length < MIN_KEY_BYTE_LENGTH) {
        throw new Error(
          `FATAL_KEY_CONFIG_ERROR: Signing key must be at least ${MIN_KEY_BYTE_LENGTH} bytes (256 bits) for cryptographic security.`
        );
      }
      this.signingKey = resolvedKey;
    }

    // 2. Resolve rotated verification keys
    const envRotatedKeys = process.env.VELTRIX_EVIDENCE_ROTATED_KEYS
      ? process.env.VELTRIX_EVIDENCE_ROTATED_KEYS.split(',').map((k) => k.trim()).filter(Boolean)
      : [];
    this.rotatedVerificationKeys = [
      ...(config?.rotatedVerificationKeys || []),
      ...envRotatedKeys,
    ].filter((k) => k !== this.signingKey && Buffer.from(k).length >= MIN_KEY_BYTE_LENGTH);

    // 3. Resolve service credentials (from config or environment, NO hardcoded fallbacks)
    for (const verifier of APPROVED_INTERNAL_VERIFIERS) {
      const tokens: string[] = [];
      const envVarName = SERVICE_ENV_VAR_NAMES[verifier];
      const envVal = process.env[envVarName];
      if (envVal) {
        tokens.push(...envVal.split(',').map((t: string) => t.trim()).filter(Boolean));
      }
      const configVal = config?.serviceCredentials?.[verifier];
      if (configVal) {
        if (Array.isArray(configVal)) {
          tokens.push(...configVal.map((t: string) => t.trim()).filter(Boolean));
        } else if (typeof configVal === 'string' && configVal.trim()) {
          tokens.push(configVal.trim());
        }
      }
      if (tokens.length > 0) {
        this.serviceCredentials.set(verifier, Array.from(new Set(tokens)));
      }
    }
  }

  getReplayRegistry(): IReplayRegistry {
    return this.replayRegistry;
  }

  /**
   * Constructs an authorized, signed InternalTrustedEvidenceContext.
   * Fails closed if:
   * 1. Service credentials are not configured.
   * 2. Caller service authentication fails.
   * 3. Verifier identity or signals are outside allowlists.
   * 4. EventId or OrgId bindings are missing.
   * 5. Verification timestamp is expired or future-dated.
   */
  createContext(params: CreateEvidenceContextParams): InternalTrustedEvidenceContext {
    // 1. Validate verifier identity against server-side allowlist
    if (!APPROVED_INTERNAL_VERIFIERS.includes(params.verifierIdentity)) {
      throw new Error(
        `UNAUTHORIZED_VERIFIER_IDENTITY: '${params.verifierIdentity}' is not an approved server-side verifier. Allowed: ${APPROVED_INTERNAL_VERIFIERS.join(', ')}`
      );
    }

    const verifier = params.verifierIdentity;

    // 2. Fail closed if no credential is configured for this verifier
    const validCredentials = this.serviceCredentials.get(verifier);
    if (!validCredentials || validCredentials.length === 0) {
      throw new Error(
        `UNCONFIGURED_SERVICE_CREDENTIAL: No authentication credential configured for verifier '${verifier}'. Service authentication must fail closed.`
      );
    }

    // 3. Authenticate caller credential using timing-safe comparison
    if (!params.serviceAuthToken || typeof params.serviceAuthToken !== 'string') {
      throw new Error(`UNAUTHORIZED_SERVICE: Missing service authentication credential for '${verifier}'`);
    }

    const actualTokenBuf = Buffer.from(params.serviceAuthToken);
    let isAuthenticated = false;
    for (const expectedToken of validCredentials) {
      const expectedTokenBuf = Buffer.from(expectedToken);
      if (
        actualTokenBuf.length === expectedTokenBuf.length &&
        timingSafeEqual(actualTokenBuf, expectedTokenBuf)
      ) {
        isAuthenticated = true;
        break;
      }
    }

    if (!isAuthenticated) {
      throw new Error(
        `UNAUTHORIZED_SERVICE: Invalid service authentication credential for verifier '${verifier}'`
      );
    }

    // 4. Validate provenance
    if (
      params.provenance !== 'TRUSTED_SERVER_COMPONENT' &&
      params.provenance !== 'AUTHENTICATED_COLLECTOR'
    ) {
      throw new Error(`UNAUTHORIZED_PROVENANCE: '${params.provenance}' is not a valid trusted provenance level`);
    }

    // 5. Validate verified signal identifiers against server-side allowlist
    const signals = params.verifiedSignalIdentifiers || [];
    for (const sig of signals) {
      if (!ALLOWED_VERIFIED_SIGNALS.includes(sig)) {
        throw new Error(
          `UNAUTHORIZED_SIGNAL_IDENTIFIER: '${sig}' is not in the allowed verified signals list. Allowed: ${ALLOWED_VERIFIED_SIGNALS.join(', ')}`
        );
      }
    }

    // 6. Validate event and tenant binding
    if (!params.eventId || typeof params.eventId !== 'string') {
      throw new Error('INVALID_EVENT_BINDING: eventId is required to bind evidence to its event');
    }
    if (!params.orgId || typeof params.orgId !== 'string') {
      throw new Error('INVALID_EVENT_BINDING: orgId is required to bind evidence to its tenant');
    }
    const siteId = params.siteId || '';

    // 7. Validate timestamp freshness
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

    // 8. Generate single-use nonce
    const nonce = params.nonce || randomBytes(16).toString('hex');
    const evidenceReferences = Array.isArray(params.evidenceReferences) ? [...params.evidenceReferences] : [];

    // 9. Deterministic canonical serialization and signature
    const canonicalPayload = this.computeCanonicalPayload({
      version: 'VELTRIX_EVIDENCE_V2',
      nonce,
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

    const signature = this.computeSignature(canonicalPayload, this.signingKey);

    return {
      version: 'VELTRIX_EVIDENCE_V2',
      nonce,
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
   * Verifies context signature, binding, and freshness WITHOUT consuming the single-use nonce.
   */
  verifyContext(
    context: unknown,
    expectedBinding?: ExpectedEventBinding
  ): context is InternalTrustedEvidenceContext {
    return this.internalVerify(context, expectedBinding, false);
  }

  /**
   * Verifies context signature, binding, and freshness AND consumes the single-use nonce.
   * If the nonce has already been consumed (replay attack), returns false.
   * If the nonce was consumed by the identical event (idempotent retry), returns true.
   */
  verifyAndConsumeContext(
    context: unknown,
    expectedBinding?: ExpectedEventBinding
  ): context is InternalTrustedEvidenceContext {
    return this.internalVerify(context, expectedBinding, true);
  }

  /**
   * Asynchronously verifies context and consumes single-use nonce in distributed replay storage.
   */
  async verifyAndConsumeContextAsync(
    context: unknown,
    expectedBinding?: ExpectedEventBinding
  ): Promise<boolean> {
    return this.internalVerifyAsync(context, expectedBinding, true);
  }

  /**
   * Asynchronously verifies context WITHOUT consuming single-use nonce.
   */
  async verifyContextAsync(
    context: unknown,
    expectedBinding?: ExpectedEventBinding
  ): Promise<boolean> {
    return this.internalVerifyAsync(context, expectedBinding, false);
  }

  private internalVerify(
    context: unknown,
    expectedBinding: ExpectedEventBinding | undefined,
    consumeNonce: boolean
  ): context is InternalTrustedEvidenceContext {
    const validated = this.validateContextStructureAndSignature(context, expectedBinding);
    if (!validated) {
      return false;
    }

    const { c, tsEpoch } = validated;

    if (consumeNonce) {
      if (this.replayRegistry.consumeNonceSync) {
        const consumeResult = this.replayRegistry.consumeNonceSync({
          nonce: c.nonce,
          eventId: c.eventId,
          orgId: c.orgId,
          siteId: c.siteId || '',
          timestampEpoch: tsEpoch,
          expiresAtEpoch: tsEpoch + MAX_EVIDENCE_AGE_MS,
        });

        if (consumeResult.isReplayAttack) {
          console.warn(`[VELTRIX-SECURITY] Replay attack detected: nonce '${c.nonce}' has already been consumed`);
          return false;
        }

        if (consumeResult.isIdempotentRetry) {
          console.warn(`[VELTRIX-SECURITY] Idempotent retry detected for nonce '${c.nonce}'; context already consumed`);
          return false;
        }

        if (!consumeResult.success) {
          console.warn(`[VELTRIX-SECURITY] Nonce consumption rejected: ${consumeResult.reason}`);
          return false;
        }
      } else {
        // Asynchronous-only registry (e.g. DynamoDB) called from synchronous verification method
        if (this.isProduction) {
          console.error(
            '[VELTRIX-SECURITY] Synchronous verification invoked in production with persistent replay registry. Failing closed; use verifyAndConsumeContextAsync.'
          );
          return false;
        }
      }
    }

    return true;
  }

  private async internalVerifyAsync(
    context: unknown,
    expectedBinding: ExpectedEventBinding | undefined,
    consumeNonce: boolean
  ): Promise<boolean> {
    const validated = this.validateContextStructureAndSignature(context, expectedBinding);
    if (!validated) {
      return false;
    }

    const { c, tsEpoch } = validated;

    if (consumeNonce) {
      try {
        const consumeResult = await this.replayRegistry.consumeNonce({
          nonce: c.nonce,
          eventId: c.eventId,
          orgId: c.orgId,
          siteId: c.siteId || '',
          timestampEpoch: tsEpoch,
          expiresAtEpoch: tsEpoch + MAX_EVIDENCE_AGE_MS,
        });

        if (consumeResult.isReplayAttack) {
          console.warn(`[VELTRIX-SECURITY] Replay attack detected: nonce '${c.nonce}' has already been consumed`);
          return false;
        }

        if (consumeResult.isIdempotentRetry) {
          console.warn(`[VELTRIX-SECURITY] Idempotent retry detected for nonce '${c.nonce}'; context already consumed`);
          return false;
        }

        if (!consumeResult.success) {
          console.warn(`[VELTRIX-SECURITY] Nonce consumption rejected: ${consumeResult.reason}`);
          return false;
        }
      } catch (err) {
        if (this.isProduction) {
          console.error('[VELTRIX-SECURITY] Persistent replay verification failed in production. Failing closed:', err);
          return false;
        }
        throw err;
      }
    }

    return true;
  }

  private validateContextStructureAndSignature(
    context: unknown,
    expectedBinding: ExpectedEventBinding | undefined
  ): { c: InternalTrustedEvidenceContext; tsEpoch: number } | null {
    if (!context || typeof context !== 'object') {
      return null;
    }

    const c = context as InternalTrustedEvidenceContext;

    // 1. Version check
    if (c.version !== 'VELTRIX_EVIDENCE_V2') {
      return null;
    }

    // 2. Nonce check
    if (!c.nonce || typeof c.nonce !== 'string') {
      return null;
    }

    // 3. Signature format check
    if (!c.authoritySignature || typeof c.authoritySignature !== 'string') {
      return null;
    }

    // 4. Provenance check
    if (
      c.verifiedProvenance !== 'TRUSTED_SERVER_COMPONENT' &&
      c.verifiedProvenance !== 'AUTHENTICATED_COLLECTOR'
    ) {
      return null;
    }

    // 5. Approved verifier check
    if (!APPROVED_INTERNAL_VERIFIERS.includes(c.verifierIdentity as ApprovedVerifierIdentity)) {
      return null;
    }

    // 6. Signal allowlist check
    if (!Array.isArray(c.verifiedSignalIdentifiers)) {
      return null;
    }
    for (const sig of c.verifiedSignalIdentifiers) {
      if (!ALLOWED_VERIFIED_SIGNALS.includes(sig as AllowedVerifiedSignal)) {
        return null;
      }
    }

    // 7. Evidence references check
    if (!Array.isArray(c.evidenceReferences)) {
      return null;
    }

    // 8. Event and tenant binding checks
    if (typeof c.eventId !== 'string' || typeof c.orgId !== 'string') {
      return null;
    }

    if (expectedBinding) {
      if (expectedBinding.eventId && c.eventId !== expectedBinding.eventId) {
        return null;
      }
      if (expectedBinding.orgId && c.orgId !== expectedBinding.orgId) {
        return null;
      }
      if (expectedBinding.siteId !== undefined) {
        const normExpectedSite = expectedBinding.siteId || '';
        const normContextSite = c.siteId || '';
        if (normExpectedSite !== normContextSite) {
          return null;
        }
      }
    }

    // 9. Freshness checks
    const tsEpoch = new Date(c.verificationTimestamp).getTime();
    if (isNaN(tsEpoch)) {
      return null;
    }
    const now = Date.now();
    if (tsEpoch > now + ALLOWED_CLOCK_SKEW_MS) {
      return null;
    }
    if (now - tsEpoch > MAX_EVIDENCE_AGE_MS) {
      return null;
    }

    // 10. Deterministic canonical payload re-computation
    const canonicalPayload = this.computeCanonicalPayload({
      version: c.version,
      nonce: c.nonce,
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

    // 11. Constant-time signature verification (trying current key and rotated keys)
    const actualBuf = Buffer.from(c.authoritySignature, 'hex');
    const allKeys = [this.signingKey, ...this.rotatedVerificationKeys];
    let signatureValid = false;

    for (const key of allKeys) {
      const expectedSig = this.computeSignature(canonicalPayload, key);
      const expectedBuf = Buffer.from(expectedSig, 'hex');
      if (expectedBuf.length === actualBuf.length && timingSafeEqual(expectedBuf, actualBuf)) {
        signatureValid = true;
        break;
      }
    }

    if (!signatureValid) {
      return null;
    }

    return { c, tsEpoch };
  }

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
      `nonce=${params.nonce}`,
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

  private computeSignature(canonicalPayload: string, secret: string): string {
    return createHmac('sha256', secret).update(canonicalPayload).digest('hex');
  }

  /**
   * Resets replay registry (used for test isolation).
   */
  clearReplayRegistryForTesting(): void {
    if (this.replayRegistry.clearForTesting) {
      this.replayRegistry.clearForTesting();
    }
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

/**
 * Test-only utility to clear default replay registry.
 */
export function clearReplayRegistryForTesting(): void {
  if (defaultAuthority) {
    defaultAuthority.clearReplayRegistryForTesting();
  }
}
