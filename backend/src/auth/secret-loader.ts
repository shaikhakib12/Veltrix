import {
  SecretsManagerClient,
  GetSecretValueCommand,
} from '@aws-sdk/client-secrets-manager';
import {
  APPROVED_INTERNAL_VERIFIERS,
  SERVICE_ENV_VAR_NAMES,
  MIN_KEY_BYTE_LENGTH,
  type ApprovedVerifierIdentity,
} from '../detection/evidence-authority.js';

export interface SecretLoaderConfig {
  client?: SecretsManagerClient;
  signingKeySecretId?: string;
  serviceCredentialsSecretId?: string;
  cacheTtlMs?: number;
  strictEnforcement?: boolean;
}

export interface LoadedSecrets {
  signingKey?: string;
  rotatedVerificationKeys: string[];
  serviceCredentials: Partial<Record<ApprovedVerifierIdentity, string[]>>;
}

/**
 * Production-ready AWS Secrets Manager & Environment Secret Loader.
 *
 * Implements:
 * 1. Runtime retrieval of 256-bit HMAC signing keys and internal service tokens.
 * 2. Separation of HMAC signing keys from verifier service credentials.
 * 3. In-memory caching with configurable TTL (default 5 minutes) to protect against rate limits.
 * 4. Multi-token support for key rotation windows without downtime.
 * 5. Strict fail-closed enforcement in production if secrets cannot be loaded.
 */
export class SecretLoader {
  private client: SecretsManagerClient;
  private readonly signingKeySecretId: string;
  private readonly serviceCredentialsSecretId: string;
  private readonly cacheTtlMs: number;
  private readonly isProduction: boolean;

  private cachedSecrets: LoadedSecrets | null = null;
  private cacheExpiry: number = 0;

  constructor(config?: SecretLoaderConfig) {
    const region = process.env.AWS_REGION || 'us-east-1';
    this.client = config?.client || new SecretsManagerClient({ region });

    const env = process.env.ENVIRONMENT || 'dev';
    this.signingKeySecretId =
      config?.signingKeySecretId ||
      process.env.VELTRIX_EVIDENCE_SIGNING_KEY_SECRET_ARN ||
      `veltrix/evidence-signing-key-${env}`;

    this.serviceCredentialsSecretId =
      config?.serviceCredentialsSecretId ||
      process.env.VELTRIX_SERVICE_CREDENTIALS_SECRET_ARN ||
      `veltrix/evidence-service-credentials-${env}`;

    this.cacheTtlMs = config?.cacheTtlMs || 5 * 60 * 1000; // 5 minutes default
    this.isProduction =
      process.env.NODE_ENV === 'production' || config?.strictEnforcement === true;
  }

  /**
   * Loads secrets, using cached values if within cacheTtlMs.
   */
  async loadSecrets(forceRefresh: boolean = false): Promise<LoadedSecrets> {
    const now = Date.now();
    if (!forceRefresh && this.cachedSecrets && now < this.cacheExpiry) {
      return this.cachedSecrets;
    }

    // 1. First, check direct environment variables
    const envSigningKey = process.env.VELTRIX_EVIDENCE_SIGNING_KEY;
    const envRotatedKeys = process.env.VELTRIX_EVIDENCE_ROTATED_KEYS
      ? process.env.VELTRIX_EVIDENCE_ROTATED_KEYS.split(',').map((k: string) => k.trim()).filter(Boolean)
      : [];

    const envServiceCreds: Partial<Record<ApprovedVerifierIdentity, string[]>> = {};
    for (const verifier of APPROVED_INTERNAL_VERIFIERS) {
      const envVar = SERVICE_ENV_VAR_NAMES[verifier];
      const val = process.env[envVar];
      if (val) {
        envServiceCreds[verifier] = val.split(',').map((t: string) => t.trim()).filter(Boolean);
      }
    }

    let smSigningKey: string | undefined;
    let smRotatedKeys: string[] = [];
    const smServiceCreds: Partial<Record<ApprovedVerifierIdentity, string[]>> = {};

    // 2. If in AWS environment or explicit secret ID provided, attempt Secrets Manager fetch
    const shouldFetchSecretsManager =
      process.env.STORAGE_MODE === 'aws' ||
      Boolean(process.env.VELTRIX_EVIDENCE_SIGNING_KEY_SECRET_ARN) ||
      this.isProduction;

    if (shouldFetchSecretsManager) {
      try {
        const signingSecretRes = await this.client.send(
          new GetSecretValueCommand({ SecretId: this.signingKeySecretId })
        );

        if (signingSecretRes.SecretString) {
          try {
            const parsed = JSON.parse(signingSecretRes.SecretString);
            smSigningKey = parsed.signingKey || parsed.VELTRIX_EVIDENCE_SIGNING_KEY;
            if (parsed.rotatedKeys && Array.isArray(parsed.rotatedKeys)) {
              smRotatedKeys = parsed.rotatedKeys;
            }
          } catch {
            smSigningKey = signingSecretRes.SecretString.trim();
          }
        }
      } catch (err: unknown) {
        const msg = (err as Error).message || String(err);
        if (this.isProduction && !envSigningKey) {
          console.error('[VELTRIX-SECRETS] Failed to fetch signing key from Secrets Manager in production:', msg);
          throw new Error(`SECRETS_MANAGER_FETCH_FAILED: Unable to load signing key: ${msg}`);
        }
      }

      try {
        const credsSecretRes = await this.client.send(
          new GetSecretValueCommand({ SecretId: this.serviceCredentialsSecretId })
        );

        if (credsSecretRes.SecretString) {
          try {
            const parsed = JSON.parse(credsSecretRes.SecretString);
            if (parsed.canaryService) {
              smServiceCreds['canary-service:v1'] = [parsed.canaryService];
            }
            if (parsed.collectorNginx) {
              smServiceCreds['collector:nginx:authenticated'] = [parsed.collectorNginx];
            }
            if (parsed.wafEdge) {
              smServiceCreds['waf:edge-gateway:authenticated'] = [parsed.wafEdge];
            }
            if (parsed.internalTesting) {
              smServiceCreds['veltrix:internal:testing'] = [parsed.internalTesting];
            }
          } catch {
            // SecretString was not JSON
          }
        }
      } catch (err: unknown) {
        const msg = (err as Error).message || String(err);
        if (this.isProduction && Object.keys(envServiceCreds).length === 0) {
          console.error('[VELTRIX-SECRETS] Failed to fetch service credentials from Secrets Manager in production:', msg);
          throw new Error(`SECRETS_MANAGER_FETCH_FAILED: Unable to load service credentials: ${msg}`);
        }
      }
    }

    // Merge env and Secrets Manager results (Secrets Manager takes precedence in AWS mode)
    const finalSigningKey = smSigningKey || envSigningKey;
    const finalRotatedKeys = [
      ...new Set([...smRotatedKeys, ...envRotatedKeys]),
    ].filter((k) => k !== finalSigningKey && Buffer.from(k).length >= MIN_KEY_BYTE_LENGTH);

    const finalServiceCreds: Partial<Record<ApprovedVerifierIdentity, string[]>> = {};
    for (const verifier of APPROVED_INTERNAL_VERIFIERS) {
      const smTokens = smServiceCreds[verifier] || [];
      const envTokens = envServiceCreds[verifier] || [];
      const combined = [...new Set([...smTokens, ...envTokens])];
      if (combined.length > 0) {
        finalServiceCreds[verifier] = combined;
      }
    }

    if (this.isProduction) {
      if (!finalSigningKey) {
        throw new Error(
          'FATAL_KEY_CONFIG_ERROR: No valid signing key found in Secrets Manager or environment for production.'
        );
      }
      if (Buffer.from(finalSigningKey).length < MIN_KEY_BYTE_LENGTH) {
        throw new Error(
          `FATAL_KEY_CONFIG_ERROR: Resolved signing key has insufficient entropy (< ${MIN_KEY_BYTE_LENGTH} bytes).`
        );
      }
    }

    this.cachedSecrets = {
      signingKey: finalSigningKey,
      rotatedVerificationKeys: finalRotatedKeys,
      serviceCredentials: finalServiceCreds,
    };
    this.cacheExpiry = now + this.cacheTtlMs;

    return this.cachedSecrets;
  }

  clearCacheForTesting(): void {
    this.cachedSecrets = null;
    this.cacheExpiry = 0;
  }
}

let defaultSecretLoader: SecretLoader | null = null;

export function getDefaultSecretLoader(): SecretLoader {
  if (!defaultSecretLoader) {
    defaultSecretLoader = new SecretLoader();
  }
  return defaultSecretLoader;
}

export function resetDefaultSecretLoaderForTesting(): void {
  defaultSecretLoader = null;
}
