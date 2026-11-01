import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  PutCommand,
  GetCommand,
} from '@aws-sdk/lib-dynamodb';

/** Maximum age allowed for trusted evidence (15 minutes). */
export const MAX_EVIDENCE_AGE_MS = 15 * 60 * 1000;

export interface ReplayRecord {
  nonce: string;
  eventId: string;
  orgId: string;
  siteId?: string;
  timestampEpoch: number; // verification timestamp epoch (ms)
  expiresAtEpoch: number; // timestampEpoch + MAX_EVIDENCE_AGE_MS (ms)
}

export interface ReplayConsumeResult {
  success: boolean;
  isReplayAttack: boolean;
  isIdempotentRetry: boolean;
  reason?: string;
}

export interface IReplayRegistry {
  /**
   * Consumes a nonce atomically.
   * If the nonce has not been seen, it is recorded and returns { success: true, isReplayAttack: false, isIdempotentRetry: false }.
   * If the nonce already exists with identical eventId, orgId, and siteId, returns:
   *   { success: false, isReplayAttack: false, isIdempotentRetry: true, reason: 'IDEMPOTENT_RETRY' }.
   * If the nonce exists with different eventId, orgId, or siteId, returns:
   *   { success: false, isReplayAttack: true, isIdempotentRetry: false, reason: 'REPLAY_ATTACK_NONCE_REUSED' }.
   */
  consumeNonce(record: ReplayRecord): Promise<ReplayConsumeResult>;

  /**
   * Synchronous consumption method for in-memory registry or fast paths.
   */
  consumeNonceSync?(record: ReplayRecord): ReplayConsumeResult;

  /**
   * Checks whether a nonce has been consumed.
   */
  hasNonce(nonce: string): Promise<boolean>;

  /**
   * Synchronous check for in-memory registry.
   */
  hasNonceSync?(nonce: string): boolean;

  /**
   * Clear all records (testing only).
   */
  clearForTesting?(): Promise<void> | void;
}

/**
 * In-memory sliding-window replay registry for single-use nonce tracking.
 * Used for development, local testing, or as an in-memory test fallback.
 */
export class MemoryReplayRegistry implements IReplayRegistry {
  private readonly records: Map<string, ReplayRecord & { consumedAt: string }>;
  private readonly maxAgeMs: number;

  constructor(
    sharedMap?: Map<string, ReplayRecord & { consumedAt: string }>,
    maxAgeMs = MAX_EVIDENCE_AGE_MS
  ) {
    this.records = sharedMap || new Map();
    this.maxAgeMs = maxAgeMs;
  }

  consumeNonceSync(record: ReplayRecord): ReplayConsumeResult {
    this.cleanup();
    const now = Date.now();

    // 15-minute expiration check independent of external TTL
    if (now - record.timestampEpoch > this.maxAgeMs || record.expiresAtEpoch < now) {
      return {
        success: false,
        isReplayAttack: false,
        isIdempotentRetry: false,
        reason: 'EVIDENCE_EXPIRED',
      };
    }

    const existing = this.records.get(record.nonce);
    if (existing) {
      // Check for legitimate idempotent retry of identical event
      if (
        existing.eventId === record.eventId &&
        existing.orgId === record.orgId &&
        (existing.siteId || '') === (record.siteId || '')
      ) {
        return {
          success: false,
          isReplayAttack: false,
          isIdempotentRetry: true,
          reason: 'IDEMPOTENT_RETRY',
        };
      }

      // Nonce re-used across different events, tenants, or sites: REPLAY ATTACK
      return {
        success: false,
        isReplayAttack: true,
        isIdempotentRetry: false,
        reason: 'REPLAY_ATTACK_NONCE_REUSED',
      };
    }

    this.records.set(record.nonce, {
      ...record,
      consumedAt: new Date(now).toISOString(),
    });

    return {
      success: true,
      isReplayAttack: false,
      isIdempotentRetry: false,
    };
  }

  async consumeNonce(record: ReplayRecord): Promise<ReplayConsumeResult> {
    return this.consumeNonceSync(record);
  }

  hasNonceSync(nonce: string): boolean {
    this.cleanup();
    const existing = this.records.get(nonce);
    if (!existing) return false;
    if (Date.now() > existing.expiresAtEpoch) {
      this.records.delete(nonce);
      return false;
    }
    return true;
  }

  async hasNonce(nonce: string): Promise<boolean> {
    return this.hasNonceSync(nonce);
  }

  clearForTesting(): void {
    this.records.clear();
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [nonce, record] of this.records.entries()) {
      if (now > record.expiresAtEpoch) {
        this.records.delete(nonce);
      }
    }
  }
}

/**
 * Backward-compatible alias for MemoryReplayRegistry.
 */
export class EvidenceReplayRegistry extends MemoryReplayRegistry {
  constructor(maxAgeMs = MAX_EVIDENCE_AGE_MS) {
    super(undefined, maxAgeMs);
  }

  /**
   * Legacy backward-compatible boolean consume signature.
   */
  consume(nonce: string, timestampEpoch: number): boolean {
    const res = this.consumeNonceSync({
      nonce,
      eventId: 'legacy-event',
      orgId: 'legacy-org',
      timestampEpoch,
      expiresAtEpoch: timestampEpoch + MAX_EVIDENCE_AGE_MS,
    });
    return res.success;
  }

  has(nonce: string): boolean {
    return this.hasNonceSync(nonce);
  }

  clear(): void {
    this.clearForTesting();
  }
}

export interface DynamoDBReplayRegistryOptions {
  docClient?: DynamoDBDocumentClient;
  client?: DynamoDBClient;
  tableName?: string;
  maxAgeMs?: number;
}

/**
 * Persistent atomic distributed replay registry backed by AWS DynamoDB.
 * Enforces single-use nonces across horizontally scaled Lambdas and ECS containers
 * via conditional writes (attribute_not_exists(PK)).
 *
 * Implements:
 * 1. Atomic conditional write: ConditionExpression: 'attribute_not_exists(PK)'
 * 2. Idempotency handling: If conditional check fails, retrieves existing record.
 *    If eventId, orgId, and siteId match identically, flags as IDEMPOTENT_RETRY.
 *    If any field differs, flags as REPLAY_ATTACK_NONCE_REUSED.
 * 3. 15-minute expiration check in application logic independent of DynamoDB TTL.
 * 4. DynamoDB TTL attribute set with 1-hour safety buffer for eventual background garbage collection.
 * 5. Fail-closed behavior on persistent storage unavailability in production.
 */
export class DynamoDBReplayRegistry implements IReplayRegistry {
  private docClient: DynamoDBDocumentClient;
  private readonly tableName: string;
  private readonly maxAgeMs: number;

  constructor(options?: DynamoDBReplayRegistryOptions) {
    const rawClient =
      options?.client ||
      new DynamoDBClient({ region: process.env.AWS_REGION || 'us-east-1' });

    this.docClient =
      options?.docClient ||
      DynamoDBDocumentClient.from(rawClient, {
        marshallOptions: { removeUndefinedValues: true },
      });

    const env = process.env.ENVIRONMENT || 'dev';
    this.tableName =
      options?.tableName ||
      process.env.DYNAMODB_REPLAY_TABLE ||
      `Veltrix-EvidenceReplay-${env}`;

    this.maxAgeMs = options?.maxAgeMs || MAX_EVIDENCE_AGE_MS;
  }

  async consumeNonce(record: ReplayRecord): Promise<ReplayConsumeResult> {
    const now = Date.now();

    // 1. Application-level 15-minute expiration check (independent of DynamoDB TTL)
    if (now - record.timestampEpoch > this.maxAgeMs || record.expiresAtEpoch < now) {
      return {
        success: false,
        isReplayAttack: false,
        isIdempotentRetry: false,
        reason: 'EVIDENCE_EXPIRED',
      };
    }

    // TTL epoch in seconds (includes 1-hour safety buffer for DynamoDB background expiration)
    const ttlSeconds = Math.floor((record.expiresAtEpoch + 3600 * 1000) / 1000);

    try {
      // 2. Atomic conditional write
      await this.docClient.send(
        new PutCommand({
          TableName: this.tableName,
          Item: {
            PK: `NONCE#${record.nonce}`,
            SK: 'REPLAY_RECORD',
            nonce: record.nonce,
            eventId: record.eventId,
            orgId: record.orgId,
            siteId: record.siteId || '',
            timestampEpoch: record.timestampEpoch,
            expiresAtEpoch: record.expiresAtEpoch,
            ttl: ttlSeconds,
            consumedAt: new Date(now).toISOString(),
          },
          ConditionExpression: 'attribute_not_exists(PK)',
        })
      );

      return {
        success: true,
        isReplayAttack: false,
        isIdempotentRetry: false,
      };
    } catch (err: unknown) {
      const errorObj = err as { name?: string; message?: string };

      if (errorObj?.name === 'ConditionalCheckFailedException') {
        // Nonce was already consumed. Retrieve existing item to differentiate
        // a legitimate idempotent ingestion retry from an active cross-event replay attack.
        try {
          const getRes = await this.docClient.send(
            new GetCommand({
              TableName: this.tableName,
              Key: {
                PK: `NONCE#${record.nonce}`,
                SK: 'REPLAY_RECORD',
              },
            })
          );

          const existing = getRes.Item;
          if (
            existing &&
            existing.eventId === record.eventId &&
            existing.orgId === record.orgId &&
            (existing.siteId || '') === (record.siteId || '')
          ) {
            return {
              success: false,
              isReplayAttack: false,
              isIdempotentRetry: true,
              reason: 'IDEMPOTENT_RETRY',
            };
          }
        } catch {
          // If read fails, fail-closed into replay attack classification
        }

        return {
          success: false,
          isReplayAttack: true,
          isIdempotentRetry: false,
          reason: 'REPLAY_ATTACK_NONCE_REUSED',
        };
      }

      // Fail-closed on persistent storage failure
      console.error(
        '[VELTRIX-REPLAY] Persistent storage error in DynamoDBReplayRegistry:',
        errorObj?.message || errorObj
      );
      throw new Error(
        `PERSISTENT_STORAGE_UNAVAILABLE: ${errorObj?.message || 'DynamoDB error'}`
      );
    }
  }

  async hasNonce(nonce: string): Promise<boolean> {
    try {
      const res = await this.docClient.send(
        new GetCommand({
          TableName: this.tableName,
          Key: {
            PK: `NONCE#${nonce}`,
            SK: 'REPLAY_RECORD',
          },
        })
      );

      if (!res.Item) return false;

      // 15-minute expiration check in application logic
      const now = Date.now();
      if (res.Item.expiresAtEpoch && res.Item.expiresAtEpoch < now) {
        return false;
      }

      return true;
    } catch (err: unknown) {
      const errorObj = err as { message?: string };
      console.error(
        '[VELTRIX-REPLAY] Failed to query nonce in DynamoDB:',
        errorObj?.message || errorObj
      );
      throw new Error(
        `PERSISTENT_STORAGE_UNAVAILABLE: ${errorObj?.message || 'DynamoDB error'}`
      );
    }
  }
}
