import { AuditRecord, AuditVerificationResult } from '../shared/types/index.js';
import { sha256, generateId } from '../shared/utils/crypto.js';
import { MemoryStore } from '../shared/db/memoryStore.js';

export class AuditLogger {
  private store: MemoryStore;

  constructor(store?: MemoryStore) {
    this.store = store || MemoryStore.getInstance();
  }

  /**
   * Appends an auditable record to the cryptographic ledger.
   */
  public log(
    orgId: string,
    actor: string,
    action: string,
    targetResource: string,
    result: 'SUCCESS' | 'FAILURE' | 'DENIED',
    metadata: Record<string, unknown> = {}
  ): AuditRecord {
    const timestamp = new Date().toISOString();
    const logId = generateId('audit');

    // Get previous record's integrity hash (or genesis hash)
    const logs = this.store.auditLogs;
    const lastRecord = logs.length > 0 ? logs[logs.length - 1] : null;
    const previousHash = lastRecord 
      ? lastRecord.integrityHash 
      : '0000000000000000000000000000000000000000000000000000000000000000';

    const payloadToHash = {
      logId,
      orgId,
      timestamp,
      actor,
      action,
      targetResource,
      result,
      metadata,
      previousHash,
    };

    const integrityHash = sha256(payloadToHash);

    const record: AuditRecord = {
      logId,
      orgId,
      timestamp,
      actor,
      action,
      targetResource,
      result,
      metadata,
      previousHash,
      integrityHash,
    };

    this.store.auditLogs.push(record);
    return record;
  }

  /**
   * Verifies the cryptographic integrity of the audit log chain.
   */
  public verifyChain(records?: AuditRecord[]): AuditVerificationResult {
    const logs = records || this.store.auditLogs;

    if (logs.length === 0) {
      return {
        verified: true,
        totalRecordsChecked: 0,
        timestamp: new Date().toISOString(),
      };
    }

    for (let i = 0; i < logs.length; i++) {
      const record = logs[i];

      // Genesis check
      if (i === 0) {
        if (record.logId === 'audit-genesis') {
          continue;
        }
      }

      // Check chaining from previous record
      if (i > 0) {
        const prev = logs[i - 1];
        if (record.previousHash !== prev.integrityHash) {
          return {
            verified: false,
            totalRecordsChecked: i,
            brokenRecordId: record.logId,
            error: `Hash chain discontinuity at record ${record.logId}. Expected previousHash ${prev.integrityHash}, found ${record.previousHash}.`,
            timestamp: new Date().toISOString(),
          };
        }
      }

      // Verify self-integrity hash
      const payloadToHash = {
        logId: record.logId,
        orgId: record.orgId,
        timestamp: record.timestamp,
        actor: record.actor,
        action: record.action,
        targetResource: record.targetResource,
        result: record.result,
        metadata: record.metadata,
        previousHash: record.previousHash,
      };

      const calculatedHash = sha256(payloadToHash);
      if (calculatedHash !== record.integrityHash) {
        return {
          verified: false,
          totalRecordsChecked: i,
          brokenRecordId: record.logId,
          error: `Tampering detected at record ${record.logId}. Signature mismatch. Expected ${calculatedHash}, found ${record.integrityHash}.`,
          timestamp: new Date().toISOString(),
        };
      }
    }

    return {
      verified: true,
      totalRecordsChecked: logs.length,
      timestamp: new Date().toISOString(),
    };
  }
}
