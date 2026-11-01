# VELTRIX: DynamoDB Schema & Access Patterns (`specs/database-schema.md`)

**Document Version:** 2.2.0 (Verified & Sharding-Hardened)  
**Status:** In Review (Phase 1 Final Verification)  
**Database Engine:** Amazon DynamoDB (On-Demand / `PAY_PER_REQUEST`)  
**Data Encryption:** AWS KMS (AES-256) at rest  

---

## 1. Table Definitions & Key Schemas

VELTRIX uses access-optimized tables designed around specific query access patterns, incorporating time-sharding on high-velocity telemetry to eliminate hot-partition bottlenecks.

| Table Name | Partition Key (PK) | Sort Key (SK) | Global Secondary Indexes (GSI) | TTL Attribute |
| :--- | :--- | :--- | :--- | :--- |
| **`Veltrix-SecurityEvents`** | `ORG#{orgId}#DATE#{YYYY-MM-DD}` *(Optional `#SHARD#{0..N-1}`)* | `EVENT#{timestampIso}#{eventId}` | `GSI1_PK: ORG#{orgId}#TYPE#{eventType}`, `GSI1_SK: timestampIso`<br/>`GSI2_PK: ORG#{orgId}#IP#{sourceIp}`, `GSI2_SK: timestampIso` | `ttl` (Epoch seconds, 30 days) |
| **`Veltrix-Incidents`** | `ORG#{orgId}` | `INCIDENT#{timestampIso}#{incidentId}` | `GSI1_PK: ORG#{orgId}#STATUS#{status}`, `GSI1_SK: riskScore` (Numeric)<br/>`GSI2_PK: ORG#{orgId}#SEVERITY#{severity}`, `GSI2_SK: timestampIso` | `ttl` (Epoch seconds, 90 days) |
| **`Veltrix-DetectionRules`** | `ORG#{orgId}` | `RULE#{ruleId}` | `GSI1_PK: category`, `GSI1_SK: severity` | — |
| **`Veltrix-ThreatIndicators`** | `INDICATOR#{type}` | `VALUE#{value}` | `GSI1_PK: severity`, `GSI1_SK: confidence` (Numeric) | — |
| **`Veltrix-ResponseExecutions`**| `ORG#{orgId}` | `RESP#{timestampIso}#{executionId}` | `GSI1_PK: INCIDENT#{incidentId}`, `GSI1_SK: timestampIso` | `ttl` (Epoch seconds, 60 days) |
| **`Veltrix-AuditLogs`** | `ORG#{orgId}` | `AUDIT#{timestampIso}#{logId}` | `GSI1_PK: ORG#{orgId}#ACTOR#{actorId}`, `GSI1_SK: timestampIso` | Retained (WORM Archival) |
| **`Veltrix-AuditState`** | `ORG#{orgId}` | `STATE` | — | Checkpoint State |

---

## 2. Event Idempotency & Atomic Duplicate Prevention

### Client Retries & Event ID Stability
- Ingesting systems (syslog agents, web gateway middleware, Simulation Lab) generate a client-side `eventId` (UUIDv7 or UUIDv4) or explicit `idempotencyKey` once.
- Across network timeouts or HTTP 5xx retries, the client MUST transmit the exact same `eventId` and `idempotencyKey`.

### Atomic Conditional Write Pattern
When writing to `Veltrix-SecurityEvents`:
```json
{
  "TableName": "Veltrix-SecurityEvents",
  "Item": {
    "PK": "ORG#org-enterprise-01#DATE#2026-10-31",
    "SK": "EVENT#2026-10-31T22:15:30.120Z#018d5f30-74e1-7cb2-b43a-e9fa651f8b1c",
    "idempotencyKey": "018d5f30-74e1-7cb2-b43a-e9fa651f8b1c",
    "eventType": "auth.login.failed",
    "sourceIp": "198.51.100.42",
    "username": "sarah.connors",
    "ttl": 1796169330
  },
  "ConditionExpression": "attribute_not_exists(PK) AND attribute_not_exists(SK)"
}
```
- **Handling Retries:** If a retry occurs with the same `PK` and `SK`, DynamoDB throws `ConditionalCheckFailedException`. The ingestion handler catches this exception, suppresses the duplicate, and returns `202 Accepted` with status `DUPLICATE_SUPPRESSED` so the client does not retry indefinitely.
- **Handling High-Velocity Brute Force:** Legitimate repeated failed logins generated within milliseconds of each other possess unique `eventId` values. Their `SK` values differ, so `attribute_not_exists` evaluates to true, and **every distinct failed attempt is atomically recorded**.
- **Tenant Isolation on Deduplication:** All keys are prefixed with `ORG#{orgId}`, preventing cross-organization collision or malicious idempotency lockouts.

---

## 3. DynamoDB Write Sharding Strategy

### Daily Partition Evaluation ($N = 1$ Baseline)
- A single DynamoDB physical partition can sustain $1,000\text{ WCU}$ ($1,000\text{ writes/sec}$ for items $\le 1\text{ KB}$).
- For normal workloads and demonstration scenarios ($100,000\text{ events/month} \approx 2.3\text{ events/min}$, with peak simulation bursts of $50–100\text{ events/sec}$), a daily partition key `ORG#{orgId}#DATE#{YYYY-MM-DD}` is well within partition limits and maintains simple, deterministic queries.

### High-Volume Write Sharding ($N > 1$)
For enterprise organizations generating sustained high-velocity telemetry ($> 1,000\text{ events/sec}$):
- Partition key formula:
  $$\text{PK} = \text{ORG\#}\{\text{orgId}\}\text{\#DATE\#}\{\text{YYYY-MM-DD}\}\text{\#SHARD\#}\{\text{shardId}\}$$
  where $\text{shardId} = \text{hash}(\text{eventId}) \pmod N$, and $N \in \{1, 4, 8\}$.
- **Initial Implementation:** $N = 1$ (no suffix, maintaining simplicity). The table design isolates sharding to a helper function `getEventPartitionKey(orgId, timestamp, shardCount)` allowing dynamic shard scaling per organization tier without breaking existing data.

### Multi-Shard Query Aggregation (Scatter-Gather)
When $N > 1$, reading a day's telemetry requires scatter-gather aggregation:
1. Issue $N$ parallel `Query` calls for shards $0$ through $N-1$ using `Promise.all()`.
2. Perform a k-way merge-sort on the results ordered by `SK` (`timestampIso` descending).
3. Pagination across shards uses a compound cursor structure: `nextCursor = base64(JSON.stringify({ shards: [cursor0, cursor1, ... cursorN-1] }))`.

---

## 4. Global Secondary Indexes & Query Access Patterns

### Access Pattern 1: Query events by type across a time range
- **Index:** `GSI1-EventType`
- **Key Condition:** `GSI1_PK = ORG#{orgId}#TYPE#{eventType} AND GSI1_SK BETWEEN :startTime AND :endTime`
- **Purpose:** Sub-second retrieval of all failed authentications (`auth.login.failed`) or data exfiltrations.

### Access Pattern 2: Forensic lookup of all activity from a specific IP
- **Index:** `GSI2-SourceIp`
- **Key Condition:** `GSI2_PK = ORG#{orgId}#IP#{sourceIp} AND GSI2_SK BETWEEN :startTime AND :endTime`
- **Purpose:** Fast attacker IP dossier generation.

### Access Pattern 3: Query active incidents sorted by risk score
- **Index:** `Veltrix-Incidents` `GSI1-StatusRisk`
- **Key Condition:** `GSI1_PK = ORG#{orgId}#STATUS#NEW` ordered descending by numeric `riskScore`.
- **Purpose:** Direct retrieval of highest-priority threats for SOC triage.

---

## 5. S3 Object Lock & Compliance Archival

### Prototype vs Production-Grade Hardening
1. **Prototype / Competition Environment:**
   - Audit trail is secured via application-level SHA-256 hash chaining in DynamoDB (`Veltrix-AuditLogs`).
   - One-click API `POST /api/v1/audit-logs/verify-chain` verifies hash continuity and detects tampering in real-time.
2. **Production-Grade Compliance Hardening (Optional Cloud Architecture):**
   - **S3 Bucket Versioning:** Mandatory prerequisite for S3 Object Lock; enabled on bucket creation.
   - **Object Lock Configuration:** Configured in **Compliance Mode** (or **Governance Mode** if emergency administrative overrides are required with `s3:BypassGovernanceRetention`).
   - **Replication Flow:** DynamoDB Streams $\to$ AWS Kinesis Data Firehose $\to$ S3 Object Lock Bucket with a default 365-day retention policy.
   - **Recovery Considerations:** Once placed in Compliance Mode, even root accounts cannot delete objects until retention expires. For test/demo environments, Governance Mode or standard versioning is recommended to allow decommissioning without account lockup.

---

## 6. Threat Detection Storage & Keyset Pagination (Phase 5)

### Incidents Table Dual-Use Record Layout (`Veltrix-Incidents`)
Threat detections generated by the autonomous Detection Engine are stored directly in `Veltrix-Incidents-${Environment}` using dedicated sort key prefixes and indexes:

| Record Type | Partition Key (PK) | Sort Key (SK) | GSI1 (`GSI1-RuleIndex` / `StatusRisk`) | GSI2 (`GSI2-SeverityIndex`) | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Primary Detection** | `ORG#{orgId}` | `DETECTION#{detectedAt}#{detectionId}` | `GSI1_PK: ORG#{orgId}#RULE#{ruleId}`<br/>`GSI1_SK: detectedAt` | `GSI2_PK: ORG#{orgId}#SEVERITY#{severity}`<br/>`GSI2_SK: detectedAt` | Chronological, tenant-isolated detection record with full evidence and MITRE ATT&CK taxonomy. |
| **Detection ID Pointer** | `ORG#{orgId}` | `ORG#{orgId}#DETECTIONID#{detectionId}` | — | — | Provides $O(1)$ direct lookup by `detectionId` without table scans. Stores `targetSk`. |
| **Deduplication Lock** | `ORG#{orgId}` | `DEDUP#{dedupKey}` | — | — | Idempotency token written atomically via `TransactWriteItems` to prevent duplicate detections. |

### Query Access & Keyset Pagination
- **Chronological Tenant Retrieval:** Evaluates `PK = ORG#{orgId} AND begins_with(SK, "DETECTION#")` in descending chronological order (`ScanIndexForward: false`).
- **Severity-Filtered Query:** Evaluates `GSI2-SeverityIndex` using `GSI2_PK = ORG#{orgId}#SEVERITY#{severity} AND GSI2_SK BETWEEN :startTime AND :endTime`. Zero table scans.
- **HMAC-SHA256 Signed Keyset Pagination:** Pagination cursors encode `exclusiveStartKey` alongside the tenant `orgId` and SHA-256 filter hash. Any modification or cross-tenant replay immediately invalidates the cursor with an `INVALID_CURSOR` error.
