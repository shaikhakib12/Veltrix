# VELTRIX: DynamoDB Schema & Access Patterns (`specs/database-schema.md`)

**Document Version:** 2.1.0 (Post-Audit Hardened)  
**Status:** In Review (Phase 1 Specification)  
**Database Engine:** Amazon DynamoDB (On-Demand / `PAY_PER_REQUEST`)  
**Data Encryption:** AWS KMS (AES-256) at rest  

---

## 1. Table Definitions & Key Schemas

VELTRIX uses access-optimized tables designed around specific query access patterns, incorporating time-sharding on high-velocity telemetry to eliminate hot-partition bottlenecks.

| Table Name | Partition Key (PK) | Sort Key (SK) | Global Secondary Indexes (GSI) | TTL Attribute |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`Veltrix-SecurityEvents`** | `ORG#{orgId}#DATE#{YYYY-MM-DD}` | `EVENT#{timestampIso}#{eventId}` | `GSI1_PK: ORG#{orgId}#TYPE#{eventType}`, `GSI1_SK: timestampIso`<br/>`GSI2_PK: ORG#{orgId}#IP#{sourceIp}`, `GSI2_SK: timestampIso` | `ttl` (Epoch seconds, 30 days) |
| **`Veltrix-Incidents`** | `ORG#{orgId}` | `INCIDENT#{timestampIso}#{incidentId}` | `GSI1_PK: ORG#{orgId}#STATUS#{status}`, `GSI1_SK: riskScore` (Numeric)<br/>`GSI2_PK: ORG#{orgId}#SEVERITY#{severity}`, `GSI2_SK: timestampIso` | `ttl` (Epoch seconds, 90 days) |
| **`Veltrix-DetectionRules`** | `ORG#{orgId}` | `RULE#{ruleId}` | `GSI1_PK: category`, `GSI1_SK: severity` | — |
| **`Veltrix-ThreatIndicators`** | `INDICATOR#{type}` | `VALUE#{value}` | `GSI1_PK: severity`, `GSI1_SK: confidence` (Numeric) | — |
| **`Veltrix-ResponseExecutions`**| `ORG#{orgId}` | `RESP#{timestampIso}#{executionId}` | `GSI1_PK: INCIDENT#{incidentId}`, `GSI1_SK: timestampIso` | `ttl` (Epoch seconds, 60 days) |
| **`Veltrix-AuditLogs`** | `ORG#{orgId}` | `AUDIT#{timestampIso}#{logId}` | `GSI1_PK: ORG#{orgId}#ACTOR#{actorId}`, `GSI1_SK: timestampIso` | Retained (WORM Compliance) |

---

## 2. Hot Partition Mitigation Strategy

### The Hot-Partition Risk
In DynamoDB, a single physical partition supports up to 1,000 Write Request Units (WRUs) and 3,000 Read Request Units (RRUs).
If an organization generates a burst of 1,000 events/second (e.g. during a DDoS attack or multi-stage simulation), partitioning solely by `ORG#{orgId}` directs all traffic to one physical partition, causing `ProvisionedThroughputExceededException`.

### Solution: Time-Sharded Compound Partition Key
On `Veltrix-SecurityEvents`:
- **Primary Partition Key:** `ORG#{orgId}#DATE#{YYYY-MM-DD}`
- If throughput exceeds 1,000 WRU/sec continuously, a salt suffix is added: `ORG#{orgId}#DATE#{YYYY-MM-DD}#SHARD#{0..N}`.
- This spreads write traffic evenly across physical storage nodes while keeping single-day queries deterministic.

---

## 3. Global Secondary Indexes & Query Access Patterns

### Access Pattern 1: High-Velocity Event Ingestion & Deduplication
- **Target Table:** `Veltrix-SecurityEvents`
- **Operation:** `PutItem`
- **Condition Expression:** `attribute_not_exists(idempotencyKey)`
- **Behavior:** Suppresses true network retries while preserving distinct events.

### Access Pattern 2: Query security events by type across a time range
- **Index:** `Veltrix-SecurityEvents` `GSI1-EventType`
- **Key Condition:** `GSI1_PK = ORG#{orgId}#TYPE#{eventType} AND GSI1_SK BETWEEN :startTime AND :endTime`
- **Projected Attributes:** `ALL`
- **Purpose:** Sub-second retrieval of all failed authentications (`auth.login.failed`) or privilege escalation attempts.

### Access Pattern 3: Forensic lookup of all activity from a specific IP
- **Index:** `Veltrix-SecurityEvents` `GSI2-SourceIp`
- **Key Condition:** `GSI2_PK = ORG#{orgId}#IP#{sourceIp} AND GSI2_SK BETWEEN :startTime AND :endTime`
- **Purpose:** Fast attacker IP dossier generation.

### Access Pattern 4: Query active incidents sorted by risk score
- **Index:** `Veltrix-Incidents` `GSI1-StatusRisk`
- **Key Condition:** `GSI1_PK = ORG#{orgId}#STATUS#NEW` ordered descending by numeric `riskScore`.
- **Purpose:** Populates the SOC incident queue with highest-risk threats at the top.

### Access Pattern 5: Audit ledger sequential retrieval for verification
- **Target Table:** `Veltrix-AuditLogs`
- **Key Condition:** `PK = ORG#{orgId} AND begins_with(SK, 'AUDIT#')` ordered ascending by timestamp.
- **Purpose:** Provides ordered input stream to the SHA-256 chain verification engine.

---

## 4. Tenant Isolation Enforcement

1. **Partition Key Isolation:** Every query on tenant-scoped tables requires `ORG#{orgId}` in the Partition Key.
2. **Backend Claims Verification:** The API Gateway authorizer and Lambda middleware extract `orgId` exclusively from the verified Cognito JWT payload. Any query attempting to access a different `orgId` is blocked at the application boundary with `403 Forbidden`.
3. **IAM Scoping:** Cloud IAM policies restrict Lambda database operations to the specific environment table ARNs.

---

## 5. Pagination & TTL Lifecycle

- **Pagination:** List endpoints return a base64-encoded `nextCursor` reflecting DynamoDB's `LastEvaluatedKey`. The subsequent request passes `cursor=<base64>` which deserializes into `ExclusiveStartKey`. This guarantees constant memory overhead regardless of dataset size.
- **TTL Policies:**
  - `Veltrix-SecurityEvents`: `ttl` set to `epochSeconds + 2,592,000` (30 days).
  - `Veltrix-Incidents`: `ttl` set to `epochSeconds + 7,776,000` (90 days).
  - DynamoDB purges expired items automatically in the background without consuming read or write capacity units.
