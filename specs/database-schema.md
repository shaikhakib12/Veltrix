# VELTRIX: DynamoDB Schema & Access Patterns (`specs/database-schema.md`)

**Document Version:** 2.0.0  
**Status:** In Review (Phase 1 Specification)  
**Database Engine:** Amazon DynamoDB (On-Demand / `PAY_PER_REQUEST`)  
**Data Encryption:** AWS KMS (AES-256) at rest  

---

## 1. Table Definitions & Key Schemas

VELTRIX uses dedicated, access-optimized tables partitioned by `ORG#{orgId}` to guarantee multi-tenant security and single-digit millisecond query latency.

| Table Name | Partition Key (PK) | Sort Key (SK) | Global Secondary Indexes (GSI) | TTL Attribute |
| :--- | :--- | :--- | :--- | :--- |
| **`Veltrix-SecurityEvents`** | `ORG#{orgId}` | `EVENT#{timestamp}#{eventId}` | `GSI1_PK: ORG#{orgId}#TYPE#{eventType}`, `GSI1_SK: timestamp`<br/>`GSI2_PK: ORG#{orgId}#IP#{sourceIp}`, `GSI2_SK: timestamp` | `ttl` (30 days) |
| **`Veltrix-Incidents`** | `ORG#{orgId}` | `INCIDENT#{timestamp}#{incidentId}` | `GSI1_PK: ORG#{orgId}#STATUS#{status}`, `GSI1_SK: riskScore`<br/>`GSI2_PK: ORG#{orgId}#SEVERITY#{severity}`, `GSI2_SK: timestamp` | `ttl` (90 days) |
| **`Veltrix-DetectionRules`** | `ORG#{orgId}` | `RULE#{ruleId}` | `GSI1_PK: category`, `GSI1_SK: severity` | — |
| **`Veltrix-ThreatIndicators`** | `INDICATOR#{type}` | `VALUE#{value}` | `GSI1_PK: severity`, `GSI1_SK: confidence` | — |
| **`Veltrix-ResponseExecutions`**| `ORG#{orgId}` | `RESP#{timestamp}#{executionId}` | `GSI1_PK: INCIDENT#{incidentId}`, `GSI1_SK: timestamp` | `ttl` (60 days) |
| **`Veltrix-AuditLogs`** | `ORG#{orgId}` | `AUDIT#{timestamp}#{logId}` | `GSI1_PK: ORG#{orgId}#ACTOR#{actorId}`, `GSI1_SK: timestamp` | Retained (Immutable) |

---

## 2. Access Patterns & Query Implementations

### Access Pattern 1: Ingest and deduplicate event
- **Target Table:** `Veltrix-SecurityEvents`
- **Operation:** `PutItem` with condition `attribute_not_exists(idempotencyHash)`
- **Partition Key:** `ORG#{orgId}`
- **Sort Key:** `EVENT#{timestamp}#{eventId}`

### Access Pattern 2: Query events for an organization within a time range
- **Target Table:** `Veltrix-SecurityEvents`
- **Operation:** `Query`
- **Key Condition:** `PK = :orgId AND SK BETWEEN :start AND :end`

### Access Pattern 3: Query failed logins by IP address
- **Target Index:** `Veltrix-SecurityEvents` `GSI2`
- **Key Condition:** `GSI2_PK = ORG#{orgId}#IP#{sourceIp}` ordered descending by timestamp.

### Access Pattern 4: List active incidents sorted by risk score
- **Target Index:** `Veltrix-Incidents` `GSI1`
- **Key Condition:** `GSI1_PK = ORG#{orgId}#STATUS#NEW` ordered descending by `riskScore`.

### Access Pattern 5: Fetch complete audit ledger for cryptographic chain verification
- **Target Table:** `Veltrix-AuditLogs`
- **Operation:** `Query`
- **Key Condition:** `PK = ORG#{orgId} AND begins_with(SK, 'AUDIT#')` ordered ascending by timestamp.

---

## 3. Storage Retention & Cost Optimization
- **Raw Events:** 30-day epoch timestamp stored in `ttl` attribute. DynamoDB natively deletes expired items with zero compute cost.
- **Incidents:** 90-day retention before automated archival to Amazon S3 Glacier.
- **Audit Logs:** Permanently retained to meet enterprise SOC 2 and ISO 27001 compliance standards.
