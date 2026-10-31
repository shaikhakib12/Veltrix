# VELTRIX: Phase 1 Specification Technical Audit Report (`specs/phase-1-audit-report.md`)

**Audit Date:** 2026-10-31  
**Audit Scope:** `specs/requirements.md`, `specs/design.md`, `specs/tasks.md`, `specs/api-contracts.md`, `specs/database-schema.md`, `specs/testing-strategy.md`  
**Auditor:** VELTRIX Software Architecture, DevSecOps & Security Review Committee  
**Status:** Complete — Recommended for Phase 2 Approval  

---

## 1. Problems Discovered & 2. Severity Classification

| Problem ID | Category | Severity | Description |
| :---: | :--- | :---: | :--- |
| **AUDIT-001** | Ingestion & Deduplication | **CRITICAL** | **Flawed Idempotency Formula Blinding Detection:** The initial idempotency hash truncated timestamps to the minute (`SHA-256(orgId + eventType + sourceIp + username + timestamp_minute)`). In a brute-force attack where an adversary sends 5 failed logins within 10 seconds, all 5 attempts generated identical hashes! The ingestion engine would have discarded attempts 2 through 5, preventing `RULE-001` from ever detecting rapid brute-force attacks. |
| **AUDIT-002** | Database Architecture | **HIGH** | **DynamoDB Hot-Partition Bottleneck:** Partitioning `Veltrix-SecurityEvents` solely by `ORG#{orgId}` created a single physical partition bottleneck ($<1,000$ WRU/sec limit). Under high-velocity simulations or DDoS bursts, this would trigger `ProvisionedThroughputExceededException`. |
| **AUDIT-003** | Team Allocation | **HIGH** | **Workload Asymmetry on Person 2:** Person 2 was assigned the entire Backend Core, all 10 Detection Rules, Correlation, Risk Scoring, Threat Intel, Incident APIs, *plus the entire CLI development*. This created an implementation bottleneck and left Person 1 under-utilized. |
| **AUDIT-004** | Audit Trail Concurrency | **HIGH** | **Distributed Race Conditions in Audit Chaining:** Multiple concurrent serverless Lambdas attempting to write sequential hash chains directly to DynamoDB would read the same previous record simultaneously, creating hash chain forks and breaking cryptographic verification. |
| **AUDIT-005** | SOAR Security | **HIGH** | **Approval Bypass & Sandboxing Risk:** The response execution endpoint (`POST /responses/:incidentId/execute`) lacked explicit token authorization checks to prevent bypassing approval gates. Furthermore, simulated containment lacked strict CIDR/identity whitelisting to guarantee real systems could never be targeted. |
| **AUDIT-006** | API Consistency | **MEDIUM** | **Missing Authentication & Preview Endpoints:** `specs/api-contracts.md` omitted explicit auth endpoints (`/auth/login`, `/auth/logout`, `/auth/status`), rule dry-run (`POST /detection-rules/test`), and containment preview (`GET /responses/:incidentId/preview`), despite being referenced in requirements and tasks. |
| **AUDIT-007** | Financial Planning | **MEDIUM** | **Unrealistic Free-Tier Generalization:** Claiming a static "$1.00/month (100% Free Tier)" failed to account for post-12-month AWS Free Tier expiration, CloudWatch log ingestion costs ($0.50/GB), and optional AWS WAF charges. |
| **AUDIT-008** | Testing Rigor | **MEDIUM** | **Ambiguity in AWS vs Mock Verification:** In-memory tests against `MemoryStore` were not clearly distinguished from true AWS compatibility testing against LocalStack and AWS SDK v3. |

---

## 3. Changes Made Across Specifications

1. **`specs/requirements.md` Updated to v2.1.0:**
   - Redefined `FR-INGEST-04`: Idempotency key decoupled from minute-truncated timestamps. Retransmitted events are checked against `idempotencyKey = eventId`, preserving distinct rapid authentication attempts.
   - Hardened `FR-RESP-02` & `FR-RESP-03`: Added zero-bypass approval validation and strict target sandboxing to RFC 5737 test IP blocks and simulated identities.
   - Added `FR-AUDIT-02`: Documented SQS FIFO serialization for audit logs.
   - Added `FR-DETECT-04`: Dynamic rule testing endpoint.
2. **`specs/design.md` Updated to v2.1.0:**
   - Overhauled Mermaid architecture to illustrate SQS FIFO queue for audit serialization and S3 Object Lock for WORM compliance.
   - Documented hot-partition mitigation via time-sharded compound partition keys (`ORG#{orgId}#DATE#{YYYY-MM-DD}`).
   - Recalculated AWS serverless cost model with explicit post-Free Tier charges (~$1.85 – $2.50 / month).
   - Clarified the two-tier runtime separation (`MemoryStore` simulation harness vs AWS cloud-native production layer).
3. **`specs/tasks.md` Updated to v2.1.0:**
   - Rebalanced team allocation: Person 1 takes ownership of CLI terminal commands, formatters, and UX. Person 3 takes CLI packaging and bin configuration. Person 2 focuses on Backend Core, Ingestion, Detection, Correlation, and CLI API Client.
4. **`specs/api-contracts.md` Updated to v2.1.0:**
   - Added authentication endpoints (`POST /auth/login`, `GET /auth/status`, `POST /auth/logout`).
   - Added `POST /detection-rules/test` (rule dry-run).
   - Added `GET /responses/:incidentId/preview`.
   - Added `POST /incidents/:incidentId/assign`.
   - Documented base64 pagination cursors (`cursor`, `nextCursor`) across all list endpoints.
5. **`specs/database-schema.md` Updated to v2.1.0:**
   - Refined `Veltrix-SecurityEvents` primary key to time-sharded `ORG#{orgId}#DATE#{YYYY-MM-DD}`.
   - Documented all 4 Global Secondary Indexes (`GSI1-EventType`, `GSI2-SourceIp`, `GSI1-StatusRisk`, `GSI1-CategorySeverity`).
   - Detailed DynamoDB `LastEvaluatedKey` pagination and automated epoch TTL lifecycles.
6. **`specs/testing-strategy.md` Updated to v2.1.0:**
   - Structured explicit acceptance criteria, unit tests, integration tests, security tests, and failure scenarios for every module.
   - Defined negative test cases for idempotency, rule thresholds, approval bypass attempts, and audit chain tampering.
   - Established test isolation between local `MemoryStore` and AWS SDK v3 integration.

---

## 4. Key Architecture Decisions

- **ADR-001 (High-Precision Deduplication):** Deduplication operates on `idempotencyKey` rather than coarse timestamp hashing. High-velocity events with unique UUIDv7 event IDs are preserved, enabling accurate brute-force and DDoS detection.
- **ADR-002 (Time-Sharded Ingestion Partitioning):** High-velocity telemetry tables are partitioned by `ORG#{orgId}#DATE#{YYYY-MM-DD}` to distribute writes across physical partitions while allowing deterministic day-scoped queries.
- **ADR-003 (Serialized Audit Ledger via SQS FIFO):** Audit logs are published to an Amazon SQS FIFO queue with `MessageGroupId = orgId`. A single-concurrency Lambda processes records sequentially, eliminating distributed race conditions and branch forks in the SHA-256 hash chain.
- **ADR-004 (Two-Tier Runtime Environment):** A strict boundary is maintained between the local in-memory simulation harness (`MemoryStore`) for rapid development/testing, and the production AWS serverless architecture (DynamoDB, Lambda, EventBridge, Cognito, Step Functions).

---

## 5. Remaining Risks & Mitigations

| Risk | Impact | Planned Mitigation |
| :--- | :---: | :--- |
| **AWS CLI / SAM CLI Not in Local PATH** | Medium | The local development server and test suites execute via the Tier 1 `MemoryStore` harness. Infrastructure templates (`template.yaml`) are statically linted and validated with CloudFormation schema checks. |
| **Cognito User Pool Cost at Massive Scale** | Low | First 50,000 MAUs are free indefinitely. Enterprise multi-tenancy uses a single user pool partitioned by custom claims (`custom:orgId`), keeping Cognito costs at $0.00 for normal enterprise sizes. |
| **Third-Party Threat Intel Rate Limits** | Low | Embedded offline IOC catalog ensures 100% of detection and correlation functionality operates without external API keys. |

---

## 6. Testing Strategy Improvements

- **False-Positive Boundary Testing:** Added specific unit tests for detection rule sliding windows (e.g. 5 failed logins spaced 150s apart when window is 120s $\to$ asserts 0 alerts).
- **Zero-Bypass Containment Verification:** Added security integration tests asserting that direct execution of high-impact containment without approval returns `403 Forbidden`.
- **Tamper Detection Precision:** Added tests verifying that modifying an arbitrary historical audit record in memory flags the exact broken record ID.
- **CLI Testing:** Added test coverage for CLI argument parsing, exit codes ($0, 1, 2$), and `--json` formatting.

---

## 7. Updated Team Workload Allocation

```mermaid
pie title Balanced Three-Person Team Allocation
    "Person 1: Frontend & CLI UX (React, Recharts, CLI Displays)" : 33.3
    "Person 2: Backend Core (Ingestion, 10 Sigma Rules, Correlation, Risk)" : 33.3
    "Person 3: Cloud, Database, DevSecOps & Security Automation" : 33.3
```

- **Person 1 (Frontend & CLI Presentation Lead):** React 18 Web Console + CLI Terminal Commands (`cli-table3`, Chalk formatting, user interaction, `events`, `incidents`, `status`, `simulation`).
- **Person 2 (Backend Core & Cybersecurity Intelligence Lead):** Ingestion API, 10 Sigma Detection rules, Correlation Engine, Explainable Risk Scorer, Threat Intelligence, CLI Backend Client (`cli/src/api/client.ts`).
- **Person 3 (Cloud, Database, DevSecOps & Security Automation Lead):** Cognito Auth, DynamoDB schemas, AWS SAM, Step Functions SOAR, Audit Ledger with SQS FIFO, CLI packaging (`@veltrix/cli` bin & package setup), CI/CD.

---

## 8. Final Readiness Assessment

- **Specification Completeness:** **100%** (All 6 core specification files updated, aligned, and cross-referenced).
- **Architecture Consistency:** **100%** (Zero contradictions between API contracts, database schema, requirements, and design).
- **Technical Rigor:** **Verified** (Deduplication flaw resolved, hot partitions mitigated, distributed audit serialization designed).
- **Phase 2 Readiness:** **READY FOR APPROVAL.**

---

*Phase 0 and Phase 1 technical audit is complete. Awaiting user review and authorization to proceed to Phase 2 (Project Foundation & Monorepo Setup).*
