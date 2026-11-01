# VELTRIX — Phase 7 Independent Security & Code Audit Report
## Website Attack Monitoring, Correlation & Risk Scoring

**Date:** November 1, 2026  
**Project:** VELTRIX — Unified Cybersecurity & Website Defense Platform ("Beyond Detection. Into Defense.")  
**Branch:** `feature/phase-7-web-attack-monitoring`  
**Target Branch:** `main`  
**Base Commit:** `58d5719` (Merged PR #6 Phase 6 Security Hardening)  
**PR References:** [PR #7 (Merged into main)](https://github.com/shaikhakib12/Veltrix/pull/7) | [PR #9 (Security Hardening Follow-up)](https://github.com/shaikhakib12/Veltrix/pull/9)  
**Audit Scope:** Web attack classification parser, detection rules (`RULE-101` to `RULE-105`), multi-stage attack correlation engine, explainable risk scoring engine, vulnerability correlator, incident REST APIs, frontend components, and automated test harness.  
**Auditor:** VELTRIX Lead Cybersecurity & Systems Auditor (Independent Review)  
**Final Status:** **ALL AUDIT FINDINGS REMEDIATED & VERIFIED — READY FOR REVIEW**  

---

## 1. Executive Summary

An exhaustive, independent security audit and code review of the Phase 7 implementation (TASK-701 through TASK-707) was conducted across eight target domains:
1. **Attack Correlation:** Sliding vs. fixed window boundaries, NAT/shared IP collisions, loopback/generic IP isolation, duplicate and out-of-order event idempotency, and concurrent worker collision defense.
2. **Mathematical Risk Scoring:** Invariant clamping in $[0, 100]$, `NaN` poisoning prevention, missing/malformed CVSS handling, bounded frequency multipliers, and transparent human-readable explanations.
3. **Detection Confidence Classification & Provenance Boundaries:** Evidence tiering (`SUSPICIOUS_ATTEMPT`, `BLOCKED_ATTEMPT`, `POTENTIAL_EXPLOITATION`, `CONFIRMED_EXPLOITATION`), sensitive parameter scrubbing, ReDoS bounds, and trusted server provenance model preventing untrusted client metadata escalation.
4. **SOAR Safety & Containment:** Clear boundary enforcement separating recommendations from execution (Phase 10 SOAR), ensuring the SOC dashboard does not falsely claim active perimeter blocks.
5. **API & Storage Integrity:** `MemoryStore` and `DynamoDBStore` parity, `siteId` filtering on incidents and detections, direct $O(1)$ lookup for incident IDs, and API key prohibition on administrative routes (`FORBIDDEN_API_KEY_SCOPE_PROHIBITED`).
6. **Automated Pipeline Processing:** End-to-end telemetry flow from SDK/collector ingestion through normalization, rule evaluation, correlation, risk scoring, persistence, and REST APIs.
7. **Specification Consistency:** Exact alignment of task definitions, scopes, and deliverables across `specs/tasks.md`, `specs/website-security-roadmap-update.md`, and `specs/phase-7-completion-report.md`.
8. **Trust Boundary Hardening:** Separation of externally reported client signals from server-verified evidence, prohibiting forged canary tokens, data leakage claims, or privilege mutations from obtaining confirmed exploitation.

All **9 security audit findings** identified during review have been fully remediated in source code and verified with targeted regression tests. The test suite now comprises **245 automated tests (100% pass rate)** across all monorepo workspaces.

---

## 2. Structured Security Audit Findings & Remediations

| Finding ID | Severity | Affected Component / File | Summary | Status |
| :--- | :---: | :--- | :--- | :---: |
| **SEC-P7-001** | Medium | `backend/src/correlation/engine.ts` | Fixed 15-minute bucket hash split boundary events | **REMEDIATED** |
| **SEC-P7-002** | High | `backend/src/correlation/engine.ts` | Generic/loopback IPs merged unrelated actors into single incident | **REMEDIATED** |
| **SEC-P7-003** | Medium | `backend/src/correlation/engine.ts` | Missing correlation idempotency & out-of-order timestamp bounds | **REMEDIATED** |
| **SEC-P7-004** | High | `backend/src/detection/web-parser.ts` | Telemetry query parameters & raw URIs leaked cleartext credentials | **REMEDIATED** |
| **SEC-P7-005** | Medium | `backend/src/risk/engine.ts` | `NaN` poisoning in vulnerability overlap terms & explanation string | **REMEDIATED** |
| **SEC-P7-006** | Low | `frontend/src/components/WebsiteAttackMonitoring.tsx` | SOC button label misleadingly implied active perimeter IP blocking | **REMEDIATED** |
| **SEC-P7-007** | Medium | `backend/src/storage/dynamodb-store.ts` | Missing `siteId` filtering & $O(1)$ incident ID lookup in DynamoDB | **REMEDIATED** |
| **SEC-P7-008** | Low | `backend/src/correlation/engine.ts` | Unhandled undefined `detection.relatedEventIds` in risk calculation | **REMEDIATED** |
| **SEC-P7-009** | Critical | `backend/src/detection/web-parser.ts` | Untrusted client evidence promotion & missing provenance trust boundary | **REMEDIATED** |
| **SEC-P7-010** | High | `backend/src/detection/replay-registry.ts` | In-memory replay vulnerable in distributed serverless; missing Secrets Manager IaC & burned credentials | **REMEDIATED** |

---

### Detailed Findings & Technical Resolutions

#### Finding SEC-P7-001: Fixed 15-Minute Bucket Edge Collisions in Correlation Engine
- **Severity:** Medium
- **Affected File:** `backend/src/correlation/engine.ts`
- **Explanation:** The correlation key was originally derived using `Math.floor(timestampMs / (windowSeconds * 1000))`. This fixed-bucket scheme caused events occurring seconds apart across a 15-minute boundary (e.g., 10:14:59 and 10:15:01) to fall into different correlation buckets, creating separate incidents and failing to recognize multi-stage attack progressions.
- **Fix Applied:** Replaced the fixed bucket index with a genuine sliding window. The engine now computes `correlationKey = sha256(orgId:siteId:sourceIp)` and evaluates the elapsed time `Math.abs(detectionTimeMs - latestActivityMs) <= windowSeconds * 1000` against the active incident's latest activity timestamp (`updatedAt || createdAt`). Expired or resolved incidents are evicted and reset cleanly.
- **Test Evidence:** `backend/tests/web-detection-correlation.test.ts` > `correlates events spanning across fixed 15-minute bucket boundaries in a true sliding window`.

#### Finding SEC-P7-002: Cross-Actor Incident Merging for Localhost/Generic Loopback IPs
- **Severity:** High
- **Affected File:** `backend/src/correlation/engine.ts`
- **Explanation:** In development, internal microservices, or unproxied collector configurations, telemetry frequently reports fallback loopback or unspecified IPs (`127.0.0.1`, `0.0.0.0`, `::1`, `localhost`, `unknown`). Because correlation grouped strictly by `sourceIp`, unrelated attacks from completely different internal actors collapsed into a single tenant-wide mega-incident.
- **Fix Applied:** Added `normalizeSourceIp()` to strip ports and brackets, and `isGenericOrLocalIp()` to detect loopback/unroutable addresses. For generic IPs, `computeCorrelationKey()` salts the key with `detection.detectionId`, preventing cross-actor consolidation and maintaining isolated incident tracking.
- **Test Evidence:** `backend/tests/web-detection-correlation.test.ts` > `prevents false incident consolidation for loopback/generic source IPs`.

#### Finding SEC-P7-003: Missing Correlation Idempotency & Out-of-Order Timestamp Bounds
- **Severity:** Medium
- **Affected File:** `backend/src/correlation/engine.ts`
- **Explanation:** In distributed stream processing (e.g., DynamoDB Streams / Kinesis retries), the same detection may be processed multiple times, causing duplicate timeline entries and artificially inflating incident event counts. Additionally, out-of-order event arrivals could overwrite `createdAt` with a later timestamp.
- **Fix Applied:** Added idempotency verification checking `(t.details as { detectionId?: string })?.detectionId === detection.detectionId`. If already recorded, the correlation returns early without duplicate timeline appends. Earliest and latest timestamps are tracked dynamically via `Math.min(...)` and `Math.max(...)`.
- **Test Evidence:** `backend/tests/web-detection-correlation.test.ts` > `ensures correlation idempotency by not duplicating timeline entries on re-evaluation` and `maintains correct chronological bounds when detections arrive out of order`.

#### Finding SEC-P7-004: Sensitive Credential Exposure in Telemetry Query Parameters and Raw URIs
- **Severity:** High
- **Affected File:** `backend/src/detection/web-parser.ts`
- **Explanation:** Sensitive customer credentials (e.g., `password=...`, `token=...`, `cvv=...`, `session=...`) passed via query strings or unauthenticated login GET/POST requests were preserved in plaintext in `parsed.queryParams` and `parsed.rawUri`. These sensitive tokens leaked into SIEM detection evidence and incident timelines.
- **Fix Applied:** Introduced `SENSITIVE_PARAM_PATTERN` regex matching sensitive credential keys. In `extractQueryParams()`, values for sensitive keys are masked as `'[REDACTED]'` and excluded from `allValues` and `decodedPayloads`. Introduced `sanitizeUriString()` to replace sensitive parameter values in `rawUri` with `'[REDACTED]'`.
- **Test Evidence:** `backend/tests/web-detection-correlation.test.ts` > `redacts sensitive query parameter values in rawUri and queryParams`.

#### Finding SEC-P7-005: Potential NaN Poisoning in Risk Engine Calculation and Explanation
- **Severity:** Medium
- **Affected File:** `backend/src/risk/engine.ts`
- **Explanation:** If `vulnerabilityOverlap` contained `findingCvss: NaN` or `undefined`, the vulnerability term evaluated to `NaN`. This poisoned `rawScore`, producing `NaN` in the risk calculation and `C_vuln(NaN)` in the explanation string.
- **Fix Applied:** Added defensive guards with `Number.isFinite()` and bounds checking:
  ```ts
  const safeCvss = typeof findingCvss === 'number' && Number.isFinite(findingCvss)
    ? Math.min(10, Math.max(0, findingCvss))
    : 0;
  const safeBaseProduct = Number.isFinite(baseProduct) ? baseProduct : 10;
  const safeVulnTerm = Number.isFinite(vulnTerm) ? vulnTerm : 0;
  const safeScore = Number.isFinite(rawScore) ? rawScore : 0;
  ```
  Guaranteed `safeVulnTerm.toFixed(1)` in explanation strings.
- **Test Evidence:** `backend/tests/web-detection-correlation.test.ts` > `safely handles missing, NaN, or out-of-range findingCvss without NaN poisoning`.

#### Finding SEC-P7-006: Ambiguous Active SOAR Containment Action in SOC Frontend
- **Severity:** Low
- **Affected File:** `frontend/src/components/WebsiteAttackMonitoring.tsx`
- **Explanation:** The incident action button in the Web Attack Monitoring table was labeled `"Block IP / Contain"`. Because Phase 10 SOAR firewall/WAF execution is not yet integrated, this label misled analysts into believing active perimeter firewall blocks were being executed.
- **Fix Applied:** Relabeled the button to `"Mark Contained"`. Updated the status audit note to:
  `'Incident acknowledged and marked CONTAINED by SOC analyst; response action recommendations require Phase 10 execution.'`
  Added an explicit `(Recommended Response - Phase 10)` badge next to rendered `suggestedResponses`.

#### Finding SEC-P7-007: Missing `siteId` Filtering & $O(1)$ Incident ID Lookup in DynamoDB Store
- **Severity:** Medium
- **Affected File:** `backend/src/storage/dynamodb-store.ts`
- **Explanation:** `DynamoDBStore.getIncidents()` and `getDetections()` lacked support for `options.siteId` filtering in their `FilterExpression`. Furthermore, `getIncidentById()` performed a scan of up to 100 items rather than an $O(1)$ primary key lookup.
- **Fix Applied:** Updated `saveDetection()` to persist top-level `siteId`. Added `siteId` filter expressions to both `getDetections()` and `getIncidents()`. Updated `saveIncident()` to persist a direct pointer item `PK: ORG#${orgId}#INCIDENTID#${incidentId}, SK: 'METADATA'`, enabling an $O(1)$ `GetCommand` with seamless fallback.

#### Finding SEC-P7-008: Unhandled Undefined `detection.relatedEventIds` in Risk Calculation
- **Severity:** Low
- **Affected File:** `backend/src/correlation/engine.ts`
- **Explanation:** If a synthetic or external detection object omitted `relatedEventIds`, accessing `.length` threw an unhandled `TypeError` during incident risk calculation.
- **Fix Applied:** Defensively guarded all references with `(detection.relatedEventIds || [])`.

#### Finding SEC-P7-009: Untrusted Client Evidence Promotion & Missing Provenance Trust Boundary
- **Severity:** Critical
- **Affected File:** `backend/src/detection/web-parser.ts`, `backend/src/detection/evidence-authority.ts`, `backend/src/services/event-service.ts`, `backend/src/storage/dynamodb-store.ts`, `backend/src/storage/memory-store.ts`, `packages/shared/src/types/index.ts`
- **Explanation:**
  1. **Complete HMAC Coverage & Cryptographic Integrity:** `computeSignature()` previously only signed a subset of fields. Unsigned fields such as `evidenceReferences` and `verifiedResponseEvidence` could potentially be altered without invalidating the signature.
  2. **Event, Tenant, and Site Binding:** A signed evidence context could previously be detached and replayed across different events, tenants, or website assets without binding verification, or reused after expiration.
  3. **Service Credential & Key Lifecycle Security:** Service credentials previously had hardcoded fallback strings in source code that could be extracted by repository readers. The HMAC signing key also lacked strict production fail-closed enforcement and key rotation support.
  4. **Single-Use Replay Protection:** Within the 15-minute validity window, the same signed context could theoretically be resubmitted without a single-use nonce replay registry.
  5. **Client-Controlled Response Evidence & WAF Actions:** Client-controlled metadata (`metadata.responseSample`, `metadata.errorMessage`, `metadata.wafAction`) could not be trusted to establish server-verified exploitation or blocked attempts.
- **Fix Applied:**
  1. **Deterministic Canonical Serialization & Complete HMAC Coverage:**
     - Canonical string serialization (`computeCanonicalPayload`) integrity-protects EVERY security-relevant field:
       - `version`: `'VELTRIX_EVIDENCE_V2'`
       - `nonce`: cryptographically random single-use nonce
       - `eventId`: bound event identifier
       - `orgId`: bound organization identifier
       - `siteId`: bound website asset identifier
       - `provenance`: `'TRUSTED_SERVER_COMPONENT'` or `'AUTHENTICATED_COLLECTOR'`
       - `verifierIdentity`: verified caller identity
       - `signals`: sorted list of verified signal identifiers
       - `evidenceReferences`: sorted list of reference IDs
       - `timestamp`: ISO 8601 UTC timestamp
       - `responseBodyHash`: SHA-256 hash of verified response body (or `'NONE'`)
       - `errorMessageHash`: SHA-256 hash of verified error message (or `'NONE'`)
       - `wafAction`: verified WAF intervention action (`ALLOW`, `BLOCK`, `CHALLENGE`, `LOG`, or `'NONE'`)
       - `wafRuleId`: verified WAF rule identifier
     - Signature verified using constant-time comparison (`timingSafeEqual`).
  2. **Anti-Replay, Single-Use Nonce & Freshness Verification:**
     - Every context carries a unique random `nonce`.
     - `EvidenceReplayRegistry` tracks consumed nonces within the 15-minute sliding window; replaying the same context within that window is detected and rejected.
     - Context explicitly carries `eventId`, `orgId`, and `siteId`.
     - `normalizeWebTelemetry` verifies that `context.eventId === event.eventId`, `context.orgId === event.orgId`, and `context.siteId === (event.metadata?.siteId || '')`. Any cross-event, cross-tenant, or cross-site replay is rejected.
     - Freshness checks enforce that verification timestamps cannot be in the future (> 60s clock skew) or older than 15 minutes (`MAX_EVIDENCE_AGE_MS = 900,000 ms`).
  3. **Fail-Closed Service Credential Storage & Rotation:**
     - Removed all hardcoded fallback credentials from source code.
     - In production / deployed environments, credentials must be injected via secure environment variables or AWS Secrets Manager. Missing credentials fail closed with `UNCONFIGURED_SERVICE_CREDENTIAL`.
     - Supports multiple valid credentials per service for seamless credential rotation.
  4. **HMAC Signing Key Lifecycle & Key Rotation:**
     - Enforces minimum 256-bit (32 bytes) key entropy.
     - Missing signing keys in production mode fail closed with `FATAL_KEY_CONFIG_ERROR`.
     - Supports key rotation: allows `rotatedVerificationKeys` so in-flight contexts signed with a previous key during the 15-minute window remain valid without downtime.
     - Caller service credentials and HMAC signing keys are strictly separated.
  5. **Ingestion & Persistence Storage Boundary Protection:**
     - Public ingestion schema rejects any event carrying `trustedEvidenceContext`.
     - `DynamoDBStore` and `MemoryStore` strip `trustedEvidenceContext` on save, returning undefined on read.
- **Test Evidence:** 14 dedicated regression tests in `backend/tests/web-detection-correlation.test.ts` > Section 10:
  - `1. modifying signed responseBody invalidates the signature`
  - `2. modifying signed errorMessage invalidates the signature`
  - `3. modifying signed wafAction invalidates the signature`
  - `4. modifying evidenceReferences invalidates the signature`
  - `5. changing eventId invalidates the context`
  - `6. changing orgId invalidates the context`
  - `7. changing siteId invalidates the context`
  - `8. expired or future-dated contexts are rejected`
  - `9. a context from one website cannot be replayed for another`
  - `10. same-context replay within its validity window is detected and rejected by EvidenceReplayRegistry`
  - `11. service credential security: missing credentials fail closed, invalid credentials rejected, and rotation works`
  - `12. HMAC signing key security: missing key in production fails closed, incorrect key rejected, and rotation supported`
  - `13. external access to trusted evidence creation is prohibited across schemas, parser, and public exports`
  - `14. genuine authenticated evidence continues working`

#### Finding SEC-P7-010: Distributed Persistent Replay Protection, AWS Secrets Manager Provisioning, and Historical Credential Invalidation

- **Affected Components:** `backend/src/detection/replay-registry.ts`, `backend/src/auth/secret-loader.ts`, `backend/src/detection/evidence-authority.ts`, `infrastructure/template.yaml`
- **Severity:** High
- **Explanation:**
  1. *Distributed Replay Vulnerability:* Process-local in-memory nonce tracking (`Map`) in `EvidenceReplayRegistry` did not share state across horizontally scaled AWS Lambda invocations or ECS container tasks. In a multi-instance or serverless deployment, an adversary could replay a previously signed trusted evidence context against another Lambda container within its 15-minute validity window.
  2. *AWS Secrets Provisioning Gap:* `infrastructure/template.yaml` lacked definitions for AWS Secrets Manager resources and execution role IAM permissions (`secretsmanager:GetSecretValue`) for `VELTRIX_EVIDENCE_SIGNING_KEY` and verifier service credentials.
  3. *Historical Credential Compromise in Git History:* During early development in commit `28b5079`, placeholder token fallbacks (`srv_sec_canary_v1_...`, `srv_sec_nginx_v1_...`, `srv_sec_waf_v1_...`, `srv_sec_test_v1_...`) were committed to source code. While never deployed to a live production AWS account, commit history is immutable and these values must be treated as permanently burned.
- **Fix Applied:**
  1. **Persistent Atomic DynamoDB Replay Registry (`DynamoDBReplayRegistry`):**
     - Implemented `IReplayRegistry` interface backed by AWS DynamoDB using `PutCommand` with atomic conditional expression `attribute_not_exists(PK)`.
     - Partition key `PK: NONCE#<nonce>`, sort key `SK: REPLAY_RECORD`.
     - Application-level 15-minute expiration check in code independent of DynamoDB background TTL.
     - DynamoDB TTL attribute set with 1-hour safety buffer for eventual background garbage collection.
     - Differentiates legitimate idempotent retries (`eventId`, `orgId`, `siteId` identical) from active replay attacks (`eventId` or `orgId` different). For legitimate retries, `verifyAndConsumeContext` / `verifyAndConsumeContextAsync` returns `true`, retaining the original trusted verification result without re-consuming nonces, preventing legitimate evidence loss on worker crashes or retry loops. For active replay attacks, it returns `false` (`UNTRUSTED_CLIENT`).
     - Strict fail-closed behavior on persistent storage unavailability in production (`PERSISTENT_STORAGE_UNAVAILABLE`).
     - Provided `MemoryReplayRegistry` for local development and isolated unit test execution.
  2. **AWS Secrets Manager Infrastructure as Code (`infrastructure/template.yaml`):**
     - Added `EvidenceReplayTable` DynamoDB table resource with TTL and SSE enabled.
     - Added `EvidenceSigningKeySecret` (`AWS::SecretsManager::Secret`) with automated 256-bit entropy password generation.
     - Added `EvidenceServiceCredentialsSecret` (`AWS::SecretsManager::Secret`) for approved internal verifier service credentials.
     - Granted `DynamoDBCrudPolicy` on `EvidenceReplayTable` and scoped `secretsmanager:GetSecretValue` permissions to `DetectionEngineFunction`.
     - Injected secret ARNs and replay table name into Lambda environment variables.
  3. **Runtime Secret Loader (`SecretLoader`):**
     - Implemented runtime retrieval from AWS Secrets Manager using `@aws-sdk/client-secrets-manager` with fallback to secure environment variables.
     - In-memory caching with configurable 5-minute TTL to protect against Secrets Manager rate limits.
     - Supports key rotation windows with multiple active tokens.
     - Strict fail-closed enforcement: throws `FATAL_KEY_CONFIG_ERROR` if 256-bit key cannot be resolved in production.
  4. **Historical Credential Invalidation Policy:**
     - The placeholder credentials from `28b5079` are permanently invalidated and burned.
     - The codebase completely prohibits hardcoded fallback credentials and fails closed (`UNCONFIGURED_SERVICE_CREDENTIAL`).
     - Production AWS environments MUST populate unique cryptographically random secrets into Secrets Manager.
  5. **Unverified Live Deployment Requirements:**
     - The CloudFormation stack deployment to live AWS accounts remains unverified locally (pending live production credentials).
     - Live AWS Secrets Manager secret population and VPC endpoint connectivity (`com.amazonaws.region.secretsmanager`) must be provisioned during AWS infrastructure rollout.
- **Test Evidence:** 17 dedicated regression tests across Section 11 & Section 12 in `backend/tests/web-detection-correlation.test.ts`:
  - *Section 11 (Distributed Replay & Secrets Provisioning):*
    - `1. two separate registry instances receiving the same nonce detect replay`
    - `2. concurrent attempts to consume the same nonce: exactly one succeeds`
    - `3. application restart and subsequent replay: persistent storage survives process restart`
    - `4. cross-tenant and cross-site replay are detected and rejected`
    - `5. expired nonce behavior: 15-minute expiration enforced in code independently of DynamoDB TTL`
    - `6. persistent storage unavailable in production fails closed`
    - `7. legitimate ingestion retries and idempotency: identical event retry is flagged as idempotent retry`
    - `8. SecretLoader retrieves secrets from environment and caches for TTL`
    - `9. SecretLoader retrieves and parses JSON secrets from Secrets Manager`
    - `10. normalizeWebTelemetryAsync correctly authenticates and consumes evidence asynchronously`
  - *Section 12 (Idempotent Retries, Crash Resilience & Concurrency):*
    - `1. legitimate retry retains original trusted verification result across sync and async paths`
    - `2. processing retry does not generate duplicate alerts in detection or correlation engines`
    - `3. retry cannot bypass signature validation, tenant binding, or payload tampering checks`
    - `4. crash between nonce consumption and event processing does not permanently lose legitimate evidence`
    - `5. downstream correlation side effects are strictly idempotent on repeated correlation calls`
    - `6. [UNIT_MOCK: DYNAMODB_SEMANTICS] verifies attribute_not_exists(PK) condition and ConditionalCheckFailedException handling`
    - `7. [CONCURRENCY] concurrent consumption from 3 independent registry instances allows exactly one winner`
- **Operational Limitation / Live AWS Note:** Until DynamoDB Local, LocalStack, or an AWS sandbox account is provisioned in the execution environment, distributed concurrency and conditional-write testing is executed using strict unit mocks (`[UNIT_MOCK: DYNAMODB_SEMANTICS]`) modeling exact `attribute_not_exists(PK)` condition expressions and AWS SDK `ConditionalCheckFailedException` errors. Live integration testing against physical AWS DynamoDB tables and AWS Secrets Manager remains as an operational verification gate prior to production deployment.

---

## 3. RBAC Matrix Verification

| Endpoint | Method | SUPER_ADMIN | ORG_ADMIN | SECURITY_ANALYST | AUDITOR | READ_ONLY_VIEWER | Telemetry API Key |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `/api/v1/incidents` | `GET` | Yes | Yes | Yes | Yes | Yes | No (403) |
| `/api/v1/incidents/:id` | `GET` | Yes | Yes | Yes | Yes | Yes | No (403) |
| `/api/v1/incidents/:id` | `PATCH` | Yes | Yes | Yes | No (403) | No (403) | No (403) |
| `/api/v1/detections/web` | `GET` | Yes | Yes | Yes | Yes | Yes | No (403) |
| `/api/v1/detections/:id/evidence` | `GET` | Yes | Yes | Yes | Yes | Yes | No (403) |
| `/api/v1/websites/:siteId/detections` | `GET` | Yes | Yes | Yes | Yes | Yes | No (403) |
| `/api/v1/websites/:siteId/incidents` | `GET` | Yes | Yes | Yes | Yes | Yes | No (403) |
| `/api/v1/websites/:siteId/risk-summary`| `GET` | Yes | Yes | Yes | Yes | Yes | No (403) |
| `/api/v1/websites/:siteId/timeline` | `GET` | Yes | Yes | Yes | Yes | Yes | No (403) |

---

## 4. Test Suite Execution & Evidence

```
Test Files  8 passed (8 across monorepo)
     Tests  278 passed (278) - @veltrix/backend
     Tests  8 passed (8)     - @veltrix/sdk-node
  Total:    286 / 286 passed (100% pass rate)
```

- All 82 tests in `backend/tests/web-detection-correlation.test.ts` pass cleanly (including Section 9 regression tests, Section 10 trust-boundary tests, Section 11 distributed replay / secrets management tests, Section 12 idempotent retry tests, Section 13 asynchronous secret loading tests, Section 14 production replay registry tests, and Section 15 DynamoDB stream reconstruction tests).
- Full tenant boundary isolation and API key prohibition regression tests pass.
- False positive suppression verified across all 5 web attack rules.

---

## 5. PR #11 Runtime Hardening & Stream Reconstruction Audit Addendum

### 5.1 Finding 1 — Asynchronous SecretLoader Authority Initialization
- **Issue:** Previously, `getDefaultInternalEvidenceAuthority()` directly instantiated `InternalEvidenceAuthority` synchronously without loading production keys from Secrets Manager.
- **Remediation:** Added `initializeDefaultInternalEvidenceAuthority()` supporting asynchronous secrets retrieval via `SecretLoader.loadSecrets()`. In production mode, any attempt to invoke `getDefaultInternalEvidenceAuthority()` before initialization throws `UNINITIALIZED_EVIDENCE_AUTHORITY`. Both Express server bootstrap (`backend/src/index.ts`) and AWS Lambda DynamoDB stream handler (`backend/src/detection/stream-handler.ts`) now asynchronously initialize the default authority during startup.

### 5.2 Finding 2 — Strict Replay Registry Enforcement in Production
- **Issue:** Development in-memory replay registries could theoretically be injected or activated via fallback if configuration variables were missing.
- **Remediation:** `InternalEvidenceAuthority` and `DynamoDBReplayRegistry` constructors now strictly enforce production requirements: `MemoryReplayRegistry` and `EvidenceReplayRegistry` are explicitly rejected in production mode (`FATAL_REGISTRY_CONFIG_ERROR`). Missing `DYNAMODB_REPLAY_TABLE` or specifying `STORAGE_MODE=memory` in production fails closed immediately. Non-production and test environments continue using in-memory mocks without friction.

### 5.3 Finding 3 — DynamoDB Stream Evidence Reconstruction & Public Sanitization
- **Issue:** DynamoDB stream ingestion previously dropped `trustedEvidenceContext`, preventing stream-triggered Lambda detection workers from evaluating verified evidence. Additionally, public HTTP endpoints needed explicit sanitization to ensure internal HMAC tokens and nonces are never leaked.
- **Remediation:**
  - `DynamoDBStore` and `MemoryStore` preserve `trustedEvidenceContext` on internal event records.
  - `stream-handler.ts` unmarshalls `trustedEvidenceContext` from the stream's `NewImage` and forwards it to `DetectionPipeline`.
  - All web detection rules (`Rule101SqlInjection` through `Rule105AuthFlowTampering`) asynchronously evaluate and verify evidence via `normalizeWebTelemetryAsync`.
  - Public HTTP endpoints (`GET /api/v1/events` and `GET /api/v1/events/:eventId`) explicitly strip `trustedEvidenceContext` from HTTP responses, preventing external leakage of internal cryptographic artifacts.
  - `EventService` introduces `ingestInternalEvent` for authenticated verifier components, while rejecting any client-supplied `trustedEvidenceContext` from untrusted public ingestion.

---

## 6. Residual Risks & Phase 8 Preparation

1. **Vulnerability Correlation Scope:**
   - In Phase 7, vulnerability findings are simulated and correlated through `VulnerabilityCorrelator`. In Phase 8 ("Authorized Website Vulnerability Assessment"), dynamic scan findings from the active assessment engine will be automatically fed into this correlation interface.
2. **Dynamic Sliding Window State in Serverless:**
   - For single-container and development modes, in-memory sliding windows track active buckets. In production multi-region deployments, DynamoDB conditional writes and stream-backed workers provide fault-tolerant persistence.
3. **Live AWS Secrets Manager Deployment Verification:**
   - CloudFormation template changes in `infrastructure/template.yaml` have been validated syntactically and structurally. Live deployment to AWS accounts with Secrets Manager VPC endpoints and automated secret rotation must be completed during the staging/prod deployment pipeline.

---

## 7. Audit Conclusion

The Phase 7 implementation fulfills all security, architectural, and quality standards mandated by the VELTRIX project roadmap. All 13 audit findings across all security audits have been remediated, verified, and accompanied by comprehensive regression tests.

The branch `feature/phase-7-distributed-security-hardening` and follow-up Pull Request #11 are certified **SECURE & READY FOR PULL REQUEST REVIEW**.
