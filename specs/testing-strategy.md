# VELTRIX: Testing & Quality Assurance Strategy (`specs/testing-strategy.md`)

**Document Version:** 3.0.0 (Unified Website Security Platform Expansion)  
**Status:** Approved Testing Strategy  
**Testing Frameworks:** Vitest 3.x (Unit & Integration), Playwright (E2E), Node.js Assertions  

---

## 1. Testing Pyramid & Quality Philosophy

VELTRIX adheres to a strict test-driven development cycle:
**PLAN $\to$ BUILD $\to$ TEST $\to$ DEBUG $\to$ FIX $\to$ RETEST $\to$ VERIFY $\to$ DOCUMENT.**

A feature is never considered complete merely because its code was authored; it is complete only when unit, integration, and security checks pass with zero regressions.

```text
       ▲
      / \        E2E Tests (Playwright: Live Web Console & CLI Flows)
     /   \       ----------------------------------------------------
    /     \      Integration Tests (Ingestion -> Detection -> Incident -> SOAR -> Audit)
   /       \     ------------------------------------------------------------------------
  /         \    Unit Tests (10 Sigma Rules, Risk Math, Deduplication, Hash Chain Chaining)
 /___________\   --------------------------------------------------------------------------
```

---

## 2. Test Requirements by Module

### 2.1 Module A: Authentication & Tenant Isolation
- **Acceptance Criteria:** Valid Cognito tokens permit access; missing or tampered tokens return `401 Unauthorized`. Caller querying an `orgId` differing from token claims is rejected with `403 Forbidden`.
- **Unit Tests:** JWT claims extraction, RBAC permission matrix checks.
- **Security Tests:** Cross-tenant access injection: test sending request with header `x-organization-id: org-b` when authenticated as `org-a`. Must assert `403 Forbidden`.
- **Failure Scenarios:** Expired tokens, malformed signatures, missing headers.

### 2.2 Module B: Event Ingestion & Deduplication
- **Acceptance Criteria:** Valid payloads return `202 Accepted`. Malformed schemas return `400 Bad Request`. Retransmitted events with identical `idempotencyKey` are discarded; rapid legitimate failed logins with distinct IDs are all preserved.
- **Unit Tests:** Zod schema validation, ISO UTC timestamp canonicalization, IPv4/IPv6 normalization.
- **Idempotency Tests:** Send 5 rapid failed logins within 5 seconds with distinct event IDs $\to$ assert all 5 are saved and trigger `RULE-001`. Send event #3 a second time $\to$ assert only 1 copy is saved.
- **Failure Scenarios:** Payload $> 100\text{ KB}$, array with 101 items (exceeding batch limit), malformed timestamps.

### 2.3 Module C: Threat Detection Engine (10 Sigma Rules)
- **Acceptance Criteria:** Each of the 10 Sigma-inspired rules triggers when its condition, threshold, and sliding window are met. Benign events below threshold or outside time window do not trigger alerts.
- **Unit Tests:**
  - True positive tests for `RULE-001` through `RULE-010`.
  - Negative tests: 4 failed logins when threshold is 5 $\to$ assert 0 triggers.
  - Window expiration tests: 5 failed logins spaced 150 seconds apart (window 120s) $\to$ assert 0 triggers.
- **Dynamic Tuning Tests:** Update threshold via API $\to$ assert engine immediately evaluates with new threshold.

### 2.4 Module D: Event Correlation Engine
- **Acceptance Criteria:** Correlates disparate detection triggers sharing an IP or target username within 15 minutes into a single unified incident. Builds an ordered attack timeline.
- **Integration Tests:** Ingest Brute Force $\to$ Valid Login $\to$ Privilege Escalation $\to$ Bulk Exfiltration. Assert 1 incident is produced containing 4 timeline steps.
- **Failure Scenarios:** Out-of-order event timestamps, missing entity keys.

### 2.5 Module E: Explainable Risk Scoring Engine
- **Acceptance Criteria:** Computes deterministic risk score ($0–100$) and generates factor breakdown.
- **Precision Unit Tests:** Validate formula:
  $$\text{Score} = \min\left(100, \text{Round}\left(S_{\text{base}} \times M_{\text{freq}} \times M_{\text{asset}} \times M_{\text{threat}} + B_{\text{sequence}}\right)\right)$$
  Assert high base (65) targeting privileged identity ($1.35\times$) with Tor IP ($1.20\times$) and multi-stage bonus ($+25$) caps at 100 with CRITICAL tier.

### 2.6 Module F: Threat Intelligence
- **Acceptance Criteria:** Enriches IPs against local IOC catalog. Returns clean status for unknown IPs without failing.
- **Unit Tests:** Known Tor node (`198.51.100.42`) returns `isFlagged: true`, confidence $\ge 90\%$.
- **Failure Scenarios:** Offline operation test (no network access) $\to$ assert local catalog operates with zero errors.

### 2.7 Module G: Incident Management
- **Acceptance Criteria:** Full lifecycle transitions (`NEW` $\to$ `INVESTIGATING` $\to$ `CONTAINED` $\to$ `RESOLVED`). Assignee updates and note appending succeed.
- **Integration Tests:** Query incidents by status and severity with pagination cursors.

### 2.8 Module H: Defensive Response (SOAR)
- **Acceptance Criteria:** Low-impact actions execute autonomously. High-impact actions queue as `PENDING_APPROVAL`. Approval executes action and updates registry. Rollback reverts containment.
- **Zero-Bypass Security Test:** Attempt to invoke `POST /responses/:incidentId/execute` with high-impact action without approval token $\to$ assert `403 Forbidden (APPROVAL_REQUIRED)`.
- **Target Sandboxing Test:** Attempt to block a non-whitelisted IP address $\to$ assert `400 Bad Request (UNAUTHORIZED_CONTAINMENT_TARGET)`.

### 2.9 Module I: Cryptographic Security Audit Trail
- **Acceptance Criteria:** Append-only ledger anchors records with SHA-256 hashes. Verification endpoint confirms continuity on pristine chains and flags exact record ID if historical records are modified.
- **Unit Tests:** Sequential chaining verification. Intentional tampering of record #2 in memory $\to$ assert `verified: false` with `brokenRecordId = target.logId`.

### 2.10 Module L: VELTRIX CLI
- **Acceptance Criteria:** Commands execute against backend APIs with formatted tables or valid JSON. Sensitive commands prompt for confirmation.
- **Integration Tests:** Test all subcommands (`auth`, `events`, `detect`, `incidents`, `intel`, `response`, `simulate`, `status`, `config`).
- **Exit Code Verification:** $0$ on success, $1$ on operational error, $2$ on unauthorized.

---

### 2.11 Module M: Website Asset Inventory & Domain Verification
- **Acceptance Criteria:** Assets can be registered, listed, and deleted. Verification succeeds only when DNS TXT or HTTP challenge matches the exact expected token. Unverified assets cannot be scanned.
- **Unit & Security Tests:**
  - DNS TXT verification test: Mock DNS resolver returning valid vs mismatched token. Assert transition to `VERIFIED` only on exact match.
  - HTTP Challenge verification test: Mock HTTPS server returning expected JSON vs 404/500 error.
  - Expired verification test: Mock asset with `expiresAt < Date.now()`. Assert scan request rejected with `403 Forbidden (DOMAIN_VERIFICATION_EXPIRED)`.
  - Cross-tenant asset boundary test: Tenant B cannot query, update, or verify Tenant A's websites.

### 2.12 Module N: Website Attack Monitoring & Correlation
- **Acceptance Criteria:** Web attack rules (`RULE-101` to `RULE-105`) trigger on malicious payloads. Engine classifies blocked probes (`4xx`) vs potential exploitation (`200/500`). Correlates attacks with asset open vulnerabilities.
- **Unit & Integration Tests:**
  - SQLi, XSS, Path Traversal payload tests against sliding temporal windows.
  - Disambiguation test: Assert probe returning 403 generates detection alert but lower incident base severity; request returning 200 with SQL error generates CRITICAL severity.
  - Vulnerability-weighted correlation test: Asset with open finding for XSS on `/search` receives $1.5\times$ risk multiplier penalty when inbound attack targets `/search`.

### 2.13 Module O: Vulnerability Assessment & Scanner Sandboxing
- **Acceptance Criteria:** Safe passive assessment identifies missing headers, weak TLS, and cookie flags. Active scanner enforces target scope, rate limits, and circuit breakers.
- **Safety & Sandboxing Tests:**
  - Zero-Bypass test: Attempt to launch active scan on unverified domain $\to$ assert `403 Forbidden`.
  - Out-of-scope drop test: Spider encountering third-party redirect (e.g. `https://auth0.com`) $\to$ assert request dropped and logged as `DROPPED_OUT_OF_SCOPE`.
  - SSRF private IP egress test: Scanner target pointing to `169.254.169.254` or `10.0.0.1` $\to$ assert egress guard immediately blocks socket connection.
  - Rate limiting test: Verify scanner never exceeds configured requests per second (e.g. 5 req/s).
  - Emergency abort test: Trigger `POST /scans/:scanId/abort` $\to$ assert running worker immediately terminates execution.

---

## 3. Test Isolation: Local Simulation vs AWS Integration

- **Tier 1 (Unit & Local Tests):** Run against `MemoryStore` for rapid developer feedback ($< 1\text{ second}$ test execution).
- **Tier 2 (AWS Integration Tests):** Validate AWS SAM templates with AWS CloudFormation linter (`cfn-lint`), and test AWS SDK v3 client commands against DynamoDB Local / LocalStack before production deployment.
