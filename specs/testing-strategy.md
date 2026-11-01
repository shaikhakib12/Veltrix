# VELTRIX: Testing & Quality Assurance Strategy (`specs/testing-strategy.md`)

**Document Version:** 3.0.0 (Unified Website Security Platform Expansion)  
**Status:** PROPOSED / IN REVIEW (PR #4 Architecture Review)  
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
  - **Grace Period Scan Freeze Test:** Mock asset transitioning to `GRACE_PERIOD` after failed daily check. Assert: (1) launch scan returns `403 Forbidden (DOMAIN_VERIFICATION_SUSPENDED)`, (2) queued scans are cancelled immediately, (3) running worker receives abort signal.
  - Cross-tenant asset boundary test: Tenant B cannot query, update, or verify Tenant A's websites.

### 2.12 Module N: Website Attack Monitoring & Correlation
- **Acceptance Criteria:** Web attack rules (`RULE-101` to `RULE-105`) trigger on malicious payloads. Classifies telemetry into four confidence tiers without automatically creating Critical incidents from status codes alone. Correlates attacks with asset open vulnerabilities using configurable risk contributions.
- **Unit & Integration Tests:**
  - SQLi, XSS, Path Traversal payload tests against sliding temporal windows.
  - **Confidence Classification Tests:**
    - Probe intercepted by WAF returning 403 $\to$ assert classified as `BLOCKED_ATTEMPT` (no incident created).
    - Request returning 200 without application error signals $\to$ assert classified as `SUSPICIOUS_ATTEMPT` (does NOT generate Critical incident).
    - Request returning 500 accompanied by database error traceback $\to$ assert classified as `POTENTIAL_EXPLOITATION` (generates High incident).
    - Verified database data leakage $\to$ assert classified as `CONFIRMED_EXPLOITATION` (Critical tier).
  - **Configurable Risk Model Calibration Test:** Asset with open finding for XSS on `/search?q=` receives additive score $C_{vuln\_match}$ based on exact parameter overlap ($w=25$) and confidence tier.

### 2.13 Module O: Vulnerability Assessment & Scanner Sandboxing
- **Acceptance Criteria:** Safe passive assessment identifies missing headers, weak TLS, and cookie flags. Active scanner enforces target scope, rate limits, and circuit breakers.
- **Safety & Sandboxing Tests:**
  - Zero-Bypass test: Attempt to launch active scan on unverified domain $\to$ assert `403 Forbidden`.
  - Out-of-scope drop test: Spider encountering third-party redirect (e.g. `https://auth0.com`) $\to$ assert request dropped and logged as `DROPPED_OUT_OF_SCOPE`.
  - **Comprehensive SSRF & Egress Protection Tests:**
    - **Application-Level Connection Validation Tests:**
      - Connection to IPv4 private (`10.0.0.1`, `192.168.1.1`, `172.16.0.1`) $\to$ assert blocked.
      - Connection to Cloud Metadata (`169.254.169.254`) $\to$ assert blocked.
      - Connection to IPv6 loopback (`::1`), unique-local (`fc00::1`), and link-local (`fe80::1`) $\to$ assert blocked.
      - Connection to IPv4-mapped IPv6 (`::ffff:127.0.0.1`, `::ffff:169.254.169.254`) $\to$ assert blocked.
      - Connection to unspecified (`0.0.0.0`, `::`) $\to$ assert blocked.
      - **DNS Rebinding Test:** Mock DNS server returning public IP on lookup #1 but returning `127.0.0.1` on connection lookup $\to$ assert socket hook validates IP and blocks connection before TCP handshake.
      - **DNS Pinning Test:** Assert socket connects directly to validated IP (`socket.connect({ host: validatedIp })`) while preserving TLS SNI (`servername`) and HTTP `Host` header.
      - **Recursive CNAME Test:** Target domain alias pointing to `internal.service.local` $\to$ assert connection rejected.
      - **HTTP 3xx Redirect Re-Validation Test:** Target redirecting to internal IP or unapproved domain $\to$ assert redirect intercepted and dropped.
    - **Proposed Cloud Network Controls Validation (Proposed Phase 11/12 Cloud Infrastructure Tests):**
      - *CloudFormation / SAM Linter Test:* Validate proposed template specifies restrictive Security Group allow rules (outbound TCP 80/443 only; assert no claims of explicit deny rules in SG).
      - *NACL Rule Ordering Test:* Validate proposed CloudFormation template defines explicit high-priority outbound DENY rules for `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, and `169.254.169.254/32` on the Scanner Subnet NACL before default allow.
      - *AWS Network Firewall Route Table Test:* Validate proposed routing configuration directs default route `0.0.0.0/0` from Scanner Subnet $\to$ Network Firewall VPC Endpoint $\to$ NAT Gateway $\to$ IGW, and verifies IGW edge route table for symmetric return traffic.
      - *Route 53 Resolver DNS Firewall Test:* Validate proposed DNS Firewall rule group association blocks queries for private hosted zones.
  - **Rate Limiting & Adaptive Backoff:** Verify scanner never exceeds configured rate (5 req/s). Mock 3 consecutive 429/503 responses $\to$ assert scanner backs off and aborts if unrecovered.
  - **Emergency Abort Target SLO Test:** Trigger `POST /scans/:scanId/abort` $\to$ assert worker terminates sockets, cleans up processes, and reports `ABORTED` state within target SLO. If unresponsive for 10s $\to$ assert `ABORT_FAILED_TIMED_OUT`.

---

## 3. Test Isolation: Local Simulation vs AWS Integration

- **Tier 1 (Unit & Local Tests):** Run against `MemoryStore` for rapid developer feedback ($< 1\text{ second}$ test execution).
- **Tier 2 (AWS Integration Tests):** Validate AWS SAM templates with AWS CloudFormation linter (`cfn-lint`), and test AWS SDK v3 client commands against DynamoDB Local / LocalStack before production deployment.
