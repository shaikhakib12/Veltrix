# VELTRIX: Autonomous Cyber Threat Detection & Response Platform
## System Requirements Specification (`specs/requirements.md`)

**Document Version:** 3.0.0 (Unified Website Security Platform Expansion)  
**Status:** PROPOSED / IN REVIEW (PR #4 Architecture Review)  
**Project:** VELTRIX  
**Tagline:** Beyond Detection. Into Defense.  
**Classification:** Enterprise Cyber Threat Detection & Controlled Response Platform  

---

## 1. Executive Summary & Vision

VELTRIX is an autonomous, event-driven Security Information and Event Management (SIEM) and Security Orchestration, Automation, and Response (SOAR) platform. Modern Security Operations Centers (SOC) face crippling alert fatigue, uncoordinated alerts from disparate systems, and delayed manual containment actions.

VELTRIX resolves these challenges by:
1. Ingesting and normalizing security telemetry with high-precision idempotency verification (preventing accidental deduplication of rapid brute-force attempts).
2. Evaluating signals in real-time against 10 Sigma-inspired detection rules with sliding temporal windows.
3. Correlating disparate alerts across time, IP, and identity into coherent attack sequences mapped to the MITRE ATT&CK® matrix.
4. Computing explainable, deterministic mathematical risk scores ($0–100$) with transparent factor breakdowns.
5. Providing unified operational interfaces: a dark-first Web SOC Console and a high-performance terminal CLI (`@veltrix/cli`).
6. Enforcing controlled, approval-gated defensive responses (`BLOCK_IP`, `SUSPEND_USER`, `REVOKE_SESSION`, `STEP_UP_AUTH`) with zero-bypass authorization and instant rollback.
7. Anchoring all operational actions in an append-only, SHA-256 cryptographic audit ledger serialized via SQS FIFO.

---

## 2. Multi-Tenancy & Role-Based Access Control (RBAC)

VELTRIX enforces strict organization-level data isolation backed by Amazon Cognito and backend claim validation.

| Role | Scope & Privileges | Primary Persona |
| :--- | :--- | :--- |
| **Super Admin** | Platform-wide monitoring, cross-organization administration, global detection rule publishing, emergency kill-switch. | MSSP Lead / Platform Owner |
| **Organization Admin** | Organization user provisioning, custom detection rule management, SOAR response policy authorization, audit ledger export. | Enterprise CISO / SecOps Director |
| **Security Analyst** | Real-time event triage, attack timeline inspection, manual containment dispatch (with approval gates), investigation notes. | SOC Lead / Incident Responder (Tier 1 & 2) |
| **Read-Only Viewer** | Executive dashboards, read-only analytics, incident timeline audits without mutation or containment privileges. | Compliance Auditor / Executive Stakeholder |

---

## 3. Functional Requirements (FR)

### Module A — Authentication & Organization Management
- **FR-AUTH-01:** Secure user authentication (registration, login, MFA, session token invalidation) via Amazon Cognito User Pools.
- **FR-AUTH-02:** Organization tenant isolation: every security event, rule, incident, and audit record must carry a verified `orgId`.
- **FR-AUTH-03:** Backend claims verification: The backend API Gateway and Lambda authorizer validate JWT tokens; client-provided `orgId` parameters must match JWT claims or be rejected with `403 Forbidden`.
- **FR-AUTH-04:** Role-Based Access Control (RBAC) enforced on every API route, UI action, and CLI command.

### Module B — Event Ingestion API & High-Precision Deduplication
- **FR-INGEST-01:** High-throughput REST endpoint `POST /api/v1/events` supporting single and batch telemetry payloads (up to 100 events/batch).
- **FR-INGEST-02:** Standardized Event Schema: `eventId`, `orgId`, `timestamp` (ISO 8601 UTC), `eventType`, `severity`, `category` (AUTHENTICATION, NETWORK, PRIVILEGE, API, DATA_ACCESS, SYSTEM), `sourceIp`, `username`, `sourceSystem`, `metadata`, `isSimulated`, `idempotencyKey`.
- **FR-INGEST-03:** Schema validation via Zod, rejecting malformed, untyped, or malicious injection payloads with structured error diagnostic responses.
- **FR-INGEST-04 (Hardened Deduplication):** To prevent discarding legitimate high-velocity brute-force events (e.g. 5 failed logins within 10 seconds), deduplication distinguishes between true network retries and distinct attacks:
  - If `idempotencyKey` is provided by the client, it is used for deduplication.
  - If omitted, `idempotencyKey = eventId` (UUIDv7/UUIDv4 generated per event).
  - Deduplication fingerprint: `SHA-256(orgId + idempotencyKey)`.
  - Legitimate repeated authentication attempts with unique event IDs are **never** discarded.

### Module C — Threat Detection Engine (Sigma-Inspired)
- **FR-DETECT-01:** Independent, rule-based detection engine evaluating sliding temporal windows.
- **FR-DETECT-02:** Support dynamic rule enablement, threshold tuning, and time-window adjustment via REST API and CLI without restarting backend processes.
- **FR-DETECT-03:** Ten (10) built-in Sigma-inspired detection rules:
  1. `RULE-001`: Distributed Brute-Force Authentication Attempt (MITRE `T1110.001`, $\ge 5$ failed logins in 120s from single IP).
  2. `RULE-002`: Password Spraying Across Multiple Accounts (MITRE `T1110.003`, $\ge 3$ distinct accounts from same IP in 300s).
  3. `RULE-003`: Compromise After Failure / Credential Stuffing Success (MITRE `T1078`, valid login following failed attempts on same account in 600s).
  4. `RULE-004`: Anomalous Geolocation / Impossible Travel (MITRE `T1078.004`, successive logins across distant regions in $< 30$ min).
  5. `RULE-005`: Known Malicious / Tor / Proxy IP Activity (MITRE `T1090`, telemetry from confirmed threat intelligence indicators).
  6. `RULE-006`: Privilege Escalation Indicator (MITRE `T1068`, unauthorized administrative role assumption or policy mutation).
  7. `RULE-007`: Bulk Sensitive Data Access / Exfiltration (MITRE `T1530`, query/export $> 10,000$ records or high bandwidth transfer).
  8. `RULE-008`: Excessive / Burst API Requests (MITRE `T1499`, burst $> 100$ requests/minute to sensitive endpoints).
  9. `RULE-009`: Multi-Account Targeted Reconnaissance (MITRE `T1595`, single IP probing $> 4$ user handles in 180s).
  10. `RULE-010`: Off-Hours Administrative Anomaly (MITRE `T1078`, administrative actions executed outside 06:00 - 22:00 window).
- **FR-DETECT-04:** Dynamic Rule Testing: Expose `POST /api/v1/detection-rules/test` allowing analysts to dry-run rules against synthetic payloads without persisting alerts.

### Module D — Event Correlation Engine
- **FR-CORR-01:** Temporal sliding window correlation across common source IPs and target usernames (15-minute default window).
- **FR-CORR-02:** Attack Sequence Detection: Recognize multi-stage progression across MITRE tactics (*Credential Access $\to$ Valid Accounts $\to$ Privilege Escalation $\to$ Exfiltration*).
- **FR-CORR-03:** Alert deduplication & grouping: Merge related triggers into a single unified `Incident`, preventing alert storming.
- **FR-CORR-04:** Chronological Attack Timelines: Maintain timestamped progression of every attack phase.

### Module E — Explainable Risk Scoring Engine
- **FR-RISK-01:** Calculate a deterministic normalized score ($0 - 100$) for every incident:
  $$\text{RiskScore} = \min\left(100, \text{Round}\left(S_{\text{base}} \times M_{\text{freq}} \times M_{\text{asset}} \times M_{\text{threat}} + B_{\text{sequence}}\right)\right)$$
- **FR-RISK-02:** Classification tiers: Low ($0–24$), Medium ($25–49$), High ($50–74$), Critical ($75–100$).
- **FR-RISK-03:** Transparency: Store full human-readable factor breakdown (Base severity, frequency multiplier, asset criticality, threat intelligence multiplier, attack sequence bonus) with each incident.

### Module F — Threat Intelligence
- **FR-TI-01:** Embedded offline IOC repository with Tor exit nodes, botnet C2s, and malicious proxy indicators.
- **FR-TI-02:** Interactive IP reputation inspection via web console and CLI (`veltrix intel ip <address>`).
- **FR-TI-03:** Graceful degradation: Functions seamlessly offline without requiring third-party API keys.
- **FR-TI-04:** MITRE ATT&CK technique mapping and mitigation recommendations.

### Module G — Incident Management
- **FR-INC-01:** Complete incident lifecycle: `NEW` $\to$ `INVESTIGATING` $\to$ `CONTAINED` $\to$ `RESOLVED` (or `FALSE_POSITIVE`).
- **FR-INC-02:** Analyst assignees, triage severity overrides, and investigative notes thread.
- **FR-INC-03:** Search, multi-criteria filtering, and pagination.

### Module H — Defensive Response Engine (SOAR)
- **FR-RESP-01:** Supported containment actions against simulated targets: `REVOKE_SESSION`, `SUSPEND_USER`, `BLOCK_IP`, `STEP_UP_AUTH`, `ESCALATE_ALERT`.
- **FR-RESP-02 (Zero-Bypass Approval Gates):** High-impact actions (`BLOCK_IP`, `SUSPEND_USER`) queue as `PENDING_APPROVAL`. Direct execution via `/execute` without approval token or Org Admin authorization is rejected with `403 Forbidden`.
- **FR-RESP-03 (Target Whitelisting & Sandboxing):** All containment actions strictly validate that targets match authorized simulated CIDR blocks or test identities. Actions against non-whitelisted IP ranges or production identities are structurally rejected.
- **FR-RESP-04 (Rollback Registry):** Instant operational rollback support (`UNBLOCK_IP`, `REINSTATE_USER`) for all containment actions.

### Module I — Security Audit Logging & Cryptographic Ledger
- **FR-AUDIT-01:** Append-only recording of all logins, rule changes, detections, incident transitions, and containment actions.
- **FR-AUDIT-02 (Serialized Chaining):** To prevent race conditions in distributed serverless environments, audit writes are serialized via SQS FIFO queue with `MessageGroupId = orgId`.
- **FR-AUDIT-03 (SHA-256 Fingerprint Chain):** Every record anchors to the previous record's hash:
  $$\text{IntegrityHash}_k = \text{SHA-256}(\text{IntegrityHash}_{k-1} \,\|\, \text{Payload})$$
- **FR-AUDIT-04:** Verification API: One-click validation recalculating all hashes to detect any tampering or chain discontinuity.
- **FR-AUDIT-05:** Real-cloud immutability: Backed by DynamoDB IAM restrictions (disallowing `DeleteItem`/`UpdateItem`) and S3 Object Lock in Compliance Mode for long-term compliance.

### Module J — Security Operations Center (SOC) Dashboard
- **FR-DASH-01:** Dark-first cyber aesthetic: Midnight Navy canvas (`#0B0F19`), Electric Cyan (`#00F5FF`), Royal Blue.
- **FR-DASH-02:** Real-time metrics: Ingested events, detected threats, open incidents, MTTD, MTTR.
- **FR-DASH-03:** Visualizations: Ingestion velocity area chart, severity donut distribution, MITRE ATT&CK tactic bar chart, auth success/failure trends.

### Module K — Simulation Lab
- **FR-SIM-01:** Six pre-built sandboxed attack scenarios with synthetic event injection:
  1. *Distributed Password Spraying & Brute Force*
  2. *Impossible Travel & Geolocation Anomaly*
  3. *Multi-Stage Account Compromise & Exfiltration*
  4. *Unauthorized Administrative Role Assumption*
  5. *Cloud Storage Bulk Data Exfiltration*
  6. *Excessive API Rate-Limit Breach & Scraping*
- **FR-SIM-02:** Synthetic telemetry tagged with `isSimulated: true`.
- **FR-SIM-03:** Live terminal streaming injected events, detection alerts, and correlated incident links.

### Module L — VELTRIX CLI (`@veltrix/cli`)
- **FR-CLI-01:** Standalone terminal CLI built with Node.js, TypeScript, Commander.js, Chalk, Ora, Cli-table3, and Zod.
- **FR-CLI-02:** Shared backend: The CLI calls the same REST APIs as the web dashboard; business logic is never duplicated.
- **FR-CLI-03:** Full command suite:
  - `veltrix auth login / logout / status`
  - `veltrix events list / show / ingest --dry-run`
  - `veltrix detect run / rules list / rules test`
  - `veltrix incidents list / show / update / assign`
  - `veltrix intel ip / indicators list / mitre`
  - `veltrix response policies list / preview / execute / history`
  - `veltrix simulate list / run / results`
  - `veltrix status / config show`
- **FR-CLI-04:** Output formats: Rich colored human-readable tables and machine-readable `--json` output with exit codes ($0$ success, $1$ error, $2$ auth required).
- **FR-CLI-05:** Approval enforcement: Sensitive actions require interactive confirmation or explicit `--yes` flag.

### Module M — Website Asset Inventory & Domain Verification
- **FR-ASSET-01:** Tenant-isolated website asset registry supporting registration of primary domain, approved subdomains, environment tier (`PRODUCTION`, `STAGING`, `DEVELOPMENT`), asset criticality, and integration metadata.
- **FR-ASSET-02 (Domain Ownership Verification):** Software-enforced cryptographic proof of ownership before allowing any vulnerability scans via:
  1. DNS TXT record challenge: `_veltrix-challenge.<domain>` = `veltrix-verify=<orgId>.<token>`
  2. HTTP challenge endpoint: `https://<domain>/.well-known/veltrix-challenge/<token>` returning valid JSON payload over HTTPS.
- **FR-ASSET-03 (Ownership Revocation & Grace Period Safety Freeze):** Verification expires after 90 days. Daily background re-checks transition modified records to `GRACE_PERIOD` (7 days) then `REVOKED`.
  - **Scan Freeze:** Entering `GRACE_PERIOD` immediately blocks new scans, cancels queued/scheduled scans, and signals running workers to abort.
  - The 7-day grace period is strictly an administrative renewal period for alerting the domain owner; it is never permission to continue scanning. Successful re-verification is strictly required to resume scans.
- **FR-ASSET-04:** Asset & integration health tracking: Real-time telemetry velocity, last event received timestamp, integration agent heartbeat, and delivery error rates.

### Module N — Website Attack Monitoring & Correlation
- **FR-WAM-01:** Dedicated web attack detection rules covering SQL injection (`RULE-101`), Cross-Site Scripting (`RULE-102`), Path Traversal / LFI (`RULE-103`), Malicious Bot / Scraper activity (`RULE-104`), and Authentication Flow Abuse (`RULE-105`).
- **FR-WAM-02 (Attack vs. Exploitation Confidence Classification):** HTTP status codes (200, 4xx, 5xx) alone must not establish successful exploitation. The engine enforces four evidence-based confidence tiers:
  1. `SUSPICIOUS_ATTEMPT`: Inbound pattern detected; unverified impact.
  2. `BLOCKED_ATTEMPT`: Verified security control (WAF/middleware) intercepted the attack (e.g. 403 Forbidden with WAF rule match).
  3. `POTENTIAL_EXPLOITATION`: Inbound attack reached application accompanied by corroborating signals (unhandled DB syntax error traceback in error logs, database timeout spike, anomalous latency).
  4. `CONFIRMED_EXPLOITATION`: Multi-source proof (verified data leakage in payload, unauthorized privilege change, canary token trigger).
  - No automatic Critical incidents are created solely from response status or response size without corroborating evidence.
- **FR-WAM-03 (Configurable Risk Contribution Model):** Evaluates risk through a transparent, explainable additive model:
  $\text{RiskScore} = \min\left(100, \text{Round}\left(S_{\text{base}} \times M_{\text{freq}} \times M_{\text{asset}} \times M_{\text{threat}} + C_{\text{vuln\_match}} + B_{\text{sequence}}\right)\right)$
  where $C_{\text{vuln\_match}}$ is calibrated by attack surface overlap (exact path and parameter match vs open finding) and confidence tier.

### Module O — Authorized Website Vulnerability Assessment
- **FR-VULN-01 (Isolated Scanner Architecture):** Decoupled scanning execution using containerized workers (evaluating OWASP ZAP) communicating via SQS FIFO queues with rate limiting (max 5-10 req/s).
- **FR-VULN-02 (Safe Passive Assessment):** Non-destructive inspection of TLS configuration, HTTP security headers (HSTS, CSP, X-Frame-Options, etc.), cookie flags (`Secure`, `HttpOnly`, `SameSite`), CORS headers, and information disclosure banners.
- **FR-VULN-03 (Controlled Active Assessment & Emergency Abort):** Strict opt-in active probing requiring valid `scanAuthorizationToken`, confirmed domain ownership, approved FQDN scope, and emergency abort kill-switch targeting a 500ms Service Level Objective (SLO) for socket termination.
- **FR-VULN-04 (Vulnerability Findings Lifecycle):** Persistent finding state machine (`OPEN` $\to$ `CONFIRMED` $\to$ `IN_REMEDIATION` $\to$ `RESOLVED` $\to$ `ACCEPTED_RISK` $\to$ `FALSE_POSITIVE`) with CVSS v3.1 scoring, remediation guidance, and automated re-scan verification.
- **FR-VULN-05 (Comprehensive SSRF Egress Safeguards & Prohibitions):** Prohibit DoS/DDoS testing, destructive data modification, automated brute-forcing of production forms, and out-of-scope scanning. Enforce socket-level connection-time IP validation and network egress security groups blocking IPv4 private (RFC 1918), loopback, link-local (169.254.169.254), IPv6 loopback (::1), unique-local, link-local, IPv4-mapped IPv6 (::ffff:0:0/96), unspecified, DNS rebinding, and recursive CNAME bypasses.

---

## 4. Non-Functional Requirements (NFR)

### Performance & Latency
- **NFR-PERF-01:** P95 event ingestion latency $< 100\text{ ms}$.
- **NFR-PERF-02:** End-to-end detection and correlation latency $< 1.5\text{ seconds}$.
- **NFR-PERF-03:** CLI command execution time $< 800\text{ ms}$ for standard queries.
- **NFR-PERF-04:** Web UI initial load time $< 1.2\text{ seconds}$.

### Scalability & Availability
- **NFR-SCALE-01:** Cloud-native serverless architecture with zero continuously running idle compute instances.
- **NFR-SCALE-02:** DynamoDB Time-Sharded Partitioning supporting burst workloads up to 1,000 events/second without hot-partition throttling.

### Security & Governance
- **NFR-SEC-01:** Zero hardcoded secrets or credentials in repository.
- **NFR-SEC-02:** Tenant isolation enforced at database partition key level (`ORG#{orgId}#DATE#{YYYY-MM-DD}`).
- **NFR-SEC-03:** Least-privilege IAM roles scoped without wildcard permissions.
- **NFR-SEC-04:** Data encrypted in transit (TLS 1.3) and at rest (AWS KMS AES-256).
