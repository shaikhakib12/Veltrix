# VELTRIX: Autonomous Cyber Threat Detection & Response Platform
## System Requirements Specification (`requirements.md`)

**Document Version:** 1.0.0  
**Status:** Approved for Implementation Planning  
**Classification:** Enterprise Security Architecture Specification  
**Project Name:** VELTRIX  
**Primary Tagline:** Beyond Detection. Into Defense.  
**Alternative Tagline:** Intelligence. Detection. Defense.  

---

## 1. Executive Summary & Project Vision

VELTRIX is an autonomous, event-driven Security Information and Event Management (SIEM) and Security Orchestration, Automation, and Response (SOAR) platform designed for modern cloud and hybrid environments. It combines high-throughput event ingestion, Sigma-inspired rule detection, multi-stage event correlation, explainable risk scoring, integrated threat intelligence, and controlled defensive response orchestration into an enterprise-grade Security Operations Center (SOC) experience.

Unlike basic CRUD portals or synthetic dashboards, VELTRIX executes real serverless detection pipelines, correlates atomic security anomalies into complex attack narratives mapped to the MITRE ATT&CK® framework, and provides automated, approval-gated containment workflows with full cryptographic auditability.

---

## 2. Core Stakeholders & Role-Based Access Control (RBAC)

VELTRIX enforces strict multi-tenancy and Organization-Level Data Isolation backed by AWS Cognito and backend claim validation.

| Role | Permissions & Operational Scope | Target Persona |
| :--- | :--- | :--- |
| **Super Administrator** | Cross-organization administration, global platform configuration, system health monitoring, infrastructure auditing, and emergency kill-switch activation. | Managed Security Service Provider (MSSP) Lead / Platform Owner |
| **Organization Administrator** | Organization-level user provisioning, detection rule customization, response policy authorization, audit log export, and integration credential management. | Enterprise Security Director / CISO |
| **Security Analyst (Tier 1 & 2)** | Event ingestion monitoring, incident triage, correlation graph inspection, manual defensive response triggering (with approval gates), and investigation notes. | SOC Lead / Incident Responder |
| **Read-Only Viewer** | Read-only access to executive SOC dashboards, analytics reports, and post-incident review timelines without modification or response rights. | Compliance Auditor / Executive Stakeholder |

---

## 3. Functional Requirements (FR)

### Module A: Authentication & Organization Management
- **FR-AUTH-01:** Support user registration, email verification, multi-factor authentication (MFA), password reset, and session termination via Amazon Cognito User Pools.
- **FR-AUTH-02:** Organization tenancy model where each user belongs to at least one Organization (`orgId`).
- **FR-AUTH-03:** Backend claims verification: The backend API Gateway and Lambda Authorizer must validate the Cognito JWT token, verify tenant membership, and reject requests where the caller attempts to query or mutate an `orgId` outside their authorized scope.
- **FR-AUTH-04:** Enforce Role-Based Access Control (RBAC) across all API endpoints and UI action buttons.

### Module B: Security Event Ingestion API
- **FR-INGEST-01:** Ingestion REST endpoint `POST /events` accepting single and batch events from authentication systems, web firewalls, server syslog, cloud endpoints, and event generators.
- **FR-INGEST-02:** Standardized Event Schema containing:
  - `eventId` (UUIDv7 / UUIDv4)
  - `orgId` (Organization UUID)
  - `timestamp` (ISO 8601 UTC)
  - `eventType` (e.g., `auth.login.failed`, `auth.login.success`, `api.request.anomaly`, `iam.privilege.escalation`, `data.exfiltration.bulk`)
  - `severity` (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
  - `category` (`AUTHENTICATION`, `NETWORK`, `PRIVILEGE`, `API`, `DATA_ACCESS`)
  - `sourceIp` (IPv4/IPv6 address)
  - `username` (Target or acting user identity)
  - `sourceSystem` (Agent/hostname/ARN)
  - `metadata` (Key-value map of arbitrary context: user agent, status code, bytes transferred, HTTP method, target resource)
- **FR-INGEST-03:** Schema validation and normalization ensuring strict field typing, sanitization against command/SQL/NoSQL injection, and rejection of malformed events.
- **FR-INGEST-04:** Idempotency & Deduplication: Compute an event hash (`SHA-256(orgId + eventType + sourceIp + username + timestamp_minute)`) to suppress duplicate retransmissions within a sliding window.
- **FR-INGEST-05:** Rate limiting and throttling per organization tier using API Gateway Usage Plans.

### Module C: Threat Detection Engine
- **FR-DETECT-01:** Implement a modular, rule-based detection engine inspired by Sigma rule definitions.
- **FR-DETECT-02:** Support dynamic rule enablement, threshold adjustment, and parameter overrides stored in DynamoDB without code redeployment.
- **FR-DETECT-03:** Deliver ten (10) production-ready built-in detection rules:
  1. **RULE-001 (Brute-Force Authentication):** $\ge 5$ failed logins within a 2-minute window from the same `sourceIp` targeting any account (MITRE T1110.001).
  2. **RULE-002 (Targeted Account Password Spraying):** $\ge 3$ failed logins across distinct usernames from a single `sourceIp` within 5 minutes (MITRE T1110.003).
  3. **RULE-003 (Compromise After Failure / Credential Stuffing Success):** Successful login to an account within 10 minutes of $\ge 3$ failed attempts on that account (MITRE T1078).
  4. **RULE-004 (Anomalous Geolocation / Impossible Travel):** Successive logins for the same account from distinct geographic regions within an impossibly brief interval ($< 30$ minutes) (MITRE T1078.004).
  5. **RULE-005 (Known Malicious / Tor / Proxy IP Activity):** Any security event originating from an IP marked in Threat Intelligence as high-risk or malicious (MITRE T1090).
  6. **RULE-006 (Privilege Escalation Indicator):** Unauthorized attempt to assume administrative roles, attach elevated IAM policies, or invoke `sudo/admin` endpoints (MITRE T1068 / T1098).
  7. **RULE-007 (Bulk Sensitive Data Access / Exfiltration Indicator):** Read/export operation exceeding 10,000 records or transfer $> 500\text{ MB}$ from an anomalous IP/account (MITRE T1530 / T1567).
  8. **RULE-008 (Excessive / Burst API Requests):** $> 100$ requests within 60 seconds from a single caller to sensitive or rate-limited endpoints (MITRE T1499).
  9. **RULE-009 (Multi-Account Targeted Reconnaissance):** Single source IP probing $> 5$ unique endpoints or user handles within a 3-minute window (MITRE T1595).
  10. **RULE-010 (Off-Hours Administrative Anomaly):** High-privilege administrative action executed outside normal enterprise operating hours (22:00 - 06:00 local time) (MITRE T1078).
- **FR-DETECT-04:** Every detection trigger outputs an explainable match structure: `ruleId`, `matchedConditions`, `triggeringEvents`, `confidence`, and `recommendedResponse`.

### Module D: Event Correlation Engine
- **FR-CORR-01:** Correlate disparate events across time windows, source IPs, and target accounts to construct coherent Attack Sequences (Kill Chains).
- **FR-CORR-02:** Recognize multi-stage compromise sequences (e.g., *Reconnaissance / Brute Force $\to$ Successful Login $\to$ Privilege Escalation $\to$ Bulk Data Exfiltration*).
- **FR-CORR-03:** Auto-group correlated events into a single Security Incident to prevent alert fatigue.
- **FR-CORR-04:** Maintain incident chronological timelines illustrating the progression of the attack across systems.
- **FR-CORR-05:** Compute a correlation confidence score ($0 - 1.0$) based on entity linkage (shared IP, shared user, causal temporal order).

### Module E: Explainable Risk Scoring Engine
- **FR-RISK-01:** Calculate a normalized risk score between $0$ and $100$ for every incident.
- **FR-RISK-02:** Formulaic transparency: Deconstruct the total score into quantifiable contributing signals:
  $$\text{RiskScore} = \min\left(100, \sum_{i} W_i \cdot S_i\right)$$
  where factors include:
  - Base Rule Severity ($S_{\text{base}}$: Low=15, Med=35, High=65, Crit=90)
  - Frequency & Volume Multiplier ($M_{\text{freq}}$)
  - Target Asset Sensitivity / Privilege Level ($M_{\text{asset}}$)
  - Threat Intelligence Reputation Weight ($W_{\text{threat}}$)
  - Correlation Sequence Depth Multiplier ($M_{\text{corr}}$)
- **FR-RISK-03:** Risk Tier Classification:
  - **Low:** $0 - 24$ (Informational / minor hygiene)
  - **Medium:** $25 - 49$ (Suspicious single-event anomalies)
  - **High:** $50 - 74$ (Multi-event corroborated attacks)
  - **Critical:** $75 - 100$ (Active multi-stage compromise or data exfiltration)
- **FR-RISK-04:** Persist full human-readable factor breakdown with each incident for analyst review and explainability audits.

### Module F: Threat Intelligence Enrichment
- **FR-TI-01:** Track suspicious IP indicators, autonomous system numbers (ASN), geolocation hints, and threat reputation scores.
- **FR-TI-02:** Provide an integrated local threat indicator feed pre-populated with realistic simulated threat actors (Tor exit nodes, botnet IPs, compromised test proxies).
- **FR-TI-03:** Graceful offline degradation: External threat intelligence APIs (e.g., AbuseIPDB, AlienVault OTX) are fully optional; if no API key is supplied or network is unavailable, the local enriched repository operates seamlessly without errors.
- **FR-TI-04:** MITRE ATT&CK knowledge base mapping: Display technique ID, tactic name, detection guidance, and mitigation recommendations on all alerts and incidents.

### Module G: Incident Management & Triage
- **FR-INC-01:** Incident lifecycle state machine:
  $$\text{New} \longrightarrow \text{Investigating} \longrightarrow \text{Contained} \longrightarrow \text{Resolved} \quad (\text{or } \text{False Positive})$$
- **FR-INC-02:** Assignee workflow: Enable Tier 1/2 analysts to claim, reassign, or escalate incidents.
- **FR-INC-03:** Analyst notes and timeline auditing: Append timestamped investigation findings.
- **FR-INC-04:** Query capabilities: Filter by organization, status, severity, assignee, date range, and keyword search with DynamoDB pagination.

### Module H: Automated Defensive Response Engine (SOAR)
- **FR-RESP-01:** Support simulated safe containment actions:
  - `REVOKE_SESSION`: Terminate active simulated user session tokens.
  - `SUSPEND_USER`: Lock target simulated user account.
  - `BLOCK_IP`: Inject IP into simulated firewall blocklist / WAF policy.
  - `STEP_UP_AUTH`: Flag account requiring immediate MFA step-up verification.
  - `ESCALATE_ALERT`: Trigger high-priority notification to SOC lead.
- **FR-RESP-02:** Execution Modes:
  - **Automatic (Policy-driven):** Execute immediately if incident severity $\ge \text{CRITICAL}$ and policy explicitly authorizes hands-off mitigation.
  - **Manual Approval Gate:** Require explicit analyst or administrator approval for disruptive actions (`SUSPEND_USER`, `BLOCK_IP`).
- **FR-RESP-03:** Safety Boundaries: Actions only affect explicitly tagged test systems and simulated identities. Rollback actions (`UNBLOCK_IP`, `REINSTATE_USER`) supported for all containment tasks.
- **FR-RESP-04:** Full execution audit: Log executor, timestamp, target entity, approval token, pre-action state, and post-action state.

### Module I: Security Audit Trail & Cryptographic Fingerprinting
- **FR-AUDIT-01:** Record every system event, user login, policy change, detection execution, incident mutation, and defensive response.
- **FR-AUDIT-02:** Cryptographic Integrity Fingerprint: Compute a SHA-256 hash over the payload and previous record hash, creating an append-only verification chain:
  $$\text{Fingerprint}_k = \text{SHA-256}(\text{Fingerprint}_{k-1} \,\|\, \text{Timestamp} \,\|\, \text{Actor} \,\|\, \text{Action} \,\|\, \text{Payload})$$
- **FR-AUDIT-03:** Audit trail tamper verification tool: Expose an API endpoint and UI utility to verify chain continuity and alert on any detected discrepancies.

### Module J: Security Analytics SOC Dashboard
- **FR-DASH-01:** Real-time KPI summary: Total Ingested Events (24h), Active Threats Detected, Open Incidents, Critical Incident Count, High-Risk IPs, Mean Time to Detect (MTTD), Mean Time to Respond (MTTR).
- **FR-DASH-02:** Visual Analytics:
  - Ingestion Velocity and Event Volume Trend (Recharts area/bar chart)
  - Severity Distribution Breakdown (Recharts donut/pie)
  - MITRE ATT&CK Tactic Heatmap
  - Failed vs. Successful Authentication Timeline
  - Top 10 Attacking Source IPs and Targeted User Accounts
- **FR-DASH-03:** Multi-tenant organization selector and dynamic date range filtering (Last 1 hour, 6 hours, 24 hours, 7 days, Custom).

### Module K: VELTRIX Simulation Lab
- **FR-SIM-01:** Self-contained, sandboxed security attack simulation lab with six (6) automated interactive scenarios:
  1. *Distributed Brute-Force Password Spray*
  2. *Impossible Travel / Suspicious Geo-Anomaly*
  3. *Full Multi-Stage Account Takeover (Brute-force $\to$ Login $\to$ Escalation $\to$ Bulk Exfil)*
  4. *Privilege Escalation via Unauthorized IAM Role Assumption*
  5. *Cloud Storage Bulk Data Exfiltration*
  6. *DDoS / Excessive API Rate-Limit Breach*
- **FR-SIM-02:** Real-time feedback loop: Triggering a scenario in the UI transmits synthetic telemetry through the actual ingestion pipeline, displaying live detection triggers, incident creation, risk score calculation, and defensive response execution.
- **FR-SIM-03:** Safe-lab guarantees: All simulation payloads are strictly isolated with `isSimulated: true` flags, preventing confusion with production monitoring.

---

## 4. Non-Functional Requirements (NFR)

### Performance & Latency
- **NFR-PERF-01:** Ingestion endpoint response time $< 100\text{ ms}$ at 95th percentile (P95) under steady load.
- **NFR-PERF-02:** End-to-end detection pipeline latency (from event ingestion to rule evaluation and DynamoDB record creation) $< 1.5\text{ seconds}$.
- **NFR-PERF-03:** Frontend dashboard initial render $< 1.2\text{ seconds}$; chart rendering $< 300\text{ ms}$.

### Scalability & Availability
- **NFR-SCALE-01:** Completely serverless backend architecture utilizing AWS Lambda, DynamoDB On-Demand, and API Gateway with zero always-on idle compute instances.
- **NFR-SCALE-02:** Elastic scaling supporting burst workloads up to 1,000 events/second without manual provisioning.

### Security, Isolation & Compliance
- **NFR-SEC-01:** Tenant Isolation: Every DynamoDB query and mutation must incorporate `orgId` as part of the partition key or strictly enforce claim matching.
- **NFR-SEC-02:** Least Privilege IAM: Separate execution roles for Ingestion, Detection, Incident Management, Response, and Audit Lambdas with zero wildcard (`*`) resource permissions.
- **NFR-SEC-03:** Data Protection: All data encrypted in transit via TLS 1.3 and at rest via AWS KMS (AES-256).
- **NFR-SEC-04:** Zero Secrets in Codebase: No AWS credentials, API tokens, or secrets committed to repository. Configuration passed via AWS Systems Manager Parameter Store / Secrets Manager or environment variables.

### Reliability & Fault Tolerance
- **NFR-REL-01:** Idempotent event processing preventing duplicated incident generation when events are retried.
- **NFR-REL-02:** Dead-Letter Queues (DLQ) configured on asynchronous processing channels to preserve failed event payloads for investigation.

---

## 5. User Stories & Acceptance Criteria

### US-01: Security Analyst Detects Multi-Stage Attack
- **User Story:** *As a Tier 2 SOC Analyst, I want the system to correlate distinct anomalous events across time so that I can immediately identify and contain a coordinated account compromise before data is exfiltrated.*
- **Acceptance Criteria:**
  - **Given** an attacker attempts 5 failed logins from IP `198.51.100.42` against user `sarah.connors@acme.corp`, followed by a successful login, an IAM privilege elevation call, and a 12,000-record query within 15 minutes;
  - **When** the events pass through the ingestion engine;
  - **Then** the correlation engine links all 4 events under a single Incident labeled `"Account Compromise & Privilege Escalation Sequence"`;
  - **And** the risk scoring engine calculates a score $\ge 85$ (Critical);
  - **And** the incident timeline clearly renders the MITRE ATT&CK progression (T1110 $\to$ T1078 $\to$ T1068 $\to$ T1530).

### US-02: SOC Lead Executes Automated Response with Approval Gate
- **User Story:** *As an Incident Response Lead, I want high-impact containment actions to require human confirmation while low-risk notifications execute automatically, so that critical services are protected from accidental disruption.*
- **Acceptance Criteria:**
  - **Given** a Critical incident is flagged with a recommended response of `BLOCK_IP` and `SUSPEND_USER`;
  - **When** the automated response engine triggers;
  - **Then** `ESCALATE_ALERT` executes automatically without human delay;
  - **And** `BLOCK_IP` and `SUSPEND_USER` enter a `PENDING_APPROVAL` state with an explicit prompt in the Response Center;
  - **And** when the analyst clicks "Approve", the simulated containment action executes, updates the incident status to `Contained`, and logs a SHA-256 hashed audit record.

### US-03: Competition Judge Evaluates Live Simulation Lab
- **User Story:** *As a competition judge, I want to run a one-click attack scenario in the Simulation Lab and observe the real-time detection, correlation, risk scoring, and defensive response without manual setup.*
- **Acceptance Criteria:**
  - **Given** a judge selects the "Credential Stuffing to Data Exfiltration" scenario and clicks "Execute Simulation";
  - **When** the simulation generator fires synthetic events into the live ingestion pipeline;
  - **Then** the dashboard displays animated real-time event counters incrementing;
  - **And** within 2 seconds, detection alerts appear in the Threat Detection tab;
  - **And** the Correlated Incident appears in the Incident Center with an interactive attack timeline and explainable risk breakdown.
