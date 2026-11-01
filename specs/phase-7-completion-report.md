# VELTRIX — Phase 7 Implementation & Verification Completion Report
## Website Attack Monitoring, Correlation & Risk Scoring | TASK-701 through TASK-707

**Date:** November 1, 2026  
**Project:** VELTRIX — Unified Cybersecurity & Website Defense Platform ("Beyond Detection. Into Defense.")  
**Branch:** `feature/phase-7-web-attack-monitoring`  
**Base Commit:** `58d5719` (PR #6 Phase 6 Security Hardening merged into `main`)  
**PR Reference:** [PR #7 (shaikhakib12/Veltrix#7)](https://github.com/shaikhakib12/Veltrix/pull/7)  
**Status:** COMPLETE, AUDITED, HARDENED & VERIFIED — READY FOR REVIEW  
**Security Review Reference:** [`specs/phase-7-security-review.md`](file:///d:/Veltrix/specs/phase-7-security-review.md)  

---

## 1. Executive Summary

Phase 7 delivers core Layer B ("Analysis Layer") and Layer C ("Defense Layer") capabilities for the VELTRIX Unified Cybersecurity and Website Defense Platform. Building directly upon the Phase 6 Website Asset Inventory and Integration Foundation, Phase 7 establishes continuous, automated detection, classification, correlation, and mathematical risk quantification for website attacks.

Key accomplishments delivered across TASK-701 through TASK-707:
1. **Web Attack Signature & Rule Definitions (TASK-701):**
   - `RULE-101`: SQL Injection Probing & Exploitation (Boolean, UNION, stacked queries, syntax errors, and false-positive suppression).
   - `RULE-102`: Cross-Site Scripting (XSS) Probing (DOM sinks, script tags, event handlers, pseudo-protocols, and math comparison suppression).
   - `RULE-103`: Path Traversal & Local File Inclusion (Directory climbing, sensitive files, wrappers, null-bytes, and system leak detection).
   - `RULE-104`: Malicious Bot, Scraper & Endpoint Reconnaissance (Automated security tools, sensitive path enumeration, and benign script user-agent suppression).
   - `RULE-105`: Web Authentication Flow Tampering & Credential Stuffing (Brute-force login loops, credential stuffing across distinct usernames, and password reset abuse).
2. **Attack vs. Exploitation Confidence Classification (TASK-702):** A normalized telemetry parser (`normalizeWebTelemetry`) with multi-pass URL decoding, HTTP request normalization, sensitive parameter scrubbing (`password`, `token`, `secret`, `cookie`, `cvv` masked as `[REDACTED]`), and a 4-tier confidence classification hierarchy (`SUSPICIOUS_ATTEMPT`, `BLOCKED_ATTEMPT`, `POTENTIAL_EXPLOITATION`, `CONFIRMED_EXPLOITATION`). Prohibits automatic critical alerts based solely on HTTP status codes without corroborating exploitation evidence.
3. **Multi-Stage Attack Correlation Engine (TASK-703):** Genuine sliding temporal window (15m default) tracking grouped by deterministic correlation fingerprint `sha256(orgId:siteId:sourceIp)` with local/loopback IP isolation, idempotency checks against duplicate stream deliveries, and out-of-order timestamp preservation. Automatically aggregates isolated detections into unified incidents with chronological timelines and automated SOAR action recommendations.
4. **Explainable Mathematical Risk Scoring Engine (TASK-704):** Deterministic, strictly bounded ($0 \le \text{RiskScore} \le 100$) risk calculation:
   $$\text{RiskScore} = \min(100, \max(0, \text{Round}(S_{\text{base}} \times M_{\text{freq}} \times M_{\text{asset}} \times M_{\text{threat}} + C_{\text{vuln\_match}} + B_{\text{sequence}})))$$
   With transparent factor explanations, `NaN` poisoning prevention, and risk band mapping (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
5. **Configurable Risk Contribution Model & Vulnerability Prioritization (TASK-705):** Cross-references active attack targets against open asset vulnerability findings (`EXACT`, `PATH`, `ASSET`, `NONE` match levels), applying confidence-scaled additive scoring ($C_{\text{vuln\_match}} = w_{\text{overlap}} \times \frac{\text{CVSS}}{10} \times K_{\text{confidence}}$) when attacks strike unmitigated vulnerabilities.
6. **Incident Persistence & Storage Harness (TASK-706):** Production DynamoDB `Veltrix-Incidents` GSI support, direct $O(1)$ incident ID pointer items, `MemoryStore` parity, `siteId` filtering on incidents and detections, and REST endpoints under `/api/v1/incidents`, `/api/v1/detections/web`, `/api/v1/detections/:detectionId/evidence`, and `/api/v1/websites/:siteId/*`.
7. **Automated Test Suite & Verification (TASK-707):** 41 comprehensive tests in `backend/tests/web-detection-correlation.test.ts` bringing total workspace test count to **245 / 245 tests passing** (100% pass rate).

### Verification Key Metrics
- **Automated Tests:** **245 / 245 passed** (0 failures across all 9 test suites).
  - 237 tests in `@veltrix/backend` (including 41 dedicated web detection, correlation, and audit regression tests).
  - 8 tests in `@veltrix/sdk-node`.
- **TypeScript Typecheck:** **0 errors** across all 5 monorepo workspaces (`@veltrix/shared`, `@veltrix/backend`, `@veltrix/sdk-node`, `@veltrix/frontend`, `@veltrix/cli`).
- **Production Monorepo Build:** Clean production compilation across all workspaces (Vite production bundle generated cleanly).
- **Linting:** 0 warnings / 0 errors.
- **Security Audit:** All 9 audit findings (SEC-P7-001 through SEC-P7-009) verified and remediated.

---

## 2. Shared Data Models & Schemas (TASK-701)

Defined in `@veltrix/shared`:
- **`WebConfidenceTier`**: `'SUSPICIOUS_ATTEMPT' | 'BLOCKED_ATTEMPT' | 'POTENTIAL_EXPLOITATION' | 'CONFIRMED_EXPLOITATION'`
- **`WebAttackType`**: `'SQLI' | 'XSS' | 'PATH_TRAVERSAL' | 'BOT_ACTIVITY' | 'AUTH_TAMPERING' | 'API_ABUSE'`
- **`RiskBand`**: `'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'`
- **`Incident` Extensions**:
  - `siteId?: string`
  - `domain?: string`
  - `sourceIp?: string`
  - `attackTypes?: string[]`
  - `highestConfidence?: WebConfidenceTier`
  - `riskBand?: RiskBand`
  - `webRiskFactors?: WebRiskFactors`
- **`WebRiskFactors`**: Explainable breakdown of factors including base severity score, multipliers ($M_{\text{freq}}, M_{\text{asset}}, M_{\text{threat}}$), vulnerability overlap term ($C_{\text{vuln\_match}}$), sequence progression bonus ($B_{\text{sequence}}$), and human-readable explanation string.
- **`WebSecurityEventMetadata`**: Normalized representation of HTTP request and response context, including `httpMethod`, `requestUri`, `httpStatus`, `responseContentType`, `headers`, `requestBody`, and `responseBody`.

---

## 3. Normalized Telemetry Classification & Web Parser (TASK-701 & TASK-702)

Implemented in `backend/src/detection/web-parser.ts`:
- **Safe URI Multi-Pass Decoding:** Recursively decodes URL-encoded entities (up to 3 passes) while catching and recovering safely from malformed URI components.
- **Sensitive Parameter Redaction:** Automatically strips or redacts sensitive keys (`password`, `token`, `secret`, `authorization`, `cookie`, `session`, `cvv`) from telemetry query parameters and `rawUri` metadata to prevent accidental credential leakage in SIEM logs.
- **Exploitation Corroboration:**
  - Evaluates response body patterns for database syntax exceptions (MySQL, PostgreSQL, Oracle, SQLite, MSSQL error strings).
  - Evaluates response body patterns for system file disclosures (`root:x:0:0`, Windows system directory paths).
  - Inspects response status codes: 403/401 indicates `BLOCKED_ATTEMPT`; 500 with DB error indicates `POTENTIAL_EXPLOITATION`; 200 with system file or DB leakage indicates `CONFIRMED_EXPLOITATION`.
  - Prohibits raising alerts to `CRITICAL` or `CONFIRMED_EXPLOITATION` based on HTTP status codes alone.

---

## 4. Web Attack Detection Rules (TASK-701, TASK-702, TASK-705)

All rules inherit from `BaseDetectionRule` and are registered in `DetectionEngine`:

| Rule ID | Rule Name | MITRE ATT&CK | Category | Default Severity | Key Detection Mechanisms | False-Positive Mitigations |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`RULE-101`** | SQL Injection Probing & Exploitation | T1190 | `NETWORK` | `HIGH` | Boolean-based payloads (`' OR 1=1`), UNION SELECT, stacked queries, database schema enumeration (`information_schema`), time-based sleep functions, and DB syntax error leakage. | Suppresses benign English contractions (`don't`, `it's`, `let's`), natural language queries, and math comparisons without SQL keywords. |
| **`RULE-102`** | Cross-Site Scripting (XSS) Probing | T1059.007 | `NETWORK` | `MEDIUM` | Raw `<script>` tags, inline HTML event handlers (`onload=`, `onerror=`, `onclick=`), `javascript:` pseudo-protocols, and DOM sinks (`eval()`, `document.cookie`). | Suppresses mathematical comparisons (`x < y && z > w`), Markdown formatting, and benign HTML entities without script execution context. |
| **`RULE-103`** | Path Traversal & Local File Inclusion | T1083 / T1059 | `NETWORK` | `HIGH` | Directory traversal (`../`, `..\\`), Unix system targets (`/etc/passwd`, `/etc/shadow`), Windows targets (`win.ini`, `system32`), PHP wrappers (`php://filter`), and null-byte injection (`%00`). | Suppresses normal relative application paths (e.g., `../../assets/img.png`) that resolve within authorized static directories. |
| **`RULE-104`** | Malicious Bot, Scraper & Reconnaissance | T1595.002 | `NETWORK` | `MEDIUM` | Known offensive tooling user-agents (`sqlmap`, `nikto`, `nmap`, `gobuster`, `dirbuster`), sensitive file enumeration (`.env`, `.git`, `wp-login.php`, `actuator/health`), and high-frequency 404 probing. | Strict requirement: Common script user-agents (`curl`, `python-requests`, `httpx`) NEVER flag without corroborating path enumeration or abnormal request frequency. |
| **`RULE-105`** | Web Authentication Flow Tampering | T1110.003 | `AUTHENTICATION` | `HIGH` | Repeated login failures within sliding window, multi-account credential stuffing across distinct usernames, and password reset endpoint abuse targeting website assets. | Scoped to website context (`hasWebContext`: web path, `siteId`, or domain) to prevent collision with generic internal IAM brute force (`RULE-001`). Escalates to `CRITICAL` when multiple distinct accounts are targeted. |

---

## 5. Multi-Stage Attack Correlation Engine (TASK-703 & TASK-706)

Implemented in `backend/src/correlation/engine.ts`:
- **Deterministic Correlation Fingerprinting & Genuine Sliding Window:**
  $$\text{CorrelationKey} = \text{SHA-256}(\text{orgId} : \text{siteId} : \text{sourceIp})$$
  Evaluated against elapsed time from latest activity: $\Delta t \le 15\text{ min}$.
- **Loopback & Generic IP Isolation:** Localhost (`127.0.0.1`, `0.0.0.0`, `::1`) salts the correlation key with `detectionId` to prevent collapsing unrelated internal actors into a single mega-incident.
- **Correlation Idempotency & Chronological Bounds:** Prevents duplicate timeline entries on re-evaluation and maintains earliest `createdAt` and latest `updatedAt`.
- **Multi-Stage Sequence Progression:** When distinct attack vectors (e.g., Bot Reconnaissance followed by SQL Injection) occur within the correlation window, the engine applies a **Sequence Progression Bonus** ($B_{\text{sequence}} = +10$).
- **Automated SOAR Action Recommendations:** Automatically recommends response actions based on risk score (e.g., `BLOCK_IP` for medium/high risk, plus `REVOKE_SESSION` and `STEP_UP_AUTH` when risk score $\ge 50$). Clearly labeled as recommendations pending Phase 10 SOAR execution.

---

## 6. Mathematical Risk Scoring Engine & Vulnerability Prioritization (TASK-704 & TASK-705)

Implemented in `backend/src/risk/engine.ts` and `backend/src/correlation/vuln-correlator.ts`:
- **Deterministic Scoring Formula:**
  $$\text{RiskScore} = \min(100, \max(0, \text{Round}(S_{\text{base}} \times M_{\text{freq}} \times M_{\text{asset}} \times M_{\text{threat}} + C_{\text{vuln\_match}} + B_{\text{sequence}})))$$
- **Factor Definitions:**
  - $S_{\text{base}}$: Base severity score ($\text{CRITICAL} = 40, \text{HIGH} = 30, \text{MEDIUM} = 20, \text{LOW} = 10$).
  - $M_{\text{freq}}$: Frequency multiplier ($1.0$ for 1 event, $1.15$ for $2\text{--}5$, $1.3$ for $6\text{--}15$, $1.5$ for $> 15$).
  - $M_{\text{asset}}$: Asset criticality multiplier ($\text{PRODUCTION} = 1.3, \text{STAGING} = 1.0, \text{DEVELOPMENT} = 0.8$).
  - $M_{\text{threat}}$: Threat intelligence multiplier ($1.0$ if clean, $1.2$ if flagged, $1.4$ if flagged with CRITICAL/HIGH severity).
  - $C_{\text{vuln\_match}}$: Additive vulnerability correlation term ($w_{\text{overlap}} \times \frac{\text{CVSS}}{10} \times K_{\text{confidence}}$):
    - Overlap weights: $\text{EXACT} = 25, \text{PATH} = 15, \text{ASSET} = 5, \text{NONE} = 0$.
    - Confidence multipliers: $\text{CONFIRMED} = 1.0, \text{POTENTIAL} = 0.8, \text{SUSPICIOUS} = 0.4, \text{BLOCKED} = 0.1$.
  - $B_{\text{sequence}}$: Sequence progression bonus ($+10$ when 2 or more distinct attack vectors occur).
- **Risk Bands:** $\text{LOW} \in [0, 24]$, $\text{MEDIUM} \in [25, 49]$, $\text{HIGH} \in [50, 74]$, $\text{CRITICAL} \in [75, 100]$.
- **Robustness:** Complete immunity to `NaN` poisoning with `Number.isFinite()` and bounds clamping.

---

## 7. Storage Interfaces & REST Endpoints (TASK-706)

### Storage Parity & Performance
- `StorageInterface`, `MemoryStore`, and `DynamoDBStore` updated to support `siteId?: string` filtering across `getIncidents()` and `getDetections()`.
- Direct $O(1)$ incident lookup via pointer items: `PK = ORG#{orgId}#INCIDENTID#{incidentId}, SK = METADATA`.
- Production DynamoDB schema mapping for `Veltrix-Incidents`:
  - `PK = ORG#{orgId}`, `SK = INC#{incidentId}`
  - `GSI1PK = ORG#{orgId}`, `GSI1SK = STATUS#{status}#SEV#{severity}#TIME#{createdAt}`

### REST API Endpoints
All endpoints enforce Bearer authentication, tenant isolation, and RBAC:
1. `GET /api/v1/incidents`: Lists correlated incidents for tenant, supporting filtering by `siteId` and `status`.
2. `GET /api/v1/incidents/:incidentId`: Fetches details of a correlated incident ($O(1)$).
3. `PATCH /api/v1/incidents/:incidentId`: Allows `SECURITY_ANALYST` or higher to update incident status (`INVESTIGATING`, `CONTAINED`, `RESOLVED`, `FALSE_POSITIVE`) and append analyst investigation notes.
4. `GET /api/v1/detections/web`: Returns web-specific threat detections (`RULE-101` to `RULE-105`).
5. `GET /api/v1/detections/:detectionId/evidence`: Returns explainable evidence payload for a detection.
6. `GET /api/v1/websites/:siteId/detections`: Returns detections targeting a specific website asset.
7. `GET /api/v1/websites/:siteId/incidents`: Returns correlated incidents for a specific website asset.
8. `GET /api/v1/websites/:siteId/risk-summary`: Returns explainable risk score, posture band, active attack types, and factor breakdown.
9. `GET /api/v1/websites/:siteId/timeline`: Returns chronological sequence of incidents and detections for the asset.
10. `GET /api/v1/websites/:siteId/attacks`: Alias endpoint for website attack detections.

---

## 8. Frontend SOC Dashboard Extension

Implemented in `frontend/src/components/WebsiteAttackMonitoring.tsx` and integrated into `frontend/src/App.tsx`:
- **Asset Selector:** Organization administrators and analysts can select registered website assets to inspect asset-specific security posture.
- **Risk Posture Gauge:** Visual representation of current risk score (0–100) and color-coded risk band (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) with mathematical explanation.
- **Attack Vector Breakdown Cards:** Real-time counters and indicators for SQLi, XSS, Path Traversal, Bot Probing, and Credential Abuse.
- **Correlated Incidents Table:** Comprehensive view of multi-stage incidents with `"Mark Contained"` action, status tags, attack vector chips, and clear `(Recommended Response - Phase 10)` badges.
- **Live Detections Feed:** Real-time stream of web detections featuring MITRE ATT&CK technique badges and 4-tier confidence badges.
- **Interactive Chronological Timeline:** Visual timeline mapping attacker actions sequentially from reconnaissance to exploitation attempts.

---

## 9. Automated Test Suite Verification (TASK-707)

Dedicated test suite in `backend/tests/web-detection-correlation.test.ts` executes 41 tests covering:
1. Positive and negative payload verification for `RULE-101` (SQLi).
2. Positive and negative payload verification for `RULE-102` (XSS).
3. Positive and negative payload verification for `RULE-103` (Path Traversal).
4. Automated bot and tool verification vs. benign script user-agents for `RULE-104`.
5. Credential stuffing and brute-force verification for `RULE-105`.
6. Multi-stage attack correlation and incident merging across sliding windows.
7. Explainable mathematical risk score calculation, boundary clamping (0–100), and sequence progression bonus ($+10$).
8. Vulnerability-aware attack surface correlation ($C_{\text{vuln\_match}}$).
9. REST APIs, keyset pagination, tenant isolation (Tenant B cannot access Tenant A data: 404 `WEBSITE_NOT_FOUND`), and API key scoping (`FORBIDDEN_API_KEY_SCOPE_PROHIBITED`).
10. Security audit regressions: credential redaction in query parameters/raw URIs, NaN poisoning defense, generic IP collision defense, correlation idempotency, sliding window bucket boundary correlation, and out-of-order timestamp preservation.
11. Evidence provenance & trust boundary: rejection of client-submitted `CANARY_TOKEN_BREACH`, `DATA_LEAKAGE_INDICATOR`, `UNAUTHORIZED_PRIVILEGE_MUTATION`, isolation of forged DB errors, anti-impersonation via `sourceSystem`, and server-verified evidence processing.

### Full Monorepo Test Results:
```
> veltrix-monorepo@1.0.0 test
> npm run test --workspaces --if-present

@veltrix/sdk-node: 8 passed (8 tests)
@veltrix/backend: 237 passed (237 tests)
Total: 245 / 245 passed (100% pass rate)
```

---

## 10. Conclusion & PR Management

Phase 7 (TASK-701 through TASK-707) is complete, independently audited, hardened, and verified against all criteria.
Per instructions:
- Phase 7 is NOT merged into `main`.
- Phase 8 has NOT been started.
- All changes are pushed to branch `feature/phase-7-web-attack-monitoring` updating PR #7.
