# VELTRIX: Implementation Tasks & Verification Tracking (`specs/tasks.md`)

**Document Version:** 3.0.0 (Unified Website Security Platform Expansion)  
**Status:** PROPOSED / IN REVIEW (Phases 0–5 Merged; Phase 6–13 Planning Under Review in PR #4)  
**Execution Matrix:** Balanced 3-Person Team Allocation  
- **[P1] Person 1:** Frontend & CLI Presentation Lead (React 18, Vite, Tailwind CSS, Recharts, Lucide, CLI Formatters & Terminal UX)  
- **[P2] Person 2:** Backend Core & Cybersecurity Intelligence Lead (Node.js, TypeScript, Ingestion, Detection, Correlation, Risk, Threat Intel, CLI API Client)  
- **[P3] Person 3:** Cloud, Database, DevSecOps & Security Automation Lead (AWS SAM, DynamoDB, Cognito, EventBridge, Step Functions, SQS FIFO Audit, CLI Packaging)  
- **[ALL]:** Shared Responsibilities (Architecture, Schemas, Code Reviews, Integration, Final Demo)  

---

## Phase 0 — Repository & Environment Inspection

- [x] Verified **TASK-001 [ALL]:** Inspect workspace, toolchains (Node v24.18.0, npm 11.16.0, Git 2.54, Python 3.12), and remote GitHub repository.
- [x] Verified **TASK-002 [ALL]:** Evaluate initial working directory, identify missing CLI and shared packages.
- [x] Verified **TASK-003 [ALL]:** Identify technical risks (absence of local AWS/SAM CLI, rate limiting, disruptive containment, threat intelligence offline resilience).
- [x] Verified **TASK-004 [ALL]:** Draft Phase 0 inspection and architecture assessment report.

---

## Phase 1 — Specification & Architecture

- [x] Verified **TASK-101 [ALL]:** Author comprehensive System Requirements Specification (`specs/requirements.md`) with Modules A through L.
- [x] Verified **TASK-102 [ALL]:** Formulate System Architecture & Technical Design (`specs/design.md`) including Web and CLI clients.
- [x] Verified **TASK-103 [ALL]:** Establish Granular Tasks Breakdown with testable states (`specs/tasks.md`).
- [x] Verified **TASK-104 [P2/P3]:** Document complete REST API Contracts for Web & CLI (`specs/api-contracts.md`).
- [x] Verified **TASK-105 [P3]:** Formulate DynamoDB Schema & Access Patterns (`specs/database-schema.md`).
- [x] Verified **TASK-106 [ALL]:** Author Full Testing & Quality Strategy (`specs/testing-strategy.md`).
- [x] Verified **TASK-107 [ALL]:** Perform Strict Specification Audit & Deliver Audit Report (`specs/phase-1-audit-report.md`).
- [x] Verified **TASK-108 [ALL]:** Team review and approval gate before initiating Phase 2 implementation.

---

## Phase 2 — Project Foundation & Monorepo Setup

- [x] Verified **TASK-201 [P3]:** Initialize monorepo root structure (`frontend/`, `backend/`, `cli/`, `infrastructure/`, `specs/`, `docs/`).
- [x] Verified **TASK-202 [P3]:** Configure root `package.json` with npm workspaces for `frontend`, `backend`, and `cli`.
- [x] Verified **TASK-203 [P2]:** Set up `backend/` TypeScript environment (`tsconfig.json`, `package.json`, Vitest).
- [x] Verified **TASK-204 [P1]:** Set up `frontend/` React 18 + Vite + Tailwind CSS + Lucide + Recharts environment.
- [x] Verified **TASK-205 [P3]:** Set up `cli/` Commander.js + TypeScript environment and executable bin wrapper.
- [x] Verified **TASK-206 [P2/P3]:** Author shared domain contracts (`types/index.ts` across backend, frontend, cli).
- [x] Verified **TASK-207 [P3]:** Configure local mock storage & AWS SDK v3 adapter harness (`MemoryStore`).
- [x] Verified **TASK-208 [P3]:** Create GitHub Actions CI pipeline (`.github/workflows/ci.yml`).

---

## Phase 3 — Authentication & Database

- [x] Verified **TASK-301 [P3]:** Define Cognito User Pool & App Client configuration in AWS SAM template (`infrastructure/template.yaml`).
- [x] Verified **TASK-302 [P3]:** Implement backend tenant authorization middleware validating JWT claims and RBAC roles.
- [x] Verified **TASK-303 [P3]:** Configure DynamoDB schemas with Time-Sharded partition keys (`ORG#{orgId}#DATE#{YYYY-MM-DD}`).
- [x] Verified **TASK-304 [P3]:** Write unit tests for tenant isolation and cross-tenant access rejection (`backend/tests/auth-isolation.test.ts`).

---

## Phase 4 — Event Ingestion API

- [x] Verified **TASK-401 [P2]:** Build Event Ingestion API (`POST /api/v1/events`):
  - Zod validation for single and batch payloads (up to 100 events).
  - High-precision deduplication using `idempotencyKey = eventId`.
  - Timestamp canonicalization (ISO 8601 UTC) and RFC 9562 UUIDv7 generation.
- [x] Verified **TASK-402 [P2]:** Implement event query endpoint with filtering and cursor pagination (`GET /api/v1/events`).
- [x] Verified **TASK-403 [P2]:** Write unit and integration tests for validation, deduplication, tenant isolation, and query pagination (`backend/tests/ingestion.test.ts`).

---

## Phase 5 — Threat Detection Engine
- [x] Completed **TASK-501 [P2]:** Implement Threat Detection Engine architecture (`backend/src/detection/engine.ts`, `types.ts`, `base-rule.ts`, `pipeline.ts`).
- [x] Completed **TASK-502 [P2]:** Implement all 10 Sigma-inspired detection rules (`RULE-001` through `RULE-010` per requirements and Sigma specs).
- [x] Completed **TASK-503 [P2]:** Implement Threat Detection Storage persistence, $O(1)$ ID pointer lookups, GSI2 severity filtering, and atomic duplicate suppression across `MemoryStore` and `DynamoDBStore`.
- [x] Completed **TASK-504 [P2]:** Implement Detection REST API endpoints (`POST /api/v1/detections/run`, `GET /api/v1/detections`, `GET /api/v1/detections/:detectionId`, `GET /api/v1/detection-rules`, `PATCH /api/v1/detection-rules/:ruleId`, `POST /api/v1/detection-rules/test`) with RBAC and tenant isolation.
- [x] Completed **TASK-505 [P2]:** Build comprehensive automated test suites (`backend/tests/detection.test.ts`, `backend/tests/detection-pipeline.test.ts`) verifying all 10 rules, automatic event-to-detection pipeline, threshold tuning, and multi-tenant isolation.

---

## Phase 6 — Website Assets & Integrations

- [ ] Not started **TASK-601 [P2/P3]:** Website Asset Inventory & Domain Registry: Data models, Zod schemas, and storage methods for `Veltrix-WebsiteAssets`. Support primary domain, approved subdomains, environment (`PROD`/`STAGING`/`DEV`), risk tier, and asset health.
- [ ] Not started **TASK-602 [P2]:** Domain Ownership Verification & Grace Period Freeze: Implement DNS TXT challenge resolution (`dns.promises.resolveTxt`) and HTTP challenge endpoint verification (`/.well-known/veltrix-challenge/<token>`). Enforce 90-day validity window. Implement immediate scan freeze upon `GRACE_PERIOD`: cancel queued/scheduled scans, emit worker abort signal, and require successful re-verification before resuming scans.
- [ ] Not started **TASK-603 [P2]:** Website Asset Management REST API: Endpoints (`POST /api/v1/websites`, `GET /api/v1/websites`, `GET /api/v1/websites/:siteId`, `PATCH /api/v1/websites/:siteId`, `POST /api/v1/websites/:siteId/verify`, `DELETE /api/v1/websites/:siteId`) with tenant isolation and RBAC.
- [ ] Not started **TASK-604 [P1/P2]:** Node.js SDK & Express Middleware Package: Author `@veltrix/sdk-node` with `VeltrixClient` and `veltrixMiddleware`. Implement strictly non-blocking async execution (never blocks host requests), bounded in-memory ring buffer (default 500 events / 5MB cap), drop-oldest overflow policy with `droppedEventsCount`, exponential backoff with jitter, duplicate suppression via `idempotencyKey`, and optional disk WAL/SQLite spool (`DurableSpoolStorage`) for zero-loss compliance.
- [ ] Not started **TASK-605 [P3]:** Reverse Proxy & Edge Ingestion Adapters: FluentBit JSON configuration templates for Nginx and Apache logs, and Cloudflare Worker telemetry forwarder script.
- [ ] Not started **TASK-606 [ALL]:** Phase 6 Automated Test Suites: Comprehensive unit and integration tests covering website CRUD, DNS/HTTP challenge verification, cross-tenant isolation, SDK ring buffer, and log parsing (`backend/tests/websites.test.ts`, `packages/sdk-node/tests/middleware.test.ts`).

---

## Phase 7 — Website Attack Monitoring, Correlation & Risk Scoring

- [x] Completed **TASK-701 [P2]:** Web Attack Signature & Rule Definitions: Implement website-specific detection rules: `RULE-101` (SQL Injection Probing), `RULE-102` (Cross-Site Scripting Probing), `RULE-103` (Path Traversal / LFI Probing), `RULE-104` (Malicious Bot & Scraper Activity), `RULE-105` (Authentication Flow Tampering).
- [x] Completed **TASK-702 [P2]:** Attack vs. Exploitation Confidence Classification: Telemetry parser implementing four evidence-based confidence tiers (`SUSPICIOUS_ATTEMPT`, `BLOCKED_ATTEMPT`, `POTENTIAL_EXPLOITATION`, `CONFIRMED_EXPLOITATION`). Require corroborating application/WAF error signals (DB syntax exceptions, latency spikes, canary triggers); prohibit automatic Critical alerts from status code or response size alone.
- [x] Completed **TASK-703 [P2]:** Multi-Stage Attack Correlation Engine: Correlate inbound web attack detections across sliding temporal windows (15m default), grouping related alerts by `sourceIp` and `siteId` into unified incidents.
- [x] Completed **TASK-704 [P2]:** Explainable Mathematical Risk Scoring Engine: Implement deterministic formula: `RiskScore = min(100, Round(S_base * M_freq * M_asset * M_threat + C_vuln_match + B_sequence))`. Generate transparent factor breakdowns and risk tier classification.
- [x] Completed **TASK-705 [P2]:** Configurable Risk Contribution Model & Calibration: Implement additive vulnerability term $C_{vuln_match}$ based on attack surface overlap ($w_{overlap}$ for exact URI+parameter vs path match), CVSS severity, and confidence tier. Implement empirical calibration and testing harness.
- [x] Completed **TASK-706 [P3]:** Incident Persistence & Storage Harness: Store correlated incidents in `Veltrix-Incidents` with GSI1 status/risk indexing, chronologically ordered attack timelines, and tenant isolation.
- [x] Completed **TASK-707 [ALL]:** Phase 7 Automated Test Suite: Test all 5 web attack rules, probe vs. exploit classification, correlation grouping, risk math verification, and vulnerability-weighted scoring (`backend/tests/web-detection-correlation.test.ts`).

---

## Phase 8 — Website Vulnerability Assessment

- [ ] Not started **TASK-801 [P2]:** Vulnerability Assessment Domain Types & Schemas: Define Zod schemas and TypeScript types for scan configurations, scan jobs, vulnerability findings, CVSS v3.1 scores, and remediation guidance.
- [ ] Not started **TASK-802 [P2]:** Safe Native Passive Assessment Engine: Implement non-destructive passive checks: TLS cipher suites/versions, HTTP security headers (HSTS, CSP, X-Frame-Options, etc.), cookie flags, CORS configuration, and info disclosure banners.
- [ ] Not started **TASK-803 [P3]:** Isolated Scanner Worker Daemon & ZAP Runner: Implement queue-polled isolated worker daemon. Evaluate and integrate headless OWASP ZAP container runner via ZAP API with safe non-destructive active scan policies.
- [ ] Not started **TASK-804 [P3]:** Comprehensive SSRF Guard, Rate Limiter & Emergency Cancellation: Enforce domain verification check, HMAC authorization tokens, connection-time IP validation and socket pinning (defeating DNS rebinding), recursive CNAME inspection, redirect re-validation, complete IPv4/IPv6/IPv4-mapped prohibited matrix, token-bucket rate limiting (max 5-10 req/s with backoff), and emergency abort kill-switch targeting 500ms SLO for socket termination.
- [ ] Not started **TASK-805 [P2/P3]:** Vulnerability Findings Registry & State Machine: Implement findings persistence in `Veltrix-VulnerabilityFindings`. Support lifecycle states: `OPEN` -> `CONFIRMED` -> `IN_REMEDIATION` -> `RESOLVED` -> `ACCEPTED_RISK` -> `FALSE_POSITIVE`.
- [ ] Not started **TASK-806 [P2]:** Vulnerability Scanning & Findings REST API: Endpoints: `POST /api/v1/scans`, `GET /api/v1/scans`, `GET /api/v1/scans/:scanId`, `POST /api/v1/scans/:scanId/abort`, `GET /api/v1/findings`, `PATCH /api/v1/findings/:findingId`.
- [ ] Not started **TASK-807 [P2]:** Security & Compliance Report Generator: Generate structured Executive Summary, Vulnerability Assessment Detail, and OWASP Top 10 compliance reports in JSON and Markdown formats.
- [ ] Not started **TASK-808 [ALL]:** Phase 8 Automated Test Suite: Test passive analyzers, rate limiter, SSRF egress guard, unauthorized scan rejection, findings state machine transitions, and report generation (`backend/tests/vulnerability-assessment.test.ts`).

---

## Phase 9 — Threat Intelligence & Incident Management

- [ ] Not started **TASK-901 [P2]:** Embedded Threat Intelligence IOC Catalog: Offline-capable IOC database containing known Tor exit nodes, malicious proxies, and botnet IPs with periodic feed sync capabilities.
- [ ] Not started **TASK-902 [P2]:** IP Reputation & Dossier Lookup Tool: Comprehensive IP dossier API returning threat score, ASN, geolocation, known attack history across tenant assets, and flag indicators.
- [ ] Not started **TASK-903 [P2]:** Incident Lifecycle State Machine: Transition workflow: `NEW` -> `INVESTIGATING` -> `CONTAINED` -> `RESOLVED` (or `FALSE_POSITIVE`). Enforce authorized transition rules and assignee tracking.
- [ ] Not started **TASK-904 [P2]:** Investigative Notes & Evidence Thread: Multi-user analyst comment thread with chronological evidence attachments and tagging.
- [ ] Not started **TASK-905 [P2]:** Incident Search & Cursor Pagination API: Query incidents with multi-attribute filtering (status, severity, siteId, time range) using signed HMAC-SHA256 cursors.
- [ ] Not started **TASK-906 [ALL]:** Phase 9 Automated Test Suite: Unit and integration tests for IOC lookups, incident lifecycle transitions, assignee updates, and query cursor pagination (`backend/tests/incidents.test.ts`).

---

## Phase 10 — Controlled Response & Audit Trail

- [ ] Not started **TASK-1001 [P3]:** Defensive Response Engine (SOAR): Implement containment actions: `BLOCK_IP` (WAF/Cloudflare), `RATE_LIMIT_IP`, `REVOKE_SESSION`, `SUSPEND_USER`, `STEP_UP_AUTH`.
- [ ] Not started **TASK-1002 [P3]:** Zero-Bypass Human Approval Gates: High-impact actions (`BLOCK_IP`, `SUSPEND_USER`) queue as `PENDING_APPROVAL`. Execution strictly requires Org Admin approval token.
- [ ] Not started **TASK-1003 [P3]:** Target Sandboxing & Whitelist Validation: Safeguard preventing containment actions from executing against internal gateways, DNS resolvers, or non-whitelisted target IP ranges.
- [ ] Not started **TASK-1004 [P3]:** Operational Rollback Registry: Handlers for reverting containment actions (`UNBLOCK_IP`, `REINSTATE_USER`) with complete state restoration.
- [ ] Not started **TASK-1005 [P3]:** Cryptographic Audit Logger & SHA-256 Ledger: Append-only ledger linking records: `Hash_k = SHA256(Hash_{k-1} || Payload)`. Serialized via SQS FIFO queue with `MessageGroupId = orgId`.
- [ ] Not started **TASK-1006 [ALL]:** Phase 10 Automated Test Suite: Test automated actions, approval gate rejection, target sandboxing, rollback execution, and cryptographic chain verification/tamper detection (`backend/tests/response-audit.test.ts`).

---

## Phase 11 — Functional SOC Dashboard

- [ ] Not started **TASK-1101 [P1]:** Navigation Shell & Global State Refactor: Refactor existing `App.tsx` layout into modular shell with persistent sidebar, top navbar, tenant context switcher, and React Query API state management.
- [ ] Not started **TASK-1102 [P1]:** SOC Executive Overview Page: Live KPI tiles (events, attack detections, open incidents, active scans, asset health), telemetry velocity chart, and severity donut.
- [ ] Not started **TASK-1103 [P1]:** Live Security Events & Log Explorer: Real-time paginated table of ingested events with search, severity filter, category filter, and JSON event drawer.
- [ ] Not started **TASK-1104 [P1]:** Threat Detections & Rules Management: Active threat alerts view and 10 Sigma rules catalog with toggle switches, sensitivity sliders, and threshold tuning.
- [ ] Not started **TASK-1105 [P1]:** Website Asset Inventory & Domain Verification UI: Registered websites list, add website modal, DNS TXT & HTTP challenge instructions, verification status badges, and asset health indicators.
- [ ] Not started **TASK-1106 [P1]:** Website Integrations Management: Integration catalog (Node.js SDK, Nginx, Apache, Cloudflare, AWS WAF), API key generation, copy-paste config snippets, and agent heartbeats.
- [ ] Not started **TASK-1107 [P1]:** Vulnerability Assessment & Scan Runner UI: Scan scheduler, on-demand scan modal (Passive vs. Active toggle), live scan progress bar, and emergency abort button.
- [ ] Not started **TASK-1108 [P1]:** Vulnerability Findings & Reports View: Findings list with severity badges, CVSS filter, affected URI inspector, remediation guidance tab, and export report button (PDF/MD/JSON).
- [ ] Not started **TASK-1109 [P1]:** Incidents & Attack Kill-Chain Timeline: Incident triage queue, explainable risk score breakdown card, MITRE kill-chain visualizer, analyst notes thread, and SOAR response buttons.
- [ ] Not started **TASK-1110 [P1]:** Audit Ledger Inspector & Settings: Cryptographic hash chain viewer with one-click "Verify Ledger Integrity" button, user management, and tenant settings.

---

## Phase 12 — CLI, SDK Packaging & Distribution

- [ ] Not started **TASK-1201 [P3]:** `@veltrix/cli` Command Architecture & Client: Scaffold Commander.js CLI client sharing backend REST contracts with colored table formatters and `--json` support.
- [ ] Not started **TASK-1202 [P1]:** CLI Authentication & Configuration Commands: Implement `veltrix auth login / logout / status` and `veltrix config show / set`.
- [ ] Not started **TASK-1203 [P1]:** CLI Websites & Telemetry Commands: Implement `veltrix websites list / add / verify` and `veltrix events list / tail / ingest`.
- [ ] Not started **TASK-1204 [P2]:** CLI Vulnerability Scanning Commands: Implement `veltrix scan launch / status / abort` and `veltrix findings list / show`.
- [ ] Not started **TASK-1205 [P1/P2]:** CLI Incidents & Response Commands: Implement `veltrix incidents list / show / update` and `veltrix response block / rollback`.
- [ ] Not started **TASK-1206 [P3]:** SDK Package Bundling & Distribution Setup: Configure `@veltrix/sdk-node` npm packaging, TypeScript declarations, and documentation guides.
- [ ] Not started **TASK-1207 [ALL]:** Phase 12 Automated Test Suite: CLI execution tests, exit code verification, table formatting tests, and SDK package build checks (`cli/tests/cli.test.ts`).

---

## Phase 13 — End-to-End Integration, Security Audit & Deployment

- [ ] Not started **TASK-1301 [ALL]:** Full-Lifecycle Attack-to-Defense Simulation Lab: Build 6 realistic attack simulation scenarios (SQLi attack against vulnerable website, credential stuffing, brute force, exfiltration, etc.).
- [ ] Not started **TASK-1302 [ALL]:** End-to-End System Synchronization Verification: Verify seamless real-time synchronization across Web SOC Console, Terminal CLI, and backend DynamoDB stores.
- [ ] Not started **TASK-1303 [ALL]:** Independent DevSecOps & Dependency Security Audit: Run `npm audit`, zero-secret scan, and static code analysis across all monorepo workspaces. Document zero high/critical vulnerabilities.
- [ ] Not started **TASK-1304 [ALL]:** Multi-Tenant Penetration & Cross-Tenant Boundary Test: Comprehensive adversarial penetration test asserting zero cross-tenant data leakage across events, websites, scans, findings, and incidents.
- [ ] Not started **TASK-1305 [ALL]:** Cryptographic Audit Chain Adversarial Tamper Test: Prove that modifying any historical audit record in memory or storage breaks hash chain verification and identifies the tampered record.
- [ ] Not started **TASK-1306 [ALL]:** AWS Infrastructure SAM Template & Cloud Verification: Validate `infrastructure/template.yaml` (DynamoDB tables, ECS Fargate scanner task, Cognito User Pool, SQS FIFO queues, IAM least privilege).
- [ ] Not started **TASK-1307 [ALL]:** Documentation & Competition Presentation Kit: Finalize `README.md`, `docs/api-reference.md`, `docs/deployment-guide.md`, and 5-minute competition presentation demo script.
- [ ] Not started **TASK-1308 [ALL]:** Final Competition & Enterprise Production Readiness Sign-off: Complete final readiness review matrix confirming 100% test pass rate, clean builds, and zero blockers.
