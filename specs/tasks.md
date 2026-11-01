# VELTRIX: Implementation Tasks & Verification Tracking (`specs/tasks.md`)

**Document Version:** 2.3.0 (Phase 3 Completed)  
**Status:** In Progress (Phase 0, 1, 2 & 3 Complete; Awaiting Review for Phase 4)  
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

## Phase 6 — Threat Intelligence & Incidents

- [ ] Not started **TASK-601 [P2]:** Build embedded offline IOC repository (Tor nodes, botnets, proxies) & IP lookup tool.
- [ ] Not started **TASK-602 [P2]:** Implement Incident Management CRUD and status state machine (`NEW` $\to$ `INVESTIGATING` $\to$ `CONTAINED` $\to$ `RESOLVED`).
- [ ] Not started **TASK-603 [P2]:** Write unit tests for incident lifecycle transitions and threat intel enrichment (`backend/tests/incidents.test.ts`).

---

## Phase 7 — Defensive Response & Audit Ledger

- [ ] Not started **TASK-701 [P3]:** Implement Automated Defensive Response Engine (SOAR) (`backend/src/response/handler.ts`):
  - Safe simulated containment: `BLOCK_IP`, `SUSPEND_USER`, `REVOKE_SESSION`, `STEP_UP_AUTH`.
  - Zero-bypass Human Approval Gates for high-impact actions (`PENDING_APPROVAL`).
  - Target sandboxing: strict validation against whitelisted test identities/CIDRs.
  - Operational rollback handlers (`UNBLOCK_IP`, `REINSTATE_USER`).
- [ ] Not started **TASK-702 [P3]:** Implement Cryptographic Security Audit Logger (`backend/src/audit/integrityChain.ts`):
  - Append-only SHA-256 hash chaining with SQS FIFO serialization.
  - One-click cryptographic chain verification API (`POST /api/v1/audit-logs/verify-chain`).
- [ ] Not started **TASK-703 [P3]:** Write unit tests for containment execution, approval gates, rollback, and tamper detection (`backend/tests/response-audit.test.ts`).

---

## Phase 8 — Frontend SOC Dashboard

- [ ] Not started **TASK-801 [P1]:** Implement responsive SOC Shell Layout (`Header.tsx`, `Sidebar.tsx`) with Midnight Navy & Electric Cyan styling.
- [ ] Not started **TASK-802 [P1]:** Build `DashboardOverview.tsx` with Recharts telemetry area chart, severity donut, and MITRE tactic matrix.
- [ ] Not started **TASK-803 [P1]:** Build `LiveEvents.tsx` with real-time telemetry stream, search, and JSON modal inspector.
- [ ] Not started **TASK-804 [P1]:** Build `ThreatDetection.tsx` with 10 Sigma rules catalog, toggle controls, and threshold sliders.
- [ ] Not started **TASK-805 [P1]:** Build `Incidents.tsx` with incident queue, explainable risk breakdown cards, and attack kill-chain timeline.
- [ ] Not started **TASK-806 [P1]:** Build `ThreatIntelligence.tsx` with IOC database and IP enrichment tool.
- [ ] Not started **TASK-807 [P1]:** Build `ResponseCenter.tsx` with human approval queue, active blocklist, and rollback buttons.
- [ ] Not started **TASK-808 [P1]:** Build `SimulationLab.tsx` with 6 interactive scenario cards and live terminal stream.
- [ ] Not started **TASK-809 [P1]:** Build `AuditLogs.tsx` with SHA-256 hash inspector and interactive "Verify Ledger Integrity" tool.
- [ ] Not started **TASK-810 [P1]:** Build `Settings.tsx` with organization multi-tenancy controls and RBAC matrix.
- [ ] Not started **TASK-811 [P1]:** Verify frontend production compilation (`npm --prefix frontend run build`).

---

## Phase 9 — VELTRIX CLI (`@veltrix/cli`)

- [ ] Not started **TASK-901 [P3]:** Scaffold `cli/` executable (`bin/veltrix.ts`) and packaging (`package.json`).
- [ ] Not started **TASK-902 [P2]:** Build CLI API Client (`cli/src/api/client.ts`) connecting to shared backend REST endpoints.
- [ ] Not started **TASK-903 [P1]:** Implement `veltrix auth login / logout / status` with chalk terminal banners.
- [ ] Not started **TASK-904 [P1]:** Implement `veltrix events list / show / ingest --dry-run` with table formatting.
- [ ] Not started **TASK-905 [P2]:** Implement `veltrix detect run / rules list / rules test`.
- [ ] Not started **TASK-906 [P1]:** Implement `veltrix incidents list / show / update / assign` with risk color badges.
- [ ] Not started **TASK-907 [P2]:** Implement `veltrix intel ip / indicators list / mitre`.
- [ ] Not started **TASK-908 [P2/P1]:** Implement `veltrix response policies list / preview / execute / history` with interactive confirmation.
- [ ] Not started **TASK-909 [P1]:** Implement `veltrix simulate list / run / results` with spinners (`ora`).
- [ ] Not started **TASK-910 [P1]:** Implement `veltrix status` and `veltrix config show`.
- [ ] Not started **TASK-911 [P2]:** Write CLI unit and integration tests (`cli/tests/cli.test.ts`).

---

## Phase 10 — Full Integration & Simulation Verification

- [ ] Not started **TASK-1001 [ALL]:** Implement the 6 Synthetic Simulation Scenarios (`backend/src/simulation/runner.ts`).
- [ ] Not started **TASK-1002 [ALL]:** Test complete end-to-end event progression:
  Telemetry Ingestion $\to$ Normalization $\to$ Sigma Detection $\to$ Correlation $\to$ Risk Scoring $\to$ Incident Creation $\to$ SOAR Containment $\to$ Audit Logging $\to$ Dashboard & CLI Sync.
- [ ] Not started **TASK-1003 [ALL]:** Verify that identical incident and event telemetry is visible simultaneously in the Web SOC Console and CLI.

---

## Phase 11 — Security & DevSecOps Audit

- [ ] Not started **TASK-1101 [P3]:** Run automated dependency vulnerability scan (`npm audit`).
- [ ] Not started **TASK-1102 [P3]:** Perform static analysis and zero-secret scan across all files.
- [ ] Not started **TASK-1103 [P3]:** Conduct cross-tenant data isolation security test.
- [ ] Not started **TASK-1104 [P3]:** Verify cryptographic audit chain tamper-detection tests.

---

## Phase 12 — Deployment & AWS Infrastructure Verification

- [ ] Not started **TASK-1201 [P3]:** Validate AWS SAM template (`infrastructure/template.yaml`).
- [ ] Not started **TASK-1202 [P3]:** Verify IAM least-privilege policies.
- [ ] Not started **TASK-1203 [P3]:** Finalize AWS serverless cost optimization analysis (`docs/aws-cost-analysis.md`).

---

## Phase 13 — Final Quality Assurance & Competition Readiness

- [ ] Not started **TASK-1301 [ALL]:** Run full test suite across backend, frontend, and CLI.
- [ ] Not started **TASK-1302 [ALL]:** Compile final test and coverage report.
- [ ] Not started **TASK-1303 [ALL]:** Finalize comprehensive `README.md`, `docs/api-reference.md`, `docs/deployment-guide.md`, and 5-minute `docs/demo-script.md`.
- [ ] Not started **TASK-1304 [ALL]:** Verify competition-ready status.
