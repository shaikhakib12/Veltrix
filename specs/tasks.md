# VELTRIX: Autonomous Cyber Threat Detection & Response Platform
## Implementation Work Breakdown Structure (`tasks.md`)

**Document Version:** 1.0.0  
**Status:** Approved for Implementation Planning  
**Execution Model:** 3-Person Team Allocation (Person 1: Frontend Lead, Person 2: Backend Lead, Person 3: Cloud/DevSecOps Lead)  

---

## Team Ownership Matrix

- **[P1] Person 1:** Frontend & User Experience Lead (React, Vite, Tailwind CSS, Recharts, Lucide, Playwright)
- **[P2] Person 2:** Backend & Cybersecurity Intelligence Lead (Node.js, TypeScript, Lambda, Detection, Correlation, Risk Engine)
- **[P3] Person 3:** Cloud, Database & DevSecOps Lead (DynamoDB, Cognito, EventBridge, Step Functions, SAM/IaC, Audit)
- **[ALL]:** Shared Architectural & Review Responsibilities

---

## Phase 1: Planning & Specification (Current Milestone)

- [x] **TASK-101 [ALL]:** Inspect repository environment, detect installed runtimes (Node 24, Python 3.12, Git 2.54), and assess tooling constraints.
- [x] **TASK-102 [ALL]:** Draft comprehensive System Requirements Specification (`specs/requirements.md`) with FRs, NFRs, and user stories.
- [x] **TASK-103 [ALL]:** Formulate System Architecture & Technical Design (`specs/design.md`) including DynamoDB schemas, API endpoints, Sigma rules, and cost model.
- [x] **TASK-104 [ALL]:** Establish detailed testable Work Breakdown Structure (`specs/tasks.md`).
- [ ] **TASK-105 [P3]:** Author Kiro steering files (`.kiro/steering/*`) for coding, architecture, security, AWS, testing, and documentation standards.
- [ ] **TASK-106 [P3]:** Author Kiro hooks (`.kiro/hooks/*`) for automated linting, security scanning, and test verification.
- [ ] **TASK-107 [ALL]:** Present Phase 1 plan for user review and approval prior to code implementation.

---

## Phase 2: Monorepo Foundation & Shared Core

- [ ] **TASK-201 [P3]:** Initialize monorepo structure (`frontend/`, `backend/`, `infrastructure/`, `specs/`, `scripts/`, `docs/`).
- [ ] **TASK-202 [P2]:** Set up `backend/` Node.js + TypeScript environment (`tsconfig.json`, `package.json`, Vitest).
- [ ] **TASK-203 [P1]:** Initialize `frontend/` React + Vite + Tailwind CSS + Lucide + Recharts environment.
- [ ] **TASK-204 [P2]:** Define shared TypeScript domain schemas and interfaces (`backend/src/shared/types/` & mirrored in `frontend/src/types/`):
  - `SecurityEvent`, `NormalizedEvent`, `DetectionRule`, `Incident`, `RiskBreakdown`, `ThreatIndicator`, `ResponsePolicy`, `ResponseExecution`, `AuditRecord`.
- [ ] **TASK-205 [P3]:** Create local mock DynamoDB & AWS SDK v3 adapter harness to allow running tests and local execution without active AWS cloud provisioning.
- [ ] **TASK-206 [P1]:** Configure Tailwind design tokens for Midnight Navy palette (`#0B0F19`), Electric Cyan (`#00F5FF`), and cyber borders.

---

## Phase 3: Authentication, Organization Management & Ingestion API

- [ ] **TASK-301 [P3]:** Define Cognito User Pool & App Client configuration in AWS SAM template (`infrastructure/auth/cognito.yaml`).
- [ ] **TASK-302 [P3]:** Implement backend tenant authorization middleware validating `orgId` claims and RBAC roles.
- [ ] **TASK-303 [P2]:** Build Event Ingestion Lambda handler (`POST /api/v1/events`):
  - Schema validation with Zod.
  - Normalization: ISO timestamping, IPv4/IPv6 canonicalization.
  - Idempotency hashing (`SHA-256`) to suppress duplicates.
- [ ] **TASK-304 [P3]:** Configure DynamoDB `Veltrix-SecurityEvents` table schema and GSI definitions.
- [ ] **TASK-305 [P2]:** Write comprehensive unit tests for ingestion validation, normalization, and deduplication (`backend/tests/ingestion.test.ts`).
- [ ] **TASK-306 [P1]:** Build Authentication UI: Login, Registration, MFA Verification, and Organization Selector pages.

---

## Phase 4: Cybersecurity Intelligence, Detection & Correlation

- [ ] **TASK-401 [P2]:** Implement the Threat Detection Engine (`backend/src/detection/engine.ts`).
- [ ] **TASK-402 [P2]:** Code and verify the 10 built-in Sigma-inspired detection rules:
  - `RULE-001`: Brute-Force Authentication Attempt
  - `RULE-002`: Targeted Account Password Spraying
  - `RULE-003`: Compromise After Failure (Credential Stuffing Success)
  - `RULE-004`: Anomalous Geolocation / Impossible Travel
  - `RULE-005`: Known Malicious / Tor / Proxy IP Activity
  - `RULE-006`: Privilege Escalation Indicator
  - `RULE-007`: Bulk Sensitive Data Exfiltration Indicator
  - `RULE-008`: Excessive / Burst API Requests
  - `RULE-009`: Multi-Account Targeted Reconnaissance
  - `RULE-010`: Off-Hours Administrative Anomaly
- [ ] **TASK-403 [P2]:** Build the Event Correlation Engine (`backend/src/correlation/`):
  - Temporal sliding window aggregator.
  - Multi-stage attack kill-chain sequence matcher.
  - Incident deduplication and entity grouping.
- [ ] **TASK-404 [P2]:** Develop Explainable Risk Scoring Engine (`backend/src/risk-engine/`):
  - Mathematical factor scoring formula (Base + Frequency + Asset + Threat Intel + Sequence).
  - Human-readable explanation generation.
- [ ] **TASK-405 [P2]:** Implement Threat Intelligence lookup module with embedded offline IOC feed and MITRE ATT&CK reference mapping.
- [ ] **TASK-406 [P2]:** Write unit tests for all 10 detection rules, correlation sequences, and risk scoring equations (`backend/tests/detection.test.ts`).

---

## Phase 5: Automated Defensive Response (SOAR) & Cryptographic Audit

- [ ] **TASK-501 [P3]:** Build Automated Defensive Response Engine (`backend/src/response/`):
  - Action handlers: `REVOKE_SESSION`, `SUSPEND_USER`, `BLOCK_IP`, `STEP_UP_AUTH`.
  - Rollback handlers: `UNBLOCK_IP`, `REINSTATE_USER`.
- [ ] **TASK-502 [P3]:** Implement Human Approval Gate for high-impact actions (`PENDING_APPROVAL`, `APPROVED`, `REJECTED`).
- [ ] **TASK-503 [P3]:** Design AWS Step Functions state machine template for SOAR response orchestration (`infrastructure/response/soar-workflow.asl.json`).
- [ ] **TASK-504 [P3]:** Implement Cryptographic Audit Logger (`backend/src/audit/integrityChain.ts`):
  - SHA-256 blockchain-style chaining algorithm.
  - Tamper detection verification endpoint (`POST /api/v1/audit-logs/verify-chain`).
- [ ] **TASK-505 [P3]:** Write unit tests for SOAR execution, approval gates, and audit chain verification (`backend/tests/response-audit.test.ts`).

---

## Phase 6: Frontend SOC Console & Security Interfaces

- [ ] **TASK-601 [P1]:** Implement Core SOC Layout (`SOCLayout.tsx`) with collapsible cyber navigation, live threat ticker, organization badge, and quick alert drawer.
- [ ] **TASK-602 [P1]:** Build SOC Dashboard Overview (`DashboardOverview.tsx`):
  - Metrics cards: Ingested Events (24h), Active Threats, Open Incidents, MTTD, MTTR.
  - Interactive Recharts: Event Ingestion Velocity, Threat Severity Distribution, MITRE ATT&CK Tactic Heatmap, Failed vs Success Auth.
- [ ] **TASK-603 [P1]:** Build Live Security Events Explorer (`LiveEvents.tsx`):
  - Real-time event table, multi-column search, severity badges, JSON raw payload modal.
- [ ] **TASK-604 [P1]:** Build Threat Detection Rules View (`ThreatDetection.tsx`):
  - Rule catalog, rule toggle switch, threshold slider, MITRE tag filters.
- [ ] **TASK-605 [P1]:** Build Incident Management Dossier (`Incidents.tsx`):
  - Incident list with risk score badge, attack kill-chain timeline visualizer, correlated event inspector, triage notes, and status changer.
- [ ] **TASK-606 [P1]:** Build Threat Intelligence Portal (`ThreatIntelligence.tsx`):
  - Searchable IOC database, IP risk score inspector, MITRE technique navigator.
- [ ] **TASK-607 [P1]:** Build Response Center (SOAR) (`ResponseCenter.tsx`):
  - Pending approval containment action queue, active blocklists, manual containment trigger, and rollback buttons.
- [ ] **TASK-608 [P1]:** Build Cryptographic Audit Log Explorer (`AuditLogs.tsx`):
  - Append-only event table, SHA-256 hash visualizer, "Verify Ledger Integrity" interactive button with real-time green/red chain validation.

---

## Phase 7: Simulation Lab & Interactive Demo Scenarios

- [ ] **TASK-701 [P2/P3]:** Build the Simulation Engine (`backend/src/simulation/`):
  - Generator for synthetic, tagged (`isSimulated: true`) telemetry.
- [ ] **TASK-702 [P2]:** Implement the 6 pre-built attack scenarios:
  1. *Distributed Brute-Force Password Spray*
  2. *Impossible Travel / Suspicious Geo-Anomaly*
  3. *Full Multi-Stage Account Takeover (Brute-Force $\to$ Login $\to$ Escalation $\to$ Bulk Exfil)*
  4. *Privilege Escalation via Unauthorized IAM Role Assumption*
  5. *Cloud Storage Bulk Data Exfiltration*
  6. *Excessive / Burst API Denial of Service Breach*
- [ ] **TASK-703 [P1]:** Build Simulation Lab UI (`SimulationLab.tsx`):
  - Scenario launch cards with difficulty/impact ratings, real-time live terminal streaming injected events, and direct jump link to generated correlated incident.
- [ ] **TASK-704 [P1]:** Write Playwright E2E simulation test verifying that clicking "Run Scenario" produces correlated incidents and triggers alerts (`frontend/tests/e2e/simulation.spec.ts`).

---

## Phase 8: System Integration, End-to-End API Wiring & Validation

- [ ] **TASK-801 [P1/P2]:** Connect Frontend API Service Layer to Backend REST endpoints with seamless fallback to high-fidelity mock data if backend server is not running.
- [ ] **TASK-802 [P3]:** Wire DynamoDB and EventBridge handlers in SAM template (`template.yaml`).
- [ ] **TASK-803 [ALL]:** Validate end-to-end event flow: Ingestion $\to$ Detection $\to$ Correlation $\to$ Risk Score $\to$ Incident $\to$ SOAR Response $\to$ Audit Log $\to$ SOC UI.
- [ ] **TASK-804 [P3]:** Conduct Multi-Tenant Data Isolation security test: verify Organization A cannot see or mutate Organization B's events or incidents.
- [ ] **TASK-805 [P2]:** Validate false-positive suppression logic and benchmark detection latency.

---

## Phase 9: Infrastructure as Code, DevSecOps & Security Hardening

- [ ] **TASK-901 [P3]:** Finalize AWS SAM / CloudFormation templates (`infrastructure/template.yaml`):
  - API Gateway, Lambdas, DynamoDB Tables, EventBridge Bus, Cognito, IAM Roles.
- [ ] **TASK-902 [P3]:** Implement least-privilege IAM policies without wildcard permissions.
- [ ] **TASK-903 [P3]:** Configure GitHub Actions CI/CD workflow (`.github/workflows/ci.yml`):
  - Linting (ESLint, Prettier).
  - Backend Vitest suite.
  - Frontend Vitest suite.
  - Security vulnerability scan (`npm audit`).
- [ ] **TASK-904 [P3]:** Create comprehensive AWS Cost Estimation documentation based on AWS Pricing Calculator (`docs/aws-cost-analysis.md`).

---

## Phase 10: Competition Documentation, Screenshots & Live Demo Script

- [ ] **TASK-1001 [P1]:** Capture genuine UI screenshots across all 9 pages for README and presentation slides.
- [ ] **TASK-1002 [ALL]:** Create competition-grade `README.md` with architecture diagrams, quickstart guide, team breakdown, and feature matrix.
- [ ] **TASK-1003 [P2]:** Generate full REST API Documentation (`docs/api-reference.md`).
- [ ] **TASK-1004 [P3]:** Write Local Development & AWS Deployment Guide (`docs/deployment-guide.md`).
- [ ] **TASK-1005 [ALL]:** Prepare 5-Minute Live Competition Demonstration Script (`docs/demo-script.md`) highlighting the Multi-Stage Account Takeover scenario.
