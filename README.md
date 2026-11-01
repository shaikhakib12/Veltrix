# VELTRIX

> **Beyond Detection. Into Defense.**  
> Unified Website Security Monitoring & Authorized Vulnerability Assessment Platform

[![CI Pipeline](https://github.com/shaikhakib12/Veltrix/actions/workflows/ci.yml/badge.svg)](https://github.com/shaikhakib12/Veltrix/actions/workflows/ci.yml)
[![License: UNLICENSED](https://img.shields.io/badge/License-Proprietary-blue.svg)](LICENSE)
[![Node: >=22.0.0](https://img.shields.io/badge/Node-%3E%3D22.0.0-emerald.svg)](https://nodejs.org/)

---

## 1. System Overview

**VELTRIX** is a unified website security platform combining **Continuous Website Attack Monitoring** with **Authorized Website Vulnerability Assessment**. It ingests real-time web telemetry from application SDKs, reverse proxies, and cloud firewalls, detects attack patterns (SQLi, XSS, Path Traversal, Brute Force, Bots, API abuse), performs non-destructive policy-governed vulnerability scans (TLS, headers, cookies, CORS, OWASP ZAP), and correlates attacks with known asset vulnerabilities to compute explainable risk scores.

Modern Security Operations Centers (SOC) face crippling alert fatigue, uncoordinated alerts from disparate systems, and delayed manual containment actions. VELTRIX resolves these challenges by:
1. **High-Precision Telemetry Ingestion:** Ingests and normalizes multi-source events with UUIDv7 atomic idempotency checking to prevent dropping rapid brute-force attacks.
2. **Sigma-Inspired Detection Engine:** Evaluates security telemetry against 10 built-in sliding temporal window detection rules.
3. **Attack Correlation:** Reconstructs multi-stage attack paths across time, identity, and source IP mapped to the MITRE ATT&CK® framework.
4. **Explainable Risk Scoring:** Calculates deterministic normalized scores ($0 - 100$) with transparent factor breakdowns.
5. **Controlled Defensive SOAR:** Orchestrates approval-gated containment actions (`BLOCK_IP`, `SUSPEND_USER`, `REVOKE_SESSION`, `STEP_UP_AUTH`) with zero-bypass authorization and instant rollback.
6. **Cryptographic Audit Ledger:** Maintains an append-only, SHA-256 hash-chained ledger serialized via SQS FIFO for tamper-evident compliance.

---

## 2. Monorepo Structure

VELTRIX is structured as an npm workspaces monorepo:

```text
Veltrix/
├── packages/
│   └── shared/           # @veltrix/shared: Domain types, Zod schemas, constants & contracts
├── backend/              # @veltrix/backend: Express API, Sigma detection engine & MemoryStore
├── frontend/             # @veltrix/frontend: React 18, Vite, Tailwind CSS, SOC Web Console
├── cli/                  # @veltrix/cli: High-performance terminal operator CLI tool
├── infrastructure/       # AWS SAM template.yaml, DynamoDB, SQS FIFO & S3 Object Lock definitions
├── docs/                 # Architecture guides and Team Collaboration Onboarding Guide
├── specs/                # Complete Phase 1 technical specifications & verification reports
├── .github/workflows/    # Automated CI pipeline (lint, typecheck, test, build)
├── .env.example          # Baseline environment template for offline & AWS modes
├── package.json          # Root npm workspace manifest
└── tsconfig.base.json    # Shared TypeScript compiler configuration
```

---

## 3. Quick Start & Local Setup

### Prerequisites
- **Node.js:** `v22.x` or `v24.x` (LTS)
- **npm:** `v10.x` or `v11.x`
- **Git:** `2.40+`

### Installation
```bash
# Clone the repository
git clone https://github.com/shaikhakib12/Veltrix.git
cd Veltrix

# Install dependencies across all monorepo workspaces
npm install

# Copy environment configuration
cp .env.example .env
```

### Verification & Testing
```bash
# Typecheck all workspaces
npm run typecheck

# Run automated unit and integration tests
npm run test

# Build all packages
npm run build
```

### Running the Services
- **Backend API Server (Local Simulation / MemoryStore):**
  ```bash
  npm run dev --workspace=backend
  # Listens on http://localhost:4000
  ```
- **Frontend SOC Console:**
  ```bash
  npm run dev --workspace=frontend
  # Available at http://localhost:5173
  ```
- **VELTRIX Terminal CLI:**
  ```bash
  node cli/bin/veltrix.js status
  ```

---

## 4. Engineering Team Collaboration & Ownership

VELTRIX is designed with modular domain boundaries for seamless collaboration:

- **Person 1 (P1):** Frontend & CLI Presentation Lead (`frontend/`, `cli/src/formatters/`)
- **Person 2 (P2):** Backend Core & Cybersecurity Intelligence Lead (`backend/src/detection/`, `backend/src/correlation/`, `backend/src/intel/`)
- **Person 3 (P3):** Cloud, Database, DevSecOps & SOAR Lead (`infrastructure/`, `backend/src/storage/`, `packages/shared/`, CI/CD)

For branching policies, PR rules, and coding standards, consult [`docs/team-collaboration.md`](file:///d:/Veltrix/docs/team-collaboration.md).

---

## 5. Specification Roadmap

- [x] **Phase 0:** Workspace & Toolchain Inspection
- [x] **Phase 1:** Specification & Architecture Formulation
- [x] **Phase 2:** Project Foundation & Monorepo Setup *(Current)*
- [ ] **Phase 3:** Authentication & Database Integration
- [ ] **Phase 4:** Event Ingestion API
- [ ] **Phase 5:** Detection, Correlation & Risk Scoring Engine
- [ ] **Phase 6:** Defensive Response, Audit Trail & Attack Simulation
- [ ] **Phase 7:** Frontend SOC Dashboard & Terminal CLI
- [ ] **Phase 8:** Comprehensive Testing & Verification
- [ ] **Phase 9:** Competition Packaging & Final Delivery
