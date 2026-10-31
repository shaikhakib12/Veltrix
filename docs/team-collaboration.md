# VELTRIX: Engineering Team Collaboration & Ownership Guide (`docs/team-collaboration.md`)

This document defines the team collaboration workflow and modular ownership boundaries for the VELTRIX project. While Phase 2 has been initialized by a single lead engineer, the repository is architected so two additional teammates can onboard immediately without friction, code collisions, or ambiguity.

---

## 1. Modular Domain Ownership & Roles

| Role | Area of Responsibility | Primary Directory Ownership | Key Tech Stack |
| :--- | :--- | :--- | :--- |
| **Person 1 (P1)** | **Frontend & CLI Terminal UX Lead** | `frontend/`<br/>`cli/src/formatters/` | React 18, Vite, Tailwind CSS, Recharts, Lucide, Terminal UX |
| **Person 2 (P2)** | **Backend Core & Cyber Intelligence Lead** | `backend/src/detection/`<br/>`backend/src/correlation/`<br/>`backend/src/risk/`<br/>`backend/src/intel/`<br/>`cli/src/api-client/` | Node.js, TypeScript, Sigma Engine, Mathematical Risk Scoring, Threat Intel |
| **Person 3 (P3)** | **Cloud, Database, DevSecOps & SOAR Lead** | `infrastructure/`<br/>`backend/src/storage/`<br/>`backend/src/soar/`<br/>`backend/src/audit/`<br/>`packages/shared/`<br/>`.github/workflows/` | AWS SAM, DynamoDB, Cognito, SQS FIFO, S3 Object Lock, Monorepo & CI |

### Rules of Engagement
1. **Zero Overlapping Edits on Core Interfaces:** All shared types and schemas in `packages/shared/` must be proposed via PR and reviewed before consumption.
2. **Mock-First Integration:** P1 develops against mock backend contracts or `MemoryStore` running locally; P2 implements detection algorithms against standardized telemetry models; P3 provides infrastructure and database adaptations.
3. **No Direct Commits to `main`:** All work must proceed through feature branches and pull requests.

---

## 2. Git & Branching Strategy

```text
main (Protected — Production/Competition Ready)
  ▲
  │ (Pull Request with CI Green & Review)
  │
feature/phase-X-[feature-name]
```

### Branch Naming Conventions
- `feature/phase-[number]-[slug]` (e.g. `feature/phase-3-auth-cognito`)
- `fix/[slug]` (e.g. `fix/ingestion-timestamp-validation`)
- `docs/[slug]` (e.g. `docs/api-guide`)

### Pull Request Workflow
1. Branch off the latest `main`:
   ```bash
   git checkout main
   git pull origin main
   git checkout -b feature/phase-3-auth
   ```
2. Implement, run all checks locally:
   ```bash
   npm run typecheck
   npm run test
   npm run build
   ```
3. Commit with Conventional Commits:
   `feat(auth): implement Cognito JWT token validation middleware`
4. Push branch and open a PR against `main`.
5. Require all CI pipeline checks to pass before merging.

---

## 3. Local Developer Setup (Zero-Friction Onboarding)

### Prerequisites
- Node.js `v22.x` or `v24.x` (LTS)
- npm `10.x` or `11.x`
- Git `2.40+`

### One-Command Setup
```bash
# 1. Clone repository
git clone https://github.com/shaikhakib12/Veltrix.git
cd Veltrix

# 2. Install monorepo dependencies
npm install

# 3. Copy environment configuration
cp .env.example .env

# 4. Verify build & tests pass
npm run typecheck
npm run test
npm run build
```

### Running Workspaces Locally
- **Start Backend:**
  ```bash
  npm run dev --workspace=backend
  # Backend API runs at http://localhost:4000 (MemoryStore active by default)
  ```
- **Start Frontend Web SOC:**
  ```bash
  npm run dev --workspace=frontend
  # Web Console runs at http://localhost:5173
  ```
- **Execute CLI:**
  ```bash
  node cli/bin/veltrix.js status
  ```
