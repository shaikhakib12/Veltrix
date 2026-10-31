# VELTRIX Steering: Architecture Conventions
**Category:** System Architecture & Monorepo Design  
**Scope:** Whole Platform  

## 1. Monorepo Organization
- Directory structure:
  - `frontend/`: React + Vite + Tailwind CSS + Recharts UI client.
  - `backend/`: Node.js + TypeScript Lambda micro-functions and domain core.
  - `infrastructure/`: AWS SAM / CloudFormation templates and policy definitions.
  - `specs/`: Requirements, technical design, and task tracking.
  - `docs/`: User guides, API references, architecture diagrams, demo scripts.

## 2. Separation of Concerns & Clean Architecture
- **Domain Independence:** Business logic (threat detection rules, correlation graph logic, risk scoring calculation) must be decoupled from AWS SDK or transport layers.
- **Port & Adapters:** Database access and external services must be injected or wrapped behind abstract repository interfaces, allowing seamless local testing and mock execution.
- **Event-Driven Asynchrony:** Heavy processing (detection rule evaluation, correlation matching, notifications) occurs asynchronously via Amazon EventBridge and Step Functions.

## 3. Multi-Tenancy & Tenant Isolation
- Every entity belongs to an Organization (`orgId`).
- Multi-tenancy is enforced at the database partition key level (`ORG#{orgId}`).
- Cross-tenant queries are structurally disallowed by IAM and application-level authorizers.
