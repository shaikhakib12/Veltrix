# VELTRIX Steering: Security Requirements
**Category:** Security & Compliance Policy  
**Scope:** Whole Platform  

## 1. Authentication & Authorization
- Amazon Cognito User Pool is the single source of truth for identity.
- Backend authorizer extracts `orgId` and `userRole` from verified JWT claims. Frontend-submitted `orgId` parameters must match JWT claims; mismatches must be rejected with `403 Forbidden`.
- Role-Based Access Control (RBAC) with 4 tiers:
  1. `SUPER_ADMIN`
  2. `ORG_ADMIN`
  3. `SECURITY_ANALYST`
  4. `READ_ONLY_VIEWER`

## 2. Secrets Management & Zero Credential Exposure
- No AWS credentials (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`), private keys, or API tokens committed to Git.
- Pass environment configuration via `.env.example` templates and AWS Systems Manager Parameter Store / Secrets Manager in production.

## 3. Cryptographic Audit Integrity
- All security-relevant actions must be recorded in `Veltrix-AuditLogs`.
- Each record must compute a SHA-256 fingerprint anchoring to the preceding record's hash to form a verifiable tamper-evident chain.

## 4. Input Validation & Data Sanitization
- All external inputs to REST endpoints must be validated against strict schemas (e.g., Zod).
- Prevent injection attacks (NoSQL, Command, Scripting) across all ingestion handlers.
- Mask sensitive metadata (e.g. passwords, bearer tokens) before writing to raw event logs.
