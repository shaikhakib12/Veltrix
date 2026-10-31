# VELTRIX: REST API Contracts & Endpoint Specifications (`specs/api-contracts.md`)

**Document Version:** 2.1.0 (Post-Audit Hardened)  
**Status:** In Review (Phase 1 Specification)  
**Base URL:** `/api/v1`  
**Protocol:** HTTPS / TLS 1.3  

---

## 1. Authentication & Common Headers

All requests made by the Web console, CLI, and telemetry clients must include:

| Header Name | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `Content-Type` | String | Yes | `application/json` |
| `Authorization` | String | Yes (Prod) | Bearer token: `Bearer <Cognito_JWT_ID_Token>` |
| `x-organization-id` | String | Yes | Organization identifier (e.g., `org-enterprise-01`). Verified against JWT claims. |

---

## 2. API Endpoint Matrix

### 2.1 System, Health & Authentication
- **`GET /health`**
  - **Response 200 OK:**
    ```json
    {
      "status": "HEALTHY",
      "service": "VELTRIX Security Intelligence Engine",
      "version": "2.1.0",
      "mode": "SERVERLESS_LOCAL_ADAPTER",
      "timestamp": "2026-10-31T23:00:00.000Z"
    }
    ```

- **`POST /auth/login`** (Used by Web and CLI)
  - **Request Body:** `{ "email": "analyst@cyberdefend.corp", "password": "...", "orgId": "org-enterprise-01" }`
  - **Response 200 OK:**
    ```json
    {
      "success": true,
      "token": "mock-jwt-token-or-cognito-id-token",
      "user": {
        "userId": "user-analyst-01",
        "email": "analyst@cyberdefend.corp",
        "role": "SECURITY_ANALYST",
        "orgId": "org-enterprise-01"
      }
    }
    ```

- **`GET /auth/status`**
  - **Response 200 OK:** Returns active session user and role.

- **`POST /auth/logout`**
  - **Response 200 OK:** Invalidation confirmation.

---

### 2.2 Telemetry Ingestion (Module B)
- **`POST /events`**
  - **Request Body (Single):**
    ```json
    {
      "eventId": "018d5f30-74e1-7cb2-b43a-e9fa651f8b1c",
      "idempotencyKey": "opt-client-key-or-event-id",
      "eventType": "auth.login.failed",
      "category": "AUTHENTICATION",
      "sourceIp": "198.51.100.42",
      "username": "sarah.connors",
      "sourceSystem": "auth.prod.internal",
      "metadata": { "reason": "INVALID_PASSWORD" },
      "isSimulated": true
    }
    ```
  - **Request Body (Batch):** `{ "events": [ { ... }, { ... } ] }` (Max 100 events)
  - **Response 202 Accepted:**
    ```json
    {
      "success": true,
      "ingestedCount": 1,
      "triggersFired": 1,
      "incidentsUpdated": 1,
      "events": [...]
    }
    ```

- **`GET /events`**
  - **Query Parameters:** `eventType` (string), `sourceIp` (string), `username` (string), `limit` (number, default 50, max 100), `cursor` (base64 encoded `ExclusiveStartKey`).
  - **Response 200 OK:**
    ```json
    {
      "total": 45,
      "nextCursor": "eyJQSyI6...====",
      "events": [...]
    }
    ```

---

### 2.3 Threat Detection & Rules (Module C)
- **`GET /detection-rules`**
  - **Response 200 OK:** Array of all 10 Sigma-inspired detection rules.
- **`PATCH /detection-rules/:ruleId`**
  - **Request Body:** `{ "enabled": boolean, "threshold": number, "timeWindowSeconds": number }`
  - **Response 200 OK:** `{ "success": true, "rule": { ... } }`
- **`POST /detection-rules/test`** (Rule Dry-Run)
  - **Request Body:** `{ "rule": { ... }, "sampleEvents": [ { ... } ] }`
  - **Response 200 OK:** `{ "matched": boolean, "matchedCount": 5, "triggers": [...] }`

---

### 2.4 Incident Management (Module G)
- **`GET /incidents`**
  - **Query Parameters:** `status` (NEW, INVESTIGATING, CONTAINED, RESOLVED), `severity`, `limit`, `cursor`.
  - **Response 200 OK:** `{ "total": 3, "nextCursor": null, "incidents": [...] }`
- **`GET /incidents/:incidentId`**
  - **Response 200 OK:** `{ "incident": { ... }, "correlatedEvents": [...] }`
- **`PATCH /incidents/:incidentId`**
  - **Request Body:** `{ "status": string, "assignee": string, "note": string }`
  - **Response 200 OK:** `{ "success": true, "incident": { ... } }`
- **`POST /incidents/:incidentId/assign`**
  - **Request Body:** `{ "assignee": "Alex Vance" }`
  - **Response 200 OK:** `{ "success": true, "incident": { ... } }`

---

### 2.5 Threat Intelligence (Module F)
- **`GET /threat-indicators`**
  - **Response 200 OK:** Array of IOC indicators (Tor, C2, Proxies).
- **`POST /threat-indicators/enrich`**
  - **Request Body:** `{ "ip": "198.51.100.42" }`
  - **Response 200 OK:** `{ "ip": "198.51.100.42", "isFlagged": true, "indicator": { ... } }`

---

### 2.6 Defensive Response (SOAR - Module H)
- **`GET /responses/policies`**
  - **Response 200 OK:** List of configured automated defense policies.
- **`GET /responses/approvals`**
  - **Response 200 OK:** List of actions in `PENDING_APPROVAL` status.
- **`GET /responses/:incidentId/preview`**
  - **Response 200 OK:** `{ "incidentId": "...", "recommendedAction": "BLOCK_IP", "target": "198.51.100.42", "requiresApproval": true, "impactAssessment": "Disruptive: Drops simulated ingress packets" }`
- **`POST /responses/:incidentId/execute`**
  - **Request Body:** `{ "action": "BLOCK_IP" | "SUSPEND_USER" | "STEP_UP_AUTH", "approvalToken": "opt-token" }`
  - **Response 200 OK:** Returns execution result. If action requires approval and token is missing/unauthorized, returns `403 Forbidden (APPROVAL_REQUIRED)`.
- **`POST /responses/approvals/:executionId/approve`**
  - **Request Body:** `{ "analyst": string }`
  - **Response 200 OK:** `{ "success": true, "execution": { ... } }`
- **`POST /responses/executions/:executionId/rollback`**
  - **Request Body:** `{ "analyst": string }`
  - **Response 200 OK:** `{ "success": true, "execution": { ... } }`
- **`GET /responses/history`**
  - **Response 200 OK:** `{ "activeBlockedIps": [...], "suspendedUsers": [...], "history": [...] }`

---

### 2.7 Security Audit Trail (Module I)
- **`GET /audit-logs`**
  - **Query Parameters:** `limit`, `cursor`.
  - **Response 200 OK:** `{ "total": 12, "logs": [...] }`
- **`POST /audit-logs/verify-chain`**
  - **Response 200 OK:** `{ "verified": true, "totalRecordsChecked": 12, "brokenRecordId": null, "timestamp": "..." }`

---

### 2.8 Simulation Lab (Module K)
- **`GET /simulation/scenarios`**
  - **Response 200 OK:** Array of 6 attack scenario definitions.
- **`POST /simulation/execute`**
  - **Request Body:** `{ "scenarioId": "sim-account-takeover-chain" }`
  - **Response 200 OK:** `{ "scenarioId": "...", "status": "COMPLETED", "injectedEventsCount": 8, "riskScore": 94, "correlatedIncidentId": "...", "durationMs": 42 }`
- **`POST /simulation/reset`**
  - **Response 200 OK:** `{ "success": true, "message": "Platform state reset" }`
