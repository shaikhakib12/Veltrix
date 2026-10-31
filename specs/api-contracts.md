# VELTRIX: REST API Contracts & Endpoint Specifications (`specs/api-contracts.md`)

**Document Version:** 2.0.0  
**Status:** In Review (Phase 1 Specification)  
**Base URL:** `/api/v1`  
**Protocol:** HTTPS / TLS 1.3  

---

## 1. Authentication & Common Headers

All requests made by the Web console, CLI, and simulated event sources must include the following headers:

| Header Name | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `Content-Type` | String | Yes | `application/json` |
| `Authorization` | String | Yes (Prod) | Bearer token: `Bearer <Cognito_JWT_ID_Token>` |
| `x-organization-id` | String | Yes | Organization identifier (e.g., `org-enterprise-01`). Verified against JWT claims. |

---

## 2. API Endpoint Matrix

### 2.1 System & Health
- **`GET /health`**
  - **Description:** Returns the live operational status of the VELTRIX intelligence engine.
  - **Response 200 OK:**
    ```json
    {
      "status": "HEALTHY",
      "service": "VELTRIX Security Intelligence Engine",
      "version": "1.0.0",
      "mode": "SERVERLESS_LOCAL_ADAPTER",
      "timestamp": "2026-10-31T23:00:00.000Z"
    }
    ```

### 2.2 Telemetry Ingestion (Module B)
- **`POST /events`**
  - **Description:** Ingests single or batch security events.
  - **Request Body (Single):**
    ```json
    {
      "eventType": "auth.login.failed",
      "category": "AUTHENTICATION",
      "sourceIp": "198.51.100.42",
      "username": "sarah.connors",
      "sourceSystem": "auth.prod.internal",
      "metadata": { "reason": "INVALID_PASSWORD" },
      "isSimulated": true
    }
    ```
  - **Request Body (Batch):**
    ```json
    {
      "events": [ { ... }, { ... } ]
    }
    ```
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
  - **Query Parameters:** `eventType` (string), `sourceIp` (string), `username` (string), `limit` (number).
  - **Response 200 OK:**
    ```json
    {
      "total": 45,
      "events": [...]
    }
    ```

### 2.3 Threat Detection & Rules (Module C)
- **`GET /detection-rules`**
  - **Response 200 OK:** Returns array of all 10 Sigma-inspired detection rules.
- **`PATCH /detection-rules/:ruleId`**
  - **Request Body:** `{ "enabled": boolean, "threshold": number, "timeWindowSeconds": number }`
  - **Response 200 OK:** `{ "success": true, "rule": { ... } }`

### 2.4 Incident Management (Module G)
- **`GET /incidents`**
  - **Query Parameters:** `status` (NEW, INVESTIGATING, CONTAINED, RESOLVED), `severity`.
  - **Response 200 OK:** `{ "total": 3, "incidents": [...] }`
- **`GET /incidents/:incidentId`**
  - **Response 200 OK:** `{ "incident": { ... }, "correlatedEvents": [...] }`
- **`PATCH /incidents/:incidentId`**
  - **Request Body:** `{ "status": string, "assignee": string, "note": string }`
  - **Response 200 OK:** `{ "success": true, "incident": { ... } }`

### 2.5 Threat Intelligence (Module F)
- **`GET /threat-indicators`**
  - **Response 200 OK:** Returns array of IOC indicators (Tor, C2, Proxies).
- **`POST /threat-indicators/enrich`**
  - **Request Body:** `{ "ip": "198.51.100.42" }`
  - **Response 200 OK:** `{ "ip": "198.51.100.42", "isFlagged": true, "indicator": { ... } }`

### 2.6 Defensive Response (SOAR - Module H)
- **`GET /responses/approvals`**
  - **Response 200 OK:** `{ "pendingApprovals": [...] }`
- **`GET /responses/history`**
  - **Response 200 OK:** `{ "activeBlockedIps": [...], "suspendedUsers": [...], "history": [...] }`
- **`POST /responses/:incidentId/execute`**
  - **Request Body:** `{ "action": "BLOCK_IP" | "SUSPEND_USER" | "STEP_UP_AUTH" }`
  - **Response 200 OK:** `{ "success": true, "execution": { ... }, "incident": { ... } }`
- **`POST /responses/approvals/:executionId/approve`**
  - **Request Body:** `{ "analyst": string }`
  - **Response 200 OK:** `{ "success": true, "execution": { ... } }`
- **`POST /responses/executions/:executionId/rollback`**
  - **Request Body:** `{ "analyst": string }`
  - **Response 200 OK:** `{ "success": true, "execution": { ... } }`

### 2.7 Security Audit Trail (Module I)
- **`GET /audit-logs`**
  - **Response 200 OK:** `{ "total": 12, "logs": [...] }`
- **`POST /audit-logs/verify-chain`**
  - **Response 200 OK:** `{ "verified": true, "totalRecordsChecked": 12, "timestamp": "..." }`

### 2.8 Simulation Lab (Module K)
- **`GET /simulation/scenarios`**
  - **Response 200 OK:** Array of 6 attack scenario definitions.
- **`POST /simulation/execute`**
  - **Request Body:** `{ "scenarioId": "sim-account-takeover-chain" }`
  - **Response 200 OK:** `{ "scenarioId": "...", "status": "COMPLETED", "injectedEventsCount": 8, "riskScore": 94, "correlatedIncidentId": "...", "durationMs": 42 }`
- **`POST /simulation/reset`**
  - **Response 200 OK:** `{ "success": true, "message": "Platform state reset" }`
