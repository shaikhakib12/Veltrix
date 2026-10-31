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
| `Idempotency-Key` | String | Optional | Client-supplied request deduplication key for safe network retries. |

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

### 2.2 Telemetry Ingestion & Query (Module B)

#### 2.2.1 Event Ingestion (`POST /api/v1/events`)
- **Authentication:** Bearer JWT required (`Authorization: Bearer <token>`).
- **Authorization / RBAC:** Permitted for `SUPER_ADMIN`, `ORG_ADMIN`, and `SECURITY_ANALYST`. Blocked for `READ_ONLY_VIEWER` (`403 FORBIDDEN_INSUFFICIENT_PERMISSIONS`).
- **Multi-Tenancy:** The organization context is strictly derived from the verified JWT (`req.tenantOrgId`). Any conflicting `orgId` in payload, query, or headers is rejected with `403 FORBIDDEN_CROSS_TENANT_ACCESS`.

##### A. Single Event Request Body
```json
{
  "eventId": "018d5f30-74e1-7cb2-b43a-e9fa651f8b1c",
  "eventType": "auth.login.failed",
  "timestamp": "2026-11-01T00:30:00.000Z",
  "severity": "HIGH",
  "category": "AUTHENTICATION",
  "sourceIp": "198.51.100.42",
  "username": "sarah.connors",
  "sourceSystem": "auth.prod.internal",
  "metadata": { "reason": "INVALID_PASSWORD", "attempt": 3 },
  "isSimulated": true,
  "idempotencyKey": "opt-client-key-or-event-id"
}
```
- *Notes:* `eventId` (UUIDv7/UUIDv4), `timestamp`, and `idempotencyKey` are optional. If `eventId` is omitted, the server generates an RFC 9562 UUIDv7. If `idempotencyKey` is omitted, `idempotencyKey = eventId`.

##### Single Event Responses
- **Response 202 Accepted (New Event Ingested):**
  ```json
  {
    "success": true,
    "data": {
      "status": "ACCEPTED",
      "eventId": "018d5f30-74e1-7cb2-b43a-e9fa651f8b1c",
      "event": {
        "eventId": "018d5f30-74e1-7cb2-b43a-e9fa651f8b1c",
        "orgId": "org-enterprise-01",
        "timestamp": "2026-11-01T00:30:00.000Z",
        "eventType": "auth.login.failed",
        "severity": "HIGH",
        "category": "AUTHENTICATION",
        "sourceIp": "198.51.100.42",
        "username": "sarah.connors",
        "sourceSystem": "auth.prod.internal",
        "metadata": { "reason": "INVALID_PASSWORD", "attempt": 3 },
        "isSimulated": true,
        "idempotencyKey": "opt-client-key-or-event-id",
        "ingestedAt": "2026-11-01T00:30:00.125Z"
      }
    },
    "meta": { "timestamp": "2026-11-01T00:30:00.125Z" }
  }
  ```
- **Response 202 Accepted (Duplicate Event Suppressed via Idempotency):**
  ```json
  {
    "success": true,
    "data": {
      "status": "DUPLICATE_SUPPRESSED",
      "eventId": "018d5f30-74e1-7cb2-b43a-e9fa651f8b1c"
    },
    "meta": { "timestamp": "2026-11-01T00:30:00.125Z" }
  }
  ```

##### B. Batch Ingestion Request Body (Max 100 Events)
```json
{
  "events": [
    {
      "eventType": "auth.login.failed",
      "severity": "HIGH",
      "category": "AUTHENTICATION",
      "sourceIp": "198.51.100.42",
      "sourceSystem": "auth.prod.internal"
    },
    {
      "eventType": "network.port.scan",
      "severity": "MEDIUM",
      "category": "NETWORK",
      "sourceIp": "203.0.113.88",
      "sourceSystem": "ids-edge-01"
    }
  ]
}
```

##### Batch Event Responses
- **Response 202 Accepted (Batch Processed):**
  ```json
  {
    "success": true,
    "data": {
      "total": 2,
      "accepted": 2,
      "duplicates": 0,
      "rejected": 0,
      "results": [
        { "eventId": "018d5f30-74e1-7cb2-b43a-e9fa651f8b1c", "status": "ACCEPTED" },
        { "eventId": "018d5f31-85f2-7dc3-c54b-f0ab762a9c2d", "status": "ACCEPTED" }
      ]
    },
    "meta": { "timestamp": "2026-11-01T00:30:00.125Z", "total": 2 }
  }
  ```
- **Response 422 Unprocessable Entity (All Batch Items Invalid):**
  Returned when every item in the batch failed validation.
- **Response 400 Bad Request (`BATCH_SIZE_EXCEEDED`):**
  Returned when batch exceeds 100 items.

---

#### 2.2.2 Event Query & Filtering (`GET /api/v1/events`)
- **Authentication:** Bearer JWT required.
- **Authorization / RBAC:** Permitted for all roles (`SUPER_ADMIN`, `ORG_ADMIN`, `SECURITY_ANALYST`, `READ_ONLY_VIEWER`).
- **Query Parameters:**
  - `limit` (Integer, 1-100, default `50`): Page size.
  - `cursor` (Base64 string): Opaque cursor for pagination continuation. Bound cryptographically to authorized `orgId`.
  - `startTime` (ISO 8601 UTC): Filter events timestamp $ge$ startTime.
  - `endTime` (ISO 8601 UTC): Filter events timestamp $le$ endTime. Must be $ge$ startTime.
  - `eventType` (String, e.g. `auth.login.failed`): Filter by event type (uses DynamoDB `GSI1-EventTypeIndex`).
  - `severity` (Enum: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`): Filter by severity.
  - `sourceIp` (IP address string): Forensic search by source IP (uses DynamoDB `GSI2-SourceIpIndex`).
  - `username` (String): Search by targeted user account.
  - `sourceSystem` (String): Filter by reporting ingestion agent.

##### Query Responses
- **Response 200 OK:**
  ```json
  {
    "success": true,
    "data": {
      "events": [
        {
          "eventId": "018d5f30-74e1-7cb2-b43a-e9fa651f8b1c",
          "orgId": "org-enterprise-01",
          "timestamp": "2026-11-01T00:30:00.000Z",
          "eventType": "auth.login.failed",
          "severity": "HIGH",
          "category": "AUTHENTICATION",
          "sourceIp": "198.51.100.42",
          "username": "sarah.connors",
          "sourceSystem": "auth.prod.internal",
          "metadata": { "reason": "INVALID_PASSWORD" },
          "isSimulated": true,
          "ingestedAt": "2026-11-01T00:30:00.125Z"
        }
      ],
      "total": 45,
      "nextCursor": "eypvcmdJZCI6Im9yZy1lbnRlcnByaXNlLTAxIiwib2Zmc2V0IjoxNX0="
    },
    "meta": {
      "timestamp": "2026-11-01T00:30:00.125Z",
      "cursor": "eypvcmdJZCI6Im9yZy1lbnRlcnByaXNlLTAxIiwib2Zmc2V0IjoxNX0=",
      "hasMore": true,
      "total": 45
    }
  }
  ```

---

#### 2.2.3 Single Event Retrieval (`GET /api/v1/events/:eventId`)
- **Authentication:** Bearer JWT required.
- **Parameters:** `eventId` (UUID string in URL path).
- **Response 200 OK:** Returns normalized `SecurityEvent`.
- **Response 404 Not Found (`EVENT_NOT_FOUND`):** Returned if event does not exist or belongs to another organization.

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
