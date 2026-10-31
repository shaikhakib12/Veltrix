# VELTRIX: REST API Reference Documentation
**Version:** 1.0.0  
**Base URL:** `/api/v1`  
**Authentication:** Amazon Cognito JWT Bearer Token / `x-organization-id` header  

---

## 1. System Health
### `GET /health`
Returns the operational status of the VELTRIX intelligence engine.
- **Response 200 OK:**
  ```json
  {
    "status": "HEALTHY",
    "service": "VELTRIX Security Intelligence Engine",
    "version": "1.0.0",
    "mode": "SERVERLESS_LOCAL_ADAPTER",
    "timestamp": "2026-10-31T22:30:00.000Z"
  }
  ```

---

## 2. Security Events Ingestion
### `POST /events`
Ingests single or batch security telemetry from simulated endpoints, firewalls, and cloud hosts.
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

### `GET /events`
Queries ingested events with query filtering (`eventType`, `sourceIp`, `username`, `limit`).

---

## 3. Threat Detection Rules
### `GET /detection-rules`
Lists all 10 built-in Sigma-inspired detection rules.
### `PATCH /detection-rules/:ruleId`
Updates threshold, sliding window, or enabled status for a rule.
- **Request Body:**
  ```json
  {
    "enabled": true,
    "threshold": 3
  }
  ```

---

## 4. Incidents & Triage
### `GET /incidents`
Returns paginated list of security incidents sorted by risk score and creation time. Query filters: `status`, `severity`.
### `GET /incidents/:incidentId`
Returns complete incident dossier including correlated events and attack kill-chain timeline.
### `PATCH /incidents/:incidentId`
Updates incident lifecycle status (`INVESTIGATING`, `CONTAINED`, `RESOLVED`, `FALSE_POSITIVE`) or appends analyst notes.

---

## 5. Defensive Response (SOAR)
### `GET /responses/approvals`
Lists containment actions currently in `PENDING_APPROVAL` status requiring analyst authorization.
### `POST /responses/:incidentId/execute`
Dispatches a manual or automated defensive action (`BLOCK_IP`, `SUSPEND_USER`, `STEP_UP_AUTH`).
### `POST /responses/approvals/:executionId/approve`
Approves and executes a previously queued containment action.
### `POST /responses/executions/:executionId/rollback`
Reverts an active containment action (e.g., Unblocks IP or reinstates suspended user).

---

## 6. Cryptographic Audit Trail
### `GET /audit-logs`
Returns the append-only audit trail records.
### `POST /audit-logs/verify-chain`
Recalculates all SHA-256 hashes across the audit chain and verifies ledger continuity.
- **Response 200 OK:**
  ```json
  {
    "verified": true,
    "totalRecordsChecked": 42,
    "timestamp": "2026-10-31T22:30:00.000Z"
  }
  ```

---

## 7. Simulation Lab
### `GET /simulation/scenarios`
Returns the 6 pre-built attack scenarios with metadata and estimated duration.
### `POST /simulation/execute`
Executes an attack scenario, streaming synthetic events into the live pipeline.
- **Request Body:**
  ```json
  {
    "scenarioId": "sim-account-takeover-chain"
  }
  ```
