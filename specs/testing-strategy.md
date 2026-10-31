# VELTRIX: Testing & Quality Assurance Strategy (`specs/testing-strategy.md`)

**Document Version:** 2.0.0  
**Status:** In Review (Phase 1 Specification)  
**Testing Frameworks:** Vitest 3.x (Backend, Unit, Integration), Playwright (E2E), Node.js Assertions  

---

## 1. Testing Pyramid & Quality Philosophy

VELTRIX adheres to a strict test-driven and evidence-based development cycle:
**PLAN $\to$ BUILD $\to$ TEST $\to$ DEBUG $\to$ FIX $\to$ RETEST $\to$ VERIFY $\to$ DOCUMENT.**

A feature is never considered complete merely because its code was authored; it is complete only when unit, integration, and security checks pass with zero regressions.

```text
       ▲
      / \        E2E Tests (Playwright: Live Web Console & CLI Flows)
     /   \       ----------------------------------------------------
    /     \      Integration Tests (Ingestion -> Detection -> Incident -> SOAR -> Audit)
   /       \     ------------------------------------------------------------------------
  /         \    Unit Tests (10 Sigma Rules, Risk Math, Deduplication, Hash Chain Chaining)
 /___________\   --------------------------------------------------------------------------
```

---

## 2. Test Suites by Module

### 2.1 Event Ingestion & Normalization (`backend/tests/ingestion.test.ts`)
- **Schema Validation:** Asserts valid inputs succeed and malformed payloads (missing fields, invalid IPs, oversized metadata) return `400 Bad Request`.
- **Normalization:** Asserts timestamps become ISO UTC, usernames are lowercased, and IPs are canonicalized.
- **Idempotency Deduplication:** Generates events with identical attributes within the same minute window and asserts duplicates are discarded.

### 2.2 Threat Detection Engine (`backend/tests/detection.test.ts`)
- **10 Rule Verifications:** Dedicated positive and negative test cases for every rule (`RULE-001` through `RULE-010`).
- **Sliding Window:** Tests that events outside the sliding window expire and do not trigger false alerts.
- **Dynamic Tuning:** Tests updating thresholds on the fly and asserting the engine adapts dynamically.

### 2.3 Event Correlation & Risk Scoring (`backend/tests/correlation-risk.test.ts`)
- **Multi-Stage Attack Sequence:** Simulates a 4-stage kill-chain (*Brute Force $\to$ Valid Login $\to$ Privilege Escalation $\to$ Exfiltration*) and asserts all 4 events link to a single incident.
- **Risk Math Precision:** Asserts base score, frequency multiplier, asset criticality multiplier ($1.35\times$), threat intel multiplier ($1.20\times$), and sequence bonus ($+25$) match the formulaic output exactly.

### 2.4 Defensive SOAR Containment & Audit Ledger (`backend/tests/response-audit.test.ts`)
- **Approval Queue:** Asserts high-impact actions enter `PENDING_APPROVAL` and do not execute until an analyst approves.
- **Rollback:** Asserts `UNBLOCK_IP` and `REINSTATE_USER` restore initial operational states.
- **Cryptographic Chaining:** Asserts pristine hash chains verify successfully, and intentional modification of historical records triggers tamper alarms.

### 2.5 Simulation Lab Engine (`backend/tests/simulation.test.ts`)
- **Scenario Execution:** Asserts all 6 scenarios inject the expected number of events and produce correlated incidents with proper risk scores.

### 2.6 VELTRIX CLI (`cli/tests/cli.test.ts`)
- **Command Syntax & Output:** Tests `auth`, `events`, `detect`, `incidents`, `intel`, `response`, and `simulate`.
- **Exit Codes:** Asserts exit code $0$ for successful execution, $1$ for operational errors, and $2$ for unauthenticated calls.
- **JSON Output:** Asserts `--json` outputs valid, parseable JSON payloads.

---

## 3. Automated Self-Testing Workflow

1. Before merging any change, run:
   ```bash
   npm run test:backend
   npm run build
   ```
2. Any test failure must be investigated and fixed at the root cause. Weakening assertions or using mock responses to hide failures is strictly prohibited.
