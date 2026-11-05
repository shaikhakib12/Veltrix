# Frontend Integration Plan: Phase 8 Vulnerability Scanner & Domain Verification

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Connect the frontend SOC Console to the newly merged Phase 8 backend capabilities: live domain verification challenges, authorized scan execution, real vulnerability scanner evidence, and website attack timelines.

**Architecture:** Expose the backend Phase 8 scanner subsystem (`Crawler`, `PassiveAnalyzer`, `ActiveAnalyzer`, `DomainVerificationService`) via a clean `/api/v1/scans` and `/api/v1/findings` REST surface in `@veltrix/backend`. Wire `@veltrix/frontend` to these live endpoints with interactive verification challenge modals, profile-aware scan dispatching, and evidence viewers, replacing client-side mock datasets while strictly enforcing the domain ownership scan gate.

**Tech Stack:** Express, TypeScript, Zod, React 18, React Query v5, Tailwind CSS, Lucide React, Vitest, React Testing Library.

**Spec Reference:** Phase 8 Architecture Specs (`docs/phase-8-vulnerability-assessment-architecture.md`, TASK-801 through TASK-805), and Backend Routes in `backend/src/routes/websites.ts`.

## Global Constraints

- **Zero Unverified Scanning:** Scans against domains with `scanBlocked === true` or status not in `['VERIFIED']` must be rejected with HTTP 403 `SCAN_UNAUTHORIZED_UNVERIFIED_DOMAIN`.
- **No Mock State in Production Paths:** `ScansPage` and `FindingsPage` must fetch real data through `@tanstack/react-query` adapters instead of hardcoded component state.
- **Strict Evidence Transparency:** Findings must display full evidence payloads (`targetUrl`, `responseStatus`, `responseHeaders`, `responseBodySnippet`, `matchedPattern`, `confidence`).
- **All Quality Gates Must Pass:** `npm run typecheck` across all workspaces and `vitest run` must pass with zero errors.

## Review Focus

1. **Unverified Scan Attempt:** A user attempts to launch a scan on an unverified site. Expected: Launch button is disabled with tooltip or API returns 403 and UI displays an actionable "Verify Domain First" prompt.
2. **Active Probe Profile Gating:** A user selects `FULL_AUDIT` vs `PASSIVE_BASELINE`. Expected: Active probes (SQLi, XSS, Path Traversal) are only scheduled if consent is verified; passive profile only runs TLS, headers, cookies, disclosures.
3. **Domain Verification Token Copy:** User clicks copy button for DNS TXT, HTTP Challenge, or Meta Tag. Expected: Correct challenge payload is copied to clipboard with visual checkmark feedback.
4. **Scan Progress & Abort:** Scan is running in background. Expected: UI displays current stage (`DISCOVERY`, `CRAWL`, `PASSIVE_EVALUATION`, `ACTIVE_PROBING`, `REPORT_GENERATION`) and user can abort safely.
5. **Finding Detail Evidence Reproduction:** User views finding detail. Expected: Shows curl command reproduction and exact response body snippet containing the vulnerability evidence.

---

### Task 1: Backend Scans & Findings REST API Router

**Files:**
- Create: `backend/src/routes/scans.ts`
- Create: `backend/src/routes/findings.ts`
- Modify: `backend/src/app.ts:100-110`
- Test: `backend/tests/scans-api.test.ts`

**Interfaces:**
- Consumes: `DomainVerificationService.isScanAuthorized`, `getStorage`, `PassiveAnalyzer`, `ActiveAnalyzer`, `Crawler`
- Produces: 
  - `POST /api/v1/scans` (body: `{ siteId: string, profile: 'PASSIVE_BASELINE' | 'STANDARD_ACTIVE' | 'FULL_AUDIT', maxDepth?: number, maxPages?: number }`)
  - `GET /api/v1/scans` (query: `siteId?: string, status?: string`)
  - `GET /api/v1/scans/:scanId`
  - `POST /api/v1/scans/:scanId/abort`
  - `GET /api/v1/findings` (query: `siteId?: string, severity?: string, confidence?: string`)
  - `GET /api/v1/findings/:findingId`

- [ ] **Step 1: Write the failing backend integration test**
  Write `backend/tests/scans-api.test.ts` asserting:
  - `POST /api/v1/scans` returns 403 `SCAN_UNAUTHORIZED_UNVERIFIED_DOMAIN` for unverified website.
  - `POST /api/v1/scans` succeeds with 201 for verified website and returns `scanId`, `status: 'RUNNING'`, and `profile`.
  - `GET /api/v1/scans` lists tenant scan jobs.
  - `GET /api/v1/findings` returns normalized findings list with `ruleId`, `confidence`, and `evidence`.

- [ ] **Step 2: Run test to verify it fails**
  Run: `npm --prefix backend test -- scans-api.test.ts`
  Expected: FAIL (routes `/api/v1/scans` not implemented / 404).

- [ ] **Step 3: Implement `scans.ts` and `findings.ts` routers**
  - Implement `createScansRouter()` in `backend/src/routes/scans.ts` with tenant isolation and domain verification gate check.
  - Implement `createFindingsRouter()` in `backend/src/routes/findings.ts`.
  - Register `/api/v1/scans` and `/api/v1/findings` in `backend/src/app.ts`.

- [ ] **Step 4: Run test to verify it passes**
  Run: `npm --prefix backend test -- scans-api.test.ts`
  Expected: PASS.

- [ ] **Step 5: Commit**
  ```bash
  git -C Veltrix add backend/src/routes/scans.ts backend/src/routes/findings.ts backend/src/app.ts backend/tests/scans-api.test.ts
  git -C Veltrix commit -m "feat(backend): implement scans and findings REST API routes with domain verification gating"
  ```

---

### Task 2: Frontend API Client Adapters for Scans, Findings & Verification

**Files:**
- Modify: `frontend/src/lib/api/types.ts`
- Modify: `frontend/src/lib/api/endpoints.ts`
- Test: `frontend/tests/scans-api-adapter.test.ts`

**Interfaces:**
- Consumes: `@veltrix/shared`, Backend `/api/v1/websites`, `/api/v1/scans`, `/api/v1/findings`
- Produces:
  - `verifyDomain(siteId: string, method: 'DNS_TXT' | 'HTTP_CHALLENGE' | 'META_TAG'): Promise<DomainVerifyResponse>`
  - `fetchScanAuthorization(siteId: string): Promise<ScanAuthResponse>`
  - `revokeDomainVerification(siteId: string, reason?: string): Promise<void>`
  - `fetchScans(params?: { siteId?: string }): Promise<ScanJob[]>`
  - `createScan(input: CreateScanInput): Promise<ScanJob>`
  - `abortScan(scanId: string): Promise<void>`
  - `fetchFindings(params?: { siteId?: string, severity?: string }): Promise<FindingDetail[]>`
  - `fetchWebsiteTimeline(siteId: string): Promise<WebsiteTimelineItem[]>`

- [ ] **Step 1: Write the failing frontend adapter test**
  Write `frontend/tests/scans-api-adapter.test.ts` asserting that `verifyDomain`, `fetchScanAuthorization`, `fetchScans`, `createScan`, and `fetchFindings` properly call typed endpoints and normalize response envelopes.

- [ ] **Step 2: Run test to verify it fails**
  Run: `npm --prefix frontend test -- scans-api-adapter.test.ts`
  Expected: FAIL with missing functions.

- [ ] **Step 3: Implement typed endpoint functions**
  Add the verification, scans, findings, and timeline API functions in `frontend/src/lib/api/endpoints.ts` and define contract types in `frontend/src/lib/api/types.ts`.

- [ ] **Step 4: Run test to verify it passes**
  Run: `npm --prefix frontend test -- scans-api-adapter.test.ts`
  Expected: PASS.

- [ ] **Step 5: Commit**
  ```bash
  git -C Veltrix add frontend/src/lib/api/types.ts frontend/src/lib/api/endpoints.ts frontend/tests/scans-api-adapter.test.ts
  git -C Veltrix commit -m "feat(frontend): implement typed api adapters for domain verification, scans, and findings"
  ```

---

### Task 3: Interactive Domain Verification Modal & Card

**Files:**
- Create: `frontend/src/components/DomainVerificationModal.tsx`
- Modify: `frontend/src/pages/WebsiteDetailPage.tsx`
- Modify: `frontend/src/components/WebsiteInventory.tsx`
- Test: `frontend/tests/domain-verification-ui.test.tsx`

**Interfaces:**
- Consumes: `verifyDomain`, `fetchScanAuthorization`, `revokeDomainVerification`, `WebsiteAsset`
- Produces: React component `DomainVerificationModal` and enhanced `WebsiteDetailPage`

- [ ] **Step 1: Write the failing UI component test**
  Write `frontend/tests/domain-verification-ui.test.tsx` testing:
  - Renders DNS TXT challenge record tab with copy button.
  - Renders HTTP challenge file path and content tab.
  - Renders Meta tag tab.
  - Triggers `verifyDomain` with selected method and shows success badge when verified.
  - Displays error toast when verification fails (e.g. DNS record not propagated).

- [ ] **Step 2: Run test to verify it fails**
  Run: `npm --prefix frontend test -- domain-verification-ui.test.tsx`
  Expected: FAIL.

- [ ] **Step 3: Implement `DomainVerificationModal` and wire into `WebsiteDetailPage`**
  - Build `DomainVerificationModal` with 3 tabbed challenge views, syntax highlight boxes, 1-click clipboard copy, and interactive "Verify Ownership" trigger.
  - Add "Verify Domain" action pill in `WebsiteInventory.tsx` and header button in `WebsiteDetailPage.tsx`.
  - Add live `scan-authorization` status badge showing whether active probes are unlocked.

- [ ] **Step 4: Run test to verify it passes**
  Run: `npm --prefix frontend test -- domain-verification-ui.test.tsx`
  Expected: PASS.

- [ ] **Step 5: Commit**
  ```bash
  git -C Veltrix add frontend/src/components/DomainVerificationModal.tsx frontend/src/pages/WebsiteDetailPage.tsx frontend/src/components/WebsiteInventory.tsx frontend/tests/domain-verification-ui.test.tsx
  git -C Veltrix commit -m "feat(frontend): add interactive domain verification modal and scan authorization indicator"
  ```

---

### Task 4: Live Vulnerability Scans Orchestration Screen

**Files:**
- Modify: `frontend/src/pages/ScansPage.tsx`
- Test: `frontend/tests/scans-page.test.tsx`

**Interfaces:**
- Consumes: `fetchScans`, `createScan`, `abortScan`, `fetchWebsites`
- Produces: Updated `ScansPage` component wired to backend API

- [ ] **Step 1: Write the failing ScansPage component test**
  Write `frontend/tests/scans-page.test.tsx` asserting:
  - Renders scan jobs from backend query (`PASSIVE_BASELINE`, `STANDARD_ACTIVE`, `FULL_AUDIT`).
  - Opens "Launch Vulnerability Scan" modal.
  - Unverified websites show "Domain Verification Required" warning and disable the launch button.
  - Verified websites can launch scans with selected profile and crawl depth.
  - Running scans allow aborting via `abortScan`.

- [ ] **Step 2: Run test to verify it fails**
  Run: `npm --prefix frontend test -- scans-page.test.tsx`
  Expected: FAIL.

- [ ] **Step 3: Refactor `ScansPage.tsx` with live query hooks and verification gate**
  - Replace `DEFAULT_DEMO_SCANS` with `useQuery({ queryKey: ['scans'], queryFn: fetchScans })`.
  - Add `useMutation` for `createScan` and `abortScan`.
  - Enforce domain verification check in launch modal: show verification warning if target site is unverified.
  - Display scan stages (`DISCOVERY`, `CRAWL`, `PASSIVE_EVALUATION`, `ACTIVE_PROBING`, `REPORT_GENERATION`).

- [ ] **Step 4: Run test to verify it passes**
  Run: `npm --prefix frontend test -- scans-page.test.tsx`
  Expected: PASS.

- [ ] **Step 5: Commit**
  ```bash
  git -C Veltrix add frontend/src/pages/ScansPage.tsx frontend/tests/scans-page.test.tsx
  git -C Veltrix commit -m "feat(frontend): wire ScansPage to live backend scanner with verification gating"
  ```

---

### Task 5: Live Findings Evidence Catalog & Reproduction View

**Files:**
- Modify: `frontend/src/pages/FindingsPage.tsx`
- Test: `frontend/tests/findings-page.test.tsx`

**Interfaces:**
- Consumes: `fetchFindings`, `ScannerFinding`, `FindingDetail`
- Produces: Updated `FindingsPage` with real evidence inspector

- [ ] **Step 1: Write the failing FindingsPage component test**
  Write `frontend/tests/findings-page.test.tsx` asserting:
  - Renders findings from `fetchFindings`.
  - Displays Phase 8 Rule badges (`RULE_PASSIVE_TLS`, `RULE_PASSIVE_HEADERS`, `RULE_ACTIVE_XSS_CANARY`, `RULE_ACTIVE_SQLI_ANOMALY`).
  - Displays confidence indicators (`CONFIRMED`, `HIGH`, `MEDIUM`, `LOW`).
  - Detail drawer shows curl reproduction command and response body snippet.

- [ ] **Step 2: Run test to verify it fails**
  Run: `npm --prefix frontend test -- findings-page.test.tsx`
  Expected: FAIL.

- [ ] **Step 3: Refactor `FindingsPage.tsx` with live backend query and evidence drawer**
  - Replace `DEFAULT_FINDINGS` with `useQuery({ queryKey: ['findings'], queryFn: fetchFindings })`.
  - Render evidence inspector: response headers, matched pattern highlight, and generated curl command.
  - Add filters for vulnerability type (`SQL_INJECTION`, `XSS`, `INSECURE_TLS`, `MISSING_HEADERS`, etc.) and severity.

- [ ] **Step 4: Run test to verify it passes**
  Run: `npm --prefix frontend test -- findings-page.test.tsx`
  Expected: PASS.

- [ ] **Step 5: Commit**
  ```bash
  git -C Veltrix add frontend/src/pages/FindingsPage.tsx frontend/tests/findings-page.test.tsx
  git -C Veltrix commit -m "feat(frontend): wire FindingsPage to live backend findings with evidence viewer"
  ```

---

### Task 6: Interactive Website Attack Timeline

**Files:**
- Modify: `frontend/src/pages/WebsiteDetailPage.tsx`
- Test: `frontend/tests/website-timeline.test.tsx`

**Interfaces:**
- Consumes: `fetchWebsiteTimeline(siteId)`
- Produces: Visual attack kill-chain timeline on `WebsiteDetailPage`

- [ ] **Step 1: Write the failing Timeline test**
  Write `frontend/tests/website-timeline.test.tsx` verifying:
  - Fetches and displays chronological attack attempts from `GET /api/v1/websites/:siteId/timeline`.
  - Differentiates Detection events vs Correlated Incidents with timeline badges and source IPs.

- [ ] **Step 2: Run test to verify it fails**
  Run: `npm --prefix frontend test -- website-timeline.test.tsx`
  Expected: FAIL.

- [ ] **Step 3: Implement Visual Timeline in `WebsiteDetailPage.tsx`**
  - Add `useQuery` for `fetchWebsiteTimeline(siteId)`.
  - Render vertical stepped timeline with icons for recon, probe, and attack sequence stages.

- [ ] **Step 4: Run test to verify it passes**
  Run: `npm --prefix frontend test -- website-timeline.test.tsx`
  Expected: PASS.

- [ ] **Step 5: Commit**
  ```bash
  git -C Veltrix add frontend/src/pages/WebsiteDetailPage.tsx frontend/tests/website-timeline.test.tsx
  git -C Veltrix commit -m "feat(frontend): render live chronological attack timeline on website detail page"
  ```

---

### Task 7: Full Monorepo Quality Gate Verification

**Files:**
- Monorepo root check

- [ ] **Step 1: Run full typecheck across all workspaces**
  Run: `npm --prefix Veltrix run typecheck`
  Expected: 0 errors across `@veltrix/backend`, `@veltrix/frontend`, `@veltrix/shared`, `@veltrix/cli`.

- [ ] **Step 2: Run backend test suites**
  Run: `npm --prefix Veltrix/backend test`
  Expected: All backend tests pass.

- [ ] **Step 3: Run frontend test suites**
  Run: `npm --prefix Veltrix/frontend test`
  Expected: All frontend tests pass.

- [ ] **Step 4: Push to feature branch**
  Run: `git -C Veltrix push origin feature/soc-console-and-cli`

