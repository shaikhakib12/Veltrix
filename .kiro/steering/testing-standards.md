# VELTRIX Steering: Testing Standards
**Category:** Quality Assurance & Test Automation  
**Scope:** Vitest, Playwright, Backend Unit/Integration, Frontend E2E  

## 1. Test Pyramid & Tooling
- **Unit Testing:** Vitest for lightning-fast TypeScript unit tests across all backend domain logic (detection rules, risk scoring, correlation graph, deduplication).
- **Integration Testing:** Vitest integration tests against local mock DynamoDB and API Gateway handlers.
- **End-to-End (E2E) Testing:** Playwright for frontend user journeys, live simulation runs, and incident containment workflows.

## 2. Test Coverage & Critical Paths
- All 10 Sigma-inspired detection rules must have dedicated positive and negative unit test cases.
- Correlation sequences (e.g. Account Takeover) must be verified against synthetic event streams.
- Mathematical risk score calculation must be validated against precision tolerances.
- Cryptographic hash chaining must test both valid chains and intentionally tampered records to verify failure detection.

## 3. Mocking & Test Isolation
- Tests must execute independently without requiring an active AWS internet connection or live credentials.
- In-memory mock repositories and DynamoDB test doubles must strictly emulate AWS SDK v3 contracts.
