# VELTRIX: Local Development & AWS Deployment Guide

---

## 1. Local Development Setup

### Prerequisites
- Node.js `v20.x` or higher (verified on Node `v24.18.0`)
- npm `v10.x` or higher
- Git

### Quickstart (Running Locally)
```bash
# 1. Clone repository
git clone https://github.com/veltrix-cyber/veltrix.git
cd veltrix

# 2. Install monorepo dependencies
npm install

# 3. Start Backend Intelligence Server (Port 4000)
npm run backend:dev

# 4. In a separate terminal, start Frontend SOC Console (Port 3000)
npm run frontend:dev
```
Open your browser to `http://localhost:3000` to interact with the VELTRIX Security Operations Center console.

### Running Test Suites
```bash
# Run all backend Vitest tests (17 unit & integration tests)
npm --prefix backend run test:run

# Verify TypeScript builds
npm run build
```

---

## 2. AWS Serverless Cloud Deployment

### Prerequisites
- AWS CLI configured with valid IAM credentials (`aws configure`)
- AWS SAM CLI installed (`sam --version`)

### Deployment Steps
```bash
# 1. Navigate to infrastructure directory
cd infrastructure

# 2. Build SAM application
sam build

# 3. Deploy guided stack to AWS
sam deploy --guided \
  --stack-name veltrix-platform-prod \
  --capabilities CAPABILITY_IAM CAPABILITY_AUTO_EXPAND
```

### Deployed Resources
- **Amazon API Gateway:** HTTPS endpoint for `/api/v1/events` and management APIs.
- **AWS Lambda:** Ingestion, Threat Detection, Correlation, and Audit execution.
- **Amazon DynamoDB:** `Veltrix-SecurityEvents`, `Veltrix-Incidents`, `Veltrix-AuditLogs`.
- **Amazon EventBridge:** `veltrix-event-bus` for asynchronous event routing.
- **AWS Step Functions:** SOAR state machine with human-in-the-loop task tokens.
- **Amazon Cognito:** User pool for analyst authentication and organization multi-tenancy.
