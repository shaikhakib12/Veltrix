# VELTRIX Steering: AWS Conventions
**Category:** Cloud Infrastructure & Serverless Best Practices  
**Scope:** AWS SAM, CloudFormation, Lambda, DynamoDB, Cognito, EventBridge  

## 1. Serverless-First Principles
- No EC2 instances, containers, or provisioned clusters. All compute runs on AWS Lambda.
- DynamoDB billing mode is `PAY_PER_REQUEST` (On-Demand capacity) to guarantee zero idle cost.
- TTL (Time-to-Live) enabled on `Veltrix-SecurityEvents` (30 days), `Veltrix-Incidents` (90 days), and `Veltrix-ResponseExecutions` (60 days) to prevent unbounded storage costs.

## 2. Infrastructure as Code (IaC)
- Manage all AWS resources via AWS SAM (`template.yaml`).
- Parameterize region, environment (`dev`, `staging`, `prod`), and tenant tier.
- Use explicit resource naming with the project prefix: `Veltrix-<ResourceName>-<Stage>`.

## 3. Least Privilege IAM
- Every Lambda function has an independent IAM execution role.
- Prohibit wildcard (`*`) resource actions. Scope permissions strictly to target table ARNs, event bus ARNs, or state machine ARNs.

## 4. Structured Observability
- All Lambdas log in structured JSON (`timestamp`, `level`, `requestId`, `orgId`, `action`, `message`).
- Trace requests using AWS X-Ray where feasible.
