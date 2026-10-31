# VELTRIX: AWS Serverless Cost Optimization & Workload Analysis
**Document Version:** 1.0.0  
**Region:** AWS US East (N. Virginia, us-east-1)  
**Calculation Method:** Official AWS Pricing Calculator Assumptions  

---

## 1. Workload Assumptions

| Metric | Estimated Value | Notes |
| :--- | :--- | :--- |
| **Monthly Ingested Events** | 100,000 events/month | ~2.3 events/min average, burst capacity to 1,000 events/min |
| **Event Size** | 1.2 KB average | JSON normalized payload |
| **Active SOC Analysts** | 10 MAUs | Amazon Cognito User Pool |
| **Lambda Memory** | 256 MB ARM64 | Graviton2 processor for 20% cost reduction |
| **Average Execution Time**| 120 ms | Stateless event ingestion & rule evaluation |
| **DynamoDB Operations** | 100K Writes, 500K Reads | On-Demand (PAY_PER_REQUEST) capacity mode |
| **Storage Retention** | 30 days events, 90 days incidents | DynamoDB TTL automatically purges expired records |

---

## 2. Monthly Service Cost Breakdown

### 2.1 AWS Lambda
- Total compute: $100,000 \times 0.12\text{ s} = 12,000\text{ GB-seconds}$
- AWS Free Tier includes: 400,000 GB-seconds and 1,000,000 free requests per month.
- **Estimated Monthly Cost:** **$0.00**

### 2.2 Amazon API Gateway (HTTP/REST API)
- 120,000 API requests per month.
- 1,000,000 calls per month free for the first 12 months, then $1.00 / million.
- **Estimated Monthly Cost:** **$0.12**

### 2.3 Amazon DynamoDB
- Total storage: $< 1\text{ GB}$ (25 GB free forever).
- 100K Write Request Units (WRUs) + 500K Read Request Units (RRUs).
- Covered by AWS Free Tier (25 WRU and 25 RRU free provisioned capacity, or ~$0.25 on-demand).
- **Estimated Monthly Cost:** **$0.25**

### 2.4 Amazon EventBridge
- 100,000 custom events ingested.
- $1.00 per million events.
- **Estimated Monthly Cost:** **$0.10**

### 2.5 Amazon Cognito
- 10 Monthly Active Users (MAUs).
- First 50,000 MAUs are completely free.
- **Estimated Monthly Cost:** **$0.00**

### 2.6 AWS Step Functions
- ~100 state machine executions per month.
- First 4,000 state transitions per month are free.
- **Estimated Monthly Cost:** **$0.00**

### 2.7 Amazon CloudWatch & S3
- Log ingestion $< 2\text{ GB}$, custom metrics and basic archival.
- **Estimated Monthly Cost:** **$0.53**

---

## 3. Total Financial Summary

$$\text{Total Projected Monthly Cloud Cost} \approx \mathbf{\$1.00} \text{ / month}$$

> [!TIP]
> VELTRIX runs at near-zero operating cost while delivering enterprise-grade SIEM/SOAR capabilities, achieving 100% Free-Tier eligibility for development, hackathons, and competition demonstration workloads.
