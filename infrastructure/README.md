# VELTRIX Cloud Infrastructure (`infrastructure/`)

This directory contains the AWS Serverless Application Model (SAM) definitions and CloudFormation resources for production and staging environments of VELTRIX.

## Overview
- **`template.yaml`**: SAM template defining Amazon DynamoDB on-demand tables with time-sharded partition keys, SQS FIFO queues for tamper-evident audit logging, and S3 Object Lock (WORM) archival buckets.
- **`samconfig.toml.example`**: Deployment configuration template for AWS SAM CLI.

## Deployment Mode Separation
- **Local Development / Offline Simulation (`STORAGE_MODE=memory`):**
  VELTRIX executes entirely in-memory using `MemoryStore` without connecting to AWS or requiring cloud credentials.
- **Cloud Deployment (`STORAGE_MODE=aws`):**
  Requires AWS CLI credentials and SAM CLI:
  ```bash
  sam build
  sam deploy --guided
  ```
