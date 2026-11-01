# @veltrix/sdk-node

Official Node.js SDK and Express middleware for the **VELTRIX Autonomous Cybersecurity Platform**.

## Key Features
- **Zero Runtime Disruption:** Operates strictly asynchronously; never delays or blocks normal host request/response processing.
- **Fail-Open Policy:** If the VELTRIX API is unreachable, host applications serve user requests completely unaffected.
- **Bounded In-Memory Ring Buffer:** Default 500 events / 5MB memory ceiling with drop-oldest overflow policy.
- **Automatic Exponential Backoff:** Re-transmits transient failures with randomized jitter and stable idempotency keys.
- **Sensitive Data Redaction:** Automatically sanitizes passwords, session tokens, authorization headers, and API keys.

## Installation
```bash
npm install @veltrix/sdk-node
```

## Quickstart (Express Middleware)
```typescript
import express from 'express';
import { VeltrixClient, veltrixMiddleware } from '@veltrix/sdk-node';

const app = express();

const veltrix = new VeltrixClient({
  apiKey: process.env.VELTRIX_API_KEY!,
  orgId: process.env.VELTRIX_ORG_ID!,
  siteId: 'site-ecommerce-prod',
  endpoint: 'https://api.veltrix.io',
});

// Register middleware
app.use(veltrixMiddleware(veltrix));

app.get('/api/products', (req, res) => {
  res.json({ products: [] });
});

app.listen(3000);
```
