# @veltrix/sdk-node

Official Node.js SDK and Express middleware for the **VELTRIX Unified Cybersecurity & Website Defense Platform**.

## Key Features
- **Zero Runtime Disruption:** Operates strictly asynchronously; never delays or blocks normal host request/response processing.
- **Fail-Open Policy:** If the VELTRIX API is unreachable, host applications serve user requests completely unaffected.
- **Bounded In-Memory Ring Buffer:** Default 500 events / 5MB memory ceiling with drop-oldest overflow policy.
- **Automatic Exponential Backoff:** Re-transmits transient failures with randomized jitter, Retry-After header compliance, and stable idempotency keys.
- **Sensitive Data Redaction:** Automatically sanitizes passwords, session tokens, authorization headers, cookies, and private API keys. Circular objects are gracefully handled without recursion overflow.

## Operational Reality & Delivery Guarantees
> [!IMPORTANT]
> The in-memory ring buffer prioritizes host web application performance and prevents memory leaks via a **drop-oldest** overflow policy.
>
> However, because telemetry events are buffered in host memory prior to asynchronous dispatch, sudden unhandled process crashes, hard container kills (`SIGKILL`), or node power failures can result in the loss of pending buffered events. VELTRIX **does not claim zero-loss delivery** for pure in-memory SDK buffering.
>
> Organizations requiring strict zero-loss persistence should deploy persistent log collector sidecars (e.g. Fluent Bit / Nginx / Apache log shippers) that read from persistent disk storage.

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
