import dotenv from 'dotenv';
import { createApp } from './app.js';
import { initializeDefaultInternalEvidenceAuthority } from './detection/evidence-authority.js';
import { seedDemoDataset } from './routes/demo.js';

dotenv.config();

// Resilience: Log unhandled errors without terminating the Node.js process
process.on('unhandledRejection', (reason) => {
  console.error('[VELTRIX] Unhandled Promise Rejection (suppressed):', reason);
});

process.on('uncaughtException', (err) => {
  console.error('[VELTRIX] Uncaught Exception (suppressed):', err);
});

const port = process.env.PORT || 4000;

async function bootstrap(): Promise<void> {
  try {
    // Asynchronously initialize internal evidence authority and load secrets
    await initializeDefaultInternalEvidenceAuthority();
  } catch (err) {
    console.error('[VELTRIX] Fatal error initializing internal evidence authority:', err);
    if (process.env.NODE_ENV === 'production' && !process.env.JWT_SECRET) {
      process.exit(1);
    }
  }

  // Pre-seed demo telemetry and assets in memory or evaluation environments
  const storageMode = process.env.STORAGE_MODE || 'memory';
  if (storageMode !== 'aws' || process.env.AUTO_SEED_DEMO === 'true') {
    try {
      await seedDemoDataset('org-enterprise-01');
      console.log('[VELTRIX] Pre-seeded demo dataset for evaluation tenant (org-enterprise-01)');
    } catch (err) {
      console.warn('[VELTRIX] Pre-seeding notice:', (err as Error).message);
    }
  }

  const app = createApp();

  app.listen(port, () => {
    console.log(`[VELTRIX] Backend API running at http://localhost:${port}`);
    console.log(`[VELTRIX] Storage mode: ${storageMode}`);
  });
}

void bootstrap();
