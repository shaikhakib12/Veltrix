import dotenv from 'dotenv';
import { createApp } from './app.js';
import { initializeDefaultInternalEvidenceAuthority } from './detection/evidence-authority.js';

dotenv.config();

const port = process.env.PORT || 4000;

async function bootstrap(): Promise<void> {
  try {
    // Asynchronously initialize internal evidence authority and load secrets
    await initializeDefaultInternalEvidenceAuthority();
  } catch (err) {
    console.error('[VELTRIX] Fatal error initializing internal evidence authority:', err);
    if (process.env.NODE_ENV === 'production') {
      process.exit(1);
    }
  }

  const app = createApp();

  app.listen(port, () => {
    console.log(`[VELTRIX] Backend API running at http://localhost:${port}`);
    console.log(`[VELTRIX] Storage mode: ${process.env.STORAGE_MODE || 'memory'}`);
  });
}

void bootstrap();
