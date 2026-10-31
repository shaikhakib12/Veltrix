import dotenv from 'dotenv';
import { createApp } from './app.js';

dotenv.config();

const port = process.env.PORT || 4000;
const app = createApp();

app.listen(port, () => {
  console.log(`[VELTRIX] Backend API running at http://localhost:${port}`);
  console.log(`[VELTRIX] Storage mode: ${process.env.STORAGE_MODE || 'memory'}`);
});
