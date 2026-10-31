import type { StorageInterface } from './storage-interface.js';
import { MemoryStore } from './memory-store.js';

let storageInstance: StorageInterface | null = null;

export function getStorage(): StorageInterface {
  if (!storageInstance) {
    const mode = process.env.STORAGE_MODE || 'memory';
    if (mode === 'memory') {
      storageInstance = new MemoryStore();
    } else {
      // In Phase 3, AWS DynamoDB Adapter will be plugged in here
      console.warn(`[VELTRIX] Storage mode '${mode}' requested; defaulting to MemoryStore for Phase 2.`);
      storageInstance = new MemoryStore();
    }
  }
  return storageInstance;
}

export function resetStorageForTesting(): void {
  storageInstance = null;
}

export * from './storage-interface.js';
export * from './memory-store.js';
