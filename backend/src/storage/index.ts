import type { StorageInterface } from './storage-interface.js';
import { MemoryStore } from './memory-store.js';
import { DynamoDBStore } from './dynamodb-store.js';

let storageInstance: StorageInterface | null = null;

export function getStorage(): StorageInterface {
  if (!storageInstance) {
    const mode = process.env.STORAGE_MODE || 'memory';
    if (mode === 'aws') {
      try {
        storageInstance = new DynamoDBStore();
      } catch (err) {
        console.warn(`[VELTRIX] Failed to initialize DynamoDBStore (${(err as Error).message}); falling back to MemoryStore.`);
        storageInstance = new MemoryStore();
      }
    } else {
      storageInstance = new MemoryStore();
    }
  }
  return storageInstance;
}

export function resetStorageForTesting(instance?: StorageInterface): void {
  storageInstance = instance || null;
}

export * from './storage-interface.js';
export * from './memory-store.js';
export * from './dynamodb-store.js';
