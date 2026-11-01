import type { SecurityEvent } from '@veltrix/shared';

export class RingBuffer {
  private queue: SecurityEvent[] = [];
  private maxItems: number;
  private maxBytes: number;
  private currentBytes = 0;
  private droppedCount = 0;
  private lastWarningTimestamp = 0;

  constructor(maxItems = 500, maxBytes = 5 * 1024 * 1024) {
    this.maxItems = maxItems;
    this.maxBytes = maxBytes;
  }

  push(event: SecurityEvent): boolean {
    const itemBytes = this.estimateSize(event);

    // If single item exceeds max buffer bytes, drop it immediately
    if (itemBytes > this.maxBytes) {
      this.droppedCount++;
      this.logWarning('Single telemetry event exceeded maximum buffer capacity; dropped.');
      return false;
    }

    // Drop oldest items if capacity or byte limit reached (drop-oldest overflow policy)
    while (
      this.queue.length >= this.maxItems ||
      (this.currentBytes + itemBytes > this.maxBytes && this.queue.length > 0)
    ) {
      const dropped = this.queue.shift();
      if (dropped) {
        this.currentBytes -= this.estimateSize(dropped);
        this.droppedCount++;
      }
    }

    this.queue.push(event);
    this.currentBytes += itemBytes;
    return true;
  }

  drain(count = 100): SecurityEvent[] {
    const items = this.queue.splice(0, count);
    for (const item of items) {
      this.currentBytes -= this.estimateSize(item);
    }
    if (this.currentBytes < 0) this.currentBytes = 0;
    return items;
  }

  size(): number {
    return this.queue.length;
  }

  getDroppedCount(): number {
    return this.droppedCount;
  }

  getCurrentBytes(): number {
    return this.currentBytes;
  }

  clear(): void {
    this.queue = [];
    this.currentBytes = 0;
  }

  private estimateSize(event: SecurityEvent): number {
    return (
      (event.eventId?.length || 36) +
      event.orgId.length +
      event.eventType.length +
      (event.sourceIp?.length || 15) +
      (event.sourceSystem?.length || 20) +
      (event.metadata ? JSON.stringify(event.metadata).length : 50) +
      100 // baseline overhead
    );
  }

  private logWarning(msg: string): void {
    const now = Date.now();
    // Rate limit warnings to at most once per 10 seconds
    if (now - this.lastWarningTimestamp > 10000) {
      this.lastWarningTimestamp = now;
      console.warn(`[VELTRIX-SDK-BUFFER] ${msg} Total dropped: ${this.droppedCount}`);
    }
  }
}
