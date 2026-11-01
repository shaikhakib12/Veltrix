import type { SecurityEvent, Detection } from '@veltrix/shared';
import type { StorageInterface } from '../storage/storage-interface.js';
import { getStorage } from '../storage/index.js';
import { DetectionEngine } from './engine.js';
import { AttackCorrelationEngine } from '../correlation/engine.js';

export interface DetectionPipelineOptions {
  storage?: StorageInterface;
  engine?: DetectionEngine;
  correlationEngine?: AttackCorrelationEngine;
  maxWindowSeconds?: number;
  maxRetries?: number;
  retryDelayMs?: number;
}

export class DetectionPipeline {
  private storage: StorageInterface;
  private engine: DetectionEngine;
  private correlationEngine: AttackCorrelationEngine;
  private maxWindowSeconds: number;
  private maxRetries: number;
  private retryDelayMs: number;

  // In-memory async worker queue
  private queue: SecurityEvent[] = [];
  private isProcessing = false;
  private pendingResolvers: Array<() => void> = [];

  constructor(options?: DetectionPipelineOptions) {
    this.storage = options?.storage || getStorage();
    this.engine = options?.engine || new DetectionEngine(this.storage);
    this.correlationEngine =
      options?.correlationEngine || new AttackCorrelationEngine(this.storage);
    this.maxWindowSeconds = options?.maxWindowSeconds ?? 600; // 10 minutes covers all Sigma rules
    this.maxRetries = options?.maxRetries ?? 3;
    this.retryDelayMs = options?.retryDelayMs ?? 50;
  }

  getEngine(): DetectionEngine {
    return this.engine;
  }

  getCorrelationEngine(): AttackCorrelationEngine {
    return this.correlationEngine;
  }

  /**
   * Non-blocking dispatch of an ingested event to the asynchronous detection pipeline.
   * Ingestion HTTP response is NOT blocked and will never fail due to detection errors.
   */
  dispatch(event: SecurityEvent): void {
    this.queue.push(event);
    this.scheduleProcessing();
  }

  /**
   * Non-blocking batch dispatch.
   */
  dispatchBatch(events: SecurityEvent[]): void {
    for (const event of events) {
      this.queue.push(event);
    }
    this.scheduleProcessing();
  }

  /**
   * Schedules queue drain on the next event loop tick.
   */
  private scheduleProcessing(): void {
    if (this.isProcessing) return;
    setImmediate(() => {
      void this.processQueue();
    });
  }

  /**
   * Internal queue processor with bounded retries and error isolation.
   */
  private async processQueue(): Promise<void> {
    if (this.isProcessing) return;
    this.isProcessing = true;

    try {
      while (this.queue.length > 0) {
        const event = this.queue.shift();
        if (!event) continue;

        let attempt = 0;
        let success = false;

        while (attempt < this.maxRetries && !success) {
          try {
            await this.processEvent(event);
            success = true;
          } catch (err) {
            attempt++;
            console.error(
              `[VELTRIX-DETECTION] Pipeline processing error for event ${event.eventId} (attempt ${attempt}/${this.maxRetries}):`,
              err
            );
            if (attempt < this.maxRetries) {
              await new Promise((res) => setTimeout(res, this.retryDelayMs * Math.pow(2, attempt - 1)));
            }
          }
        }
      }
    } finally {
      this.isProcessing = false;
      // Notify any callers waiting on waitForIdle()
      while (this.pendingResolvers.length > 0) {
        const resolve = this.pendingResolvers.shift();
        if (resolve) resolve();
      }
      // If items arrived while winding down, trigger processing again
      if (this.queue.length > 0) {
        this.scheduleProcessing();
      }
    }
  }

  /**
   * Core processing method for an individual event.
   * Loads the sliding window history, evaluates rules, persists explainable detections,
   * and automatically triggers the Attack Correlation & Risk Scoring Engine.
   */
  async processEvent(event: SecurityEvent): Promise<Detection[]> {
    const orgId = event.orgId;
    const eventTimeMs = new Date(event.timestamp).getTime();
    const windowStart = new Date(eventTimeMs - this.maxWindowSeconds * 1000).toISOString();

    // 1. Fetch recent telemetry history within the sliding window
    let recentEvents: SecurityEvent[] = [];
    try {
      const history = await this.storage.getEvents(orgId, {
        startTime: windowStart,
        endTime: event.timestamp,
        limit: 200,
      });
      recentEvents = history.items;
    } catch (err) {
      console.warn(`[VELTRIX-DETECTION] Failed to query historical window events: ${(err as Error).message}`);
      recentEvents = [];
    }

    // Ensure the triggering event is in the evaluation batch
    if (!recentEvents.some((e) => e.eventId === event.eventId)) {
      recentEvents.push(event);
    }

    // 2. Evaluate all active detection rules
    const evalResult = await this.engine.evaluate(
      {
        organizationId: orgId,
        events: recentEvents,
        currentTime: new Date(event.timestamp),
      },
      {
        persistDetections: true,
      }
    );

    // 3. Automatically correlate detections into unified Incidents & compute risk scores (TASK-706, TASK-707)
    for (const detection of evalResult.detections) {
      try {
        await this.correlationEngine.correlateDetection(detection, recentEvents);
      } catch (err) {
        console.error(
          `[VELTRIX-CORRELATION] Error correlating detection ${detection.detectionId}:`,
          err
        );
      }
    }

    return evalResult.detections;
  }

  /**
   * Waits until the in-memory processing queue is empty and current tasks have settled.
   * Essential for deterministic integration and end-to-end tests.
   */
  async waitForIdle(): Promise<void> {
    if (!this.isProcessing && this.queue.length === 0) {
      return;
    }
    return new Promise<void>((resolve) => {
      this.pendingResolvers.push(resolve);
    });
  }

  /**
   * Returns current queue backlog count.
   */
  get queueLength(): number {
    return this.queue.length;
  }

  /**
   * Returns whether the pipeline worker is currently executing.
   */
  get active(): boolean {
    return this.isProcessing;
  }

  /**
   * Resets queue and correlation state for testing.
   */
  clear(): void {
    this.queue = [];
    this.isProcessing = false;
    this.pendingResolvers = [];
    this.correlationEngine.clear();
  }
}

// Global pipeline singleton instance
let pipelineInstance: DetectionPipeline | null = null;

export function getDetectionPipeline(): DetectionPipeline {
  if (!pipelineInstance) {
    pipelineInstance = new DetectionPipeline();
  }
  return pipelineInstance;
}

export function setDetectionPipelineForTesting(instance: DetectionPipeline | null): void {
  pipelineInstance = instance;
}
