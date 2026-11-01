import type { StorageInterface } from '../../storage/storage-interface.js';
import { EventService } from '../event-service.js';
import { NginxLogParser } from './nginx-parser.js';
import { ApacheLogParser } from './apache-parser.js';
import type { LogParserContext, ParseBatchResult } from './base-parser.js';

export interface CollectorResult extends ParseBatchResult {
  ingestedCount: number;
}

export class LogCollectorService {
  private nginxParser: NginxLogParser;
  private apacheParser: ApacheLogParser;
  private eventService: EventService;
  private storage: StorageInterface;

  constructor(storage: StorageInterface) {
    this.storage = storage;
    this.nginxParser = new NginxLogParser();
    this.apacheParser = new ApacheLogParser();
    this.eventService = new EventService(storage);
  }

  async processLogStream(
    type: 'NGINX' | 'APACHE',
    rawLogs: string | string[],
    context: LogParserContext & { integrationId?: string }
  ): Promise<CollectorResult> {
    const parser = type === 'NGINX' ? this.nginxParser : this.apacheParser;
    const parseResult = parser.parseBatch(rawLogs, context);

    let ingestedCount = 0;

    if (parseResult.events.length > 0) {
      // Chunk events into batches of 100 for storage ingestion
      const batchSize = 100;
      for (let i = 0; i < parseResult.events.length; i += batchSize) {
        const chunk = parseResult.events.slice(i, i + batchSize);
        const result = await this.eventService.ingestBatchEvents(chunk, context.orgId);
        ingestedCount += result.accepted + result.duplicates;
      }
    }

    // Update integration health if integrationId provided
    if (context.integrationId) {
      const integration = await this.storage.getIntegrationById(context.orgId, context.integrationId);
      if (integration) {
        const nowIso = new Date().toISOString();
        const currentReceived = integration.health?.eventsReceived || 0;
        await this.storage.updateIntegration(context.orgId, context.integrationId, {
          lastSeenAt: nowIso,
          health: {
            status: parseResult.malformedCount > 0 && ingestedCount === 0 ? 'DEGRADED' : 'HEALTHY',
            eventsReceived: currentReceived + ingestedCount,
            lastSuccessAt: ingestedCount > 0 ? nowIso : integration.health?.lastSuccessAt,
            lastFailedAt: parseResult.malformedCount > 0 ? nowIso : integration.health?.lastFailedAt,
            lastError: parseResult.errors[0]?.error,
          },
        });
      }
    }

    return {
      ...parseResult,
      ingestedCount,
    };
  }
}
