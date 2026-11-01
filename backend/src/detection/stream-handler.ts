import { unmarshall } from '@aws-sdk/util-dynamodb';
import type { AttributeValue } from '@aws-sdk/client-dynamodb';
import type { SecurityEvent } from '@veltrix/shared';
import { getDetectionPipeline } from './pipeline.js';

export interface DynamoDBStreamRecord {
  eventName?: 'INSERT' | 'MODIFY' | 'REMOVE';
  dynamodb?: {
    NewImage?: Record<string, AttributeValue>;
    ApproximateCreationDateTime?: number;
    Keys?: Record<string, AttributeValue>;
  };
}

export interface DynamoDBStreamEvent {
  Records: DynamoDBStreamRecord[];
}

export interface BatchItemFailure {
  itemIdentifier: string;
}

export interface StreamHandlerResponse {
  batchItemFailures: BatchItemFailure[];
}

/**
 * AWS Lambda Event Source Mapping handler for DynamoDB Streams.
 * Receives INSERT stream records from Veltrix-SecurityEvents-${Environment},
 * transforms them into normalized SecurityEvents, and triggers automatic threat detection.
 * Returns partial batch failures (batchItemFailures) to enable DynamoDB stream checkpointing.
 */
export async function handleSecurityEventStream(
  event: DynamoDBStreamEvent
): Promise<StreamHandlerResponse> {
  const pipeline = getDetectionPipeline();
  const batchItemFailures: BatchItemFailure[] = [];

  for (let i = 0; i < event.Records.length; i++) {
    const record = event.Records[i];
    if (!record) continue;

    // Only process newly inserted event records
    if (record.eventName !== 'INSERT' || !record.dynamodb?.NewImage) {
      continue;
    }

    try {
      const rawItem = unmarshall(record.dynamodb.NewImage as Record<string, any>);

      // Only process primary event records (ignore secondary pointer or idempotency rows)
      if (!rawItem.PK?.startsWith('ORG#') || !rawItem.SK?.startsWith('EVENT#')) {
        continue;
      }

      const securityEvent: SecurityEvent = {
        eventId: rawItem.eventId,
        orgId: rawItem.orgId,
        category: rawItem.category || 'AUTHENTICATION',
        eventType: rawItem.eventType,
        severity: rawItem.severity,
        timestamp: rawItem.timestamp,
        sourceIp: rawItem.sourceIp,
        username: rawItem.username,
        sourceSystem: rawItem.sourceSystem,
        metadata: rawItem.metadata,
        idempotencyKey: rawItem.idempotencyKey,
              };

      await pipeline.processEvent(securityEvent);
    } catch (err) {
      console.error(`[VELTRIX-STREAM] Error processing stream record ${i}:`, err);
      // Report partial failure to DynamoDB stream consumer
      batchItemFailures.push({
        itemIdentifier: String(i),
      });
    }
  }

  return { batchItemFailures };
}
