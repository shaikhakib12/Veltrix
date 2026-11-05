import { DynamoDBClient, CreateTableCommand, DescribeTableCommand } from '@aws-sdk/client-dynamodb';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load .env from Veltrix root
dotenv.config({ path: join(__dirname, '..', '.env') });

const region = process.env.AWS_REGION || 'us-east-1';
const accessKeyId = process.env.AWS_ACCESS_KEY_ID;
const secretAccessKey = process.env.AWS_SECRET_ACCESS_KEY;

if (!accessKeyId || !secretAccessKey) {
  console.error('\n❌ ERROR: AWS_ACCESS_KEY_ID aur AWS_SECRET_ACCESS_KEY .env file me nahi mile!');
  console.error('Kripya Veltrix/.env file me apni AWS keys daalein aur dobara chalayein.\n');
  process.exit(1);
}

const client = new DynamoDBClient({
  region,
  credentials: {
    accessKeyId,
    secretAccessKey,
  },
});

const env = process.env.ENVIRONMENT || 'dev';

const tables = [
  {
    TableName: `Veltrix-SecurityEvents-${env}`,
    KeySchema: [
      { AttributeName: 'PK', KeyType: 'HASH' },
      { AttributeName: 'SK', KeyType: 'RANGE' },
    ],
    AttributeDefinitions: [
      { AttributeName: 'PK', AttributeType: 'S' },
      { AttributeName: 'SK', AttributeType: 'S' },
      { AttributeName: 'GSI1_PK', AttributeType: 'S' },
      { AttributeName: 'GSI1_SK', AttributeType: 'S' },
      { AttributeName: 'GSI2_PK', AttributeType: 'S' },
      { AttributeName: 'GSI2_SK', AttributeType: 'S' },
    ],
    GlobalSecondaryIndexes: [
      {
        IndexName: 'GSI1-EventTypeIndex',
        KeySchema: [
          { AttributeName: 'GSI1_PK', KeyType: 'HASH' },
          { AttributeName: 'GSI1_SK', KeyType: 'RANGE' },
        ],
        Projection: { ProjectionType: 'ALL' },
      },
      {
        IndexName: 'GSI2-SourceIpIndex',
        KeySchema: [
          { AttributeName: 'GSI2_PK', KeyType: 'HASH' },
          { AttributeName: 'GSI2_SK', KeyType: 'RANGE' },
        ],
        Projection: { ProjectionType: 'ALL' },
      },
    ],
    BillingMode: 'PAY_PER_REQUEST',
  },
  {
    TableName: `Veltrix-Incidents-${env}`,
    KeySchema: [
      { AttributeName: 'PK', KeyType: 'HASH' },
      { AttributeName: 'SK', KeyType: 'RANGE' },
    ],
    AttributeDefinitions: [
      { AttributeName: 'PK', AttributeType: 'S' },
      { AttributeName: 'SK', AttributeType: 'S' },
      { AttributeName: 'GSI1_PK', AttributeType: 'S' },
      { AttributeName: 'GSI1_SK', AttributeType: 'N' },
      { AttributeName: 'GSI2_PK', AttributeType: 'S' },
      { AttributeName: 'GSI2_SK', AttributeType: 'S' },
    ],
    GlobalSecondaryIndexes: [
      {
        IndexName: 'GSI1-IncidentRiskIndex',
        KeySchema: [
          { AttributeName: 'GSI1_PK', KeyType: 'HASH' },
          { AttributeName: 'GSI1_SK', KeyType: 'RANGE' },
        ],
        Projection: { ProjectionType: 'ALL' },
      },
      {
        IndexName: 'GSI2-IncidentStatusIndex',
        KeySchema: [
          { AttributeName: 'GSI2_PK', KeyType: 'HASH' },
          { AttributeName: 'GSI2_SK', KeyType: 'RANGE' },
        ],
        Projection: { ProjectionType: 'ALL' },
      },
    ],
    BillingMode: 'PAY_PER_REQUEST',
  },
  {
    TableName: `Veltrix-DetectionRules-${env}`,
    KeySchema: [
      { AttributeName: 'PK', KeyType: 'HASH' },
      { AttributeName: 'SK', KeyType: 'RANGE' },
    ],
    AttributeDefinitions: [
      { AttributeName: 'PK', AttributeType: 'S' },
      { AttributeName: 'SK', AttributeType: 'S' },
      { AttributeName: 'GSI1_PK', AttributeType: 'S' },
      { AttributeName: 'GSI1_SK', AttributeType: 'S' },
    ],
    GlobalSecondaryIndexes: [
      {
        IndexName: 'GSI1-RuleSeverityIndex',
        KeySchema: [
          { AttributeName: 'GSI1_PK', KeyType: 'HASH' },
          { AttributeName: 'GSI1_SK', KeyType: 'RANGE' },
        ],
        Projection: { ProjectionType: 'ALL' },
      },
    ],
    BillingMode: 'PAY_PER_REQUEST',
  },
  {
    TableName: `Veltrix-ThreatIndicators-${env}`,
    KeySchema: [
      { AttributeName: 'PK', KeyType: 'HASH' },
      { AttributeName: 'SK', KeyType: 'RANGE' },
    ],
    AttributeDefinitions: [
      { AttributeName: 'PK', AttributeType: 'S' },
      { AttributeName: 'SK', AttributeType: 'S' },
      { AttributeName: 'GSI1_PK', AttributeType: 'S' },
      { AttributeName: 'GSI1_SK', AttributeType: 'N' },
    ],
    GlobalSecondaryIndexes: [
      {
        IndexName: 'GSI1-IndicatorConfidenceIndex',
        KeySchema: [
          { AttributeName: 'GSI1_PK', KeyType: 'HASH' },
          { AttributeName: 'GSI1_SK', KeyType: 'RANGE' },
        ],
        Projection: { ProjectionType: 'ALL' },
      },
    ],
    BillingMode: 'PAY_PER_REQUEST',
  },
  {
    TableName: `Veltrix-ResponseExecutions-${env}`,
    KeySchema: [
      { AttributeName: 'PK', KeyType: 'HASH' },
      { AttributeName: 'SK', KeyType: 'RANGE' },
    ],
    AttributeDefinitions: [
      { AttributeName: 'PK', AttributeType: 'S' },
      { AttributeName: 'SK', AttributeType: 'S' },
      { AttributeName: 'GSI1_PK', AttributeType: 'S' },
      { AttributeName: 'GSI1_SK', AttributeType: 'S' },
    ],
    GlobalSecondaryIndexes: [
      {
        IndexName: 'GSI1-ResponseStatusIndex',
        KeySchema: [
          { AttributeName: 'GSI1_PK', KeyType: 'HASH' },
          { AttributeName: 'GSI1_SK', KeyType: 'RANGE' },
        ],
        Projection: { ProjectionType: 'ALL' },
      },
    ],
    BillingMode: 'PAY_PER_REQUEST',
  },
  {
    TableName: `Veltrix-AuditLogs-${env}`,
    KeySchema: [
      { AttributeName: 'PK', KeyType: 'HASH' },
      { AttributeName: 'SK', KeyType: 'RANGE' },
    ],
    AttributeDefinitions: [
      { AttributeName: 'PK', AttributeType: 'S' },
      { AttributeName: 'SK', AttributeType: 'S' },
      { AttributeName: 'GSI1_PK', AttributeType: 'S' },
      { AttributeName: 'GSI1_SK', AttributeType: 'S' },
    ],
    GlobalSecondaryIndexes: [
      {
        IndexName: 'GSI1-ActionCategoryIndex',
        KeySchema: [
          { AttributeName: 'GSI1_PK', KeyType: 'HASH' },
          { AttributeName: 'GSI1_SK', KeyType: 'RANGE' },
        ],
        Projection: { ProjectionType: 'ALL' },
      },
    ],
    BillingMode: 'PAY_PER_REQUEST',
  },
  {
    TableName: `Veltrix-AuditState-${env}`,
    KeySchema: [
      { AttributeName: 'PK', KeyType: 'HASH' },
      { AttributeName: 'SK', KeyType: 'RANGE' },
    ],
    AttributeDefinitions: [
      { AttributeName: 'PK', AttributeType: 'S' },
      { AttributeName: 'SK', AttributeType: 'S' },
    ],
    BillingMode: 'PAY_PER_REQUEST',
  },
  {
    TableName: `Veltrix-Websites-${env}`,
    KeySchema: [
      { AttributeName: 'PK', KeyType: 'HASH' },
      { AttributeName: 'SK', KeyType: 'RANGE' },
    ],
    AttributeDefinitions: [
      { AttributeName: 'PK', AttributeType: 'S' },
      { AttributeName: 'SK', AttributeType: 'S' },
      { AttributeName: 'GSI1_PK', AttributeType: 'S' },
      { AttributeName: 'GSI1_SK', AttributeType: 'S' },
      { AttributeName: 'GSI2_PK', AttributeType: 'S' },
      { AttributeName: 'GSI2_SK', AttributeType: 'S' },
    ],
    GlobalSecondaryIndexes: [
      {
        IndexName: 'GSI1-DomainIndex',
        KeySchema: [
          { AttributeName: 'GSI1_PK', KeyType: 'HASH' },
          { AttributeName: 'GSI1_SK', KeyType: 'RANGE' },
        ],
        Projection: { ProjectionType: 'ALL' },
      },
      {
        IndexName: 'GSI2-StatusIndex',
        KeySchema: [
          { AttributeName: 'GSI2_PK', KeyType: 'HASH' },
          { AttributeName: 'GSI2_SK', KeyType: 'RANGE' },
        ],
        Projection: { ProjectionType: 'ALL' },
      },
    ],
    BillingMode: 'PAY_PER_REQUEST',
  },
  {
    TableName: `Veltrix-WebsiteAssets-${env}`,
    KeySchema: [
      { AttributeName: 'PK', KeyType: 'HASH' },
      { AttributeName: 'SK', KeyType: 'RANGE' },
    ],
    AttributeDefinitions: [
      { AttributeName: 'PK', AttributeType: 'S' },
      { AttributeName: 'SK', AttributeType: 'S' },
      { AttributeName: 'GSI1_PK', AttributeType: 'S' },
      { AttributeName: 'GSI1_SK', AttributeType: 'S' },
      { AttributeName: 'GSI2_PK', AttributeType: 'S' },
      { AttributeName: 'GSI2_SK', AttributeType: 'S' },
    ],
    GlobalSecondaryIndexes: [
      {
        IndexName: 'GSI1-DomainIndex',
        KeySchema: [
          { AttributeName: 'GSI1_PK', KeyType: 'HASH' },
          { AttributeName: 'GSI1_SK', KeyType: 'RANGE' },
        ],
        Projection: { ProjectionType: 'ALL' },
      },
      {
        IndexName: 'GSI2-StatusIndex',
        KeySchema: [
          { AttributeName: 'GSI2_PK', KeyType: 'HASH' },
          { AttributeName: 'GSI2_SK', KeyType: 'RANGE' },
        ],
        Projection: { ProjectionType: 'ALL' },
      },
    ],
    BillingMode: 'PAY_PER_REQUEST',
  },
  {
    TableName: `Veltrix-Integrations-${env}`,
    KeySchema: [
      { AttributeName: 'PK', KeyType: 'HASH' },
      { AttributeName: 'SK', KeyType: 'RANGE' },
    ],
    AttributeDefinitions: [
      { AttributeName: 'PK', AttributeType: 'S' },
      { AttributeName: 'SK', AttributeType: 'S' },
      { AttributeName: 'GSI1_PK', AttributeType: 'S' },
      { AttributeName: 'GSI1_SK', AttributeType: 'S' },
    ],
    GlobalSecondaryIndexes: [
      {
        IndexName: 'GSI1-SiteIntegrationIndex',
        KeySchema: [
          { AttributeName: 'GSI1_PK', KeyType: 'HASH' },
          { AttributeName: 'GSI1_SK', KeyType: 'RANGE' },
        ],
        Projection: { ProjectionType: 'ALL' },
      },
    ],
    BillingMode: 'PAY_PER_REQUEST',
  },
  {
    TableName: `Veltrix-EvidenceReplay-${env}`,
    KeySchema: [
      { AttributeName: 'PK', KeyType: 'HASH' },
      { AttributeName: 'SK', KeyType: 'RANGE' },
    ],
    AttributeDefinitions: [
      { AttributeName: 'PK', AttributeType: 'S' },
      { AttributeName: 'SK', AttributeType: 'S' },
    ],
    BillingMode: 'PAY_PER_REQUEST',
  },
];

async function createAllTables() {
  console.log(`\n🚀 Initializing AWS DynamoDB Tables in region: [${region}]...`);
  console.log(`Environment: [${env}]\n`);

  for (const tableConfig of tables) {
    try {
      process.stdout.write(`Creating table ${tableConfig.TableName}... `);
      await client.send(new CreateTableCommand(tableConfig));
      console.log('✅ Created successfully!');
    } catch (err) {
      if (err.name === 'ResourceInUseException') {
        console.log('⚠️ Already exists (Skipped)');
      } else {
        console.log(`❌ Failed: ${err.message}`);
      }
    }
  }

  console.log('\n✨ All DynamoDB permanent tables are ready in your AWS account!\n');
}

createAllTables().catch((err) => {
  console.error('Fatal error setting up DynamoDB:', err);
  process.exit(1);
});
