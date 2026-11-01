import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import { createApp } from '../src/app.js';
import { JwtService } from '../src/auth/jwt-service.js';
import { LocalAuthProvider } from '../src/auth/local-auth-provider.js';
import { resetAuthProviderForTesting } from '../src/auth/index.js';
import { MemoryStore } from '../src/storage/memory-store.js';
import { resetStorageForTesting } from '../src/storage/index.js';
import {
  DetectionPipeline,
  getDetectionPipeline,
  setDetectionPipelineForTesting,
} from '../src/detection/pipeline.js';
import { DetectionEngine } from '../src/detection/engine.js';
import { EventService } from '../src/services/event-service.js';
import { generateUuidV7 } from '../src/utils/uuid.js';

describe('Phase 5: Automatic Event-to-Detection Pipeline (TASK-501 to TASK-505)', () => {
  let app: ReturnType<typeof createApp>;
  let jwtService: JwtService;
  let memoryStore: MemoryStore;
  let pipeline: DetectionPipeline;
  let engine: DetectionEngine;

  const testSecret = 'veltrix-phase-5-pipeline-jwt-secret-key-32c';
  const orgA = 'org-pipeline-alpha';
  const orgB = 'org-pipeline-beta';

  let analystTokenOrgA: string;
  let analystTokenOrgB: string;

  beforeEach(() => {
    jwtService = new JwtService(testSecret);
    const localProvider = new LocalAuthProvider(jwtService);
    resetAuthProviderForTesting(localProvider);

    memoryStore = new MemoryStore();
    resetStorageForTesting(memoryStore);

    engine = new DetectionEngine(memoryStore);
    pipeline = new DetectionPipeline({
      storage: memoryStore,
      engine,
      retryDelayMs: 10,
    });
    setDetectionPipelineForTesting(pipeline);

    app = createApp();

    analystTokenOrgA = jwtService.signAccessToken({
      userId: 'user-analyst-a',
      email: 'analyst@alpha.corp',
      username: 'analyst.alpha',
      role: 'SECURITY_ANALYST',
      orgId: orgA,
    });

    analystTokenOrgB = jwtService.signAccessToken({
      userId: 'user-analyst-b',
      email: 'analyst@beta.corp',
      username: 'analyst.beta',
      role: 'SECURITY_ANALYST',
      orgId: orgB,
    });
  });

  it('AUTOMATIC PIPELINE CRITICAL SCENARIO: Submitting 5 failed logins via ingestion API automatically creates brute-force detection without calling /run', async () => {
    const baseTime = Date.now();
    const sourceIp = '198.51.100.222';

    // 1. Submit 5 separate failed login events via the Phase 4 Event Ingestion API
    for (let i = 1; i <= 5; i++) {
      const res = await request(app)
        .post('/api/v1/events')
        .set('Authorization', `Bearer ${analystTokenOrgA}`)
        .send({
          category: 'AUTHENTICATION',
          eventType: 'auth.login.failed',
          severity: 'LOW',
          sourceIp,
          username: 'admin',
          sourceSystem: 'auth-gateway',
          timestamp: new Date(baseTime + i * 2000).toISOString(),
        });

      expect(res.status).toBe(202);
      expect(res.body.success).toBe(true);
      expect(res.body.data.status).toBe('ACCEPTED');
    }

    // 2. Wait for the asynchronous detection pipeline worker to finish processing
    await pipeline.waitForIdle();

    // 3. Query detections via GET /api/v1/detections (without calling /run!)
    const detectionsRes = await request(app)
      .get('/api/v1/detections')
      .set('Authorization', `Bearer ${analystTokenOrgA}`);

    expect(detectionsRes.status).toBe(200);
    expect(detectionsRes.body.success).toBe(true);
    expect(detectionsRes.body.data.items.length).toBeGreaterThanOrEqual(1);

    const bruteForceDetection = detectionsRes.body.data.items.find(
      (d: { ruleId: string }) => d.ruleId === 'RULE-001'
    );
    expect(bruteForceDetection).toBeDefined();
    expect(bruteForceDetection.severity).toBe('HIGH');
    expect(bruteForceDetection.evidence.targetEntity.value).toBe(sourceIp);
    expect(bruteForceDetection.evidence.actualCount).toBe(5);
  });

  it('AUTOMATIC PIPELINE BATCH: Ingesting a batch of spray events automatically triggers password-spray detection', async () => {
    const baseTime = Date.now();
    const sprayIp = '203.0.113.199';

    const batchEvents = ['victim1', 'victim2', 'victim3'].map((username, idx) => ({
      category: 'AUTHENTICATION',
      eventType: 'auth.login.failed',
      severity: 'LOW',
      sourceIp: sprayIp,
      username,
      sourceSystem: 'ad-fs',
      timestamp: new Date(baseTime + idx * 5000).toISOString(),
    }));

    const res = await request(app)
      .post('/api/v1/events')
      .set('Authorization', `Bearer ${analystTokenOrgA}`)
      .send({ events: batchEvents });

    expect(res.status).toBe(202);
    expect(res.body.data.accepted).toBe(3);

    // Wait for async pipeline
    await pipeline.waitForIdle();

    // Query detections
    const detectionsRes = await request(app)
      .get('/api/v1/detections?ruleId=RULE-002')
      .set('Authorization', `Bearer ${analystTokenOrgA}`);

    expect(detectionsRes.status).toBe(200);
    expect(detectionsRes.body.data.items.length).toBe(1);
    expect(detectionsRes.body.data.items[0].ruleId).toBe('RULE-002');
    expect(detectionsRes.body.data.items[0].evidence.targetEntity.value).toBe(sprayIp);
  });

  it('RESILIENCE & FAULT ISOLATION: Event ingestion succeeds even if the detection worker encounters transient errors', async () => {
    // Construct an event service where pipeline temporarily throws an error
    let failureCount = 0;
    const faultyPipeline = new DetectionPipeline({
      storage: memoryStore,
      engine,
      maxRetries: 3,
      retryDelayMs: 5,
    });

    const originalProcess = faultyPipeline.processEvent.bind(faultyPipeline);
    faultyPipeline.processEvent = async (ev) => {
      if (failureCount < 2) {
        failureCount++;
        throw new Error('Transient detection engine connection failure');
      }
      return originalProcess(ev);
    };

    const resilientEventService = new EventService(memoryStore, faultyPipeline);

    // Ingest event directly through resilient service
    const result = await resilientEventService.ingestSingleEvent(
      {
        category: 'PRIVILEGE',
        eventType: 'privilege.escalation',
        severity: 'CRITICAL',
        sourceIp: '10.0.0.9',
        username: 'intruder',
        sourceSystem: 'iam',
        metadata: { role: 'Administrator' },
      },
      orgA
    );

    // Ingestion succeeds immediately
    expect(result.status).toBe('ACCEPTED');

    // Wait for retry loop in pipeline to recover
    await faultyPipeline.waitForIdle();
    expect(failureCount).toBe(2);

    // Verify detection was eventually saved after retries
    const detections = await memoryStore.getDetections(orgA);
    expect(detections.items.length).toBe(1);
    expect(detections.items[0].ruleId).toBe('RULE-006');
  });

  it('IDEMPOTENT PIPELINE: Duplicate event submissions do not create duplicate detections', async () => {
    const baseTime = Date.now();
    const testEventId = generateUuidV7();
    const eventPayload = {
      eventId: testEventId,
      category: 'PRIVILEGE',
      eventType: 'privilege.escalation',
      severity: 'CRITICAL',
      sourceIp: '10.0.0.99',
      username: 'attacker',
      sourceSystem: 'iam',
      metadata: { role: 'Administrator' },
      timestamp: new Date(baseTime).toISOString(),
    };

    // First ingestion
    const res1 = await request(app)
      .post('/api/v1/events')
      .set('Authorization', `Bearer ${analystTokenOrgA}`)
      .send(eventPayload);
    expect(res1.status).toBe(202);

    await pipeline.waitForIdle();

    // Second ingestion with exact same payload (duplicate)
    const res2 = await request(app)
      .post('/api/v1/events')
      .set('Authorization', `Bearer ${analystTokenOrgA}`)
      .send(eventPayload);
    expect(res2.status).toBe(202);
    expect(res2.body.data.status).toBe('DUPLICATE_SUPPRESSED');

    await pipeline.waitForIdle();

    // Verify only 1 detection exists in storage
    const detections = await memoryStore.getDetections(orgA);
    expect(detections.items.length).toBe(1);
  });

  it('MULTI-TENANT PIPELINE ISOLATION: Pipeline segregates detections across distinct organizations', async () => {
    const baseTime = Date.now();

    // Ingest suspicious IP for Org A
    await request(app)
      .post('/api/v1/events')
      .set('Authorization', `Bearer ${analystTokenOrgA}`)
      .send({
        category: 'NETWORK',
        eventType: 'network.connection',
        severity: 'MEDIUM',
        sourceIp: '185.220.101.5',
        username: 'userA',
        sourceSystem: 'firewall',
        metadata: { isTorExitNode: true },
        timestamp: new Date(baseTime).toISOString(),
      });

    // Ingest suspicious IP for Org B
    await request(app)
      .post('/api/v1/events')
      .set('Authorization', `Bearer ${analystTokenOrgB}`)
      .send({
        category: 'NETWORK',
        eventType: 'network.connection',
        severity: 'MEDIUM',
        sourceIp: '185.220.101.5',
        username: 'userB',
        sourceSystem: 'firewall',
        metadata: { isTorExitNode: true },
        timestamp: new Date(baseTime).toISOString(),
      });

    await pipeline.waitForIdle();

    // Org A detections
    const resA = await request(app)
      .get('/api/v1/detections')
      .set('Authorization', `Bearer ${analystTokenOrgA}`);
    expect(resA.body.data.items.length).toBe(1);
    expect(resA.body.data.items[0].orgId).toBe(orgA);

    // Org B detections
    const resB = await request(app)
      .get('/api/v1/detections')
      .set('Authorization', `Bearer ${analystTokenOrgB}`);
    expect(resB.body.data.items.length).toBe(1);
    expect(resB.body.data.items[0].orgId).toBe(orgB);
  });
});
