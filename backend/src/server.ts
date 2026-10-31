import express, { Request, Response } from 'express';
import cors from 'cors';
import { MemoryStore } from './shared/db/memoryStore.js';
import { SecurityEventInputSchema, BatchSecurityEventInputSchema } from './ingestion/validator.js';
import { normalizeEvent } from './ingestion/normalizer.js';
import { DetectionEngine } from './detection/engine.js';
import { CorrelationEngine } from './correlation/engine.js';
import { ResponseEngine } from './response/handler.js';
import { AuditLogger } from './audit/integrityChain.js';
import { SimulationRunner } from './simulation/runner.js';
import { SecurityEvent, Incident } from './shared/types/index.js';

const app = express();
const port = process.env.PORT || 4000;

app.use(cors());
app.use(express.json());

// Initialize backend subsystems
const store = MemoryStore.getInstance();
const detectionEngine = new DetectionEngine();
const correlationEngine = new CorrelationEngine(store);
const auditLogger = new AuditLogger(store);
const responseEngine = new ResponseEngine(store, auditLogger);
const simulationRunner = new SimulationRunner(store, detectionEngine, correlationEngine, responseEngine);

// Tenant context middleware (Simulating Cognito JWT claim validation)
app.use((req, res, next) => {
  // In production, orgId is extracted directly from the verified Cognito JWT authorizer token
  const authHeader = req.headers.authorization;
  const orgHeader = req.headers['x-organization-id'] as string;
  (req as unknown as { orgId: string }).orgId = orgHeader || 'org-enterprise-01';
  next();
});

// ==========================================
// 1. Health & Status
// ==========================================
app.get('/api/v1/health', (req: Request, res: Response) => {
  res.json({
    status: 'HEALTHY',
    service: 'VELTRIX Security Intelligence Engine',
    version: '1.0.0',
    mode: 'SERVERLESS_LOCAL_ADAPTER',
    timestamp: new Date().toISOString(),
  });
});

// ==========================================
// 2. Security Events Ingestion API
// ==========================================
app.post('/api/v1/events', (req: Request, res: Response) => {
  try {
    const orgId = (req as unknown as { orgId: string }).orgId;
    let rawEvents = [];

    if (Array.isArray(req.body.events)) {
      const parsed = BatchSecurityEventInputSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ error: 'Schema validation error', details: parsed.error.issues });
      }
      rawEvents = parsed.data.events;
    } else {
      const parsed = SecurityEventInputSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ error: 'Schema validation error', details: parsed.error.issues });
      }
      rawEvents = [parsed.data];
    }

    const processedEvents: SecurityEvent[] = [];
    const triggeredDetections = [];
    const generatedIncidents: Incident[] = [];

    for (const raw of rawEvents) {
      const event = normalizeEvent(raw, orgId);

      // Check idempotency (duplicate prevention)
      const existing = Array.from(store.events.values()).find(e => e.idempotencyHash === event.idempotencyHash);
      if (existing) {
        continue; // Suppress duplicate
      }

      store.events.set(event.eventId, event);
      processedEvents.push(event);

      // Run detection engine
      const triggers = detectionEngine.evaluateEvent(event);
      for (const trig of triggers) {
        triggeredDetections.push(trig);
        store.triggers.push(trig);

        // Run correlation
        const incident = correlationEngine.correlateTrigger(trig, event);
        if (!generatedIncidents.some(i => i.incidentId === incident.incidentId)) {
          generatedIncidents.push(incident);
        }

        // Check automated defense policy
        if (incident.severity === 'CRITICAL' && incident.containmentStatus === 'NONE') {
          responseEngine.triggerResponse(incident, incident.recommendedResponse, 'AUTONOMOUS_POLICY');
        }
      }
    }

    res.status(202).json({
      success: true,
      ingestedCount: processedEvents.length,
      triggersFired: triggeredDetections.length,
      incidentsUpdated: generatedIncidents.length,
      events: processedEvents,
    });
  } catch (err) {
    res.status(500).json({ error: 'Internal ingestion error', message: String(err) });
  }
});

app.get('/api/v1/events', (req: Request, res: Response) => {
  const orgId = (req as unknown as { orgId: string }).orgId;
  const { eventType, sourceIp, username, limit = '100' } = req.query;

  let list = Array.from(store.events.values()).filter(e => e.orgId === orgId);

  if (eventType) {
    list = list.filter(e => e.eventType.includes(String(eventType)));
  }
  if (sourceIp) {
    list = list.filter(e => e.sourceIp.includes(String(sourceIp)));
  }
  if (username) {
    list = list.filter(e => e.username.includes(String(username)));
  }

  // Sort descending by timestamp
  list.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

  res.json({
    total: list.length,
    events: list.slice(0, parseInt(String(limit), 10)),
  });
});

// ==========================================
// 3. Threat Detection Rules API
// ==========================================
app.get('/api/v1/detection-rules', (req: Request, res: Response) => {
  res.json({
    rules: detectionEngine.getRules(),
  });
});

app.patch('/api/v1/detection-rules/:ruleId', (req: Request, res: Response) => {
  const ruleId = String(req.params.ruleId);
  const updated = detectionEngine.updateRule(ruleId, req.body);
  if (!updated) {
    return res.status(404).json({ error: `Rule ${ruleId} not found` });
  }
  res.json({ success: true, rule: updated });
});

// ==========================================
// 4. Incident Management API
// ==========================================
app.get('/api/v1/incidents', (req: Request, res: Response) => {
  const orgId = (req as unknown as { orgId: string }).orgId;
  const { status, severity } = req.query;

  let list = Array.from(store.incidents.values()).filter(i => i.orgId === orgId);

  if (status) {
    list = list.filter(i => i.status === status);
  }
  if (severity) {
    list = list.filter(i => i.severity === severity);
  }

  list.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());

  res.json({
    total: list.length,
    incidents: list,
  });
});

app.get('/api/v1/incidents/:incidentId', (req: Request, res: Response) => {
  const incidentId = String(req.params.incidentId);
  const incident = store.incidents.get(incidentId);
  if (!incident) {
    return res.status(404).json({ error: `Incident ${incidentId} not found` });
  }

  // Include correlated event details
  const correlatedEvents = incident.correlatedEventIds
    .map(id => store.events.get(id))
    .filter(Boolean);

  res.json({
    incident,
    correlatedEvents,
  });
});

app.patch('/api/v1/incidents/:incidentId', (req: Request, res: Response) => {
  const incidentId = String(req.params.incidentId);
  const incident = store.incidents.get(incidentId);
  if (!incident) {
    return res.status(404).json({ error: `Incident ${incidentId} not found` });
  }

  const { status, assignee, note } = req.body;
  if (status) incident.status = status;
  if (assignee !== undefined) incident.assignee = assignee;
  if (note) {
    incident.notes.push({
      author: 'Security Analyst',
      timestamp: new Date().toISOString(),
      content: note,
    });
  }
  incident.updatedAt = new Date().toISOString();

  auditLogger.log(
    incident.orgId,
    'ANALYST',
    'INCIDENT_UPDATED',
    `Incident:${incidentId}`,
    'SUCCESS',
    { status, assignee, noteAdded: Boolean(note) }
  );

  res.json({ success: true, incident });
});

// ==========================================
// 5. Threat Intelligence API
// ==========================================
app.get('/api/v1/threat-indicators', (req: Request, res: Response) => {
  res.json({
    indicators: Array.from(store.indicators.values()),
  });
});

app.post('/api/v1/threat-indicators/enrich', (req: Request, res: Response) => {
  const { ip } = req.body;
  const indicator = store.indicators.get(String(ip));
  res.json({
    ip,
    isFlagged: Boolean(indicator),
    indicator: indicator || null,
  });
});

// ==========================================
// 6. Response Center (SOAR) API
// ==========================================
app.get('/api/v1/responses/approvals', (req: Request, res: Response) => {
  const pending = Array.from(store.responseExecutions.values()).filter(r => r.status === 'PENDING_APPROVAL');
  res.json({ pendingApprovals: pending });
});

app.get('/api/v1/responses/history', (req: Request, res: Response) => {
  const executions = Array.from(store.responseExecutions.values());
  executions.sort((a, b) => new Date(b.executedAt || 0).getTime() - new Date(a.executedAt || 0).getTime());
  res.json({
    activeBlockedIps: Array.from(store.activeBlockedIps),
    suspendedUsers: Array.from(store.suspendedUsers),
    history: executions,
  });
});

app.post('/api/v1/responses/:incidentId/execute', (req: Request, res: Response) => {
  const incidentId = String(req.params.incidentId);
  const { action, actor = 'ANALYST_MANUAL' } = req.body;
  const incident = store.incidents.get(incidentId);
  if (!incident) {
    return res.status(404).json({ error: `Incident ${incidentId} not found` });
  }

  const result = responseEngine.triggerResponse(incident, action, actor, true);
  res.json({ success: true, execution: result, incident });
});

app.post('/api/v1/responses/approvals/:executionId/approve', (req: Request, res: Response) => {
  const executionId = String(req.params.executionId);
  const { analyst = 'Lead SOC Analyst' } = req.body;
  try {
    const executed = responseEngine.approveAction(executionId, analyst);
    res.json({ success: true, execution: executed });
  } catch (err) {
    res.status(400).json({ error: String(err) });
  }
});

app.post('/api/v1/responses/executions/:executionId/rollback', (req: Request, res: Response) => {
  const executionId = String(req.params.executionId);
  const { analyst = 'Lead SOC Analyst' } = req.body;
  try {
    const executed = responseEngine.rollbackAction(executionId, analyst);
    res.json({ success: true, execution: executed });
  } catch (err) {
    res.status(400).json({ error: String(err) });
  }
});

// ==========================================
// 7. Security Audit Trail API
// ==========================================
app.get('/api/v1/audit-logs', (req: Request, res: Response) => {
  const orgId = (req as unknown as { orgId: string }).orgId;
  const logs = store.auditLogs.filter(l => l.orgId === orgId);
  res.json({
    total: logs.length,
    logs: [...logs].reverse(),
  });
});

app.post('/api/v1/audit-logs/verify-chain', (req: Request, res: Response) => {
  const result = auditLogger.verifyChain();
  res.json(result);
});

// ==========================================
// 8. Analytics & Dashboard API
// ==========================================
app.get('/api/v1/analytics/overview', (req: Request, res: Response) => {
  const orgId = (req as unknown as { orgId: string }).orgId;
  const events = Array.from(store.events.values()).filter(e => e.orgId === orgId);
  const incidents = Array.from(store.incidents.values()).filter(i => i.orgId === orgId);
  const activeBlocked = Array.from(store.activeBlockedIps);

  const openIncidents = incidents.filter(i => i.status !== 'RESOLVED' && i.status !== 'FALSE_POSITIVE');
  const criticalIncidents = openIncidents.filter(i => i.severity === 'CRITICAL');

  // Severity counts
  const severityDistribution = {
    CRITICAL: incidents.filter(i => i.severity === 'CRITICAL').length,
    HIGH: incidents.filter(i => i.severity === 'HIGH').length,
    MEDIUM: incidents.filter(i => i.severity === 'MEDIUM').length,
    LOW: incidents.filter(i => i.severity === 'LOW').length,
  };

  // MITRE attack tactics frequency
  const mitreDistribution: Record<string, number> = {};
  for (const inc of incidents) {
    for (const step of inc.timeline) {
      mitreDistribution[step.phase] = (mitreDistribution[step.phase] || 0) + 1;
    }
  }

  // Failed vs Successful Logins
  const failedLogins = events.filter(e => e.eventType.includes('failed')).length;
  const successLogins = events.filter(e => e.eventType.includes('success')).length;

  res.json({
    totalEvents: events.length,
    threatsDetected: store.triggers.length,
    openIncidents: openIncidents.length,
    criticalIncidents: criticalIncidents.length,
    activeBlockedIps: activeBlocked.length,
    meanTimeToDetectMinutes: 1.2,
    meanTimeToRespondMinutes: 4.8,
    severityDistribution,
    mitreDistribution,
    authMetrics: {
      failed: failedLogins,
      success: successLogins,
    },
  });
});

// ==========================================
// 9. Simulation Lab API
// ==========================================
app.get('/api/v1/simulation/scenarios', (req: Request, res: Response) => {
  res.json({
    scenarios: simulationRunner.getScenarios(),
  });
});

app.post('/api/v1/simulation/execute', async (req: Request, res: Response) => {
  try {
    const { scenarioId } = req.body;
    const orgId = (req as unknown as { orgId: string }).orgId;
    const result = await simulationRunner.executeScenario(scenarioId, orgId);
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: String(err) });
  }
});

app.post('/api/v1/simulation/reset', (req: Request, res: Response) => {
  store.reset();
  res.json({ success: true, message: 'Platform state reset to pristine genesis state' });
});

// Only start the server when invoked directly (not during vitest import)
if (process.env.NODE_ENV !== 'test') {
  app.listen(port, () => {
    console.log(`[VELTRIX] Serverless SIEM/SOAR Engine running on http://localhost:${port}`);
    console.log(`[VELTRIX] Active Organization: org-enterprise-01 (CyberDefend Corp Global)`);
  });
}

export { app, store, detectionEngine, correlationEngine, responseEngine, auditLogger, simulationRunner };
