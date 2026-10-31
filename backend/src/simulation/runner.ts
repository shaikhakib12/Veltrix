import { 
  SimulationExecutionResult, 
  SecurityEvent, 
  DetectionTrigger, 
  Incident 
} from '../shared/types/index.js';
import { SIMULATION_SCENARIOS } from './scenarios.js';
import { normalizeEvent } from '../ingestion/normalizer.js';
import { DetectionEngine } from '../detection/engine.js';
import { CorrelationEngine } from '../correlation/engine.js';
import { ResponseEngine } from '../response/handler.js';
import { MemoryStore } from '../shared/db/memoryStore.js';
import { AuditLogger } from '../audit/integrityChain.js';

export class SimulationRunner {
  private store: MemoryStore;
  private detectionEngine: DetectionEngine;
  private correlationEngine: CorrelationEngine;
  private responseEngine: ResponseEngine;
  private auditLogger: AuditLogger;

  constructor(
    store?: MemoryStore,
    detectionEngine?: DetectionEngine,
    correlationEngine?: CorrelationEngine,
    responseEngine?: ResponseEngine
  ) {
    this.store = store || MemoryStore.getInstance();
    this.detectionEngine = detectionEngine || new DetectionEngine();
    this.correlationEngine = correlationEngine || new CorrelationEngine(this.store);
    this.auditLogger = new AuditLogger(this.store);
    this.responseEngine = responseEngine || new ResponseEngine(this.store, this.auditLogger);
  }

  public getScenarios() {
    return SIMULATION_SCENARIOS;
  }

  public async executeScenario(
    scenarioId: string, 
    orgId: string = 'org-enterprise-01'
  ): Promise<SimulationExecutionResult> {
    const startTime = Date.now();
    const scenario = SIMULATION_SCENARIOS.find(s => s.id === scenarioId);
    if (!scenario) {
      throw new Error(`Simulation scenario ${scenarioId} not found`);
    }

    const generatedEvents: SecurityEvent[] = [];
    const triggeredRules: string[] = [];
    let lastCorrelatedIncident: Incident | undefined;

    // Generate raw inputs based on scenario type
    const rawInputs = this.generateTelemetryForScenario(scenario, orgId);

    // Feed through real detection & correlation pipeline
    for (const raw of rawInputs) {
      const normalized = normalizeEvent(raw, orgId);
      this.store.events.set(normalized.eventId, normalized);
      generatedEvents.push(normalized);

      // 1. Detection
      const triggers: DetectionTrigger[] = this.detectionEngine.evaluateEvent(normalized);

      // 2. Correlation & Incident Creation
      for (const trig of triggers) {
        if (!triggeredRules.includes(trig.ruleName)) {
          triggeredRules.push(trig.ruleName);
        }
        this.store.triggers.push(trig);

        const incident = this.correlationEngine.correlateTrigger(trig, normalized);
        lastCorrelatedIncident = incident;

        // 3. Automated Response Evaluation
        if (incident.severity === 'CRITICAL' && incident.containmentStatus === 'NONE') {
          this.responseEngine.triggerResponse(
            incident, 
            incident.recommendedResponse, 
            'AUTONOMOUS_SOAR_POLICY'
          );
        }
      }
    }

    const durationMs = Date.now() - startTime;

    this.auditLogger.log(
      orgId,
      'SIMULATION_RUNNER',
      'SCENARIO_EXECUTED',
      `Scenario:${scenario.id}`,
      'SUCCESS',
      {
        scenarioId: scenario.id,
        eventsGenerated: generatedEvents.length,
        triggersFired: triggeredRules.length,
        incidentId: lastCorrelatedIncident?.incidentId,
        riskScore: lastCorrelatedIncident?.riskScore || 0,
      }
    );

    return {
      scenarioId: scenario.id,
      status: 'COMPLETED',
      injectedEventsCount: generatedEvents.length,
      triggeredRules,
      correlatedIncidentId: lastCorrelatedIncident?.incidentId,
      riskScore: lastCorrelatedIncident?.riskScore || 0,
      durationMs,
      events: generatedEvents,
    };
  }

  private generateTelemetryForScenario(scenario: typeof SIMULATION_SCENARIOS[0], orgId: string) {
    const now = new Date();
    const inputs = [];

    switch (scenario.id) {
      case 'sim-brute-force':
        for (let i = 0; i < 6; i++) {
          const t = new Date(now.getTime() - (6 - i) * 15000).toISOString();
          inputs.push({
            orgId,
            timestamp: t,
            eventType: 'auth.login.failed',
            severity: 'MEDIUM' as const,
            category: 'AUTHENTICATION' as const,
            sourceIp: scenario.attackerIp,
            username: scenario.targetUser,
            sourceSystem: 'auth.prod.internal',
            metadata: { userAgent: 'Hydra/v9.5 (Kali-Linux)', failureReason: 'INVALID_CREDENTIALS', attemptNumber: i + 1 },
            isSimulated: true,
          });
        }
        break;

      case 'sim-impossible-travel':
        inputs.push({
          orgId,
          timestamp: new Date(now.getTime() - 120000).toISOString(),
          eventType: 'auth.login.success',
          severity: 'INFO' as const,
          category: 'AUTHENTICATION' as const,
          sourceIp: '185.220.101.5',
          username: scenario.targetUser,
          sourceSystem: 'sso.cloud.corp',
          metadata: { location: 'Amsterdam, Netherlands', impossibleTravel: false },
          isSimulated: true,
        });
        inputs.push({
          orgId,
          timestamp: new Date(now.getTime()).toISOString(),
          eventType: 'auth.login.success',
          severity: 'HIGH' as const,
          category: 'AUTHENTICATION' as const,
          sourceIp: '133.242.18.99',
          username: scenario.targetUser,
          sourceSystem: 'sso.cloud.corp',
          metadata: { 
            location: 'Tokyo, Japan', 
            impossibleTravel: true, 
            distanceKm: 9289, 
            deltaMinutes: 2 
          },
          isSimulated: true,
        });
        break;

      case 'sim-account-takeover-chain':
        // Step 1: 5 Failed Logins (Brute Force)
        for (let i = 0; i < 5; i++) {
          inputs.push({
            orgId,
            timestamp: new Date(now.getTime() - (10 - i) * 30000).toISOString(),
            eventType: 'auth.login.failed',
            severity: 'MEDIUM' as const,
            category: 'AUTHENTICATION' as const,
            sourceIp: scenario.attackerIp,
            username: scenario.targetUser,
            sourceSystem: 'auth.portal.corp',
            metadata: { userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', reason: 'BAD_PASSWORD' },
            isSimulated: true,
          });
        }
        // Step 2: Successful Login (Valid Account Compromise)
        inputs.push({
          orgId,
          timestamp: new Date(now.getTime() - 4 * 30000).toISOString(),
          eventType: 'auth.login.success',
          severity: 'HIGH' as const,
          category: 'AUTHENTICATION' as const,
          sourceIp: scenario.attackerIp,
          username: scenario.targetUser,
          sourceSystem: 'auth.portal.corp',
          metadata: { authMethod: 'PASSWORD_ONLY', mfaBypassed: false },
          isSimulated: true,
        });
        // Step 3: Privilege Escalation (IAM role assumption)
        inputs.push({
          orgId,
          timestamp: new Date(now.getTime() - 2 * 30000).toISOString(),
          eventType: 'iam.privilege.escalation.attempt',
          severity: 'HIGH' as const,
          category: 'PRIVILEGE' as const,
          sourceIp: scenario.attackerIp,
          username: scenario.targetUser,
          sourceSystem: 'iam.aws.amazon.com',
          metadata: { targetRole: 'arn:aws:iam::123456789012:role/AdministratorAccess', status: 'DENIED' },
          isSimulated: true,
        });
        // Step 4: Bulk Data Exfiltration
        inputs.push({
          orgId,
          timestamp: new Date(now.getTime() - 10000).toISOString(),
          eventType: 'data.exfiltration.bulk.query',
          severity: 'CRITICAL' as const,
          category: 'DATA_ACCESS' as const,
          sourceIp: scenario.attackerIp,
          username: scenario.targetUser,
          sourceSystem: 'db.aurora.internal',
          metadata: { 
            table: 'customer_pii_vault', 
            recordsExtracted: 15420, 
            bytesTransferred: 48500200, 
            destination: 'external-drop.darknet' 
          },
          isSimulated: true,
        });
        break;

      case 'sim-privilege-escalation':
        for (let i = 0; i < 3; i++) {
          inputs.push({
            orgId,
            timestamp: new Date(now.getTime() - (3 - i) * 20000).toISOString(),
            eventType: 'iam.privilege.escalation.attempt',
            severity: 'HIGH' as const,
            category: 'PRIVILEGE' as const,
            sourceIp: scenario.attackerIp,
            username: scenario.targetUser,
            sourceSystem: 'iam.aws.amazon.com',
            metadata: { targetRole: 'SecurityLeadRole', requestedAction: 'iam:AttachUserPolicy' },
            isSimulated: true,
          });
        }
        break;

      case 'sim-data-exfiltration':
        inputs.push({
          orgId,
          timestamp: new Date(now.getTime() - 40000).toISOString(),
          eventType: 'data.exfiltration.s3.sync',
          severity: 'CRITICAL' as const,
          category: 'DATA_ACCESS' as const,
          sourceIp: scenario.attackerIp,
          username: scenario.targetUser,
          sourceSystem: 's3.us-east-1.amazonaws.com',
          metadata: { 
            bucketName: 'enterprise-financial-ledgers-prod', 
            filesDownloaded: 412, 
            totalSizeMB: 2840 
          },
          isSimulated: true,
        });
        break;

      case 'sim-api-burst-dos':
        for (let i = 0; i < 12; i++) {
          inputs.push({
            orgId,
            timestamp: new Date(now.getTime() - (12 - i) * 3000).toISOString(),
            eventType: 'api.rate_limit.exceeded',
            severity: 'MEDIUM' as const,
            category: 'API' as const,
            sourceIp: scenario.attackerIp,
            username: scenario.targetUser,
            sourceSystem: 'apigw.prod.gateway',
            metadata: { endpoint: '/api/v1/customer/search', httpStatus: 429, burstCount: (i + 1) * 15 },
            isSimulated: true,
          });
        }
        break;

      default:
        break;
    }

    return inputs;
  }
}
