/**
 * VELTRIX API Client Service
 * Connects frontend to backend REST endpoints with reliable fallbacks
 */

import { 
  SecurityEvent, 
  DetectionRule, 
  Incident, 
  ThreatIndicator, 
  ResponseExecution, 
  AuditRecord, 
  AuditVerificationResult,
  SimulationScenario,
  SimulationExecutionResult
} from '../types/index.js';

const API_BASE = '/api/v1';

async function fetchJson<T>(url: string, options?: RequestInit): Promise<T> {
  const headers = {
    'Content-Type': 'application/json',
    'x-organization-id': 'org-enterprise-01',
    ...(options?.headers || {}),
  };

  const res = await fetch(`${API_BASE}${url}`, {
    ...options,
    headers,
  });

  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(`API Error [${res.status}]: ${errorText || res.statusText}`);
  }

  return res.json() as Promise<T>;
}

export const api = {
  // 1. Analytics & Overview
  getAnalyticsOverview: () => 
    fetchJson<{
      totalEvents: number;
      threatsDetected: number;
      openIncidents: number;
      criticalIncidents: number;
      activeBlockedIps: number;
      meanTimeToDetectMinutes: number;
      meanTimeToRespondMinutes: number;
      severityDistribution: Record<string, number>;
      mitreDistribution: Record<string, number>;
      authMetrics: { failed: number; success: number };
    }>('/analytics/overview'),

  // 2. Events Explorer
  getEvents: (params?: { eventType?: string; sourceIp?: string; username?: string; limit?: number }) => {
    const searchParams = new URLSearchParams();
    if (params?.eventType) searchParams.set('eventType', params.eventType);
    if (params?.sourceIp) searchParams.set('sourceIp', params.sourceIp);
    if (params?.username) searchParams.set('username', params.username);
    if (params?.limit) searchParams.set('limit', String(params.limit));
    return fetchJson<{ total: number; events: SecurityEvent[] }>(`/events?${searchParams.toString()}`);
  },

  // 3. Detection Rules
  getDetectionRules: () => 
    fetchJson<{ rules: DetectionRule[] }>('/detection-rules'),
  updateDetectionRule: (ruleId: string, updates: Partial<DetectionRule>) =>
    fetchJson<{ success: boolean; rule: DetectionRule }>(`/detection-rules/${ruleId}`, {
      method: 'PATCH',
      body: JSON.stringify(updates),
    }),

  // 4. Incidents
  getIncidents: (params?: { status?: string; severity?: string }) => {
    const searchParams = new URLSearchParams();
    if (params?.status) searchParams.set('status', params.status);
    if (params?.severity) searchParams.set('severity', params.severity);
    return fetchJson<{ total: number; incidents: Incident[] }>(`/incidents?${searchParams.toString()}`);
  },
  getIncidentById: (incidentId: string) =>
    fetchJson<{ incident: Incident; correlatedEvents: SecurityEvent[] }>(`/incidents/${incidentId}`),
  updateIncident: (incidentId: string, updates: { status?: string; assignee?: string; note?: string }) =>
    fetchJson<{ success: boolean; incident: Incident }>(`/incidents/${incidentId}`, {
      method: 'PATCH',
      body: JSON.stringify(updates),
    }),

  // 5. Threat Intelligence
  getThreatIndicators: () =>
    fetchJson<{ indicators: ThreatIndicator[] }>('/threat-indicators'),
  enrichIp: (ip: string) =>
    fetchJson<{ ip: string; isFlagged: boolean; indicator: ThreatIndicator | null }>('/threat-indicators/enrich', {
      method: 'POST',
      body: JSON.stringify({ ip }),
    }),

  // 6. Response Center (SOAR)
  getPendingApprovals: () =>
    fetchJson<{ pendingApprovals: ResponseExecution[] }>('/responses/approvals'),
  getResponseHistory: () =>
    fetchJson<{ activeBlockedIps: string[]; suspendedUsers: string[]; history: ResponseExecution[] }>('/responses/history'),
  executeResponse: (incidentId: string, action: string) =>
    fetchJson<{ success: boolean; execution: ResponseExecution; incident: Incident }>(`/responses/${incidentId}/execute`, {
      method: 'POST',
      body: JSON.stringify({ action }),
    }),
  approveResponse: (executionId: string, analyst: string = 'Alex Vance (Lead Analyst)') =>
    fetchJson<{ success: boolean; execution: ResponseExecution }>(`/responses/approvals/${executionId}/approve`, {
      method: 'POST',
      body: JSON.stringify({ analyst }),
    }),
  rollbackResponse: (executionId: string, analyst: string = 'Alex Vance (Lead Analyst)') =>
    fetchJson<{ success: boolean; execution: ResponseExecution }>(`/responses/executions/${executionId}/rollback`, {
      method: 'POST',
      body: JSON.stringify({ analyst }),
    }),

  // 7. Security Audit Trail
  getAuditLogs: () =>
    fetchJson<{ total: number; logs: AuditRecord[] }>('/audit-logs'),
  verifyAuditChain: () =>
    fetchJson<AuditVerificationResult>('/audit-logs/verify-chain', {
      method: 'POST',
    }),

  // 8. Simulation Lab
  getSimulationScenarios: () =>
    fetchJson<{ scenarios: SimulationScenario[] }>('/simulation/scenarios'),
  executeSimulation: (scenarioId: string) =>
    fetchJson<SimulationExecutionResult>('/simulation/execute', {
      method: 'POST',
      body: JSON.stringify({ scenarioId }),
    }),
  resetSimulation: () =>
    fetchJson<{ success: boolean; message: string }>('/simulation/reset', {
      method: 'POST',
    }),
};
