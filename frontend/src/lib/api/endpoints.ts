import type {
  ApiResponse,
  AuditLog,
  AuthSession,
  AuthUser,
  Detection,
  DetectionRule,
  Incident,
  Integration,
  ResponseExecution,
  SecurityEvent,
  Severity,
  ThreatIndicator,
  UserRole,
  WebsiteAsset,
} from '@veltrix/shared';
import { apiRequest, buildQuery } from './client';
import type {
  DashboardSummary,
  DemoSeedResult,
  RiskSummary,
  SiteTimeline,
} from './types';

// --- Authentication ---------------------------------------------------------

export async function login(email: string, password: string, orgId?: string) {
  return apiRequest<ApiResponse<AuthSession>>('/auth/login', {
    method: 'POST',
    auth: false,
    body: { email, password, orgId },
  });
}

export async function demoLogin(role: UserRole) {
  return apiRequest<ApiResponse<AuthSession>>('/auth/demo-login', {
    method: 'POST',
    auth: false,
    body: { role },
  });
}

export async function logout(refreshToken?: string) {
  return apiRequest<ApiResponse<{ message: string }>>('/auth/logout', {
    method: 'POST',
    body: refreshToken ? { refreshToken } : {},
  });
}

export async function fetchMe() {
  return apiRequest<ApiResponse<AuthUser>>('/auth/me');
}

// --- Dashboard --------------------------------------------------------------

export async function fetchDashboardSummary(rangeHours = 24) {
  return apiRequest<ApiResponse<DashboardSummary>>(
    `/dashboard/summary${buildQuery({ rangeHours })}`
  );
}

export async function seedDemoData() {
  return apiRequest<ApiResponse<DemoSeedResult>>('/demo/seed', { method: 'POST' });
}

// --- Security events --------------------------------------------------------

export interface EventQuery {
  limit?: number;
  cursor?: string;
  startTime?: string;
  endTime?: string;
  eventType?: string;
  severity?: Severity;
  sourceIp?: string;
  username?: string;
  sourceSystem?: string;
}

export async function fetchEvents(query: EventQuery = {}) {
  return apiRequest<
    ApiResponse<{ events: SecurityEvent[]; total: number; nextCursor?: string }>
  >(`/events${buildQuery(query)}`);
}

export async function fetchEvent(eventId: string) {
  return apiRequest<ApiResponse<SecurityEvent>>(`/events/${eventId}`);
}

// --- Detections & rules -----------------------------------------------------

export interface DetectionQuery {
  ruleId?: string;
  severity?: Severity;
  status?: 'ACTIVE' | 'RESOLVED' | 'SUPPRESSED';
  siteId?: string;
  startTime?: string;
  endTime?: string;
  limit?: number;
  cursor?: string;
}

export async function fetchDetections(query: DetectionQuery = {}) {
  return apiRequest<
    ApiResponse<{ items: Detection[]; nextCursor?: string; total?: number }>
  >(`/detections${buildQuery(query)}`);
}

export async function fetchWebDetections(siteId?: string, limit = 100) {
  return apiRequest<ApiResponse<{ items: Detection[]; total: number }>>(
    `/detections/web${buildQuery({ siteId, limit })}`
  );
}

export async function fetchDetection(detectionId: string) {
  return apiRequest<ApiResponse<Detection>>(`/detections/${detectionId}`);
}

export async function fetchDetectionEvidence(detectionId: string) {
  return apiRequest<
    ApiResponse<{
      detectionId: string;
      ruleId: string;
      ruleName: string;
      severity: Severity;
      confidence: number;
      detectedAt: string;
      evidence: Detection['evidence'];
    }>
  >(`/detections/${detectionId}/evidence`);
}

export async function runDetections(body: {
  startTime?: string;
  endTime?: string;
  ruleIds?: string[];
  limit?: number;
  persistDetections?: boolean;
}) {
  return apiRequest<ApiResponse<Record<string, unknown>>>('/detections/run', {
    method: 'POST',
    body,
  });
}

export async function fetchRules() {
  return apiRequest<ApiResponse<{ rules: DetectionRule[] }>>('/detection-rules');
}

export async function updateRule(
  ruleId: string,
  updates: Partial<
    Pick<DetectionRule, 'threshold' | 'slidingWindowSeconds' | 'severity' | 'isEnabled'>
  >
) {
  return apiRequest<ApiResponse<DetectionRule>>(`/detection-rules/${ruleId}`, {
    method: 'PATCH',
    body: updates,
  });
}

export async function testRule(body: {
  ruleId: string;
  threshold?: number;
  slidingWindowSeconds?: number;
  sampleEvents?: Array<Partial<SecurityEvent>>;
}) {
  return apiRequest<ApiResponse<Record<string, unknown>>>('/detection-rules/test', {
    method: 'POST',
    body,
  });
}

// --- Websites ---------------------------------------------------------------

interface WebsiteListResponse {
  success: boolean;
  total: number;
  sites: WebsiteAsset[];
}

export async function fetchWebsites(): Promise<{ total: number; sites: WebsiteAsset[] }> {
  const response = await apiRequest<WebsiteListResponse>('/websites');
  return { total: response.total ?? response.sites?.length ?? 0, sites: response.sites || [] };
}

export async function fetchWebsite(siteId: string) {
  return apiRequest<{ success: boolean; site: WebsiteAsset }>(`/websites/${siteId}`);
}

export async function createWebsite(data: {
  name: string;
  primaryDomain: string;
  approvedSubdomains?: string[];
  environment?: 'PRODUCTION' | 'STAGING' | 'DEVELOPMENT';
  riskTier?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  tags?: string[];
}) {
  return apiRequest<{ success: boolean; site: WebsiteAsset }>('/websites', {
    method: 'POST',
    body: data,
  });
}

export async function verifyDomainOwnership(
  siteId: string,
  method: 'DNS_TXT' | 'HTTP_CHALLENGE' | 'META_TAG'
) {
  return apiRequest<{
    success: boolean;
    verified: boolean;
    status?: string;
    verifiedAt?: string;
    expiresAt?: string;
    message: string;
  }>(`/websites/${siteId}/verify`, { method: 'POST', body: { method } });
}

export async function revokeDomainVerification(siteId: string, reason?: string) {
  return apiRequest<{ success: boolean; site: WebsiteAsset; message?: string }>(
    `/websites/${siteId}/revoke`,
    { method: 'POST', body: { reason } }
  );
}

export async function deleteWebsite(siteId: string) {
  return apiRequest<{ success: boolean }>(`/websites/${siteId}`, { method: 'DELETE' });
}

export async function fetchSiteRiskSummary(siteId: string) {
  return apiRequest<ApiResponse<RiskSummary>>(`/websites/${siteId}/risk-summary`);
}

export async function fetchSiteTimeline(siteId: string) {
  return apiRequest<ApiResponse<SiteTimeline>>(`/websites/${siteId}/timeline`);
}

// --- Integrations -----------------------------------------------------------

interface IntegrationListResponse {
  success: boolean;
  total: number;
  integrations: Integration[];
}

export async function fetchIntegrations() {
  const response = await apiRequest<IntegrationListResponse>('/integrations');
  return {
    total: response.total ?? response.integrations?.length ?? 0,
    integrations: response.integrations || [],
  };
}

export async function createIntegration(data: {
  name: string;
  type: string;
  siteId?: string;
  description?: string;
}) {
  const response = await apiRequest<{ success: boolean; integration: Integration; message?: string }>(
    '/integrations',
    { method: 'POST', body: data }
  );
  return { integration: response.integration, secretKey: response.integration.secretKey || '' };
}

export async function rotateIntegrationKey(integrationId: string) {
  const response = await apiRequest<{
    success: boolean;
    secretKey: string;
    apiKeyPrefix: string;
  }>(`/integrations/${integrationId}/rotate-key`, { method: 'POST' });
  return { secretKey: response.secretKey, apiKeyPrefix: response.apiKeyPrefix };
}

export async function revokeIntegration(integrationId: string) {
  const response = await apiRequest<{ success: boolean; integration: Integration }>(
    `/integrations/${integrationId}/revoke`,
    { method: 'POST' }
  );
  return response.integration;
}

export async function deleteIntegration(integrationId: string) {
  return apiRequest<{ success: boolean }>(`/integrations/${integrationId}`, {
    method: 'DELETE',
  });
}

// --- Incidents --------------------------------------------------------------

export interface IncidentQuery {
  status?: string;
  severity?: Severity;
  siteId?: string;
  limit?: number;
  cursor?: string;
}

export async function fetchIncidents(query: IncidentQuery = {}) {
  return apiRequest<
    ApiResponse<{ items: Incident[]; nextCursor?: string; total: number }>
  >(`/incidents${buildQuery(query)}`);
}

export async function fetchIncident(incidentId: string) {
  return apiRequest<ApiResponse<Incident>>(`/incidents/${incidentId}`);
}

export async function updateIncident(
  incidentId: string,
  updates: { status?: string; assignedTo?: string; note?: string }
) {
  return apiRequest<ApiResponse<Incident>>(`/incidents/${incidentId}`, {
    method: 'PATCH',
    body: updates,
  });
}

// --- Threat intelligence ----------------------------------------------------

export async function fetchIndicators(limit = 100) {
  return apiRequest<ApiResponse<{ indicators: ThreatIndicator[] }>>(
    `/threat-indicators${buildQuery({ limit })}`
  );
}

export async function createIndicator(data: {
  type: 'IP' | 'DOMAIN' | 'HASH' | 'USER_AGENT';
  value: string;
  threatType: string;
  severity: Severity;
  confidence: number;
  description?: string;
}) {
  return apiRequest<ApiResponse<ThreatIndicator>>('/threat-indicators', {
    method: 'POST',
    body: data,
  });
}

// --- Response queue ---------------------------------------------------------

export interface ResponseQueue {
  executions: ResponseExecution[];
  total: number;
  counts: Record<string, number>;
}

export async function fetchResponseQueue(incidentId?: string) {
  const response = await apiRequest<ApiResponse<ResponseQueue>>(
    `/response${buildQuery({ incidentId })}`
  );
  return response.data;
}

export async function approveExecution(executionId: string) {
  const response = await apiRequest<ApiResponse<ResponseExecution>>(
    `/response/${executionId}/approve`,
    { method: 'POST' }
  );
  return response.data;
}

export async function rejectExecution(executionId: string) {
  const response = await apiRequest<ApiResponse<ResponseExecution>>(
    `/response/${executionId}/reject`,
    { method: 'POST' }
  );
  return response.data;
}

export async function rollbackExecution(executionId: string) {
  const response = await apiRequest<ApiResponse<ResponseExecution>>(
    `/response/${executionId}/rollback`,
    { method: 'POST' }
  );
  return response.data;
}

// --- Audit ledger -----------------------------------------------------------

export interface AuditLedger {
  entries: AuditLog[];
  total: number;
  chain: { verified: boolean; length: number; brokenRecordId?: string };
}

export async function fetchAuditLedger(limit = 200) {
  const response = await apiRequest<ApiResponse<AuditLedger>>(
    `/audit${buildQuery({ limit })}`
  );
  return response.data;
}

// --- Platform ---------------------------------------------------------------

export async function fetchPlatformStatus() {
  return apiRequest<
    ApiResponse<{
      platform: { name: string; tagline: string; version: string };
      storageMode: string;
      environment: string;
      uptimeSeconds: number;
    }>
  >('/status', { auth: false });
}

// --- Domain Verification (Phase 8) -------------------------------------------

export const verifyDomain = verifyDomainOwnership;

export async function fetchScanAuthorization(siteId: string) {
  const response = await apiRequest<ApiResponse<import('./types').ScanAuthResult>>(
    `/websites/${siteId}/scan-authorization`
  );
  return response.data;
}

// --- Vulnerability Scans (Phase 8) -------------------------------------------

export async function fetchScans(params?: { siteId?: string; status?: string }) {
  const response = await apiRequest<ApiResponse<{ items: import('./types').ScanJob[]; total: number }>>(
    `/scans${buildQuery(params || {})}`
  );
  return response.data.items;
}

export async function createScan(input: import('./types').CreateScanInput) {
  const response = await apiRequest<ApiResponse<import('./types').ScanJob>>('/scans', {
    method: 'POST',
    body: input,
  });
  return response.data;
}

export async function abortScan(scanId: string) {
  const response = await apiRequest<ApiResponse<import('./types').ScanJob>>(
    `/scans/${scanId}/abort`,
    { method: 'POST' }
  );
  return response.data;
}

// --- Vulnerability Findings (Phase 8) ----------------------------------------

export async function fetchFindings(params?: {
  siteId?: string;
  severity?: string;
  confidence?: string;
}) {
  const response = await apiRequest<
    ApiResponse<{ items: import('./types').FindingDetail[]; total: number }>
  >(`/findings${buildQuery(params || {})}`);
  return response.data.items;
}

export async function fetchFinding(findingId: string) {
  const response = await apiRequest<ApiResponse<import('./types').FindingDetail>>(
    `/findings/${findingId}`
  );
  return response.data;
}

// --- Website Timeline (Phase 7 & 8) ------------------------------------------

export async function fetchWebsiteTimeline(siteId: string) {
  const response = await apiRequest<ApiResponse<import('./types').SiteTimeline>>(
    `/websites/${siteId}/timeline`
  );
  return response.data;
}
