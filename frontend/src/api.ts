import type { WebsiteAsset, Integration, Detection, Incident } from '@veltrix/shared';

let cachedToken: string | null = null;

export async function getAuthToken(): Promise<string> {
  if (cachedToken) return cachedToken;

  try {
    const res = await fetch('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'admin@cyberdefend.corp',
        password: 'OrgAdmin#2026!',
        orgId: 'org-enterprise-01',
      }),
    });

    if (res.ok) {
      const json = await res.json();
      cachedToken = json.data?.tokens?.accessToken || null;
      if (cachedToken) return cachedToken;
    }
  } catch {
    // Backend offline or unreachable
  }

  return '';
}

async function authFetch(url: string, init: RequestInit = {}): Promise<Response> {
  const token = await getAuthToken();
  const headers = new Headers(init.headers || {});
  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
  }
  headers.set('Content-Type', 'application/json');

  return fetch(url, {
    ...init,
    headers,
  });
}

// --- Website Assets API ---

export async function fetchWebsites(): Promise<{ total: number; sites: WebsiteAsset[] }> {
  const res = await authFetch('/api/v1/websites');
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error?.message || `Failed to fetch websites (HTTP ${res.status})`);
  }
  const json = await res.json();
  return { total: json.total || json.sites?.length || 0, sites: json.sites || [] };
}

export async function createWebsite(data: {
  name: string;
  primaryDomain: string;
  approvedSubdomains?: string[];
  environment?: 'PRODUCTION' | 'STAGING' | 'DEVELOPMENT';
  riskTier?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  tags?: string[];
}): Promise<WebsiteAsset> {
  const res = await authFetch('/api/v1/websites', {
    method: 'POST',
    body: JSON.stringify(data),
  });
  const json = await res.json();
  if (!res.ok) {
    throw new Error(json.error?.message || `Failed to create website (HTTP ${res.status})`);
  }
  return json.site;
}

export async function verifyDomainOwnership(
  siteId: string,
  method: 'DNS_TXT' | 'HTTP_CHALLENGE'
): Promise<{ verified: boolean; message: string; expiresAt?: string }> {
  const res = await authFetch(`/api/v1/websites/${siteId}/verify`, {
    method: 'POST',
    body: JSON.stringify({ method }),
  });
  const json = await res.json();
  if (!res.ok) {
    throw new Error(json.error?.message || `Verification failed (HTTP ${res.status})`);
  }
  return json;
}

export async function revokeDomainVerification(siteId: string, reason?: string): Promise<WebsiteAsset> {
  const res = await authFetch(`/api/v1/websites/${siteId}/revoke`, {
    method: 'POST',
    body: JSON.stringify({ reason }),
  });
  const json = await res.json();
  if (!res.ok) {
    throw new Error(json.error?.message || `Revocation failed (HTTP ${res.status})`);
  }
  return json.site;
}

export async function deleteWebsite(siteId: string): Promise<void> {
  const res = await authFetch(`/api/v1/websites/${siteId}`, {
    method: 'DELETE',
  });
  if (!res.ok) {
    const json = await res.json().catch(() => ({}));
    throw new Error(json.error?.message || `Failed to delete website (HTTP ${res.status})`);
  }
}

// --- Integrations API ---

export async function fetchIntegrations(): Promise<{ total: number; integrations: Integration[] }> {
  const res = await authFetch('/api/v1/integrations');
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error?.message || `Failed to fetch integrations (HTTP ${res.status})`);
  }
  const json = await res.json();
  return { total: json.total || json.integrations?.length || 0, integrations: json.integrations || [] };
}

export async function createIntegration(data: {
  name: string;
  type: string;
  siteId?: string;
  description?: string;
}): Promise<{ integration: Integration; secretKey: string }> {
  const res = await authFetch('/api/v1/integrations', {
    method: 'POST',
    body: JSON.stringify(data),
  });
  const json = await res.json();
  if (!res.ok) {
    throw new Error(json.error?.message || `Failed to create integration (HTTP ${res.status})`);
  }
  return { integration: json.integration, secretKey: json.integration.secretKey };
}

export async function rotateIntegrationKey(
  integrationId: string
): Promise<{ secretKey: string; apiKeyPrefix: string }> {
  const res = await authFetch(`/api/v1/integrations/${integrationId}/rotate-key`, {
    method: 'POST',
  });
  const json = await res.json();
  if (!res.ok) {
    throw new Error(json.error?.message || `Key rotation failed (HTTP ${res.status})`);
  }
  return { secretKey: json.secretKey, apiKeyPrefix: json.apiKeyPrefix };
}

export async function revokeIntegration(integrationId: string): Promise<Integration> {
  const res = await authFetch(`/api/v1/integrations/${integrationId}/revoke`, {
    method: 'POST',
  });
  const json = await res.json();
  if (!res.ok) {
    throw new Error(json.error?.message || `Revocation failed (HTTP ${res.status})`);
  }
  return json.integration;
}

export async function deleteIntegration(integrationId: string): Promise<void> {
  const res = await authFetch(`/api/v1/integrations/${integrationId}`, {
    method: 'DELETE',
  });
  if (!res.ok) {
    const json = await res.json().catch(() => ({}));
    throw new Error(json.error?.message || `Failed to delete integration (HTTP ${res.status})`);
  }
}

// --- Website Attack Monitoring API (TASK-701 to TASK-707) ---

export async function fetchWebDetections(siteId?: string): Promise<{ items: Detection[]; total: number }> {
  const url = siteId
    ? `/api/v1/websites/${siteId}/detections`
    : '/api/v1/detections/web';

  const res = await authFetch(url);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error?.message || `Failed to fetch detections (HTTP ${res.status})`);
  }
  const json = await res.json();
  return {
    items: json.data?.items || [],
    total: json.data?.total || json.data?.items?.length || 0,
  };
}

export async function fetchWebIncidents(siteId?: string): Promise<{ items: Incident[]; total: number }> {
  const url = siteId
    ? `/api/v1/websites/${siteId}/incidents`
    : '/api/v1/incidents';

  const res = await authFetch(url);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error?.message || `Failed to fetch incidents (HTTP ${res.status})`);
  }
  const json = await res.json();
  return {
    items: json.data?.items || [],
    total: json.data?.total || json.data?.items?.length || 0,
  };
}

export async function fetchSiteRiskSummary(siteId: string): Promise<{
  siteId: string;
  domain: string;
  environment: string;
  riskTier: string;
  currentRiskScore: number;
  currentRiskBand: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  factors: any;
  detectedAttackTypes: string[];
  totalIncidentsCount: number;
  totalDetectionsCount: number;
  latestIncidents: Incident[];
  latestDetections: Detection[];
}> {
  const res = await authFetch(`/api/v1/websites/${siteId}/risk-summary`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error?.message || `Failed to fetch risk summary (HTTP ${res.status})`);
  }
  const json = await res.json();
  return json.data;
}

export async function fetchSiteTimeline(siteId: string): Promise<{
  siteId: string;
  domain: string;
  items: Array<{
    timestamp: string;
    type: 'INCIDENT' | 'DETECTION';
    title: string;
    description: string;
    severity: string;
    sourceIp?: string;
    details?: Record<string, unknown>;
  }>;
  total: number;
}> {
  const res = await authFetch(`/api/v1/websites/${siteId}/timeline`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error?.message || `Failed to fetch timeline (HTTP ${res.status})`);
  }
  const json = await res.json();
  return json.data;
}

export async function updateIncidentStatus(
  incidentId: string,
  status: string,
  note?: string
): Promise<Incident> {
  const res = await authFetch(`/api/v1/incidents/${incidentId}`, {
    method: 'PATCH',
    body: JSON.stringify({ status, note }),
  });
  const json = await res.json();
  if (!res.ok) {
    throw new Error(json.error?.message || `Failed to update incident (HTTP ${res.status})`);
  }
  return json.data;
}
