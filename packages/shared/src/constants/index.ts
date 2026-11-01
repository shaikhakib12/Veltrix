/**
 * VELTRIX Shared Constants
 */

export const PLATFORM_INFO = {
  name: 'VELTRIX',
  tagline: 'Beyond Detection. Into Defense.',
  version: '1.0.0',
} as const;

export const EVENT_CATEGORIES = [
  'AUTHENTICATION',
  'NETWORK',
  'PRIVILEGE',
  'API',
  'DATA_ACCESS',
  'SYSTEM',
] as const;

export const SUPPORTED_EVENT_TYPES = [
  'auth.login.failed',
  'auth.login.success',
  'auth.logout',
  'auth.password.reset',
  'auth.mfa.failed',
  'network.connection',
  'network.port.scan',
  'network.dns.query',
  'privilege.escalation',
  'privilege.role.assumed',
  'privilege.policy.mutation',
  'api.request',
  'api.request.burst',
  'api.anomaly',
  'data.access',
  'data.access.bulk',
  'data.exfiltration',
  'system.process.spawn',
  'system.service.stop',
  'system.file.modify',
  'admin.action',
  'recon.account.probe',
  'web.request.normal',
  'web.attack.sqli',
  'web.attack.xss',
  'web.attack.traversal',
  'web.attack.bot',
  'web.attack.api_abuse',
  'auth.credential_stuffing',
] as const;

export const SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;

export const INCIDENT_STATUSES = [
  'NEW',
  'INVESTIGATING',
  'CONTAINED',
  'RESOLVED',
  'FALSE_POSITIVE',
] as const;

export const RESPONSE_ACTION_TYPES = [
  'BLOCK_IP',
  'SUSPEND_USER',
  'REVOKE_SESSION',
  'STEP_UP_AUTH',
  'ESCALATE_ALERT',
] as const;

export const RESPONSE_EXECUTION_STATUSES = [
  'PENDING_APPROVAL',
  'APPROVED',
  'EXECUTED',
  'FAILED',
  'ROLLED_BACK',
  'REJECTED',
] as const;

export const USER_ROLES = [
  'SUPER_ADMIN',
  'ORG_ADMIN',
  'SECURITY_ANALYST',
  'READ_ONLY_VIEWER',
  'AUDITOR',
] as const;

export const AUDIT_ACTION_TYPES = [
  'EVENT_INGESTED',
  'INCIDENT_CREATED',
  'INCIDENT_UPDATED',
  'RULE_MODIFIED',
  'RESPONSE_REQUESTED',
  'RESPONSE_APPROVED',
  'RESPONSE_EXECUTED',
  'RESPONSE_ROLLED_BACK',
  'USER_LOGIN',
  'USER_SUSPENDED',
  'LEDGER_RESYNCHRONIZATION',
  'WEBSITE_REGISTERED',
  'WEBSITE_UPDATED',
  'WEBSITE_VERIFIED',
  'WEBSITE_REVOKED',
  'WEBSITE_DELETED',
  'INTEGRATION_CREATED',
  'INTEGRATION_ROTATED',
  'INTEGRATION_REVOKED',
  'INTEGRATION_DELETED',
  'WEB_ATTACK_DETECTED',
  'ATTACK_CORRELATED',
  'RISK_SCORE_UPDATED',
] as const;

export const RFC5737_SIMULATED_IP_RANGES = [
  '198.51.100.0/24', // TEST-NET-2
  '203.0.113.0/24',  // TEST-NET-3
  '192.0.2.0/24',    // TEST-NET-1
] as const;

export const MITRE_TACTICS = [
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Exfiltration',
  'Command and Control',
  'Impact',
] as const;

export const WEBSITE_ENVIRONMENTS = ['PRODUCTION', 'STAGING', 'DEVELOPMENT'] as const;
export const WEBSITE_STATUSES = [
  'PENDING_VERIFICATION',
  'VERIFIED',
  'GRACE_PERIOD',
  'REVOKED',
  'SUSPENDED',
] as const;
export const RISK_TIERS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const;
export const VERIFICATION_METHODS = ['DNS_TXT', 'HTTP_CHALLENGE'] as const;

export const INTEGRATION_TYPES = [
  'SDK_NODE',
  'EXPRESS',
  'GENERIC_HTTP',
  'NGINX',
  'APACHE',
  'CLOUDFLARE',
  'AWS_WAF',
  'AWS_CLOUDTRAIL',
] as const;

export const INTEGRATION_STATUSES = ['ACTIVE', 'INACTIVE', 'REVOKED'] as const;

export const WEB_CONFIDENCE_TIERS = [
  'SUSPICIOUS_ATTEMPT',
  'BLOCKED_ATTEMPT',
  'POTENTIAL_EXPLOITATION',
  'CONFIRMED_EXPLOITATION',
] as const;

export const WEB_ATTACK_TYPES = [
  'SQLI',
  'XSS',
  'PATH_TRAVERSAL',
  'BOT_ACTIVITY',
  'AUTH_TAMPERING',
  'API_ABUSE',
] as const;

export const RISK_BANDS = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;
