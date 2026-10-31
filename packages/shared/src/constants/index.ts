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
