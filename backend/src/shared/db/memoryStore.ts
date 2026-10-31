/**
 * VELTRIX In-Memory DynamoDB & Event Storage Engine
 * High-performance, thread-safe local adapter that emulates DynamoDB single-table
 * access patterns and EventBridge event dispatching.
 */

import { 
  SecurityEvent, 
  DetectionRule, 
  DetectionTrigger,
  Incident, 
  ThreatIndicator, 
  ResponsePolicy, 
  ResponseExecution, 
  AuditRecord,
  Organization,
  User 
} from '../types/index.js';
import { sha256 } from '../utils/crypto.js';

export class MemoryStore {
  private static instance: MemoryStore;

  public organizations: Map<string, Organization> = new Map();
  public users: Map<string, User> = new Map();
  public events: Map<string, SecurityEvent> = new Map();
  public rules: Map<string, DetectionRule> = new Map();
  public triggers: DetectionTrigger[] = [];
  public incidents: Map<string, Incident> = new Map();
  public indicators: Map<string, ThreatIndicator> = new Map();
  public policies: Map<string, ResponsePolicy> = new Map();
  public responseExecutions: Map<string, ResponseExecution> = new Map();
  public auditLogs: AuditRecord[] = [];
  public activeBlockedIps: Set<string> = new Set();
  public suspendedUsers: Set<string> = new Set();

  private constructor() {
    this.seedDefaultData();
  }

  public static getInstance(): MemoryStore {
    if (!MemoryStore.instance) {
      MemoryStore.instance = new MemoryStore();
    }
    return MemoryStore.instance;
  }

  /**
   * Resets the store for clean test suites
   */
  public reset(): void {
    this.organizations.clear();
    this.users.clear();
    this.events.clear();
    this.rules.clear();
    this.triggers = [];
    this.incidents.clear();
    this.indicators.clear();
    this.policies.clear();
    this.responseExecutions.clear();
    this.auditLogs = [];
    this.activeBlockedIps.clear();
    this.suspendedUsers.clear();
    this.seedDefaultData();
  }

  /**
   * Seeds default demo organization, users, threat intelligence IOCs, and response policies.
   */
  private seedDefaultData(): void {
    // 1. Default Organization
    const defaultOrg: Organization = {
      orgId: 'org-enterprise-01',
      name: 'CyberDefend Corp Global',
      tier: 'ENTERPRISE',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      settings: {
        retentionDays: 90,
        autoResponseEnabled: true,
        requireMFA: true,
      },
    };
    this.organizations.set(defaultOrg.orgId, defaultOrg);

    // 2. Default Users
    const secAnalyst: User = {
      userId: 'user-analyst-01',
      orgId: defaultOrg.orgId,
      email: 'analyst@cyberdefend.corp',
      fullName: 'Alex Vance (Lead SOC Analyst)',
      role: 'SECURITY_ANALYST',
      createdAt: new Date().toISOString(),
      status: 'ACTIVE',
    };
    this.users.set(secAnalyst.userId, secAnalyst);

    const adminUser: User = {
      userId: 'user-admin-01',
      orgId: defaultOrg.orgId,
      email: 'ciso@cyberdefend.corp',
      fullName: 'Elena Rostova (CISO)',
      role: 'ORG_ADMIN',
      createdAt: new Date().toISOString(),
      status: 'ACTIVE',
    };
    this.users.set(adminUser.userId, adminUser);

    // 3. Known Threat Indicators (Embedded Threat Intel)
    const seedIndicators: ThreatIndicator[] = [
      {
        indicatorId: 'ioc-001',
        type: 'IP',
        value: '198.51.100.42',
        severity: 'CRITICAL',
        confidence: 95,
        threatType: 'TOR_EXIT_NODE',
        description: 'Known Tor exit node actively observed in credential stuffing campaigns.',
        country: 'NL',
        asn: 'AS60729',
        lastSeen: new Date().toISOString(),
      },
      {
        indicatorId: 'ioc-002',
        type: 'IP',
        value: '203.0.113.195',
        severity: 'HIGH',
        confidence: 88,
        threatType: 'BOTNET_C2',
        description: 'Command & Control communication node for Mirai variant.',
        country: 'RU',
        asn: 'AS49505',
        lastSeen: new Date().toISOString(),
      },
      {
        indicatorId: 'ioc-003',
        type: 'IP',
        value: '192.0.2.77',
        severity: 'HIGH',
        confidence: 80,
        threatType: 'BRUTE_FORCE_SOURCE',
        description: 'High-frequency SSH/RDP/Web credential brute-force scanner.',
        country: 'CN',
        asn: 'AS4134',
        lastSeen: new Date().toISOString(),
      },
      {
        indicatorId: 'ioc-004',
        type: 'IP',
        value: '185.220.101.5',
        severity: 'CRITICAL',
        confidence: 98,
        threatType: 'TOR_EXIT_NODE',
        description: 'Malicious relay associated with automated API scraping and credential stuffing.',
        country: 'DE',
        asn: 'AS208323',
        lastSeen: new Date().toISOString(),
      },
      {
        indicatorId: 'ioc-005',
        type: 'CIDR',
        value: '45.154.255.0/24',
        severity: 'MEDIUM',
        confidence: 75,
        threatType: 'VPN_PROXY',
        description: 'Commercial Bulletproof Hosting provider range.',
        country: 'SC',
        lastSeen: new Date().toISOString(),
      }
    ];

    for (const ind of seedIndicators) {
      this.indicators.set(ind.value, ind);
    }

    // 4. Default Response Policies
    const seedPolicies: ResponsePolicy[] = [
      {
        policyId: 'pol-001',
        orgId: defaultOrg.orgId,
        name: 'Auto-Block Confirmed Tor & C2 IPs',
        action: 'BLOCK_IP',
        autoExecuteSeverityThreshold: 'CRITICAL',
        requiresApproval: true,
        rollbackSupported: true,
        enabled: true,
      },
      {
        policyId: 'pol-002',
        orgId: defaultOrg.orgId,
        name: 'Suspend Compromised Test Accounts',
        action: 'SUSPEND_USER',
        autoExecuteSeverityThreshold: 'CRITICAL',
        requiresApproval: true,
        rollbackSupported: true,
        enabled: true,
      },
      {
        policyId: 'pol-003',
        orgId: defaultOrg.orgId,
        name: 'Immediate Step-Up MFA Challenge',
        action: 'STEP_UP_AUTH',
        autoExecuteSeverityThreshold: 'HIGH',
        requiresApproval: false,
        rollbackSupported: false,
        enabled: true,
      },
      {
        policyId: 'pol-004',
        orgId: defaultOrg.orgId,
        name: 'Escalate Critical Incidents to On-Call',
        action: 'ESCALATE_ALERT',
        autoExecuteSeverityThreshold: 'HIGH',
        requiresApproval: false,
        rollbackSupported: false,
        enabled: true,
      }
    ];

    for (const pol of seedPolicies) {
      this.policies.set(pol.policyId, pol);
    }

    // 5. Genesis Audit Record
    const genesisTime = new Date().toISOString();
    const genesisHash = sha256(`GENESIS:${defaultOrg.orgId}:${genesisTime}`);
    this.auditLogs.push({
      logId: 'audit-genesis',
      orgId: defaultOrg.orgId,
      timestamp: genesisTime,
      actor: 'SYSTEM_GENESIS',
      action: 'PLATFORM_INITIALIZATION',
      targetResource: 'VELTRIX_CORE',
      result: 'SUCCESS',
      metadata: { version: '1.0.0', status: 'ONLINE' },
      previousHash: '0000000000000000000000000000000000000000000000000000000000000000',
      integrityHash: genesisHash,
    });
  }
}
