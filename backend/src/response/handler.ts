import { 
  Incident, 
  ResponseActionType, 
  ResponseExecution, 
  ResponseExecutionStatus 
} from '../shared/types/index.js';
import { generateId } from '../shared/utils/crypto.js';
import { MemoryStore } from '../shared/db/memoryStore.js';
import { AuditLogger } from '../audit/integrityChain.js';

export class ResponseEngine {
  private store: MemoryStore;
  private auditLogger: AuditLogger;

  constructor(store?: MemoryStore, auditLogger?: AuditLogger) {
    this.store = store || MemoryStore.getInstance();
    this.auditLogger = auditLogger || new AuditLogger(this.store);
  }

  /**
   * Evaluates and dispatches a defensive response for an incident.
   */
  public triggerResponse(
    incident: Incident,
    action: ResponseActionType,
    actor: string = 'SYSTEM_AUTONOMOUS',
    isApproved: boolean = false
  ): ResponseExecution {
    const executionId = generateId('resp');
    const targetEntity = action.includes('IP') ? incident.sourceIp : (incident.targetUser || 'UNKNOWN');
    const requiresApproval = incident.requiresApproval && !isApproved;

    const execution: ResponseExecution = {
      executionId,
      orgId: incident.orgId,
      incidentId: incident.incidentId,
      action,
      targetEntity,
      status: requiresApproval ? 'PENDING_APPROVAL' : 'EXECUTING',
      requestedBy: actor,
      approvedBy: isApproved ? actor : undefined,
      details: requiresApproval 
        ? `Defensive action ${action} on ${targetEntity} queued awaiting analyst sign-off.` 
        : `Executing defensive response ${action} against ${targetEntity}.`,
      isSimulated: incident.isSimulated,
    };

    if (requiresApproval) {
      incident.containmentStatus = 'PENDING_APPROVAL';
      this.store.responseExecutions.set(executionId, execution);

      this.auditLogger.log(
        incident.orgId,
        actor,
        'RESPONSE_QUEUED_APPROVAL',
        `Incident:${incident.incidentId}`,
        'SUCCESS',
        { executionId, action, targetEntity }
      );

      return execution;
    }

    // Execute the action immediately
    return this.executeAction(execution, incident, actor);
  }

  /**
   * Approves and executes a previously queued containment action.
   */
  public approveAction(executionId: string, analystUser: string): ResponseExecution {
    const execution = this.store.responseExecutions.get(executionId);
    if (!execution) {
      throw new Error(`Response execution ${executionId} not found`);
    }

    if (execution.status !== 'PENDING_APPROVAL') {
      throw new Error(`Response execution is in status ${execution.status}, cannot approve`);
    }

    const incident = this.store.incidents.get(execution.incidentId);
    if (!incident) {
      throw new Error(`Associated incident ${execution.incidentId} not found`);
    }

    execution.approvedBy = analystUser;
    return this.executeAction(execution, incident, analystUser);
  }

  /**
   * Reverts / rolls back an active containment action (e.g. Unblock IP, Reinstate User).
   */
  public rollbackAction(executionId: string, analystUser: string): ResponseExecution {
    const execution = this.store.responseExecutions.get(executionId);
    if (!execution) {
      throw new Error(`Response execution ${executionId} not found`);
    }

    const incident = this.store.incidents.get(execution.incidentId);

    if (execution.action === 'BLOCK_IP') {
      this.store.activeBlockedIps.delete(execution.targetEntity);
    } else if (execution.action === 'SUSPEND_USER') {
      this.store.suspendedUsers.delete(execution.targetEntity);
    }

    execution.status = 'ROLLED_BACK';
    execution.rollbackAt = new Date().toISOString();
    execution.details = `Action ${execution.action} rolled back by ${analystUser}.`;

    if (incident) {
      incident.containmentStatus = 'REVERTED';
      incident.notes.push({
        author: analystUser,
        timestamp: new Date().toISOString(),
        content: `Rollback applied: Reverted defensive action ${execution.action} on ${execution.targetEntity}.`,
      });
    }

    this.auditLogger.log(
      execution.orgId,
      analystUser,
      'RESPONSE_ROLLBACK',
      `Target:${execution.targetEntity}`,
      'SUCCESS',
      { executionId, action: execution.action }
    );

    return execution;
  }

  private executeAction(execution: ResponseExecution, incident: Incident, actor: string): ResponseExecution {
    try {
      execution.executedAt = new Date().toISOString();

      switch (execution.action) {
        case 'BLOCK_IP':
          this.store.activeBlockedIps.add(execution.targetEntity);
          execution.details = `Simulated firewall policy updated: Blocked incoming traffic from IP ${execution.targetEntity}.`;
          break;

        case 'SUSPEND_USER':
          this.store.suspendedUsers.add(execution.targetEntity);
          execution.details = `Simulated directory account status set to LOCKED for user ${execution.targetEntity}.`;
          break;

        case 'REVOKE_SESSION':
          execution.details = `Revoked active authentication tokens and invalidated session cache for ${execution.targetEntity}.`;
          break;

        case 'STEP_UP_AUTH':
          execution.details = `Enforced mandatory MFA biometric/hardware challenge requirement for ${execution.targetEntity}.`;
          break;

        case 'ESCALATE_ALERT':
          execution.details = `High-priority SOC alert dispatched to on-call incident response team.`;
          break;

        default:
          execution.details = `Executed custom response ${execution.action}.`;
      }

      execution.status = 'SUCCESS';
      incident.containmentStatus = 'CONTAINED';
      if (incident.status === 'NEW') {
        incident.status = 'CONTAINED';
      }

      incident.notes.push({
        author: actor,
        timestamp: new Date().toISOString(),
        content: `Containment action executed: ${execution.action} on ${execution.targetEntity}. Result: SUCCESS.`,
      });

      this.store.responseExecutions.set(execution.executionId, execution);

      this.auditLogger.log(
        execution.orgId,
        actor,
        'RESPONSE_EXECUTED',
        `Target:${execution.targetEntity}`,
        'SUCCESS',
        { executionId: execution.executionId, action: execution.action, details: execution.details }
      );

      return execution;
    } catch (err: unknown) {
      execution.status = 'FAILED';
      execution.details = `Execution failed: ${err instanceof Error ? err.message : String(err)}`;
      this.store.responseExecutions.set(execution.executionId, execution);

      this.auditLogger.log(
        execution.orgId,
        actor,
        'RESPONSE_FAILED',
        `Target:${execution.targetEntity}`,
        'FAILURE',
        { executionId: execution.executionId, error: execution.details }
      );

      return execution;
    }
  }
}
