import { 
  SecurityEvent, 
  DetectionRule, 
  DetectionTrigger, 
  RuleCondition 
} from '../shared/types/index.js';
import { generateId } from '../shared/utils/crypto.js';
import { BUILTIN_DETECTION_RULES } from './rules/catalog.js';

export class DetectionEngine {
  private rules: Map<string, DetectionRule> = new Map();
  // Sliding window memory buffer: Map<ruleId_entityKey, Array<{ timestamp: number, event: SecurityEvent }>>
  private windowBuffer: Map<string, Array<{ timestamp: number; event: SecurityEvent }>> = new Map();

  constructor(customRules?: DetectionRule[]) {
    // Load built-in rules
    for (const rule of BUILTIN_DETECTION_RULES) {
      this.rules.set(rule.ruleId, { ...rule });
    }
    // Overlay custom rules if provided
    if (customRules) {
      for (const rule of customRules) {
        this.rules.set(rule.ruleId, { ...rule });
      }
    }
  }

  public getRules(): DetectionRule[] {
    return Array.from(this.rules.values());
  }

  public getRule(ruleId: string): DetectionRule | undefined {
    return this.rules.get(ruleId);
  }

  public updateRule(ruleId: string, updates: Partial<DetectionRule>): DetectionRule | undefined {
    const existing = this.rules.get(ruleId);
    if (!existing) return undefined;
    const updated: DetectionRule = {
      ...existing,
      ...updates,
      updatedAt: new Date().toISOString(),
    };
    this.rules.set(ruleId, updated);
    return updated;
  }

  /**
   * Evaluates an ingested event against all active rules.
   * Returns an array of triggered detections.
   */
  public evaluateEvent(event: SecurityEvent): DetectionTrigger[] {
    const triggers: DetectionTrigger[] = [];
    const eventTimeMs = new Date(event.timestamp).getTime();

    for (const rule of this.rules.values()) {
      if (!rule.enabled) continue;

      // 1. Check conditions
      const matches = this.evaluateConditions(event, rule.conditions);
      if (!matches) continue;

      // 2. Identify entity key based on groupBy
      const entityValue = this.getEntityValue(event, rule.groupBy);
      const bufferKey = `${rule.ruleId}:${entityValue}`;

      // 3. Update sliding window buffer
      let history = this.windowBuffer.get(bufferKey) || [];
      const windowCutoff = eventTimeMs - (rule.timeWindowSeconds * 1000);
      
      // Filter out stale events outside the sliding window
      history = history.filter(item => item.timestamp >= windowCutoff);
      history.push({ timestamp: eventTimeMs, event });
      this.windowBuffer.set(bufferKey, history);

      // 4. Threshold check
      if (history.length >= rule.threshold) {
        // Special condition check for RULE-003 (Compromise after failure)
        if (rule.ruleId === 'RULE-003') {
          // Verify that prior events in buffer had failed logins
          const hasPriorFailures = history.some(item => item.event.eventType === 'auth.login.failed');
          if (!hasPriorFailures) continue;
        }

        // Special condition check for RULE-002 (Password spraying across multiple accounts)
        if (rule.ruleId === 'RULE-002') {
          const uniqueUsers = new Set(history.map(item => item.event.username));
          if (uniqueUsers.size < rule.threshold) continue;
        }

        const contributingEventIds = history.map(h => h.event.eventId);
        const trigger: DetectionTrigger = {
          triggerId: generateId('trig'),
          ruleId: rule.ruleId,
          ruleName: rule.name,
          orgId: event.orgId,
          timestamp: new Date().toISOString(),
          severity: rule.severity,
          mitreAttack: rule.mitreAttack,
          entityKey: `${rule.groupBy}:${entityValue}`,
          contributingEventIds,
          matchedCount: history.length,
          explanation: `Triggered ${rule.name}: ${history.length} occurrences matching pattern for ${rule.groupBy} '${entityValue}' within ${rule.timeWindowSeconds}s window.`,
          isSimulated: event.isSimulated,
        };

        triggers.push(trigger);

        // Reset or clear part of buffer to avoid duplicate rapid re-triggering
        this.windowBuffer.set(bufferKey, []);
      }
    }

    return triggers;
  }

  private evaluateConditions(event: SecurityEvent, conditions: RuleCondition[]): boolean {
    for (const cond of conditions) {
      const fieldValue = this.getNestedValue(event as unknown as Record<string, unknown>, cond.field);

      switch (cond.operator) {
        case 'equals':
          if (fieldValue !== cond.value) return false;
          break;
        case 'not_equals':
          if (fieldValue === cond.value) return false;
          break;
        case 'contains':
          if (typeof fieldValue === 'string' && typeof cond.value === 'string') {
            if (!fieldValue.toLowerCase().includes(cond.value.toLowerCase())) return false;
          } else {
            return false;
          }
          break;
        case 'greater_than':
          if (typeof fieldValue !== 'number' || fieldValue <= (cond.value as number)) return false;
          break;
        case 'in':
          if (Array.isArray(cond.value) && !cond.value.includes(fieldValue as string)) return false;
          break;
        default:
          return false;
      }
    }
    return true;
  }

  private getEntityValue(event: SecurityEvent, groupBy: 'sourceIp' | 'username' | 'sourceSystem'): string {
    switch (groupBy) {
      case 'sourceIp': return event.sourceIp;
      case 'username': return event.username;
      case 'sourceSystem': return event.sourceSystem;
      default: return event.sourceIp;
    }
  }

  private getNestedValue(obj: Record<string, unknown>, path: string): unknown {
    const parts = path.split('.');
    let current: unknown = obj;
    for (const part of parts) {
      if (current && typeof current === 'object' && part in current) {
        current = (current as Record<string, unknown>)[part];
      } else {
        return undefined;
      }
    }
    return current;
  }
}
