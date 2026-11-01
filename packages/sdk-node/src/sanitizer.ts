export class DataSanitizer {
  private static readonly DEFAULT_SENSITIVE_KEYS = new Set([
    'password',
    'passwd',
    'pass',
    'secret',
    'token',
    'access_token',
    'refreshtoken',
    'refresh_token',
    'auth',
    'authorization',
    'creditcard',
    'cardnumber',
    'ccv',
    'cvv',
    'cvc',
    'ssn',
    'cookie',
    'set-cookie',
    'apikey',
    'api_key',
    'privatekey',
    'private_key',
  ]);

  private sensitiveKeys: Set<string>;

  constructor(customKeys: string[] = []) {
    this.sensitiveKeys = new Set(DataSanitizer.DEFAULT_SENSITIVE_KEYS);
    for (const key of customKeys) {
      this.sensitiveKeys.add(key.toLowerCase());
    }
  }

  isSensitiveKey(key: string): boolean {
    const normalized = key.toLowerCase().replace(/[-_]/g, '');
    for (const sensitive of this.sensitiveKeys) {
      if (normalized.includes(sensitive.replace(/[-_]/g, ''))) {
        return true;
      }
    }
    return false;
  }

  sanitizeValue(key: string, value: unknown): unknown {
    if (this.isSensitiveKey(key)) {
      return '[REDACTED]';
    }

    if (value === null || value === undefined) {
      return value;
    }

    if (typeof value === 'object') {
      if (Array.isArray(value)) {
        return value.map((item) => this.sanitizeObject(item));
      }
      return this.sanitizeObject(value as Record<string, unknown>);
    }

    // Check if string looks like an authorization Bearer token
    if (typeof value === 'string' && /^bearer\s+/i.test(value)) {
      return 'Bearer [REDACTED]';
    }

    return value;
  }

  sanitizeObject<T>(input: T): T {
    if (!input || typeof input !== 'object') {
      return input;
    }

    if (Array.isArray(input)) {
      return input.map((item) => this.sanitizeObject(item)) as unknown as T;
    }

    const result: Record<string, unknown> = {};
    const record = input as Record<string, unknown>;

    for (const [key, val] of Object.entries(record)) {
      result[key] = this.sanitizeValue(key, val);
    }

    return result as T;
  }
}
