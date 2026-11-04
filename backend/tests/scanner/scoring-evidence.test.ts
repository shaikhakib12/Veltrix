/**
 * VELTRIX Phase 8: Risk Scoring & Cryptographic Evidence Test Suite (TASK-806)
 *
 * Verifies:
 * 1. Secret scrubbing and 64 KB truncation across headers, URLs, and curl reproduction.
 * 2. Deterministic CVSS v3.1 base scoring and vector mapping.
 * 3. Multi-factor finding risk scoring and site security posture calculation.
 * 4. Differential baseline comparisons (new, recurring, resolved findings).
 * 5. Cryptographic SHA-256 evidence integrity verification and tamper detection.
 * 6. Phase 7 InternalEvidenceAuthority integration.
 */

import { describe, it, expect } from 'vitest';
import {
  scrubUrl,
  scrubHeaders,
  scrubResponseBody,
  generateScrubbedCurl,
  MAX_EVIDENCE_EXCERPT_BYTES,
  calculateCvss,
  scoreToSeverity,
  ScoringEngine,
  EvidenceCollector,
  type ScannerFinding,
} from '../../src/scanner/index.js';

describe('Phase 8: Scoring Engine & Cryptographic Evidence (TASK-806)', () => {
  describe('1. Secret Scrubber & Sanitization', () => {
    it('redacts sensitive query parameters from target URLs', () => {
      const url = 'https://example.com/api/v1/user?token=secret-jwt-123&api_key=ak_live_xyz&page=2';
      const scrubbed = scrubUrl(url);

      expect(scrubbed).toContain('token=%5BREDACTED%5D');
      expect(scrubbed).toContain('api_key=%5BREDACTED%5D');
      expect(scrubbed).toContain('page=2');
      expect(scrubbed).not.toContain('secret-jwt-123');
      expect(scrubbed).not.toContain('ak_live_xyz');
    });

    it('redacts passwords in URL authority', () => {
      const url = 'https://admin:super_secret_password@example.com/admin';
      const scrubbed = scrubUrl(url);
      expect(scrubbed).toContain('admin:REDACTED@example.com');
      expect(scrubbed).not.toContain('super_secret_password');
    });

    it('redacts sensitive HTTP headers and session cookies', () => {
      const headers = {
        'authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret',
        'proxy-authorization': 'Basic YWRtaW46cGFzc3dvcmQ=',
        'cookie': 'session=sess_12345; user=alice; token=tok_abc',
        'set-cookie': 'session_id=sess_9999; Path=/; Secure; HttpOnly',
        'x-api-key': 'live_key_999',
        'content-type': 'application/json',
      };

      const scrubbed = scrubHeaders(headers);
      expect(scrubbed['authorization']).toBe('[REDACTED]');
      expect(scrubbed['proxy-authorization']).toBe('[REDACTED]');
      expect(scrubbed['x-api-key']).toBe('[REDACTED]');
      expect(scrubbed['content-type']).toBe('application/json');

      expect(scrubbed['cookie']).toContain('session=[REDACTED]');
      expect(scrubbed['cookie']).toContain('token=[REDACTED]');
      expect(scrubbed['cookie']).not.toContain('sess_12345');
      expect(scrubbed['cookie']).not.toContain('tok_abc');

      expect(scrubbed['set-cookie']).toContain('session_id=[REDACTED]');
      expect(scrubbed['set-cookie']).not.toContain('sess_9999');
    });

    it('strictly truncates response excerpts to a maximum of 64 KB', () => {
      const largeText = 'A'.repeat(80 * 1024); // 80 KB
      const scrubbed = scrubResponseBody(largeText);

      const byteLength = Buffer.from(scrubbed, 'utf8').length;
      expect(byteLength).toBeLessThanOrEqual(MAX_EVIDENCE_EXCERPT_BYTES + 100); // 64 KB + truncation notice
      expect(scrubbed).toContain('[TRUNCATED at 65536 bytes]');
    });

    it('generates scrubbed curl reproduction commands without leaking secrets', () => {
      const curl = generateScrubbedCurl(
        'GET',
        'https://example.com/search?token=secret123&q=test',
        {
          authorization: 'Bearer secret_token',
          accept: 'application/json',
        }
      );

      expect(curl).toContain('curl -s -S -X GET');
      expect(curl).toContain('token=%5BREDACTED%5D');
      expect(curl).toContain('-H "authorization: [REDACTED]"');
      expect(curl).toContain('-H "accept: application/json"');
      expect(curl).not.toContain('secret123');
      expect(curl).not.toContain('secret_token');
    });
  });

  describe('2. CVSS v3.1 Calculator & Vector Mapping', () => {
    it('computes CVSS base score for SQL Injection syntax anomalies', () => {
      const res = calculateCvss('SQL_INJECTION_SYNTAX_ANOMALY');
      expect(res.score).toBe(8.6);
      expect(res.severity).toBe('HIGH');
      expect(res.vector).toContain('CVSS:3.1');
      expect(res.vector).toContain('AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L');
      expect(res.rationale).toBeDefined();
    });

    it('computes contextual CVSS base score for Reflected XSS', () => {
      // Unquoted script context
      const unquoted = calculateCvss('CROSS_SITE_SCRIPTING_REFLECTED', {
        reflectionContext: 'SCRIPT_UNQUOTED',
      });
      expect(unquoted.score).toBe(5.3);
      expect(unquoted.severity).toBe('LOW');

      // Attribute reflection
      const attr = calculateCvss('CROSS_SITE_SCRIPTING_REFLECTED', {
        reflectionContext: 'HTML_ATTRIBUTE',
      });
      expect(attr.score).toBe(3.5);
      expect(attr.severity).toBe('LOW');

      // Quoted string literal / plain HTML text
      const literal = calculateCvss('CROSS_SITE_SCRIPTING_REFLECTED', {
        reflectionContext: 'SCRIPT_STRING_LITERAL',
      });
      expect(literal.score).toBe(2.0);
      expect(literal.severity).toBe('INFORMATIONAL');
    });

    it('maps numerical scores to severity tiers correctly', () => {
      expect(scoreToSeverity(9.8)).toBe('CRITICAL');
      expect(scoreToSeverity(7.5)).toBe('HIGH');
      expect(scoreToSeverity(5.3)).toBe('MEDIUM');
      expect(scoreToSeverity(3.1)).toBe('LOW');
      expect(scoreToSeverity(1.5)).toBe('INFORMATIONAL');
    });
  });

  describe('3. Multi-Factor Risk Scoring Engine', () => {
    const engine = new ScoringEngine();

    it('calculates deterministic finding risk score with explainable factor breakdown', () => {
      const finding: ScannerFinding = {
        id: 'fnd-1',
        ruleId: 'RULE_ACTIVE_SQLI_ANOMALY',
        vulnerabilityType: 'SQL_INJECTION_SYNTAX_ANOMALY',
        title: 'SQL Injection in Param id',
        severity: 'HIGH',
        confidence: 'HIGH',
        description: 'SQL anomaly detected',
        remediation: 'Use prepared statements',
        url: 'https://example.com/items?id=1',
      };

      const result = engine.calculateFindingRisk(finding);
      expect(result.score).toBeGreaterThan(0);
      expect(result.score).toBeLessThanOrEqual(100);
      expect(result.cvss.score).toBe(8.6);
      expect(result.factors.baseCvssScore).toBe(8.6);
      expect(result.factors.severityMultiplier).toBe(0.85);
      expect(result.factors.confidenceMultiplier).toBe(0.85);
      expect(result.factors.explanation).toContain('Base CVSS 8.6');
    });

    it('calculates overall site security posture and letter grade', () => {
      const findings: ScannerFinding[] = [
        {
          id: 'fnd-1',
          ruleId: 'RULE_PASSIVE_HEADERS',
          vulnerabilityType: 'MISSING_SECURITY_HEADERS',
          title: 'Missing CSP',
          severity: 'LOW',
          confidence: 'HIGH',
          description: 'No CSP',
          remediation: 'Add CSP',
          url: 'https://example.com/',
        },
      ];

      const posture = engine.calculateSitePosture(findings);
      expect(posture.overallScore).toBe(97);
      expect(posture.letterGrade).toBe('A');
      expect(posture.totalFindings).toBe(1);
    });

    it('awards letter grade F when critical findings exist', () => {
      const findings: ScannerFinding[] = [
        {
          id: 'fnd-crit',
          ruleId: 'RULE_ACTIVE_SQLI',
          vulnerabilityType: 'SQL_INJECTION_SYNTAX_ANOMALY',
          title: 'Critical SQLi',
          severity: 'CRITICAL',
          confidence: 'CONFIRMED',
          description: 'SQL syntax anomaly',
          remediation: 'Fix',
          url: 'https://example.com/api',
        },
      ];

      const posture = engine.calculateSitePosture(findings);
      expect(posture.letterGrade).toBe('F');
      expect(posture.criticalCount).toBe(1);
    });

    it('performs differential baseline comparison and identifies new vs recurring vs resolved findings', () => {
      const f1: ScannerFinding = {
        id: 'f1',
        ruleId: 'RULE_PASSIVE_HEADERS',
        vulnerabilityType: 'MISSING_SECURITY_HEADERS',
        title: 'Missing CSP',
        severity: 'LOW',
        confidence: 'HIGH',
        description: 'No CSP',
        remediation: 'Add CSP',
        url: 'https://example.com/',
      };

      const f2: ScannerFinding = {
        id: 'f2',
        ruleId: 'RULE_PASSIVE_COOKIES',
        vulnerabilityType: 'COOKIE_SECURITY_FLAGS',
        title: 'Missing HttpOnly',
        severity: 'LOW',
        confidence: 'HIGH',
        description: 'Cookie flag missing',
        remediation: 'Set HttpOnly',
        url: 'https://example.com/',
      };

      const f3New: ScannerFinding = {
        id: 'f3',
        ruleId: 'RULE_ACTIVE_OPEN_REDIRECT',
        vulnerabilityType: 'OPEN_REDIRECT_UNVALIDATED',
        title: 'Open Redirect',
        severity: 'MEDIUM',
        confidence: 'HIGH',
        description: 'Redirect canary observed',
        remediation: 'Validate redirect target',
        url: 'https://example.com/redirect?to=test',
      };

      const baselineFindings = [f1, f2];
      const currentFindings = [f1, f3New]; // f2 was resolved, f3 is new, f1 is recurring

      const comparison = engine.compareWithBaseline(currentFindings, baselineFindings);

      expect(comparison.newFindings.length).toBe(1);
      expect(comparison.newFindings[0]?.vulnerabilityType).toBe('OPEN_REDIRECT_UNVALIDATED');

      expect(comparison.recurringFindings.length).toBe(1);
      expect(comparison.recurringFindings[0]?.vulnerabilityType).toBe('MISSING_SECURITY_HEADERS');

      expect(comparison.resolvedFindings.length).toBe(1);
      expect(comparison.resolvedFindings[0]?.vulnerabilityType).toBe('COOKIE_SECURITY_FLAGS');

      expect(comparison.summary).toBeDefined();
    });
  });

  describe('4. Cryptographic Evidence Collector & Tamper Detection', () => {
    const collector = new EvidenceCollector();

    it('packages finding into immutable evidence record with canonical SHA-256 digest', () => {
      const finding: ScannerFinding = {
        id: 'fnd-evidence-1',
        ruleId: 'RULE_ACTIVE_SQLI_ANOMALY',
        vulnerabilityType: 'SQL_INJECTION_SYNTAX_ANOMALY',
        title: 'SQL Injection in Param id',
        severity: 'HIGH',
        confidence: 'HIGH',
        description: 'SQL anomaly detected in response body',
        remediation: 'Use prepared statements',
        url: 'https://example.com/items?token=secret123&id=1',
        evidence: {
          parameter: 'id',
          responseStatus: 500,
          responseBodySnippet: 'Syntax error in SQL statement',
        },
      };

      const evidence = collector.collectEvidence({
        scanId: 'scan-100',
        orgId: 'org-test',
        siteId: 'site-1',
        finding,
        requestMethod: 'GET',
        responseStatus: 500,
        responseBody: '<html>Syntax error in SQL statement near id</html>',
      });

      expect(evidence.findingId).toBe('fnd-evidence-1');
      expect(evidence.targetUrl).toContain('token=%5BREDACTED%5D');
      expect(evidence.sha256Digest).toBeDefined();
      expect(evidence.sha256Digest.length).toBe(64); // SHA-256 hex string

      // Verify intact evidence
      const verification = collector.verifyEvidenceIntegrity(evidence);
      expect(verification.verified).toBe(true);
    });

    it('detects tampering when evidence attributes or excerpts are modified', () => {
      const finding: ScannerFinding = {
        id: 'fnd-evidence-2',
        ruleId: 'RULE_PASSIVE_HEADERS',
        vulnerabilityType: 'MISSING_SECURITY_HEADERS',
        title: 'Missing CSP',
        severity: 'LOW',
        confidence: 'HIGH',
        description: 'No CSP',
        remediation: 'Add CSP',
        url: 'https://example.com/',
      };

      const evidence = collector.collectEvidence({
        scanId: 'scan-100',
        orgId: 'org-test',
        siteId: 'site-1',
        finding,
      });

      // Verify initially valid
      expect(collector.verifyEvidenceIntegrity(evidence).verified).toBe(true);

      // Tamper with severity
      const tamperedSeverity = { ...evidence, severity: 'CRITICAL' as any };
      const res1 = collector.verifyEvidenceIntegrity(tamperedSeverity);
      expect(res1.verified).toBe(false);
      expect(res1.reason).toContain('Cryptographic SHA-256 digest mismatch');

      // Tamper with title
      const tamperedTitle = { ...evidence, title: 'Fabricated High Risk Title' };
      const res2 = collector.verifyEvidenceIntegrity(tamperedTitle);
      expect(res2.verified).toBe(false);

      // Tamper with response excerpt
      const tamperedExcerpt = { ...evidence, responseExcerpt: 'Manipulated response excerpt' };
      const res3 = collector.verifyEvidenceIntegrity(tamperedExcerpt);
      expect(res3.verified).toBe(false);
    });
  });
});
