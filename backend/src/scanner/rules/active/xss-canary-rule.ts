/**
 * VELTRIX Active Security Rule: Reflected Cross-Site Scripting Canary (TASK-805)
 *
 * Dispatches non-executable, inert alphanumeric canaries to detect unencoded
 * parameter reflection in HTML body, attribute, or script contexts.
 *
 * Invariants:
 * - Emits strictly benign alphanumeric canary tokens: vltxcanary_<random16Hex>.
 * - Never executes payloads, alters state, or injects executable JavaScript.
 * - Performs differential baseline check to suppress pre-existing false positives.
 * - Inspects reflection context (HTML text, attribute, script block).
 * - Distinguishes raw reflection from entity-encoded reflections (&lt;canary&gt;);
 *   properly encoded reflections do NOT produce a vulnerability finding.
 * - Honesty Mandate: Alphanumeric-only canaries cannot establish confirmed XSS.
 *   Plain text reflection is reported with INFORMATIONAL/LOW severity and LOW confidence.
 *   Script block reflection is reported with MEDIUM severity and MEDIUM confidence.
 */

import crypto from 'node:crypto';
import type { CrawledPage } from '../../crawler/types.js';
import {
  type ActiveRuleInterface,
  type ActiveRuleExecutionContext,
  type ScannerFinding,
  RULE_ACTIVE_XSS_CANARY,
} from '../../types.js';

export class XssCanaryRule implements ActiveRuleInterface {
  public readonly id = RULE_ACTIVE_XSS_CANARY;
  public readonly name = 'Active Reflected XSS Canary Rule';
  public readonly description =
    'Dispatches inert, non-executable alphanumeric canaries to detect unencoded reflection across query parameters.';

  private static readonly DEFAULT_PROBE_PARAMS = ['q', 'search', 'query', 'keyword'];

  public async evaluate(
    page: CrawledPage,
    context: ActiveRuleExecutionContext
  ): Promise<readonly ScannerFinding[]> {
    const findings: ScannerFinding[] = [];
    if (!page.url.startsWith('http://') && !page.url.startsWith('https://')) {
      return Object.freeze(findings);
    }

    let parsedUrl: URL;
    try {
      parsedUrl = new URL(page.url);
    } catch {
      return Object.freeze(findings);
    }

    // Determine target parameters from existing query or default probe list
    const paramsToProbe: string[] = [];
    for (const key of parsedUrl.searchParams.keys()) {
      if (!paramsToProbe.includes(key)) {
        paramsToProbe.push(key);
      }
    }

    if (paramsToProbe.length === 0) {
      // If no query parameters, probe standard candidates
      paramsToProbe.push(...XssCanaryRule.DEFAULT_PROBE_PARAMS);
    }

    for (const param of paramsToProbe) {
      if (context.signal?.aborted) break;

      const canary = `vltxcanary_${crypto.randomBytes(8).toString('hex')}`;

      // Baseline check: Ensure canary does not already exist in baseline response
      if (page.bodyText && page.bodyText.includes(canary)) {
        continue;
      }

      // Construct probe URL with canary
      const probeUrlObj = new URL(page.url);
      probeUrlObj.searchParams.set(param, canary);
      const probeUrl = probeUrlObj.toString();

      try {
        const res = await context.dispatchProbe(probeUrl, { method: 'GET' });
        if (!res || !res.text || res.status >= 500) {
          continue;
        }

        const body = res.text;

        // Check if the canary appears anywhere in the response body
        if (!body.includes(canary)) {
          continue;
        }

        // Entity-encoded check: Verify whether reflection was sanitized or entity-escaped
        // e.g., &lt;canary&gt; or &lt;vltxcanary... or &#x3c;canary...
        const isEntityEncoded =
          body.includes(`&lt;${canary}`) ||
          body.includes(`${canary}&gt;`) ||
          body.includes(`&lt;${canary}&gt;`) ||
          body.includes(`&#60;${canary}`) ||
          body.includes(`&#x3c;${canary}`) ||
          body.includes(`&#x3C;${canary}`);

        if (isEntityEncoded) {
          // Properly encoded by the server; false positive suppressed
          continue;
        }

        // Determine reflection context
        const contextType = this.determineReflectionContext(body, canary);

        const matchIdx = body.indexOf(canary);
        const snippetStart = Math.max(0, matchIdx - 40);
        const snippetEnd = Math.min(body.length, matchIdx + canary.length + 40);
        const snippet = body.slice(snippetStart, snippetEnd).trim();

        // Honest Security Evaluation & Confidence Mapping:
        // Plain alphanumeric canaries (vltxcanary_<16Hex>) prove parameter reflection,
        // but cannot establish XSS exploitability without injecting syntax-breaking markup (<, >, ", ').
        // Plain text reflection is standard web behavior and MUST NOT be reported as CONFIRMED XSS.
        let severity: 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
        let confidence: 'MEDIUM' | 'LOW';
        let title: string;
        let description: string;

        if (contextType === 'SCRIPT_BLOCK') {
          // Reflection directly inside an executable script block is a high-risk indicator
          severity = 'MEDIUM';
          confidence = 'MEDIUM';
          title = `Reflected Parameter in Script Context ('${param}')`;
          description = `An inert alphanumeric canary (${canary}) was reflected inside an executable <script> block on ${page.url}. While this demonstrates reflection into JavaScript context, full XSS exploitability cannot be confirmed without syntax-breaking string delimiters.`;
        } else if (contextType === 'HTML_ATTRIBUTE') {
          // Reflection inside an HTML attribute
          severity = 'LOW';
          confidence = 'LOW';
          title = `Reflected Parameter in HTML Attribute ('${param}')`;
          description = `An inert alphanumeric canary (${canary}) was reflected inside an HTML tag attribute on ${page.url}. Exploitability is unconfirmed without attribute-escaping quotes.`;
        } else {
          // Plain HTML text reflection (e.g. search term reflection)
          severity = 'INFORMATIONAL';
          confidence = 'LOW';
          title = `Reflected Parameter Value in HTML Text ('${param}')`;
          description = `An inert alphanumeric canary (${canary}) was reflected in response body text on ${page.url}. This demonstrates parameter reflection, but does NOT establish XSS exploitability because alphanumeric canaries cannot demonstrate failure to escape HTML markup tags (<, >).`;
        }

        findings.push(
          Object.freeze({
            ruleId: this.id,
            vulnerabilityType: 'CROSS_SITE_SCRIPTING_REFLECTED',
            title,
            severity,
            confidence,
            description,
            remediation:
              'Apply context-aware output encoding (HTML entity encoding, attribute escaping, or JSON serialization) before rendering user input, and enforce a strong Content-Security-Policy.',
            url: page.url,
            endpoint: probeUrl,
            evidence: Object.freeze({
              targetUrl: page.url,
              parameter: param,
              canaryPayload: canary,
              reflectionContext: contextType,
              responseStatus: res.status,
              responseBodySnippet: snippet.slice(0, 300),
              limitationNotice:
                'Alphanumeric canaries demonstrate reflection without executable payload injection; exploitability is not confirmed.',
            }),
          })
        );
      } catch {
        // Probe errors fail safely without halting evaluation
      }
    }

    return Object.freeze(findings);
  }

  private determineReflectionContext(
    body: string,
    canary: string
  ): 'SCRIPT_BLOCK' | 'HTML_ATTRIBUTE' | 'HTML_TEXT' | 'RAW_BODY' {
    const idx = body.indexOf(canary);
    if (idx === -1) return 'RAW_BODY';

    // Check script block context
    const beforeText = body.slice(0, idx);
    const lastScriptOpen = beforeText.lastIndexOf('<script');
    const lastScriptClose = beforeText.lastIndexOf('</script>');
    if (lastScriptOpen !== -1 && (lastScriptClose === -1 || lastScriptOpen > lastScriptClose)) {
      return 'SCRIPT_BLOCK';
    }

    // Check HTML attribute context
    const lastTagOpen = beforeText.lastIndexOf('<');
    const lastTagClose = beforeText.lastIndexOf('>');
    if (lastTagOpen !== -1 && (lastTagClose === -1 || lastTagOpen > lastTagClose)) {
      return 'HTML_ATTRIBUTE';
    }

    return 'HTML_TEXT';
  }
}
