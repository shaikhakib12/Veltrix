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
 * - Inspects reflection context (HTML text, attribute, quoted script string, unquoted script).
 * - Distinguishes raw reflection from entity-encoded reflections (&lt;canary&gt;);
 *   properly encoded reflections do NOT produce a vulnerability finding.
 * - Honesty Mandate: Alphanumeric-only canaries cannot establish confirmed XSS.
 *   Plain text reflection is reported with INFORMATIONAL severity and LOW confidence.
 *   Canary safely contained in a quoted JavaScript string literal is reported with INFORMATIONAL severity and LOW confidence.
 *   Unquoted script block reflection is reported with LOW severity and LOW confidence.
 *   Exploitability is NEVER reported as CONFIRMED without executable syntax breakouts.
 */

import crypto from 'node:crypto';
import type { CrawledPage } from '../../crawler/types.js';
import {
  type ActiveRuleInterface,
  type ActiveRuleExecutionContext,
  type ScannerFinding,
  RULE_ACTIVE_XSS_CANARY,
} from '../../types.js';

export type XssReflectionContext =
  | 'SCRIPT_STRING_LITERAL'
  | 'SCRIPT_UNQUOTED'
  | 'HTML_ATTRIBUTE'
  | 'HTML_TEXT'
  | 'RAW_BODY';

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
        // Reflection in plain HTML text or inside quoted JavaScript strings does NOT prove code execution.
        let severity: 'LOW' | 'INFORMATIONAL';
        let confidence: 'LOW' = 'LOW';
        let title: string;
        let description: string;
        let limitationNotice: string;

        if (contextType === 'SCRIPT_STRING_LITERAL') {
          severity = 'INFORMATIONAL';
          title = `Reflected Parameter in Script String Literal ('${param}')`;
          description = `An inert alphanumeric canary (${canary}) was reflected inside a quoted JavaScript string literal within a <script> block on ${page.url}. Because the value is contained inside string delimiters and the probe contains no quote-breaking characters, this does not establish executable script injection.`;
          limitationNotice =
            'Canary is contained inside a quoted JavaScript string literal; without syntax-breaking delimiters, script execution is not demonstrated.';
        } else if (contextType === 'SCRIPT_UNQUOTED') {
          severity = 'LOW';
          title = `Reflected Parameter in Unquoted Script Context ('${param}')`;
          description = `An inert alphanumeric canary (${canary}) was reflected inside a <script> block outside of string literal delimiters on ${page.url}. While unquoted reflection in script context is an unsafe coding pattern, full XSS exploitability cannot be confirmed without syntax-breaking markup or executable code execution.`;
          limitationNotice =
            'Alphanumeric canaries demonstrate reflection without executable payload injection; exploitability is not confirmed.';
        } else if (contextType === 'HTML_ATTRIBUTE') {
          severity = 'LOW';
          title = `Reflected Parameter in HTML Attribute ('${param}')`;
          description = `An inert alphanumeric canary (${canary}) was reflected inside an HTML tag attribute on ${page.url}. Exploitability is unconfirmed without attribute-escaping quotes.`;
          limitationNotice =
            'Alphanumeric canaries demonstrate reflection without executable payload injection; exploitability is not confirmed.';
        } else {
          severity = 'INFORMATIONAL';
          title = `Reflected Parameter Value in HTML Text ('${param}')`;
          description = `An inert alphanumeric canary (${canary}) was reflected in response body text on ${page.url}. This demonstrates parameter reflection, but does NOT establish XSS exploitability because alphanumeric canaries cannot demonstrate failure to escape HTML markup tags (<, >).`;
          limitationNotice =
            'Alphanumeric canaries demonstrate reflection without executable payload injection; exploitability is not confirmed.';
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
              limitationNotice,
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
  ): XssReflectionContext {
    const idx = body.indexOf(canary);
    if (idx === -1) return 'RAW_BODY';

    // Check script block context
    const beforeText = body.slice(0, idx);
    const lastScriptOpen = beforeText.lastIndexOf('<script');
    const lastScriptClose = beforeText.lastIndexOf('</script>');
    if (lastScriptOpen !== -1 && (lastScriptClose === -1 || lastScriptOpen > lastScriptClose)) {
      // Find end of <script ...> opening tag
      const scriptTagEnd = body.indexOf('>', lastScriptOpen);
      if (scriptTagEnd !== -1 && scriptTagEnd < idx) {
        const scriptContentBeforeCanary = body.slice(scriptTagEnd + 1, idx);
        const inString = this.isInsideScriptString(scriptContentBeforeCanary);
        return inString ? 'SCRIPT_STRING_LITERAL' : 'SCRIPT_UNQUOTED';
      }
      return 'SCRIPT_UNQUOTED';
    }

    // Check HTML attribute context
    const lastTagOpen = beforeText.lastIndexOf('<');
    const lastTagClose = beforeText.lastIndexOf('>');
    if (lastTagOpen !== -1 && (lastTagClose === -1 || lastTagOpen > lastTagClose)) {
      return 'HTML_ATTRIBUTE';
    }

    return 'HTML_TEXT';
  }

  /**
   * Evaluates JavaScript script text before a reflection position to determine if the position
   * falls inside an active quoted string literal, template literal, regex literal, or comment.
   */
  private isInsideScriptString(scriptText: string): boolean {
    let inSingle = false;
    let inDouble = false;
    let inTemplate = false;
    let inRegex = false;
    let inRegexClass = false;
    let inLineComment = false;
    let inBlockComment = false;
    let escaped = false;

    for (let i = 0; i < scriptText.length; i++) {
      const ch = scriptText[i];
      const next = i + 1 < scriptText.length ? scriptText[i + 1] : '';

      if (escaped) {
        escaped = false;
        continue;
      }

      if (inLineComment) {
        if (ch === '\n' || ch === '\r') {
          inLineComment = false;
        }
        continue;
      }

      if (inBlockComment) {
        if (ch === '*' && next === '/') {
          inBlockComment = false;
          i++; // skip /
        }
        continue;
      }

      if (!inSingle && !inDouble && !inTemplate && !inRegex) {
        if (ch === '/' && next === '/') {
          inLineComment = true;
          i++; // skip second /
          continue;
        }
        if (ch === '/' && next === '*') {
          inBlockComment = true;
          i++; // skip *
          continue;
        }
        if (ch === '/') {
          let prevChar = '';
          for (let j = i - 1; j >= 0; j--) {
            if (!/\s/.test(scriptText[j])) {
              prevChar = scriptText[j];
              break;
            }
          }
          if (!prevChar || /[=(:,[!\&|?{};~^+-]/.test(prevChar)) {
            inRegex = true;
            inRegexClass = false;
            continue;
          }
        }
      } else if (inRegex) {
        if (ch === '\\') {
          escaped = true;
          continue;
        }
        if (ch === '[') {
          inRegexClass = true;
        } else if (ch === ']' && inRegexClass) {
          inRegexClass = false;
        } else if (ch === '/' && !inRegexClass) {
          inRegex = false;
        }
        continue;
      }

      if (ch === '\\') {
        escaped = true;
        continue;
      }

      if (ch === "'" && !inDouble && !inTemplate) {
        inSingle = !inSingle;
      } else if (ch === '"' && !inSingle && !inTemplate) {
        inDouble = !inDouble;
      } else if (ch === '`' && !inSingle && !inDouble) {
        inTemplate = !inTemplate;
      }
    }

    return inSingle || inDouble || inTemplate || inRegex || inLineComment || inBlockComment;
  }
}
