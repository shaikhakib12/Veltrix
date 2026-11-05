import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  Bug,
  Filter,
  Search,
  ShieldAlert,
  Terminal,
  Copy,
  Check,
  X,
  ShieldCheck,
  FileCode,
  RefreshCw,
  Sparkles,
} from 'lucide-react';
import { fetchFindings } from '../lib/api/endpoints';
import type { FindingDetail } from '../lib/api/types';
import {
  Card,
  Button,
  Badge,
  SeverityBadge,
  EmptyState,
} from '../components/ui/primitives';

export { type FindingDetail };

const DEFAULT_FALLBACK_FINDINGS: FindingDetail[] = [
  {
    findingId: 'fnd-sqli-101',
    siteId: 'site-shop-01',
    ruleId: 'RULE_ACTIVE_SQLI_ANOMALY',
    title: 'Unauthenticated SQL Injection in Authentication Endpoint',
    vulnType: 'SQL_INJECTION',
    cwe: 'CWE-89: SQL Injection',
    owasp: 'A03:2021-Injection',
    severity: 'CRITICAL',
    confidence: 'CONFIRMED',
    status: 'OPEN',
    targetUri: '/api/v1/auth/login',
    targetParameter: 'username',
    cvssScore: 9.8,
    evidenceRequest: `POST /api/v1/auth/login HTTP/1.1\nHost: shop.veltrix.io\nContent-Type: application/json\n\n{"username": "admin' OR 1=1 --", "password": "x"}`,
    evidenceResponse: `HTTP/1.1 200 OK\nContent-Type: application/json\n\n{"token": "eyJhbGciOi...", "role": "ADMIN", "bypassed": true}`,
    curlReproduction: `curl -s -X POST https://shop.veltrix.io/api/v1/auth/login \\\n  -H "Content-Type: application/json" \\\n  -d '{"username": "admin\\' OR 1=1 --", "password": "x"}'`,
    remediation: 'Use parameterized queries or an ORM with prepared statement bindings. Sanitize all dynamic SQL inputs.',
    discoveredAt: new Date(Date.now() - 1000 * 60 * 120).toISOString(),
  },
  {
    findingId: 'fnd-xss-102',
    siteId: 'site-shop-01',
    ruleId: 'RULE_ACTIVE_XSS_CANARY',
    title: 'Reflected Cross-Site Scripting (XSS) via Canary Probe',
    vulnType: 'CROSS_SITE_SCRIPTING',
    cwe: 'CWE-79: Improper Neutralization of Input During Web Page Generation',
    owasp: 'A03:2021-Injection',
    severity: 'HIGH',
    confidence: 'CONFIRMED',
    status: 'IN_REMEDIATION',
    targetUri: '/products/search?q=vxcanary7a8b9c',
    targetParameter: 'q',
    cvssScore: 7.5,
    evidenceRequest: `GET /products/search?q=vxcanary7a8b9c HTTP/1.1\nHost: shop.veltrix.io`,
    evidenceResponse: `HTTP/1.1 200 OK\nContent-Type: text/html\n\n<div class="search-term"><span>vxcanary7a8b9c</span></div>`,
    curlReproduction: `curl -s "https://shop.veltrix.io/products/search?q=vxcanary7a8b9c"`,
    remediation: 'Contextually encode all user-controlled inputs with HTML entity encoding before rendering into DOM contexts.',
    discoveredAt: new Date(Date.now() - 1000 * 60 * 240).toISOString(),
  },
  {
    findingId: 'fnd-tls-103',
    siteId: 'site-shop-01',
    ruleId: 'RULE_PASSIVE_TLS',
    title: 'TLS Certificate Expiring within 14 Days',
    vulnType: 'INSECURE_TLS',
    cwe: 'CWE-295: Improper Certificate Validation',
    owasp: 'A02:2021-Cryptographic Failures',
    severity: 'MEDIUM',
    confidence: 'HIGH',
    status: 'OPEN',
    targetUri: 'https://shop.veltrix.io',
    cvssScore: 5.3,
    evidenceRequest: `TLS Handshake ClientHello -> shop.veltrix.io:443`,
    evidenceResponse: `ServerCertificate: valid_to="2026-11-18T00:00:00Z" (Days remaining: 14)`,
    curlReproduction: `curl -Iv https://shop.veltrix.io 2>&1 | grep "expire date"`,
    remediation: 'Renew and deploy updated TLS certificate from trusted ACME / CA provider before expiration.',
    discoveredAt: new Date(Date.now() - 1000 * 60 * 360).toISOString(),
  },
];

export function FindingsPage() {
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedFinding, setSelectedFinding] = useState<FindingDetail | null>(null);
  const [copied, setCopied] = useState(false);
  const [statusOverrides, setStatusOverrides] = useState<Record<string, string>>({});

  const { data: rawFindings = DEFAULT_FALLBACK_FINDINGS, refetch } = useQuery<FindingDetail[]>({
    queryKey: ['findings', severityFilter],
    queryFn: () => fetchFindings(severityFilter !== 'ALL' ? { severity: severityFilter } : undefined),
    initialData: DEFAULT_FALLBACK_FINDINGS,
  });

  const findings = rawFindings.map((f) => ({
    ...f,
    status: (statusOverrides[f.findingId] || f.status) as FindingDetail['status'],
  }));

  const filtered = findings.filter((f) => {
    if (severityFilter !== 'ALL' && f.severity !== severityFilter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchTitle = f.title.toLowerCase().includes(q);
      const matchType = f.vulnType.toLowerCase().includes(q);
      const matchUri = f.targetUri.toLowerCase().includes(q);
      const matchCwe = (f.cwe || '').toLowerCase().includes(q);
      const matchRule = (f.ruleId || '').toLowerCase().includes(q);
      if (!matchTitle && !matchType && !matchUri && !matchCwe && !matchRule) return false;
    }
    return true;
  });

  const criticalCount = findings.filter((f) => f.severity === 'CRITICAL').length;
  const highCount = findings.filter((f) => f.severity === 'HIGH').length;
  const openCount = findings.filter((f) => f.status === 'OPEN').length;

  const handleCopy = (text: string) => {
    navigator.clipboard?.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleStatusChange = (findingId: string, newStatus: string) => {
    setStatusOverrides((prev) => ({ ...prev, [findingId]: newStatus }));
    if (selectedFinding?.findingId === findingId) {
      setSelectedFinding((prev) => (prev ? { ...prev, status: newStatus as any } : null));
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="flex items-center gap-2 text-xl font-bold text-white">
            <Bug className="h-5 w-5 text-rose-400" />
            Vulnerability Findings & Evidence Ledger
          </h1>
          <p className="text-xs text-slate-400">
            Detected security flaws, CWE/OWASP mappings, and reproducible evidence logs
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="secondary" size="sm" icon={RefreshCw} onClick={() => refetch()}>
            Refresh
          </Button>
          <Button variant="secondary" size="sm" icon={Filter} onClick={() => alert('Exporting findings ledger CSV...')}>
            Export CSV
          </Button>
        </div>
      </div>

      {/* Contract Notice Banner */}
      <div className="flex items-start gap-3 rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-4 text-cyan-200">
        <ShieldAlert className="mt-0.5 h-5 w-5 shrink-0 text-cyan-400" />
        <div className="text-xs">
          <span className="font-semibold text-cyan-300">Phase 8 Vulnerability Catalog Ready:</span>{' '}
          Findings generated during deep scans, passive analysis, and active probes are aggregated here with CWE ratings, confidence markers, and reproduction cURL commands.
        </div>
      </div>

      {/* KPI Stats Banner */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Card className="p-3">
          <div className="text-slate-400 text-xs">Total Recorded Flaws</div>
          <div className="text-xl font-bold font-mono text-white mt-0.5">{findings.length}</div>
        </Card>
        <Card className="p-3">
          <div className="text-rose-400 text-xs">Critical Vulnerabilities</div>
          <div className="text-xl font-bold font-mono text-rose-300 mt-0.5">{criticalCount}</div>
        </Card>
        <Card className="p-3">
          <div className="text-amber-400 text-xs">High Severity</div>
          <div className="text-xl font-bold font-mono text-amber-300 mt-0.5">{highCount}</div>
        </Card>
        <Card className="p-3">
          <div className="text-cyan-400 text-xs">Unresolved (Open)</div>
          <div className="text-xl font-bold font-mono text-cyan-300 mt-0.5">{openCount}</div>
        </Card>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex flex-wrap items-center gap-1.5">
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`rounded-lg px-3 py-1 text-xs font-semibold border transition ${severityFilter === sev
                  ? 'bg-cyan-500/10 border-cyan-500 text-cyan-300'
                  : 'bg-slate-900 border-slate-800 text-slate-400 hover:border-slate-700'
                }`}
            >
              {sev}
            </button>
          ))}
        </div>

        <div className="relative">
          <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-500" />
          <input
            type="text"
            placeholder="Search CWE, endpoint, vuln type..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full sm:w-64 rounded-lg border border-slate-800 bg-slate-900/60 pl-8 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
          />
        </div>
      </div>

      {/* Findings Table */}
      {filtered.length === 0 ? (
        <Card className="p-8">
          <EmptyState
            icon={Bug}
            title="No Security Findings Recorded"
            description="Verified findings from active vulnerability scans and correlation detections will appear here."
          />
        </Card>
      ) : (
        <Card className="overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-slate-800 bg-slate-900/50 text-[10px] uppercase tracking-wider text-slate-400">
                <tr>
                  <th className="px-4 py-3">Severity</th>
                  <th className="px-4 py-3">CVSS</th>
                  <th className="px-4 py-3">Vulnerability Flaw & Rule</th>
                  <th className="px-4 py-3">CWE Mapping</th>
                  <th className="px-4 py-3">Target Endpoint</th>
                  <th className="px-4 py-3">Confidence & Status</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono text-slate-300">
                {filtered.map((f) => (
                  <tr
                    key={f.findingId}
                    className="hover:bg-slate-800/30 transition cursor-pointer"
                    onClick={() => setSelectedFinding(f)}
                  >
                    <td className="px-4 py-3 font-sans">
                      <SeverityBadge severity={f.severity} />
                    </td>
                    <td className="px-4 py-3">
                      <span className="font-bold text-rose-300">{f.cvssScore}</span>
                    </td>
                    <td className="px-4 py-3 font-sans">
                      <div className="font-semibold text-white">{f.title}</div>
                      <div className="flex items-center gap-2 mt-1">
                        <span className="text-[11px] font-mono text-cyan-400">{f.vulnType}</span>
                        {f.ruleId && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300 border border-slate-700">
                            {f.ruleId}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3 font-mono text-slate-400 text-[11px]">
                      {f.cwe || 'N/A'}
                    </td>
                    <td className="px-4 py-3 font-mono text-slate-300">
                      {f.targetUri}
                    </td>
                    <td className="px-4 py-3 font-sans">
                      <div className="flex flex-col gap-1">
                        {f.confidence && (
                          <span className="inline-flex items-center gap-1 font-mono text-[10px] px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-300 border border-purple-500/20 w-fit">
                            <Sparkles className="h-2.5 w-2.5" />
                            {f.confidence}
                          </span>
                        )}
                        <Badge
                          tone={
                            f.status === 'RESOLVED'
                              ? 'success'
                              : f.status === 'IN_REMEDIATION'
                                ? 'medium'
                                : 'critical'
                          }
                        >
                          {f.status}
                        </Badge>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-right font-sans">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedFinding(f);
                        }}
                        className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold"
                      >
                        Inspect Evidence →
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {/* Finding Evidence Drawer / Modal */}
      {selectedFinding && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <Card className="w-full max-w-2xl border-slate-700 bg-slate-900 shadow-2xl p-6 space-y-5 animate-in fade-in zoom-in-95 max-h-[90vh] overflow-y-auto">
            <div className="flex items-start justify-between border-b border-slate-800 pb-3">
              <div>
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={selectedFinding.severity} />
                  <span className="font-mono text-xs font-bold text-rose-400">
                    CVSS {selectedFinding.cvssScore}
                  </span>
                  <span className="font-mono text-xs text-slate-400">
                    {selectedFinding.findingId}
                  </span>
                  {selectedFinding.ruleId && (
                    <span className="font-mono text-xs px-2 py-0.5 rounded bg-slate-800 text-cyan-300 border border-slate-700">
                      {selectedFinding.ruleId}
                    </span>
                  )}
                  {selectedFinding.confidence && (
                    <span className="font-mono text-xs px-2 py-0.5 rounded bg-purple-500/15 text-purple-300 border border-purple-500/30">
                      {selectedFinding.confidence}
                    </span>
                  )}
                </div>
                <h2 className="text-base font-bold text-white mt-1.5">{selectedFinding.title}</h2>
                <div className="flex items-center gap-2 text-xs text-slate-400 mt-1 font-mono">
                  <span>{selectedFinding.cwe}</span> • <span>{selectedFinding.owasp}</span>
                </div>
              </div>
              <button
                onClick={() => setSelectedFinding(null)}
                className="rounded-lg p-1 text-slate-400 hover:bg-slate-800 hover:text-white"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            {/* Target Endpoint */}
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs flex justify-between items-center">
              <div>
                <span className="text-slate-500">Target URI: </span>
                <span className="text-cyan-300 font-semibold">{selectedFinding.targetUri}</span>
                {selectedFinding.targetParameter && (
                  <span className="ml-2 text-slate-400">(Param: {selectedFinding.targetParameter})</span>
                )}
              </div>
              <Badge tone="info">{selectedFinding.vulnType}</Badge>
            </div>

            {/* Reproducible Evidence Section */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-bold text-white flex items-center gap-1.5">
                  <Terminal className="h-3.5 w-3.5 text-cyan-400" />
                  Reproducible PoC Command
                </h3>
                <Button
                  variant="ghost"
                  size="sm"
                  icon={copied ? Check : Copy}
                  onClick={() => handleCopy(selectedFinding.curlReproduction)}
                >
                  {copied ? 'Copied' : 'Copy cURL'}
                </Button>
              </div>
              <pre className="p-3 rounded bg-slate-950 border border-slate-800 font-mono text-xs text-emerald-300 overflow-x-auto">
                {selectedFinding.curlReproduction}
              </pre>
            </div>

            {/* Evidence HTTP Logs */}
            <div className="space-y-2">
              <h3 className="text-xs font-bold text-white flex items-center gap-1.5">
                <FileCode className="h-3.5 w-3.5 text-cyan-400" />
                Evidence HTTP Exchange
              </h3>
              <div className="space-y-1.5">
                <div className="text-[10px] text-slate-500 font-mono uppercase">Request Payload</div>
                <pre className="p-2.5 rounded bg-slate-950 border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto">
                  {selectedFinding.evidenceRequest}
                </pre>
                <div className="text-[10px] text-slate-500 font-mono uppercase">Server Response (Bypass Proof)</div>
                <pre className="p-2.5 rounded bg-slate-950 border border-slate-800 font-mono text-[11px] text-amber-200 overflow-x-auto">
                  {selectedFinding.evidenceResponse}
                </pre>
              </div>
            </div>

            {/* Remediation Guidance */}
            <div className="p-3.5 rounded-lg bg-emerald-950/20 border border-emerald-800/40 text-xs text-emerald-200 space-y-1">
              <div className="font-bold flex items-center gap-1.5 text-emerald-300">
                <ShieldCheck className="h-4 w-4" />
                Remediation Guidance
              </div>
              <p className="text-[11px] leading-relaxed text-emerald-200/90">
                {selectedFinding.remediation}
              </p>
            </div>

            {/* Status Change & Footer */}
            <div className="flex flex-wrap items-center justify-between gap-3 pt-3 border-t border-slate-800">
              <div className="flex items-center gap-2 text-xs">
                <span className="text-slate-400">Status:</span>
                <select
                  value={selectedFinding.status}
                  onChange={(e) => handleStatusChange(selectedFinding.findingId, e.target.value)}
                  className="bg-slate-950 border border-slate-800 rounded px-2 py-1 text-white text-xs"
                >
                  <option value="OPEN">OPEN</option>
                  <option value="CONFIRMED">CONFIRMED</option>
                  <option value="IN_REMEDIATION">IN_REMEDIATION</option>
                  <option value="RESOLVED">RESOLVED</option>
                  <option value="ACCEPTED_RISK">ACCEPTED_RISK</option>
                  <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
                </select>
              </div>

              <Button variant="ghost" size="sm" onClick={() => setSelectedFinding(null)}>
                Close Evidence
              </Button>
            </div>
          </Card>
        </div>
      )}
    </div>
  );
}
