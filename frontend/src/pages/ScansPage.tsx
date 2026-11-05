import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  ScanLine,
  AlertTriangle,
  ShieldCheck,
  Play,
  RefreshCw,
  StopCircle,
  Globe,
  X,
  Lock,
} from 'lucide-react';
import { fetchWebsites, fetchScans, createScan, abortScan } from '../lib/api/endpoints';
import {
  Card,
  Button,
  Badge,
  LoadingPanel,
  EmptyState,
} from '../components/ui/primitives';
import type { Tone } from '../lib/format';

export function ScansPage() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<'all' | 'running' | 'completed'>('all');
  const [showLaunchModal, setShowLaunchModal] = useState(false);

  // Form state
  const [selectedSiteId, setSelectedSiteId] = useState('');
  const [selectedProfile, setSelectedProfile] = useState<'PASSIVE_BASELINE' | 'STANDARD_ACTIVE' | 'FULL_AUDIT'>('STANDARD_ACTIVE');
  const [maxDepth, setMaxDepth] = useState(3);
  const [maxPages, setMaxPages] = useState(250);
  const [formError, setFormError] = useState<string | null>(null);

  const { data: scans = [], isLoading: scansLoading, refetch: refetchScans } = useQuery({
    queryKey: ['scans'],
    queryFn: () => fetchScans(),
  });

  const { data: websitesRes, isLoading: sitesLoading, refetch: refetchSites } = useQuery({
    queryKey: ['websites'],
    queryFn: () => fetchWebsites(),
  });

  const createMutation = useMutation({
    mutationFn: createScan,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] });
      setShowLaunchModal(false);
      setSelectedSiteId('');
      setFormError(null);
    },
    onError: (err: Error) => {
      setFormError(err.message || 'Failed to start scan.');
    },
  });

  const abortMutation = useMutation({
    mutationFn: abortScan,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] });
    },
  });

  const sites = websitesRes?.sites || [];
  const selectedSite = sites.find((s) => s.siteId === selectedSiteId);
  const isSiteVerified = selectedSite ? selectedSite.status === 'VERIFIED' && !selectedSite.scanBlocked : false;

  const filteredScans = scans.filter((scan) => {
    if (activeTab === 'running') return scan.status === 'RUNNING';
    if (activeTab === 'completed') return scan.status === 'COMPLETED' || scan.status === 'ABORTED' || scan.status === 'FAILED';
    return true;
  });

  const runningCount = scans.filter((s) => s.status === 'RUNNING').length;
  const verifiedSitesCount = sites.filter((s) => s.status === 'VERIFIED').length;
  const blockedSitesCount = sites.filter((s) => s.status !== 'VERIFIED' || s.scanBlocked).length;

  const handleAbort = (scanId: string) => {
    abortMutation.mutate(scanId);
  };

  const handleLaunch = (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedSite || !isSiteVerified) return;

    createMutation.mutate({
      siteId: selectedSite.siteId,
      profile: selectedProfile,
      maxDepth,
      maxPages,
    });
  };

  const formatStage = (stage: string) => {
    switch (stage) {
      case 'DISCOVERY':
        return 'Recon & DNS Scoping';
      case 'CRAWL':
        return 'Bounded Web Crawler';
      case 'PASSIVE_EVALUATION':
        return 'Passive Security Evaluation';
      case 'ACTIVE_PROBING':
        return 'Non-Destructive Active Probes';
      case 'REPORT_GENERATION':
        return 'Finalizing Evidence Report';
      default:
        return stage;
    }
  };

  const getStageTone = (status: string): Tone => {
    switch (status) {
      case 'RUNNING':
        return 'info';
      case 'COMPLETED':
        return 'success';
      case 'ABORTED':
        return 'critical';
      case 'FAILED':
        return 'critical';
      default:
        return 'medium';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="flex items-center gap-2 text-xl font-bold text-white">
            <ScanLine className="h-5 w-5 text-cyan-400" />
            Vulnerability Scans & Scope Verification
          </h1>
          <p className="text-xs text-slate-400">
            Authorized automated web security audits, SSRF-safe crawlers, and vulnerability probes
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="secondary"
            size="sm"
            icon={RefreshCw}
            onClick={() => {
              refetchScans();
              refetchSites();
            }}
          >
            Refresh
          </Button>

          <Button
            variant="primary"
            size="sm"
            icon={Play}
            onClick={() => {
              setShowLaunchModal(true);
              setFormError(null);
            }}
          >
            Launch Scan
          </Button>
        </div>
      </div>

      {/* Engine Status Banner */}
      <div className="flex items-start gap-3 rounded-xl border border-cyan-500/30 bg-cyan-500/10 p-3.5">
        <ShieldCheck className="h-5 w-5 text-cyan-400 shrink-0 mt-0.5" />
        <div className="text-xs space-y-1">
          <div className="font-semibold text-cyan-200">
            Phase 8 Backend Scan Engine Connected
          </div>
          <div className="text-slate-300">
            Active probes, SSRF-safe crawlers, and passive vulnerability detectors are wired with strict domain authorization enforcement.
          </div>
        </div>
      </div>

      {/* Target Asset Scope & Authorization Gate Section */}
      <Card className="p-4 space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-bold text-white flex items-center gap-2">
            <Globe className="h-4 w-4 text-cyan-400" />
            Target Asset Scope & Authorization Gate
          </h2>
          <span className="text-[11px] font-mono text-slate-500">
            Strict SSRF Scope Enforcement Active
          </span>
        </div>
        <p className="text-xs text-slate-400">
          Scans may only target assets in <strong className="text-emerald-300">VERIFIED</strong> status. Any target pending ownership confirmation is strictly blocked from crawler dispatch.
        </p>

        {sitesLoading ? (
          <LoadingPanel rows={2} />
        ) : sites.length === 0 ? (
          <div className="text-xs text-slate-500 italic py-2">No website assets registered in this organization.</div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
            {sites.map((site) => {
              const eligible = site.status === 'VERIFIED' && !site.scanBlocked;
              return (
                <div
                  key={site.siteId}
                  className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between"
                >
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-white text-xs">{site.name}</span>
                      <span className="font-mono text-[11px] text-cyan-400">{site.primaryDomain}</span>
                    </div>
                    <div className="flex items-center gap-2 mt-1">
                      <span className="text-[10px] text-slate-500 font-mono">{site.environment}</span>
                      <Badge tone={eligible ? 'success' : 'critical'}>
                        {site.status}
                      </Badge>
                    </div>
                  </div>

                  <div>
                    {eligible ? (
                      <button
                        onClick={() => {
                          setSelectedSiteId(site.siteId);
                          setShowLaunchModal(true);
                        }}
                        className="px-2.5 py-1 text-xs font-semibold rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 hover:bg-cyan-500/20"
                      >
                        Scan Asset
                      </button>
                    ) : (
                      <span className="text-[11px] font-mono text-slate-500 flex items-center gap-1">
                        <Lock className="h-3 w-3" />
                        Verification Gate
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </Card>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Card className="p-3">
          <div className="text-slate-400 text-xs">Total Scan Audits</div>
          <div className="text-xl font-bold font-mono text-white mt-0.5">{scans.length}</div>
        </Card>
        <Card className="p-3">
          <div className="text-cyan-400 text-xs">Active / In-Flight</div>
          <div className="text-xl font-bold font-mono text-cyan-300 mt-0.5">{runningCount}</div>
        </Card>
        <Card className="p-3">
          <div className="text-emerald-400 text-xs">Scope-Verified Targets</div>
          <div className="text-xl font-bold font-mono text-emerald-300 mt-0.5">{verifiedSitesCount}</div>
        </Card>
        <Card className="p-3">
          <div className="text-rose-400 text-xs">Blocked / Unverified Sites</div>
          <div className="text-xl font-bold font-mono text-rose-300 mt-0.5">{blockedSitesCount}</div>
        </Card>
      </div>

      {/* Scans Table / List */}
      <div className="space-y-3">
        <div className="flex items-center justify-between border-b border-slate-800 pb-2">
          <div className="flex items-center gap-2">
            {(['all', 'running', 'completed'] as const).map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`rounded-lg px-3 py-1.5 text-xs font-semibold capitalize transition ${
                  activeTab === tab
                    ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/40'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                {tab} Scans
              </button>
            ))}
          </div>

          <span className="text-xs text-slate-500 font-mono">
            Emergency Abort SLO: &lt;500ms
          </span>
        </div>

        {scansLoading && <LoadingPanel rows={4} />}

        {!scansLoading && filteredScans.length === 0 && (
          <EmptyState
            icon={ScanLine}
            title="No Scans Found"
            description={
              activeTab === 'all'
                ? 'Launch your first authorized vulnerability scan against a verified website.'
                : `No ${activeTab} scans in the assessment queue.`
            }
            action={
              <Button variant="primary" size="sm" icon={Play} onClick={() => setShowLaunchModal(true)}>
                Launch Scan
              </Button>
            }
          />
        )}

        <div className="space-y-3">
          {filteredScans.map((scan) => {
            const tone = getStageTone(scan.status);
            return (
              <Card key={scan.scanId} className="p-4 space-y-3">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div className="flex items-center gap-3">
                    <div className="flex flex-col items-center justify-center h-10 w-10 rounded-lg bg-cyan-500/10 border border-cyan-500/20 font-mono font-bold text-cyan-400">
                      <ScanLine className="h-5 w-5" />
                    </div>

                    <div>
                      <div className="flex items-center gap-2 font-mono text-xs">
                        <span className="font-bold text-white">{scan.scanId}</span>
                        <Badge tone={tone}>{scan.status}</Badge>
                        <span className="text-slate-400">Profile: {scan.profile}</span>
                      </div>
                      <div className="text-sm font-semibold text-slate-200 mt-0.5">
                        Target: <span className="font-mono text-cyan-300">{scan.targetDomain}</span>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    {scan.status === 'RUNNING' && (
                      <Button
                        variant="danger"
                        size="sm"
                        icon={StopCircle}
                        onClick={() => handleAbort(scan.scanId)}
                      >
                        Abort (500ms SLO)
                      </Button>
                    )}
                    <span className="text-xs font-mono text-slate-400">
                      Findings: <strong className="text-amber-400">{scan.findingsCount}</strong>
                    </span>
                  </div>
                </div>

                {/* Progress bar */}
                <div className="space-y-1.5 pt-1 font-mono text-[11px]">
                  <div className="flex justify-between text-slate-400">
                    <span>Stage: <strong className="text-white">{formatStage(scan.currentStage)}</strong></span>
                    <span>{scan.progressPercent}%</span>
                  </div>
                  <div className="w-full h-1.5 rounded-full bg-slate-950 overflow-hidden border border-slate-800">
                    <div
                      className={`h-full transition-all duration-500 ${
                        scan.status === 'COMPLETED'
                          ? 'bg-emerald-400'
                          : scan.status === 'ABORTED' || scan.status === 'FAILED'
                          ? 'bg-rose-400'
                          : 'bg-cyan-400'
                      }`}
                      style={{ width: `${scan.progressPercent}%` }}
                    />
                  </div>
                </div>
              </Card>
            );
          })}
        </div>
      </div>

      {/* Launch Scan Modal */}
      {showLaunchModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="w-full max-w-lg rounded-2xl border border-slate-800 bg-slate-900 shadow-2xl p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2 text-white font-bold text-base">
                <Play className="h-5 w-5 text-cyan-400" />
                Launch Vulnerability Scan
              </div>
              <button
                onClick={() => setShowLaunchModal(false)}
                className="text-slate-400 hover:text-white"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <form onSubmit={handleLaunch} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Target Website Asset
                </label>
                <select
                  value={selectedSiteId}
                  onChange={(e) => setSelectedSiteId(e.target.value)}
                  className="w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-xs text-white focus:border-cyan-500 focus:outline-none"
                  required
                >
                  <option value="">Select a registered website asset...</option>
                  {sites.map((s) => (
                    <option key={s.siteId} value={s.siteId}>
                      {s.name} ({s.primaryDomain}) — {s.status}
                    </option>
                  ))}
                </select>
              </div>

              {selectedSite && !isSiteVerified && (
                <div className="flex items-start gap-2.5 rounded-xl border border-amber-500/40 bg-amber-500/10 p-3 text-xs text-amber-300">
                  <Lock className="h-4 w-4 shrink-0 text-amber-400 mt-0.5" />
                  <div>
                    <span className="font-semibold text-amber-200">Domain Verification Required:</span> Active and passive vulnerability probes cannot be launched against unverified targets. Verify domain ownership in Website Details first.
                  </div>
                </div>
              )}

              {selectedSite && isSiteVerified && (
                <div className="flex items-start gap-2.5 rounded-xl border border-emerald-500/40 bg-emerald-500/10 p-3 text-xs text-emerald-300">
                  <ShieldCheck className="h-4 w-4 shrink-0 text-emerald-400 mt-0.5" />
                  <div>
                    <span className="font-semibold text-emerald-200">Domain Verified:</span> Scanning authorized under strict scope controls and rate limits.
                  </div>
                </div>
              )}

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Scanner Profile
                </label>
                <div className="space-y-2">
                  <label className="flex items-start gap-3 rounded-lg border border-slate-800 bg-slate-950/40 p-2.5 text-xs text-slate-300 cursor-pointer hover:border-slate-700">
                    <input
                      type="radio"
                      name="profile"
                      value="PASSIVE_BASELINE"
                      checked={selectedProfile === 'PASSIVE_BASELINE'}
                      onChange={() => setSelectedProfile('PASSIVE_BASELINE')}
                      className="mt-0.5"
                    />
                    <div>
                      <div className="font-semibold text-white">Passive Baseline</div>
                      <div className="text-[11px] text-slate-400">
                        TLS/SSL certificates, HTTP security headers (HSTS, CSP), insecure cookie flags, and server disclosures.
                      </div>
                    </div>
                  </label>

                  <label className="flex items-start gap-3 rounded-lg border border-slate-800 bg-slate-950/40 p-2.5 text-xs text-slate-300 cursor-pointer hover:border-slate-700">
                    <input
                      type="radio"
                      name="profile"
                      value="STANDARD_ACTIVE"
                      checked={selectedProfile === 'STANDARD_ACTIVE'}
                      onChange={() => setSelectedProfile('STANDARD_ACTIVE')}
                      className="mt-0.5"
                    />
                    <div>
                      <div className="font-semibold text-white">Standard Active (Safe)</div>
                      <div className="text-[11px] text-slate-400">
                        Includes Passive Baseline + Non-destructive Reflected XSS canary tokens and Open Redirect probes.
                      </div>
                    </div>
                  </label>

                  <label className="flex items-start gap-3 rounded-lg border border-slate-800 bg-slate-950/40 p-2.5 text-xs text-slate-300 cursor-pointer hover:border-slate-700">
                    <input
                      type="radio"
                      name="profile"
                      value="FULL_AUDIT"
                      checked={selectedProfile === 'FULL_AUDIT'}
                      onChange={() => setSelectedProfile('FULL_AUDIT')}
                      className="mt-0.5"
                    />
                    <div>
                      <div className="font-semibold text-white">Full Security Audit</div>
                      <div className="text-[11px] text-slate-400">
                        Bounded crawler + Passive evaluation + SQL injection anomaly probes + Path traversal & sensitive files checks.
                      </div>
                    </div>
                  </label>
                </div>
              </div>

              {/* Crawler Depth & Limits */}
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-[11px] font-medium text-slate-400 mb-1">Max Crawl Depth</label>
                  <input
                    type="number"
                    min={1}
                    max={10}
                    value={maxDepth}
                    onChange={(e) => setMaxDepth(Number(e.target.value))}
                    className="w-full rounded bg-slate-950 border border-slate-800 px-3 py-1.5 text-white font-mono text-xs focus:outline-none focus:border-cyan-500"
                  />
                </div>
                <div>
                  <label className="block text-[11px] font-medium text-slate-400 mb-1">Max Crawl Pages</label>
                  <input
                    type="number"
                    min={10}
                    max={1000}
                    value={maxPages}
                    onChange={(e) => setMaxPages(Number(e.target.value))}
                    className="w-full rounded bg-slate-950 border border-slate-800 px-3 py-1.5 text-white font-mono text-xs focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>

              {formError && (
                <div className="flex items-center gap-2 rounded-lg border border-rose-500/40 bg-rose-500/10 p-2.5 text-xs text-rose-300">
                  <AlertTriangle className="h-4 w-4 shrink-0 text-rose-400" />
                  <span>{formError}</span>
                </div>
              )}

              <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
                <Button variant="ghost" size="sm" type="button" onClick={() => setShowLaunchModal(false)}>
                  Cancel
                </Button>
                <Button
                  variant="primary"
                  size="sm"
                  type="submit"
                  disabled={!selectedSite || !isSiteVerified || createMutation.isPending}
                  icon={Play}
                >
                  {createMutation.isPending ? 'Launching...' : 'Start Assessment'}
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
