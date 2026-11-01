import { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Flame,
  AlertTriangle,
  Clock,
  Globe,
  RefreshCw,
  Activity,
  Layers,
} from 'lucide-react';
import type { WebsiteAsset, Detection, Incident } from '@veltrix/shared';
import {
  fetchWebsites,
  fetchWebDetections,
  fetchWebIncidents,
  fetchSiteRiskSummary,
  fetchSiteTimeline,
  updateIncidentStatus,
} from '../api';

export function WebsiteAttackMonitoring() {
  const [websites, setWebsites] = useState<WebsiteAsset[]>([]);
  const [selectedSiteId, setSelectedSiteId] = useState<string>('');
  const [detections, setDetections] = useState<Detection[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [riskSummary, setRiskSummary] = useState<any>(null);
  const [timeline, setTimeline] = useState<any[]>([]);
  const [activeSubView, setActiveSubView] = useState<'overview' | 'incidents' | 'detections' | 'timeline'>('overview');
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Load registered websites on mount
  useEffect(() => {
    fetchWebsites()
      .then((res) => {
        setWebsites(res.sites || []);
        if (res.sites && res.sites.length > 0 && !selectedSiteId) {
          const firstSite = res.sites[0];
          if (firstSite) setSelectedSiteId(firstSite.siteId);
        }
      })
      .catch((err) => {
        setError(err.message || 'Failed to load websites');
      });
  }, []);

  // Fetch telemetry whenever selected website or active subview changes
  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [detRes, incRes] = await Promise.all([
        fetchWebDetections(selectedSiteId || undefined),
        fetchWebIncidents(selectedSiteId || undefined),
      ]);
      setDetections(detRes.items || []);
      setIncidents(incRes.items || []);

      if (selectedSiteId) {
        try {
          const [summary, tl] = await Promise.all([
            fetchSiteRiskSummary(selectedSiteId),
            fetchSiteTimeline(selectedSiteId),
          ]);
          setRiskSummary(summary);
          setTimeline(tl.items || []);
        } catch {
          setRiskSummary(null);
          setTimeline([]);
        }
      } else {
        setRiskSummary(null);
        setTimeline([]);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to query attack monitoring data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadData();
  }, [selectedSiteId]);

  // Handle quick incident containment
  const handleContainIncident = async (incidentId: string) => {
    try {
      await updateIncidentStatus(
        incidentId,
        'CONTAINED',
        'Incident acknowledged and marked CONTAINED by SOC analyst; response action recommendations require Phase 10 execution.'
      );
      void loadData();
    } catch (err: any) {
      alert(`Error containing incident: ${err.message}`);
    }
  };

  // Severity & Confidence badge helpers
  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return <span className="px-2 py-0.5 text-xs font-bold rounded bg-rose-950/80 text-rose-400 border border-rose-800">CRITICAL</span>;
      case 'HIGH':
        return <span className="px-2 py-0.5 text-xs font-bold rounded bg-amber-950/80 text-amber-400 border border-amber-800">HIGH</span>;
      case 'MEDIUM':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-cyan-950/80 text-cyan-400 border border-cyan-800">MEDIUM</span>;
      default:
        return <span className="px-2 py-0.5 text-xs font-medium rounded bg-slate-800 text-slate-300 border border-slate-700">LOW</span>;
    }
  };

  const getConfidenceBadge = (conf?: string) => {
    switch (conf) {
      case 'CONFIRMED_EXPLOITATION':
        return <span className="px-2 py-0.5 text-[11px] font-bold rounded bg-red-900/90 text-red-100 border border-red-700">CONFIRMED EXPLOIT</span>;
      case 'POTENTIAL_EXPLOITATION':
        return <span className="px-2 py-0.5 text-[11px] font-semibold rounded bg-orange-950/80 text-orange-300 border border-orange-800">POTENTIAL EXPLOIT</span>;
      case 'BLOCKED_ATTEMPT':
        return <span className="px-2 py-0.5 text-[11px] font-medium rounded bg-emerald-950/80 text-emerald-300 border border-emerald-800">BLOCKED PROBE</span>;
      default:
        return <span className="px-2 py-0.5 text-[11px] font-medium rounded bg-slate-800 text-slate-300 border border-slate-700">SUSPICIOUS PROBE</span>;
    }
  };

  const getScoreColor = (score: number) => {
    if (score >= 75) return 'text-rose-400 border-rose-500 bg-rose-950/20';
    if (score >= 50) return 'text-amber-400 border-amber-500 bg-amber-950/20';
    if (score >= 25) return 'text-cyan-400 border-cyan-500 bg-cyan-950/20';
    return 'text-emerald-400 border-emerald-500 bg-emerald-950/20';
  };

  // Group attack types for quick breakdown
  const sqliCount = detections.filter((d) => d.ruleId === 'RULE-101' || (d.evidence?.details as any)?.attackType === 'SQLI').length;
  const xssCount = detections.filter((d) => d.ruleId === 'RULE-102' || (d.evidence?.details as any)?.attackType === 'XSS').length;
  const traversalCount = detections.filter((d) => d.ruleId === 'RULE-103' || (d.evidence?.details as any)?.attackType === 'PATH_TRAVERSAL').length;
  const botCount = detections.filter((d) => d.ruleId === 'RULE-104' || (d.evidence?.details as any)?.attackType === 'BOT_ACTIVITY').length;
  const authTamperingCount = detections.filter((d) => d.ruleId === 'RULE-105' || (d.evidence?.details as any)?.attackType === 'AUTH_TAMPERING').length;

  return (
    <div className="space-y-6">
      {/* Header & Asset Filter Toolbar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/60 p-5 rounded-xl border border-slate-800 backdrop-blur">
        <div>
          <div className="flex items-center space-x-2">
            <Flame className="w-5 h-5 text-rose-500 animate-pulse" />
            <h2 className="text-xl font-bold text-white tracking-wide">Website Attack Monitoring & Correlation</h2>
            <span className="px-2 py-0.5 text-xs font-semibold rounded bg-rose-950/60 text-rose-400 border border-rose-800/60">
              Phase 7 Active
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Real-time multi-stage injection, traversal, and bot attack detection with explainable risk scoring.
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <div className="flex items-center space-x-2 bg-slate-950/80 px-3 py-1.5 rounded-lg border border-slate-800">
            <Globe className="w-4 h-4 text-cyan-400" />
            <select
              value={selectedSiteId}
              onChange={(e) => setSelectedSiteId(e.target.value)}
              className="bg-transparent text-sm text-slate-200 outline-none cursor-pointer"
            >
              <option value="" className="bg-slate-900 text-slate-200">All Website Assets</option>
              {websites.map((w) => (
                <option key={w.siteId} value={w.siteId} className="bg-slate-900 text-slate-200">
                  {w.primaryDomain} ({w.environment})
                </option>
              ))}
            </select>
          </div>

          <button
            onClick={() => void loadData()}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-lg bg-rose-950/50 border border-rose-800/80 text-rose-300 text-sm flex items-center space-x-2">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Top Attack Posture & Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Risk Score Gauge */}
        <div className={`p-4 rounded-xl border flex flex-col justify-between ${getScoreColor(riskSummary?.currentRiskScore || 0)}`}>
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Website Risk Score</span>
            <ShieldAlert className="w-5 h-5 opacity-80" />
          </div>
          <div className="my-2 flex items-baseline space-x-2">
            <span className="text-3xl font-extrabold font-mono tracking-tight">
              {riskSummary?.currentRiskScore ?? 0}
            </span>
            <span className="text-xs font-medium text-slate-400">/ 100</span>
            <span className="ml-auto px-2 py-0.5 text-xs font-bold rounded uppercase">
              {riskSummary?.currentRiskBand || 'LOW'}
            </span>
          </div>
          <p className="text-[11px] text-slate-400 truncate">
            {riskSummary?.factors?.calculationExplanation || 'Zero active attack threats detected.'}
          </p>
        </div>

        {/* Total Incidents */}
        <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/50 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Correlated Incidents</span>
            <Layers className="w-5 h-5 text-indigo-400" />
          </div>
          <div className="my-2 flex items-baseline space-x-2">
            <span className="text-3xl font-extrabold font-mono text-white">{incidents.length}</span>
            <span className="text-xs text-slate-400">active attack group(s)</span>
          </div>
          <p className="text-[11px] text-slate-400">
            Grouped by source IP and 15m sliding windows
          </p>
        </div>

        {/* Total Detections */}
        <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/50 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Web Attack Detections</span>
            <Activity className="w-5 h-5 text-cyan-400" />
          </div>
          <div className="my-2 flex items-baseline space-x-2">
            <span className="text-3xl font-extrabold font-mono text-white">{detections.length}</span>
            <span className="text-xs text-slate-400">findings</span>
          </div>
          <p className="text-[11px] text-slate-400">
            SQLi, XSS, Path Traversal, Bot & Auth probes
          </p>
        </div>

        {/* Attack Surface Posture */}
        <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/50 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Target Surface</span>
            <Globe className="w-5 h-5 text-emerald-400" />
          </div>
          <div className="my-2">
            <span className="text-lg font-bold text-white font-mono truncate block">
              {riskSummary?.domain || (websites.find((w) => w.siteId === selectedSiteId)?.primaryDomain) || 'All Assets'}
            </span>
            <span className="text-xs text-emerald-400 font-medium">
              Env: {riskSummary?.environment || 'Multi-Tenant'}
            </span>
          </div>
          <p className="text-[11px] text-slate-400">
            Zero-trust telemetry verification active
          </p>
        </div>
      </div>

      {/* Attack Vectors Quick Breakdown */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        <div className="bg-slate-900/40 border border-slate-800/80 p-3 rounded-lg text-center">
          <span className="text-[11px] text-slate-400 font-medium">SQL Injection</span>
          <p className="text-lg font-bold text-rose-400 font-mono mt-0.5">{sqliCount}</p>
        </div>
        <div className="bg-slate-900/40 border border-slate-800/80 p-3 rounded-lg text-center">
          <span className="text-[11px] text-slate-400 font-medium">Cross-Site Scripting</span>
          <p className="text-lg font-bold text-amber-400 font-mono mt-0.5">{xssCount}</p>
        </div>
        <div className="bg-slate-900/40 border border-slate-800/80 p-3 rounded-lg text-center">
          <span className="text-[11px] text-slate-400 font-medium">Path Traversal / LFI</span>
          <p className="text-lg font-bold text-cyan-400 font-mono mt-0.5">{traversalCount}</p>
        </div>
        <div className="bg-slate-900/40 border border-slate-800/80 p-3 rounded-lg text-center">
          <span className="text-[11px] text-slate-400 font-medium">Bot & Scraper Recon</span>
          <p className="text-lg font-bold text-indigo-400 font-mono mt-0.5">{botCount}</p>
        </div>
        <div className="bg-slate-900/40 border border-slate-800/80 p-3 rounded-lg text-center col-span-2 sm:col-span-1">
          <span className="text-[11px] text-slate-400 font-medium">Auth Tampering</span>
          <p className="text-lg font-bold text-purple-400 font-mono mt-0.5">{authTamperingCount}</p>
        </div>
      </div>

      {/* View Sub-Tabs */}
      <div className="flex border-b border-slate-800 space-x-2">
        <button
          onClick={() => setActiveSubView('overview')}
          className={`px-4 py-2 text-xs font-semibold border-b-2 transition ${
            activeSubView === 'overview'
              ? 'border-cyan-400 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Correlated Incidents ({incidents.length})
        </button>
        <button
          onClick={() => setActiveSubView('detections')}
          className={`px-4 py-2 text-xs font-semibold border-b-2 transition ${
            activeSubView === 'detections'
              ? 'border-cyan-400 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Attack Detections Feed ({detections.length})
        </button>
        {selectedSiteId && (
          <button
            onClick={() => setActiveSubView('timeline')}
            className={`px-4 py-2 text-xs font-semibold border-b-2 transition ${
              activeSubView === 'timeline'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Chronological Timeline ({timeline.length})
          </button>
        )}
      </div>

      {/* Subview 1: Correlated Incidents Table */}
      {activeSubView === 'overview' && (
        <div className="space-y-4">
          {incidents.length === 0 ? (
            <div className="p-8 text-center text-slate-500 bg-slate-900/20 rounded-xl border border-slate-800/50">
              No correlated website attack incidents active.
            </div>
          ) : (
            <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/50">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950/80 text-slate-400 border-b border-slate-800">
                  <tr>
                    <th className="p-3">Incident Title & Entity</th>
                    <th className="p-3">Severity & Risk</th>
                    <th className="p-3">Confidence Tier</th>
                    <th className="p-3">Attack Stages</th>
                    <th className="p-3">Status</th>
                    <th className="p-3">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {incidents.map((inc) => (
                    <tr key={inc.incidentId} className="hover:bg-slate-800/30 transition">
                      <td className="p-3">
                        <div className="font-semibold text-slate-200">{inc.title}</div>
                        <div className="text-[11px] text-cyan-400 font-mono mt-0.5">
                          IP: {inc.sourceIp || 'Unknown'} | Domain: {inc.domain || inc.siteId || 'Global'}
                        </div>
                        {inc.suggestedResponses && inc.suggestedResponses.length > 0 && (
                          <div className="mt-1 flex flex-wrap items-center gap-1">
                            <span className="text-[10px] text-slate-400">Recommended:</span>
                            {inc.suggestedResponses.map((sr) => (
                              <span
                                key={sr}
                                className="px-1.5 py-0.5 text-[9px] font-mono rounded bg-slate-800 text-cyan-300 border border-slate-700"
                              >
                                {sr}
                              </span>
                            ))}
                            <span className="text-[9px] text-slate-500 italic">(Recommended Response - Phase 10)</span>
                          </div>
                        )}
                      </td>
                      <td className="p-3">
                        <div className="flex items-center space-x-2">
                          {getSeverityBadge(inc.severity)}
                          <span className="font-mono font-bold text-slate-300">{inc.riskScore}/100</span>
                        </div>
                      </td>
                      <td className="p-3">
                        {getConfidenceBadge(inc.highestConfidence)}
                      </td>
                      <td className="p-3">
                        <div className="flex flex-wrap gap-1">
                          {(inc.attackTypes || ['ATTACK']).map((at) => (
                            <span key={at} className="px-1.5 py-0.5 text-[10px] rounded bg-slate-800 text-slate-300 font-mono border border-slate-700">
                              {at}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="p-3">
                        <span className={`px-2 py-0.5 text-xs font-semibold rounded ${
                          inc.status === 'NEW' ? 'bg-rose-950 text-rose-300' :
                          inc.status === 'CONTAINED' ? 'bg-cyan-950 text-cyan-300' :
                          inc.status === 'RESOLVED' ? 'bg-emerald-950 text-emerald-300' :
                          'bg-amber-950 text-amber-300'
                        }`}>
                          {inc.status}
                        </span>
                      </td>
                      <td className="p-3">
                        {inc.status === 'NEW' && (
                          <button
                            onClick={() => void handleContainIncident(inc.incidentId)}
                            className="px-2.5 py-1 text-[11px] font-medium rounded bg-rose-900/60 hover:bg-rose-800 text-rose-200 border border-rose-700 transition"
                          >
                            Mark Contained
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Subview 2: Attack Detections Feed */}
      {activeSubView === 'detections' && (
        <div className="space-y-4">
          {detections.length === 0 ? (
            <div className="p-8 text-center text-slate-500 bg-slate-900/20 rounded-xl border border-slate-800/50">
              No web attack detections recorded.
            </div>
          ) : (
            <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/50">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950/80 text-slate-400 border-b border-slate-800">
                  <tr>
                    <th className="p-3">Detection Rule</th>
                    <th className="p-3">Target URI / Path</th>
                    <th className="p-3">Attacker IP</th>
                    <th className="p-3">Severity & Confidence</th>
                    <th className="p-3">Detected At</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {detections.map((d) => {
                    const dt = (d.evidence?.details || {}) as any;
                    return (
                      <tr key={d.detectionId} className="hover:bg-slate-800/30 transition">
                        <td className="p-3">
                          <div className="font-semibold text-slate-200">{d.title}</div>
                          <div className="text-[11px] text-slate-400 font-mono mt-0.5">{d.ruleId}</div>
                        </td>
                        <td className="p-3">
                          <div className="font-mono text-cyan-300 truncate max-w-xs">{dt.requestUri || '/'}</div>
                          <div className="text-[10px] text-slate-400">Method: {dt.httpMethod || 'GET'}</div>
                        </td>
                        <td className="p-3 font-mono text-slate-300">
                          {d.evidence?.targetEntity?.value || dt.sourceIp || 'Unknown'}
                        </td>
                        <td className="p-3">
                          <div className="flex items-center space-x-2">
                            {getSeverityBadge(d.severity)}
                            {getConfidenceBadge(dt.confidenceLevel)}
                          </div>
                        </td>
                        <td className="p-3 text-slate-400 font-mono text-[11px]">
                          {new Date(d.detectedAt).toLocaleTimeString()}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Subview 3: Chronological Attack Timeline */}
      {activeSubView === 'timeline' && (
        <div className="space-y-4">
          {timeline.length === 0 ? (
            <div className="p-8 text-center text-slate-500 bg-slate-900/20 rounded-xl border border-slate-800/50">
              No timeline events recorded for this website asset.
            </div>
          ) : (
            <div className="relative border-l border-slate-800 ml-4 space-y-6 py-2">
              {timeline.map((item, idx) => (
                <div key={idx} className="relative pl-6">
                  <span className="absolute -left-2 top-1.5 w-4 h-4 rounded-full bg-slate-900 border-2 border-cyan-400"></span>
                  <div className="bg-slate-900/60 p-4 rounded-xl border border-slate-800/80">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-sm text-slate-200">{item.title}</span>
                      <span className="text-xs text-slate-500 font-mono flex items-center space-x-1">
                        <Clock className="w-3.5 h-3.5" />
                        <span>{new Date(item.timestamp).toLocaleString()}</span>
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 mt-1">{item.description}</p>
                    <div className="flex items-center space-x-3 mt-2 text-[11px] font-mono">
                      {item.sourceIp && <span className="text-cyan-400">IP: {item.sourceIp}</span>}
                      {item.severity && <span>{getSeverityBadge(item.severity)}</span>}
                      {item.type && <span className="text-slate-500">[{item.type}]</span>}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
