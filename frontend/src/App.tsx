import { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Cpu,
  CheckCircle2,
  Globe,
  Key,
  Flame,
} from 'lucide-react';
import { PLATFORM_INFO } from '@veltrix/shared';
import { WebsiteInventory } from './components/WebsiteInventory';
import { IntegrationManagement } from './components/IntegrationManagement';
import { WebsiteAttackMonitoring } from './components/WebsiteAttackMonitoring';
import { fetchWebsites, fetchIntegrations } from './api';

export default function App() {
  const [activeTab, setActiveTab] = useState<'overview' | 'websites' | 'integrations' | 'web-monitoring' | 'modules'>('overview');
  const [backendStatus, setBackendStatus] = useState<'ONLINE' | 'OFFLINE' | 'CHECKING'>('CHECKING');
  const [websiteCount, setWebsiteCount] = useState<number | null>(null);
  const [integrationCount, setIntegrationCount] = useState<number | null>(null);

  useEffect(() => {
    // Probe backend health and fetch high-level asset summary
    fetch('/health')
      .then((res) => {
        if (res.ok) {
          setBackendStatus('ONLINE');
          fetchWebsites()
            .then((res) => setWebsiteCount(res.total ?? res.sites.length))
            .catch(() => setWebsiteCount(null));
          fetchIntegrations()
            .then((res) => setIntegrationCount(res.total ?? res.integrations.length))
            .catch(() => setIntegrationCount(null));
        } else {
          setBackendStatus('OFFLINE');
        }
      })
      .catch(() => {
        setBackendStatus('OFFLINE');
      });
  }, [activeTab]);

  return (
    <div className="min-h-screen bg-[#0A0F1D] text-slate-100 flex flex-col font-sans">
      {/* Top Navbar */}
      <header className="border-b border-slate-800 bg-[#0D1527]/80 backdrop-blur sticky top-0 z-50 px-6 py-4 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
            <ShieldAlert className="w-6 h-6 text-slate-950 stroke-[2.5]" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-bold text-xl tracking-wider text-white">
                {PLATFORM_INFO.name}
              </span>
              <span className="px-2 py-0.5 text-xs font-semibold rounded bg-cyan-950/80 text-cyan-400 border border-cyan-800/60">
                v{PLATFORM_INFO.version}
              </span>
              <span className="px-2 py-0.5 text-[11px] font-medium rounded bg-rose-950/80 text-rose-400 border border-rose-800/60">
                Phase 7: Web Attack Monitoring
              </span>
            </div>
            <p className="text-xs text-slate-400">{PLATFORM_INFO.tagline}</p>
          </div>
        </div>

        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2 text-xs px-3 py-1.5 rounded-full border bg-slate-900/80">
            <span
              className={`w-2 h-2 rounded-full ${
                backendStatus === 'ONLINE'
                  ? 'bg-emerald-400 animate-pulse'
                  : 'bg-amber-400'
              }`}
            ></span>
            <span className={backendStatus === 'ONLINE' ? 'text-emerald-400' : 'text-amber-400'}>
              API GATEWAY: {backendStatus}
            </span>
          </div>
          <div className="text-xs text-slate-400 bg-slate-800/60 border border-slate-700/60 px-3 py-1.5 rounded">
            TENANT: <span className="text-cyan-400 font-mono">org-enterprise-01 (Simulated)</span>
          </div>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-6 space-y-6">
        {/* Navigation Tabs Bar */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center space-x-1 sm:space-x-2">
            <button
              onClick={() => setActiveTab('overview')}
              className={`flex items-center space-x-2 px-4 py-2 text-sm font-medium rounded-lg transition-colors ${
                activeTab === 'overview'
                  ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <Cpu className="w-4 h-4" />
              <span>Platform Overview</span>
            </button>
            <button
              onClick={() => setActiveTab('websites')}
              className={`flex items-center space-x-2 px-4 py-2 text-sm font-medium rounded-lg transition-colors ${
                activeTab === 'websites'
                  ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <Globe className="w-4 h-4" />
              <span>Website Assets</span>
              {websiteCount !== null && (
                <span className="px-1.5 py-0.2 text-[10px] rounded-full bg-slate-800 text-slate-300 font-mono border border-slate-700">
                  {websiteCount}
                </span>
              )}
            </button>
            <button
              onClick={() => setActiveTab('integrations')}
              className={`flex items-center space-x-2 px-4 py-2 text-sm font-medium rounded-lg transition-colors ${
                activeTab === 'integrations'
                  ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <Key className="w-4 h-4" />
              <span>Integrations & Telemetry</span>
              {integrationCount !== null && (
                <span className="px-1.5 py-0.2 text-[10px] rounded-full bg-slate-800 text-slate-300 font-mono border border-slate-700">
                  {integrationCount}
                </span>
              )}
            </button>
            <button
              onClick={() => setActiveTab('web-monitoring')}
              className={`flex items-center space-x-2 px-4 py-2 text-sm font-medium rounded-lg transition-colors ${
                activeTab === 'web-monitoring'
                  ? 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <Flame className="w-4 h-4 text-rose-400" />
              <span>Web Attack Monitoring</span>
            </button>
            <button
              onClick={() => setActiveTab('modules')}
              className={`flex items-center space-x-2 px-4 py-2 text-sm font-medium rounded-lg transition-colors ${
                activeTab === 'modules'
                  ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <CheckCircle2 className="w-4 h-4" />
              <span>System Modules</span>
            </button>
          </div>
        </div>

        {/* Tab Content Rendering */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            {/* Mission Statement Hero */}
            <div className="bg-gradient-to-r from-slate-900/90 to-cyan-950/30 border border-slate-800 rounded-xl p-8 relative overflow-hidden">
              <div className="relative z-10 max-w-3xl space-y-4">
                <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-cyan-950/80 border border-cyan-800/60 text-cyan-400 text-xs font-semibold">
                  <span>Autonomous Defense Operations Ready</span>
                </div>
                <h1 className="text-3xl font-extrabold text-white tracking-tight">
                  Unified Cyber Threat Detection & Continuous Website Security
                </h1>
                <p className="text-sm text-slate-300 leading-relaxed">
                  VELTRIX unifies behavioral detection with autonomous defense. Built to monitor multi-cloud infrastructure and website applications, correlate complex multi-stage attacks, and enforce rapid, authorized containment.
                </p>
                <div className="flex flex-wrap gap-4 pt-2">
                  <button
                    onClick={() => setActiveTab('web-monitoring')}
                    className="px-4 py-2 bg-gradient-to-r from-rose-500 to-amber-600 hover:from-rose-400 hover:to-amber-500 text-slate-950 font-bold text-sm rounded-lg shadow-lg shadow-rose-500/20 transition flex items-center space-x-2"
                  >
                    <Flame className="w-4 h-4" />
                    <span>View Attack Monitoring</span>
                  </button>
                  <button
                    onClick={() => setActiveTab('websites')}
                    className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-sm font-medium rounded-lg border border-slate-700 transition flex items-center space-x-2"
                  >
                    <Globe className="w-4 h-4" />
                    <span>Manage Website Assets</span>
                  </button>
                </div>
              </div>
            </div>

            {/* Architecture Overview Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="bg-[#0D1527] border border-slate-800 rounded-lg p-5 space-y-3">
                <div className="w-8 h-8 rounded bg-cyan-950 text-cyan-400 flex items-center justify-center font-bold">1</div>
                <h3 className="font-semibold text-white">Event Telemetry Pipeline</h3>
                <p className="text-xs text-slate-400">
                  Sub-millisecond ingestion supporting Node.js SDK, reverse proxy log collectors (Nginx/Apache), and cloud perimeter WAFs.
                </p>
              </div>
              <div className="bg-[#0D1527] border border-slate-800 rounded-lg p-5 space-y-3">
                <div className="w-8 h-8 rounded bg-rose-950 text-rose-400 flex items-center justify-center font-bold">2</div>
                <h3 className="font-semibold text-white">Attack Correlation Engine</h3>
                <p className="text-xs text-slate-400">
                  Real-time pattern detection (SQLi, XSS, Path Traversal, Bot Recon, Auth Tampering) with 4-tier confidence classification.
                </p>
              </div>
              <div className="bg-[#0D1527] border border-slate-800 rounded-lg p-5 space-y-3">
                <div className="w-8 h-8 rounded bg-emerald-950 text-emerald-400 flex items-center justify-center font-bold">3</div>
                <h3 className="font-semibold text-white">Explainable Risk Scoring</h3>
                <p className="text-xs text-slate-400">
                  Deterministic mathematical risk scoring (0–100) combining base severity, frequency, asset criticality, threat intel, and vuln match.
                </p>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'websites' && <WebsiteInventory />}

        {activeTab === 'integrations' && <IntegrationManagement />}

        {activeTab === 'web-monitoring' && <WebsiteAttackMonitoring />}

        {activeTab === 'modules' && (
          <div className="bg-[#0D1527] border border-slate-800 rounded-lg p-6 space-y-4">
            <h2 className="text-lg font-semibold text-white flex items-center space-x-2">
              <CheckCircle2 className="w-5 h-5 text-emerald-400" />
              <span>Specification Modules Status (Phase 7 Active)</span>
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
              <div className="p-3 bg-slate-900/60 rounded border border-slate-800 flex items-start space-x-2">
                <span className="text-emerald-400 font-mono font-bold">TASK-701:</span>
                <span className="text-slate-300">Website Attack Event Classification & 4-Tier Confidence Model</span>
              </div>
              <div className="p-3 bg-slate-900/60 rounded border border-slate-800 flex items-start space-x-2">
                <span className="text-emerald-400 font-mono font-bold">TASK-702:</span>
                <span className="text-slate-300">SQL Injection Probing & Exploitation Detection (`RULE-101`)</span>
              </div>
              <div className="p-3 bg-slate-900/60 rounded border border-slate-800 flex items-start space-x-2">
                <span className="text-emerald-400 font-mono font-bold">TASK-703:</span>
                <span className="text-slate-300">Cross-Site Scripting (XSS) Probing & Injection Detection (`RULE-102`)</span>
              </div>
              <div className="p-3 bg-slate-900/60 rounded border border-slate-800 flex items-start space-x-2">
                <span className="text-emerald-400 font-mono font-bold">TASK-704:</span>
                <span className="text-slate-300">Path Traversal & Local File Inclusion Detection (`RULE-103`)</span>
              </div>
              <div className="p-3 bg-slate-900/60 rounded border border-slate-800 flex items-start space-x-2">
                <span className="text-emerald-400 font-mono font-bold">TASK-705:</span>
                <span className="text-slate-300">Malicious Bot Activity (`RULE-104`) & Auth Flow Tampering (`RULE-105`)</span>
              </div>
              <div className="p-3 bg-slate-900/60 rounded border border-slate-800 flex items-start space-x-2">
                <span className="text-emerald-400 font-mono font-bold">TASK-706:</span>
                <span className="text-slate-300">Multi-Stage Attack Correlation Engine & Chronological Incident Timelines</span>
              </div>
              <div className="p-3 bg-slate-900/60 rounded border border-slate-800 flex items-start space-x-2">
                <span className="text-emerald-400 font-mono font-bold">TASK-707:</span>
                <span className="text-slate-300">Explainable Mathematical Risk Scoring Engine with Vulnerability Surface Overlap</span>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800 bg-[#0D1527] py-4 px-6 text-center text-xs text-slate-500">
        VELTRIX Cybersecurity Platform — Phase 7: Web Attack Monitoring, Correlation & Risk Scoring
      </footer>
    </div>
  );
}
