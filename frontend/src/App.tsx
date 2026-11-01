import { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Terminal,
  Cpu,
  Lock,
  Layers,
  CheckCircle2,
  Globe,
  Key,
} from 'lucide-react';
import { PLATFORM_INFO } from '@veltrix/shared';
import { WebsiteInventory } from './components/WebsiteInventory';
import { IntegrationManagement } from './components/IntegrationManagement';
import { fetchWebsites, fetchIntegrations } from './api';

export default function App() {
  const [activeTab, setActiveTab] = useState<'overview' | 'websites' | 'integrations' | 'modules'>('overview');
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
              <span className="px-2 py-0.5 text-[11px] font-medium rounded bg-emerald-950/80 text-emerald-400 border border-emerald-800/60">
                Phase 6: Website Assets
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
            {/* Phase 6 Operational Banner */}
            <div className="rounded-xl border border-slate-800 bg-gradient-to-r from-[#0D1527] to-[#111C35] p-6 shadow-xl relative overflow-hidden">
              <div className="absolute -right-10 -bottom-10 w-64 h-64 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none"></div>
              <div className="max-w-3xl space-y-3">
                <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full text-xs font-medium bg-cyan-500/10 text-cyan-300 border border-cyan-500/20">
                  <Cpu className="w-3.5 h-3.5" />
                  <span>Phase 6: Website Assets & Integrations Operational</span>
                </div>
                <h1 className="text-3xl font-extrabold tracking-tight text-white sm:text-4xl">
                  Unified Website Security Monitoring & Defense
                </h1>
                <p className="text-slate-300 text-sm leading-relaxed">
                  VELTRIX expands from core SIEM/SOAR threat intelligence into a unified website defense platform. Register enterprise domains, verify ownership cryptographically via DNS TXT or HTTP well-known challenges, and ingest continuous real-time attack telemetry via the Node.js SDK, Express middleware, Nginx/Apache log collectors, or Cloudflare Workers.
                </p>
                <div className="flex flex-wrap gap-2 pt-2">
                  <button
                    onClick={() => setActiveTab('websites')}
                    className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold rounded-lg flex items-center space-x-2 transition-colors shadow-lg shadow-cyan-600/20"
                  >
                    <Globe className="w-4 h-4" />
                    <span>Manage Website Inventory</span>
                  </button>
                  <button
                    onClick={() => setActiveTab('integrations')}
                    className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white text-xs font-semibold rounded-lg border border-slate-700 flex items-center space-x-2 transition-colors"
                  >
                    <Key className="w-4 h-4" />
                    <span>Configure Ingestion Keys</span>
                  </button>
                </div>
              </div>
            </div>

            {/* Status Grid */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="bg-[#0D1527] border border-slate-800 rounded-lg p-5 space-y-2 relative">
                <div className="flex items-center justify-between text-slate-400 text-xs font-medium">
                  <span>WEBSITE ASSETS</span>
                  <Globe className="w-4 h-4 text-cyan-400" />
                </div>
                <div className="flex items-baseline space-x-2">
                  <span className="text-2xl font-bold text-white">
                    {websiteCount !== null ? websiteCount : '—'}
                  </span>
                  <span className="text-[10px] font-mono text-cyan-400/80 bg-cyan-950/60 px-1.5 py-0.5 rounded border border-cyan-800/40">
                    Live
                  </span>
                </div>
                <p className="text-xs text-slate-400">DNS TXT & HTTP challenge verification</p>
              </div>

              <div className="bg-[#0D1527] border border-slate-800 rounded-lg p-5 space-y-2 relative">
                <div className="flex items-center justify-between text-slate-400 text-xs font-medium">
                  <span>TELEMETRY INTEGRATIONS</span>
                  <Key className="w-4 h-4 text-emerald-400" />
                </div>
                <div className="flex items-baseline space-x-2">
                  <span className="text-2xl font-bold text-white">
                    {integrationCount !== null ? integrationCount : '—'}
                  </span>
                  <span className="text-[10px] font-mono text-emerald-400/80 bg-emerald-950/60 px-1.5 py-0.5 rounded border border-emerald-800/40">
                    Active
                  </span>
                </div>
                <p className="text-xs text-slate-400">Node SDK, Express, Nginx, Apache, Cloudflare</p>
              </div>

              <div className="bg-[#0D1527] border border-slate-800 rounded-lg p-5 space-y-2 relative">
                <div className="flex items-center justify-between text-slate-400 text-xs font-medium">
                  <span>THREAT DETECTION ENGINE</span>
                  <Layers className="w-4 h-4 text-blue-400" />
                </div>
                <div className="flex items-baseline space-x-2">
                  <span className="text-2xl font-bold text-white">10 Sigma Rules</span>
                  <span className="text-[10px] font-mono text-blue-400/80 bg-blue-950/60 px-1.5 py-0.5 rounded border border-blue-800/40">
                    Operational
                  </span>
                </div>
                <p className="text-xs text-slate-400">Sliding temporal windows & web attack signatures</p>
              </div>

              <div className="bg-[#0D1527] border border-slate-800 rounded-lg p-5 space-y-2 relative">
                <div className="flex items-center justify-between text-slate-400 text-xs font-medium">
                  <span>AUDIT & REPUTATION</span>
                  <Lock className="w-4 h-4 text-purple-400" />
                </div>
                <div className="flex items-baseline space-x-2">
                  <span className="text-2xl font-bold text-white">SHA-256 Intact</span>
                  <span className="text-[10px] font-mono text-purple-400/80 bg-purple-950/60 px-1.5 py-0.5 rounded border border-purple-800/40">
                    Verified
                  </span>
                </div>
                <p className="text-xs text-slate-400">Tamper-evident hash-chained logs</p>
              </div>
            </div>

            {/* Architecture Card */}
            <div className="bg-[#0D1527] border border-slate-800 rounded-lg p-6 space-y-4">
              <h2 className="text-lg font-semibold text-white flex items-center space-x-2">
                <Terminal className="w-5 h-5 text-cyan-400" />
                <span>Monorepo Architecture & Operational Interfaces</span>
              </h2>
              <p className="text-sm text-slate-300">
                VELTRIX operates as a unified TypeScript monorepo with strict package boundaries:
              </p>
              <ul className="grid grid-cols-1 md:grid-cols-4 gap-3 pt-2 text-xs">
                <li className="bg-slate-900/60 border border-slate-800 rounded p-3 space-y-1">
                  <div className="font-semibold text-cyan-400">@veltrix/shared</div>
                  <div className="text-slate-400">Shared TypeScript types, Zod schemas, website asset contracts, and API specs.</div>
                </li>
                <li className="bg-slate-900/60 border border-slate-800 rounded p-3 space-y-1">
                  <div className="font-semibold text-blue-400">@veltrix/backend</div>
                  <div className="text-slate-400">Domain verification service, log parsers, Sigma engine, and DynamoDB/Memory store.</div>
                </li>
                <li className="bg-slate-900/60 border border-slate-800 rounded p-3 space-y-1">
                  <div className="font-semibold text-emerald-400">@veltrix/sdk-node</div>
                  <div className="text-slate-400">Zero-dependency Express/Node.js telemetry agent with fail-open bounded ring buffer.</div>
                </li>
                <li className="bg-slate-900/60 border border-slate-800 rounded p-3 space-y-1">
                  <div className="font-semibold text-purple-400">@veltrix/cli</div>
                  <div className="text-slate-400">SOC terminal operator console with full authentication, triage, and asset verification.</div>
                </li>
              </ul>
            </div>
          </div>
        )}

        {activeTab === 'websites' && <WebsiteInventory />}

        {activeTab === 'integrations' && <IntegrationManagement />}

        {activeTab === 'modules' && (
          <div className="bg-[#0D1527] border border-slate-800 rounded-lg p-6 space-y-4">
            <h2 className="text-lg font-semibold text-white flex items-center space-x-2">
              <CheckCircle2 className="w-5 h-5 text-emerald-400" />
              <span>Specification Modules Status (Phase 6 Website Assets Operational)</span>
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
              <div className="p-3 bg-slate-900/60 rounded border border-slate-800 flex items-start space-x-2">
                <span className="text-emerald-400 font-mono font-bold">TASK-601:</span>
                <span className="text-slate-300">Website Asset Data Model & Storage Extension (DynamoDB & In-Memory)</span>
              </div>
              <div className="p-3 bg-slate-900/60 rounded border border-slate-800 flex items-start space-x-2">
                <span className="text-emerald-400 font-mono font-bold">TASK-602:</span>
                <span className="text-slate-300">Domain Ownership Verification (DNS TXT & HTTP Well-Known Challenges, 90-Day Expiry)</span>
              </div>
              <div className="p-3 bg-slate-900/60 rounded border border-slate-800 flex items-start space-x-2">
                <span className="text-emerald-400 font-mono font-bold">TASK-603:</span>
                <span className="text-slate-300">Website Assets & Integrations REST Routers with RBAC & Tenant Isolation</span>
              </div>
              <div className="p-3 bg-slate-900/60 rounded border border-slate-800 flex items-start space-x-2">
                <span className="text-emerald-400 font-mono font-bold">TASK-604:</span>
                <span className="text-slate-300">Node.js SDK & Express Middleware Package (`@veltrix/sdk-node`) with Ring Buffer</span>
              </div>
              <div className="p-3 bg-slate-900/60 rounded border border-slate-800 flex items-start space-x-2">
                <span className="text-emerald-400 font-mono font-bold">TASK-605:</span>
                <span className="text-slate-300">Server Log Collectors (Nginx, Apache, Cloudflare) with Streaming Ingestion</span>
              </div>
              <div className="p-3 bg-slate-900/60 rounded border border-slate-800 flex items-start space-x-2">
                <span className="text-emerald-400 font-mono font-bold">TASK-606:</span>
                <span className="text-slate-300">Comprehensive Automated Test Suite & Integration Health Metrics</span>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800 bg-[#0D1527] py-4 px-6 text-center text-xs text-slate-500">
        VELTRIX Unified Cybersecurity & Website Defense Platform — Beyond Detection. Into Defense.
      </footer>
    </div>
  );
}
