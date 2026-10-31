import { useState } from 'react';
import {
  ShieldAlert,
  Activity,
  Terminal,
  Cpu,
  Lock,
  Layers,
  CheckCircle2,
} from 'lucide-react';
import { PLATFORM_INFO } from '@veltrix/shared';

export default function App() {
  const [activeTab, setActiveTab] = useState<'overview' | 'modules'>('overview');

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
            </div>
            <p className="text-xs text-slate-400">{PLATFORM_INFO.tagline}</p>
          </div>
        </div>

        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2 text-xs text-emerald-400 bg-emerald-950/40 border border-emerald-800/40 px-3 py-1.5 rounded-full">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            <span>SIEM/SOAR CORE: ONLINE</span>
          </div>
          <div className="text-xs text-slate-400 bg-slate-800/60 border border-slate-700/60 px-3 py-1.5 rounded">
            TENANT: <span className="text-cyan-400 font-mono">org-enterprise-01</span>
          </div>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-6 space-y-8">
        {/* Banner */}
        <div className="rounded-xl border border-slate-800 bg-gradient-to-r from-[#0D1527] to-[#111C35] p-6 shadow-xl relative overflow-hidden">
          <div className="absolute -right-10 -bottom-10 w-64 h-64 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none"></div>
          <div className="max-w-2xl space-y-3">
            <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full text-xs font-medium bg-cyan-500/10 text-cyan-300 border border-cyan-500/20">
              <Cpu className="w-3.5 h-3.5" />
              <span>Phase 2 Monorepo Foundation Operational</span>
            </div>
            <h1 className="text-3xl font-extrabold tracking-tight text-white sm:text-4xl">
              Autonomous Cyber Threat Detection & Controlled Response
            </h1>
            <p className="text-slate-300 text-sm leading-relaxed">
              VELTRIX normalizes multi-source telemetry, correlates complex multi-stage attack patterns mapped to MITRE ATT&CK®, computes explainable risk scores, and coordinates defensive SOAR playbooks with zero-bypass authorization.
            </p>
          </div>
        </div>

        {/* Status Grid */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-[#0D1527] border border-slate-800 rounded-lg p-5 space-y-2">
            <div className="flex items-center justify-between text-slate-400 text-xs font-medium">
              <span>INGESTION STATUS</span>
              <Activity className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="text-2xl font-bold text-white">Active</div>
            <p className="text-xs text-slate-400">High-precision UUIDv7 deduplication</p>
          </div>

          <div className="bg-[#0D1527] border border-slate-800 rounded-lg p-5 space-y-2">
            <div className="flex items-center justify-between text-slate-400 text-xs font-medium">
              <span>DETECTION ENGINE</span>
              <Layers className="w-4 h-4 text-blue-400" />
            </div>
            <div className="text-2xl font-bold text-white">10 Sigma Rules</div>
            <p className="text-xs text-slate-400">Sliding temporal windows ready</p>
          </div>

          <div className="bg-[#0D1527] border border-slate-800 rounded-lg p-5 space-y-2">
            <div className="flex items-center justify-between text-slate-400 text-xs font-medium">
              <span>DEFENSIVE SOAR</span>
              <ShieldAlert className="w-4 h-4 text-amber-400" />
            </div>
            <div className="text-2xl font-bold text-white">Gated Defense</div>
            <p className="text-xs text-slate-400">Zero-bypass approval enforcement</p>
          </div>

          <div className="bg-[#0D1527] border border-slate-800 rounded-lg p-5 space-y-2">
            <div className="flex items-center justify-between text-slate-400 text-xs font-medium">
              <span>AUDIT LEDGER</span>
              <Lock className="w-4 h-4 text-emerald-400" />
            </div>
            <div className="text-2xl font-bold text-white">SHA-256 Intact</div>
            <p className="text-xs text-slate-400">Tamper-evident hash-chained logs</p>
          </div>
        </div>

        {/* Architecture Navigation Tabs */}
        <div className="space-y-4">
          <div className="flex items-center space-x-2 border-b border-slate-800">
            <button
              onClick={() => setActiveTab('overview')}
              className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
                activeTab === 'overview'
                  ? 'border-cyan-400 text-cyan-400'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              Architecture Overview
            </button>
            <button
              onClick={() => setActiveTab('modules')}
              className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
                activeTab === 'modules'
                  ? 'border-cyan-400 text-cyan-400'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              Workspace Modules (A–L)
            </button>
          </div>

          {activeTab === 'overview' ? (
            <div className="bg-[#0D1527] border border-slate-800 rounded-lg p-6 space-y-4">
              <h2 className="text-lg font-semibold text-white flex items-center space-x-2">
                <Terminal className="w-5 h-5 text-cyan-400" />
                <span>Monorepo Architecture & Operational Interfaces</span>
              </h2>
              <p className="text-sm text-slate-300">
                VELTRIX operates as a unified TypeScript monorepo with strict package boundaries:
              </p>
              <ul className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-2 text-xs">
                <li className="bg-slate-900/60 border border-slate-800 rounded p-3 space-y-1">
                  <div className="font-semibold text-cyan-400">@veltrix/shared</div>
                  <div className="text-slate-400">Shared TypeScript types, Zod schemas, MITRE ATT&CK taxonomy, and HTTP contracts.</div>
                </li>
                <li className="bg-slate-900/60 border border-slate-800 rounded p-3 space-y-1">
                  <div className="font-semibold text-blue-400">@veltrix/backend</div>
                  <div className="text-slate-400">Express / Serverless API, Sigma detection engine, correlation pipeline, and MemoryStore.</div>
                </li>
                <li className="bg-slate-900/60 border border-slate-800 rounded p-3 space-y-1">
                  <div className="font-semibold text-emerald-400">@veltrix/cli</div>
                  <div className="text-slate-400">SOC terminal operator console with full authentication, triage, and simulation CLI commands.</div>
                </li>
              </ul>
            </div>
          ) : (
            <div className="bg-[#0D1527] border border-slate-800 rounded-lg p-6 space-y-4">
              <h2 className="text-lg font-semibold text-white flex items-center space-x-2">
                <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                <span>Specification Modules Status (Phase 2 Foundation Ready)</span>
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                <div className="p-3 bg-slate-900/60 rounded border border-slate-800 flex items-start space-x-2">
                  <span className="text-cyan-400 font-mono font-bold">Mod A:</span>
                  <span className="text-slate-300">Authentication & Multi-Tenant RBAC Isolation</span>
                </div>
                <div className="p-3 bg-slate-900/60 rounded border border-slate-800 flex items-start space-x-2">
                  <span className="text-cyan-400 font-mono font-bold">Mod B:</span>
                  <span className="text-slate-300">Event Ingestion API & High-Precision Deduplication</span>
                </div>
                <div className="p-3 bg-slate-900/60 rounded border border-slate-800 flex items-start space-x-2">
                  <span className="text-cyan-400 font-mono font-bold">Mod C:</span>
                  <span className="text-slate-300">10 Sigma-Inspired Detection Rules Engine</span>
                </div>
                <div className="p-3 bg-slate-900/60 rounded border border-slate-800 flex items-start space-x-2">
                  <span className="text-cyan-400 font-mono font-bold">Mod D:</span>
                  <span className="text-slate-300">Multi-Stage MITRE ATT&CK Attack Correlation</span>
                </div>
                <div className="p-3 bg-slate-900/60 rounded border border-slate-800 flex items-start space-x-2">
                  <span className="text-cyan-400 font-mono font-bold">Mod E:</span>
                  <span className="text-slate-300">Explainable Mathematical Risk Scoring ($0 - 100$)</span>
                </div>
                <div className="p-3 bg-slate-900/60 rounded border border-slate-800 flex items-start space-x-2">
                  <span className="text-cyan-400 font-mono font-bold">Mod H:</span>
                  <span className="text-slate-300">Defensive SOAR Response with Zero-Bypass Authorization</span>
                </div>
              </div>
            </div>
          )}
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800 bg-[#0D1527] py-4 px-6 text-center text-xs text-slate-500">
        VELTRIX Autonomous Cybersecurity Platform — Competition Ready & Enterprise Scalable
      </footer>
    </div>
  );
}
