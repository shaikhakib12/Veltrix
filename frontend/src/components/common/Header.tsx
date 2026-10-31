import React from 'react';
import { Shield, Radio, Bell, RefreshCw } from 'lucide-react';

interface HeaderProps {
  onReset: () => void;
  isResetting: boolean;
}

export const Header: React.FC<HeaderProps> = ({ onReset, isResetting }) => {
  return (
    <header className="h-16 border-b border-slate-800/80 bg-navy-900/95 backdrop-blur px-6 flex items-center justify-between sticky top-0 z-40">
      {/* Brand Identity */}
      <div className="flex items-center space-x-3">
        <div className="w-9 h-9 rounded-lg bg-cyan-500/10 border border-cyan-400/30 flex items-center justify-center text-cyan-accent shadow-glow-cyan">
          <Shield className="w-5 h-5" />
        </div>
        <div>
          <div className="flex items-center space-x-2">
            <span className="font-bold tracking-wider text-lg text-white font-mono">VELTRIX</span>
            <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-accent border border-cyan-500/30 font-semibold">
              SIEM & SOAR
            </span>
          </div>
          <p className="text-[11px] text-slate-400 hidden sm:block">Beyond Detection. Into Defense.</p>
        </div>
      </div>

      {/* Center Operational Status */}
      <div className="hidden md:flex items-center space-x-6 text-xs">
        <div className="flex items-center space-x-2 px-3 py-1.5 rounded-full bg-slate-900/90 border border-slate-800">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
          </span>
          <span className="text-slate-300 font-mono">PIPELINE ACTIVE</span>
          <span className="text-slate-500">|</span>
          <span className="text-cyan-400 font-mono">AWS SERVERLESS</span>
        </div>

        <div className="flex items-center space-x-2 text-slate-400">
          <Radio className="w-3.5 h-3.5 text-cyan-accent animate-pulse" />
          <span className="font-mono">TENANT:</span>
          <span className="text-slate-200 font-semibold">CyberDefend Corp (Global)</span>
        </div>
      </div>

      {/* Right User & Actions */}
      <div className="flex items-center space-x-3">
        <button
          onClick={onReset}
          disabled={isResetting}
          title="Reset Simulation State to Pristine"
          className="flex items-center space-x-1.5 text-xs text-slate-400 hover:text-white px-2.5 py-1.5 rounded bg-slate-900 border border-slate-800 hover:border-slate-700 transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isResetting ? 'animate-spin text-cyan-accent' : ''}`} />
          <span className="hidden sm:inline">Reset Lab</span>
        </button>

        <div className="h-4 w-px bg-slate-800 mx-1"></div>

        <div className="flex items-center space-x-2.5 pl-1">
          <div className="w-8 h-8 rounded-full bg-cyan-950/80 border border-cyan-500/30 flex items-center justify-center text-xs font-mono font-semibold text-cyan-accent">
            AV
          </div>
          <div className="hidden lg:block text-left">
            <div className="text-xs font-medium text-slate-200">Alex Vance</div>
            <div className="text-[10px] text-cyan-400 font-mono">Lead SOC Analyst</div>
          </div>
        </div>
      </div>
    </header>
  );
};
