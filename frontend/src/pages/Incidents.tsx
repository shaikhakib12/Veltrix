import React, { useState } from 'react';
import { Incident, SecurityEvent } from '../types/index.js';
import { 
  AlertTriangle, 
  ShieldCheck, 
  Clock, 
  Flame, 
  User, 
  Globe, 
  ChevronRight, 
  CheckCircle, 
  Zap, 
  FileText,
  Send
} from 'lucide-react';

interface IncidentsProps {
  incidents: Incident[];
  onUpdateStatus: (incidentId: string, status: string) => void;
  onAddNote: (incidentId: string, note: string) => void;
  onExecuteResponse: (incidentId: string, action: string) => void;
  selectedIncident: Incident | null;
  onSelectIncident: (incident: Incident) => void;
}

export const Incidents: React.FC<IncidentsProps> = ({
  incidents,
  onUpdateStatus,
  onAddNote,
  onExecuteResponse,
  selectedIncident,
  onSelectIncident,
}) => {
  const [newNote, setNewNote] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');

  const filtered = incidents.filter(i => statusFilter === 'ALL' || i.status === statusFilter);

  const active = selectedIncident || (filtered.length > 0 ? filtered[0] : null);

  const handleNoteSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!active || !newNote.trim()) return;
    onAddNote(active.incidentId, newNote.trim());
    setNewNote('');
  };

  const getRiskScoreColor = (score: number) => {
    if (score >= 75) return 'text-rose-400 bg-rose-500/10 border-rose-500/30';
    if (score >= 50) return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
    if (score >= 25) return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
    return 'text-sky-400 bg-sky-500/10 border-sky-500/30';
  };

  return (
    <div className="space-y-6">
      {/* Header & Status Filter */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold text-white font-mono flex items-center space-x-2">
            <span>INCIDENT MANAGEMENT & CORRELATED ATTACK DOSSIERS</span>
            <span className="text-xs px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/30">
              {incidents.filter(i => i.status !== 'RESOLVED' && i.status !== 'FALSE_POSITIVE').length} Active
            </span>
          </h2>
          <p className="text-xs text-slate-400">
            Multi-stage correlated attack sequences with formulaic explainable risk scores and interactive containment workflows.
          </p>
        </div>

        <div className="flex items-center space-x-2 text-xs">
          {['ALL', 'NEW', 'INVESTIGATING', 'CONTAINED', 'RESOLVED'].map((st) => (
            <button
              key={st}
              onClick={() => setStatusFilter(st)}
              className={`px-2.5 py-1 rounded font-mono transition ${
                statusFilter === st
                  ? 'bg-cyan-500 text-slate-950 font-bold'
                  : 'bg-navy-900 border border-slate-800 text-slate-400 hover:text-white'
              }`}
            >
              {st}
            </button>
          ))}
        </div>
      </div>

      {/* Main Split Layout: Incidents List & Incident Dossier */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left: Incident List */}
        <div className="lg:col-span-5 space-y-3 max-h-[750px] overflow-y-auto pr-1">
          {filtered.length === 0 ? (
            <div className="p-8 rounded-xl bg-navy-900 border border-slate-800 text-center text-xs text-slate-500">
              No incidents match this status. Run an attack sequence in the Simulation Lab to generate test incidents.
            </div>
          ) : (
            filtered.map((inc) => {
              const isSelected = active?.incidentId === inc.incidentId;
              return (
                <div
                  key={inc.incidentId}
                  onClick={() => onSelectIncident(inc)}
                  className={`p-4 rounded-xl cursor-pointer border transition ${
                    isSelected
                      ? 'bg-navy-850 border-cyan-500/50 shadow-glow-cyan'
                      : 'bg-navy-900 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-start justify-between gap-2 mb-2">
                    <span className="text-xs font-mono font-bold text-slate-400">{inc.incidentId}</span>
                    <div className="flex items-center space-x-2">
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded border font-bold ${getRiskScoreColor(inc.riskScore)}`}>
                        RISK {inc.riskScore}
                      </span>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 font-semibold">
                        {inc.status}
                      </span>
                    </div>
                  </div>

                  <h3 className="text-xs font-semibold text-white mb-2 line-clamp-1">{inc.title}</h3>

                  <div className="grid grid-cols-2 gap-2 text-[11px] text-slate-400 font-mono">
                    <div className="flex items-center space-x-1.5 truncate">
                      <Globe className="w-3 h-3 text-cyan-accent shrink-0" />
                      <span className="truncate">{inc.sourceIp}</span>
                    </div>
                    <div className="flex items-center space-x-1.5 truncate">
                      <User className="w-3 h-3 text-slate-400 shrink-0" />
                      <span className="truncate">{inc.targetUser || 'System'}</span>
                    </div>
                  </div>

                  <div className="flex items-center justify-between mt-3 pt-2.5 border-t border-slate-800/80 text-[10px] text-slate-500">
                    <span>{new Date(inc.createdAt).toLocaleTimeString()}</span>
                    <span>{inc.timeline.length} Attack Stages</span>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Right: Detailed Dossier */}
        <div className="lg:col-span-7 rounded-xl bg-navy-900 border border-slate-800 p-6 space-y-6">
          {active ? (
            <>
              {/* Header Info */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
                <div>
                  <div className="flex items-center space-x-2 mb-1">
                    <span className="text-xs font-mono text-cyan-accent">{active.incidentId}</span>
                    <span className="text-slate-600">|</span>
                    <span className="text-xs text-slate-400 font-mono">
                      Detected: {new Date(active.createdAt).toLocaleString()}
                    </span>
                  </div>
                  <h3 className="text-base font-bold text-white">{active.title}</h3>
                </div>

                {/* Status Switcher */}
                <div className="flex items-center space-x-2">
                  <span className="text-xs text-slate-500 font-mono">Status:</span>
                  <select
                    value={active.status}
                    onChange={(e) => onUpdateStatus(active.incidentId, e.target.value)}
                    className="py-1 px-2.5 rounded bg-navy-950 border border-slate-700 text-xs font-mono text-cyan-300 focus:outline-none"
                  >
                    <option value="NEW">NEW</option>
                    <option value="INVESTIGATING">INVESTIGATING</option>
                    <option value="CONTAINED">CONTAINED</option>
                    <option value="RESOLVED">RESOLVED</option>
                    <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
                  </select>
                </div>
              </div>

              {/* Explainable Risk Scoring Breakdown */}
              <div className="p-4 rounded-xl bg-navy-950 border border-cyan-500/20 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <Flame className="w-4 h-4 text-rose-400" />
                    <span className="text-xs font-mono font-semibold text-white">EXPLAINABLE RISK SCORE BREAKDOWN</span>
                  </div>
                  <span className={`text-xs font-mono px-2.5 py-0.5 rounded border font-bold ${getRiskScoreColor(active.riskScore)}`}>
                    Score: {active.riskScore} / 100 ({active.severity})
                  </span>
                </div>

                <p className="text-xs text-slate-300 italic">
                  "{active.riskBreakdown?.explanation || active.description}"
                </p>

                <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 pt-2 text-[11px] font-mono">
                  {active.riskBreakdown?.factors?.map((f: { name: string; impact: string }) => (
                    <div key={f.name} className="p-2 rounded bg-navy-900 border border-slate-800">
                      <div className="text-[10px] text-slate-500 truncate">{f.name}</div>
                      <div className="text-xs font-bold text-cyan-accent">{f.impact}</div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Attack Timeline (Kill Chain Visualizer) */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-semibold text-slate-300 uppercase">
                    Chronological Attack Sequence Progression
                  </span>
                  <span className="text-[11px] text-slate-500 font-mono">{active.timeline.length} Observed Stages</span>
                </div>

                <div className="space-y-2 border-l-2 border-cyan-500/30 pl-4 ml-2">
                  {active.timeline.map((step) => (
                    <div key={step.stepId} className="relative pb-3 last:pb-0">
                      <div className="absolute -left-[21px] top-1 w-2.5 h-2.5 rounded-full bg-cyan-accent shadow-glow-cyan"></div>
                      <div className="text-xs flex items-center space-x-2">
                        <span className="font-mono text-slate-400 text-[10px]">
                          {new Date(step.timestamp).toLocaleTimeString()}
                        </span>
                        <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-800 text-cyan-400 border border-slate-700 font-semibold">
                          {step.phase} ({step.mitreId})
                        </span>
                      </div>
                      <p className="text-xs text-slate-200 mt-1">{step.description}</p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Containment & SOAR Action Center */}
              <div className="p-4 rounded-xl bg-navy-950 border border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-semibold text-slate-300 uppercase">
                    Automated Defensive SOAR Containment
                  </span>
                  <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold ${
                    active.containmentStatus === 'CONTAINED'
                      ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                      : active.containmentStatus === 'PENDING_APPROVAL'
                        ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                        : 'bg-slate-800 text-slate-400'
                  }`}>
                    Containment: {active.containmentStatus}
                  </span>
                </div>

                <div className="flex flex-wrap gap-2">
                  <button
                    onClick={() => onExecuteResponse(active.incidentId, 'BLOCK_IP')}
                    className="flex items-center space-x-1.5 px-3 py-1.5 rounded bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 border border-rose-500/40 text-xs font-mono font-semibold transition"
                  >
                    <Zap className="w-3.5 h-3.5" />
                    <span>Block IP: {active.sourceIp}</span>
                  </button>

                  {active.targetUser && (
                    <button
                      onClick={() => onExecuteResponse(active.incidentId, 'SUSPEND_USER')}
                      className="flex items-center space-x-1.5 px-3 py-1.5 rounded bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40 text-xs font-mono font-semibold transition"
                    >
                      <Zap className="w-3.5 h-3.5" />
                      <span>Suspend User: {active.targetUser}</span>
                    </button>
                  )}

                  <button
                    onClick={() => onExecuteResponse(active.incidentId, 'STEP_UP_AUTH')}
                    className="flex items-center space-x-1.5 px-3 py-1.5 rounded bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 text-xs font-mono font-semibold transition"
                  >
                    <Zap className="w-3.5 h-3.5" />
                    <span>Enforce Step-Up MFA</span>
                  </button>
                </div>
              </div>

              {/* Investigation Notes Thread */}
              <div className="space-y-3 pt-2">
                <span className="text-xs font-mono font-semibold text-slate-300 uppercase">
                  Analyst Investigation Journal
                </span>

                <div className="space-y-2 max-h-40 overflow-y-auto pr-1">
                  {active.notes?.map((n: { author: string; timestamp: string; content: string }, idx: number) => (
                    <div key={idx} className="p-2.5 rounded bg-navy-950 border border-slate-800 text-xs">
                      <div className="flex items-center justify-between text-[10px] text-slate-500 font-mono mb-1">
                        <span className="text-cyan-400 font-semibold">{n.author}</span>
                        <span>{new Date(n.timestamp).toLocaleTimeString()}</span>
                      </div>
                      <p className="text-slate-300 text-[11px]">{n.content}</p>
                    </div>
                  ))}
                </div>

                {/* Add Note Form */}
                <form onSubmit={handleNoteSubmit} className="flex gap-2">
                  <input
                    type="text"
                    placeholder="Append investigation finding or forensic note..."
                    value={newNote}
                    onChange={(e) => setNewNote(e.target.value)}
                    className="flex-1 py-1.5 px-3 rounded-lg bg-navy-950 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/50"
                  />
                  <button
                    type="submit"
                    className="px-3 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center space-x-1"
                  >
                    <Send className="w-3.5 h-3.5" />
                    <span>Post</span>
                  </button>
                </form>
              </div>
            </>
          ) : (
            <div className="py-20 text-center text-xs text-slate-500">
              Select an incident from the list to view its complete threat dossier and attack timeline.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
