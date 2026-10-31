import React, { useState } from 'react';
import { SecurityEvent } from '../types/index.js';
import { Search, Filter, Terminal, Shield, RefreshCw, Eye } from 'lucide-react';

interface LiveEventsProps {
  events: SecurityEvent[];
  onRefresh: () => void;
  isLoading: boolean;
}

export const LiveEvents: React.FC<LiveEventsProps> = ({ events, onRefresh, isLoading }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);

  const filteredEvents = events.filter((e) => {
    const matchesSearch = 
      e.eventType.toLowerCase().includes(searchTerm.toLowerCase()) ||
      e.sourceIp.includes(searchTerm) ||
      e.username.toLowerCase().includes(searchTerm.toLowerCase()) ||
      e.sourceSystem.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesCategory = categoryFilter === 'ALL' || e.category === categoryFilter;

    return matchesSearch && matchesCategory;
  });

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-rose-500/10 text-rose-400 border border-rose-500/30';
      case 'HIGH':
        return 'bg-amber-500/10 text-amber-400 border border-amber-500/30';
      case 'MEDIUM':
        return 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/30';
      case 'LOW':
        return 'bg-sky-500/10 text-sky-400 border border-sky-500/30';
      default:
        return 'bg-slate-800 text-slate-400 border border-slate-700';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header and Controls */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold text-white font-mono flex items-center space-x-2">
            <span>LIVE SECURITY EVENTS EXPLORER</span>
            <span className="text-xs px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-accent border border-cyan-500/30">
              {filteredEvents.length} Captured
            </span>
          </h2>
          <p className="text-xs text-slate-400">
            Real-time normalized security event stream across enterprise firewalls, authentication systems, and cloud telemetry.
          </p>
        </div>

        <button
          onClick={onRefresh}
          disabled={isLoading}
          className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-navy-900 border border-slate-800 hover:border-slate-700 text-xs text-slate-300 font-medium transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-cyan-accent' : ''}`} />
          <span>Refresh Feed</span>
        </button>
      </div>

      {/* Filter Toolbar */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 p-3 rounded-xl bg-navy-900 border border-slate-800 text-xs">
        <div className="relative sm:col-span-2">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search by IP, username, event type, or host system..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-9 pr-4 py-2 rounded-lg bg-navy-950 border border-slate-800 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/50"
          />
        </div>

        <div className="flex items-center space-x-2">
          <Filter className="w-4 h-4 text-slate-500 shrink-0" />
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="w-full py-2 px-3 rounded-lg bg-navy-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-cyan-500/50"
          >
            <option value="ALL">All Categories</option>
            <option value="AUTHENTICATION">Authentication</option>
            <option value="PRIVILEGE">Privilege Escalation</option>
            <option value="DATA_ACCESS">Data Access / Exfiltration</option>
            <option value="API">API Gateway</option>
            <option value="NETWORK">Network / Proxy</option>
          </select>
        </div>
      </div>

      {/* Events Table */}
      <div className="rounded-xl bg-navy-900 border border-slate-800 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-navy-950/80 border-b border-slate-800 text-slate-400 font-mono text-[11px] uppercase">
              <tr>
                <th className="py-3 px-4">Timestamp (UTC)</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Event Type</th>
                <th className="py-3 px-4">Category</th>
                <th className="py-3 px-4">Source IP</th>
                <th className="py-3 px-4">Target User</th>
                <th className="py-3 px-4">System</th>
                <th className="py-3 px-4 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-500">
                    No security events match the current filter criteria. Run an attack scenario in the Simulation Lab to generate live telemetry.
                  </td>
                </tr>
              ) : (
                filteredEvents.map((evt) => (
                  <tr key={evt.eventId} className="hover:bg-slate-850/50 transition">
                    <td className="py-2.5 px-4 text-slate-400 text-[11px] whitespace-nowrap">
                      {new Date(evt.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-2.5 px-4 whitespace-nowrap">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${getSeverityBadge(evt.severity)}`}>
                        {evt.severity}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 text-slate-200 font-medium">
                      {evt.eventType}
                      {evt.isSimulated && (
                        <span className="ml-1.5 text-[9px] px-1 py-0.2 rounded bg-purple-500/10 text-purple-400 border border-purple-500/30">
                          SIM
                        </span>
                      )}
                    </td>
                    <td className="py-2.5 px-4 text-slate-400 text-[11px]">
                      {evt.category}
                    </td>
                    <td className="py-2.5 px-4 text-cyan-400">
                      {evt.sourceIp}
                    </td>
                    <td className="py-2.5 px-4 text-slate-300">
                      {evt.username}
                    </td>
                    <td className="py-2.5 px-4 text-slate-500 text-[11px]">
                      {evt.sourceSystem}
                    </td>
                    <td className="py-2.5 px-4 text-right">
                      <button
                        onClick={() => setSelectedEvent(evt)}
                        className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-cyan-accent transition"
                        title="View Raw Event JSON"
                      >
                        <Eye className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Raw Event Detail Modal */}
      {selectedEvent && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="w-full max-w-2xl rounded-xl bg-navy-900 border border-slate-700 shadow-2xl p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <Terminal className="w-4 h-4 text-cyan-accent" />
                <h3 className="text-sm font-semibold text-white font-mono">
                  Normalized Event Payload: {selectedEvent.eventId}
                </h3>
              </div>
              <button
                onClick={() => setSelectedEvent(null)}
                className="text-slate-400 hover:text-white text-xs px-2 py-1 rounded bg-slate-800"
              >
                Close
              </button>
            </div>

            <div className="grid grid-cols-2 gap-3 text-xs font-mono bg-navy-950 p-3 rounded-lg border border-slate-800">
              <div><span className="text-slate-500">Idempotency Hash:</span> <span className="text-cyan-accent truncate block">{selectedEvent.idempotencyHash}</span></div>
              <div><span className="text-slate-500">Received UTC:</span> <span className="text-slate-300 block">{selectedEvent.receivedAt}</span></div>
            </div>

            <pre className="text-xs font-mono bg-navy-950 p-4 rounded-lg border border-slate-800 text-cyan-300/90 overflow-x-auto max-h-72">
              {JSON.stringify(selectedEvent, null, 2)}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
};
