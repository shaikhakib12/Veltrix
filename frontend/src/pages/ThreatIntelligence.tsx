import React, { useState } from 'react';
import { ThreatIndicator } from '../types/index.js';
import { Globe, Search, ShieldAlert, CheckCircle, ExternalLink, Activity } from 'lucide-react';
import { api } from '../services/api.js';

interface ThreatIntelligenceProps {
  indicators: ThreatIndicator[];
}

export const ThreatIntelligence: React.FC<ThreatIntelligenceProps> = ({ indicators }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [lookupIp, setLookupIp] = useState('');
  const [lookupResult, setLookupResult] = useState<{
    ip: string;
    isFlagged: boolean;
    indicator: ThreatIndicator | null;
  } | null>(null);
  const [isLookingUp, setIsLookingUp] = useState(false);

  const filtered = indicators.filter(
    (ind) =>
      ind.value.includes(searchTerm) ||
      ind.threatType.toLowerCase().includes(searchTerm.toLowerCase()) ||
      ind.description.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const handleEnrichIp = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!lookupIp.trim()) return;
    setIsLookingUp(true);
    try {
      const res = await api.enrichIp(lookupIp.trim());
      setLookupResult(res);
    } catch {
      setLookupResult(null);
    } finally {
      setIsLookingUp(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-base font-semibold text-white font-mono flex items-center space-x-2">
          <span>THREAT INTELLIGENCE & INDICATOR REPOSITORY (IOC)</span>
          <span className="text-xs px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-accent border border-cyan-500/30">
            {indicators.length} Active Feeds
          </span>
        </h2>
        <p className="text-xs text-slate-400">
          Embedded offline-capable threat repository enriched with known Tor exit nodes, botnet command-and-control addresses, and MITRE ATT&CK tactics.
        </p>
      </div>

      {/* Quick IP Reputation Lookup Tool */}
      <div className="p-5 rounded-xl bg-navy-900 border border-slate-800 space-y-4">
        <h3 className="text-xs font-mono font-semibold text-slate-300 uppercase flex items-center space-x-2">
          <Globe className="w-4 h-4 text-cyan-accent" />
          <span>Interactive IP Reputation & IOC Inspector</span>
        </h3>

        <form onSubmit={handleEnrichIp} className="flex gap-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Query IP address (e.g. 198.51.100.42, 203.0.113.195, 8.8.8.8)..."
              value={lookupIp}
              onChange={(e) => setLookupIp(e.target.value)}
              className="w-full pl-9 pr-4 py-2 rounded-lg bg-navy-950 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/50 font-mono"
            />
          </div>
          <button
            type="submit"
            disabled={isLookingUp}
            className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs font-mono transition"
          >
            {isLookingUp ? 'Enriching...' : 'Enrich IP'}
          </button>
        </form>

        {lookupResult && (
          <div className={`p-4 rounded-lg border text-xs font-mono ${
            lookupResult.isFlagged
              ? 'bg-rose-500/10 border-rose-500/30 text-rose-300'
              : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
          }`}>
            <div className="flex items-center space-x-2 font-bold mb-1">
              {lookupResult.isFlagged ? (
                <>
                  <ShieldAlert className="w-4 h-4 text-rose-400" />
                  <span>THREAT DETECTED: {lookupResult.ip} is flagged in active intelligence feeds</span>
                </>
              ) : (
                <>
                  <CheckCircle className="w-4 h-4 text-emerald-400" />
                  <span>CLEAN: {lookupResult.ip} has no known malicious indicators</span>
                </>
              )}
            </div>
            {lookupResult.indicator && (
              <div className="space-y-1 text-slate-300 pt-1 text-[11px]">
                <div>Category: <span className="text-white font-bold">{lookupResult.indicator.threatType}</span> ({lookupResult.indicator.confidence}% confidence)</div>
                <div>Country / ASN: <span className="text-white">{lookupResult.indicator.country} / {lookupResult.indicator.asn}</span></div>
                <div>Intel Summary: {lookupResult.indicator.description}</div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* IOC Catalog Table */}
      <div className="rounded-xl bg-navy-900 border border-slate-800 overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <span className="text-xs font-mono font-semibold text-slate-300 uppercase">
            Active Threat Indicators Database
          </span>
          <input
            type="text"
            placeholder="Filter indicators..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="py-1 px-3 rounded bg-navy-950 border border-slate-800 text-xs text-slate-300 font-mono focus:outline-none"
          />
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-navy-950/80 border-b border-slate-800 text-slate-400 text-[11px] uppercase">
              <tr>
                <th className="py-3 px-4">Type</th>
                <th className="py-3 px-4">Indicator Value</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Threat Category</th>
                <th className="py-3 px-4">Confidence</th>
                <th className="py-3 px-4">Origin / ASN</th>
                <th className="py-3 px-4">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filtered.map((ind) => (
                <tr key={ind.indicatorId} className="hover:bg-slate-850/50">
                  <td className="py-3 px-4 text-slate-400 font-semibold">{ind.type}</td>
                  <td className="py-3 px-4 text-cyan-accent font-bold">{ind.value}</td>
                  <td className="py-3 px-4">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      ind.severity === 'CRITICAL' 
                        ? 'bg-rose-500/10 text-rose-400 border border-rose-500/30' 
                        : 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                    }`}>
                      {ind.severity}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-slate-300">{ind.threatType}</td>
                  <td className="py-3 px-4 text-slate-300">{ind.confidence}%</td>
                  <td className="py-3 px-4 text-slate-400">{ind.country} {ind.asn && `(${ind.asn})`}</td>
                  <td className="py-3 px-4 text-slate-400 text-[11px] max-w-xs truncate">{ind.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
