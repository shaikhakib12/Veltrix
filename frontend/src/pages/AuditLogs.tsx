import React, { useState } from 'react';
import { AuditRecord, AuditVerificationResult } from '../types/index.js';
import { Lock, ShieldCheck, AlertOctagon, CheckCircle2, RefreshCw, Key } from 'lucide-react';

interface AuditLogsProps {
  logs: AuditRecord[];
  onVerifyChain: () => Promise<AuditVerificationResult>;
  isLoading: boolean;
}

export const AuditLogs: React.FC<AuditLogsProps> = ({ logs, onVerifyChain, isLoading }) => {
  const [verification, setVerification] = useState<AuditVerificationResult | null>(null);
  const [isVerifying, setIsVerifying] = useState(false);

  const handleVerify = async () => {
    setIsVerifying(true);
    try {
      const res = await onVerifyChain();
      setVerification(res);
    } finally {
      setIsVerifying(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header and Verification Button */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold text-white font-mono flex items-center space-x-2">
            <span>CRYPTOGRAPHIC SECURITY AUDIT LEDGER</span>
            <span className="text-xs px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-accent border border-cyan-500/30">
              {logs.length} Blocks Chained
            </span>
          </h2>
          <p className="text-xs text-slate-400">
            Append-only audit trail anchored with SHA-256 cryptographic hash fingerprints for immutable non-repudiation.
          </p>
        </div>

        <button
          onClick={handleVerify}
          disabled={isVerifying}
          className="flex items-center space-x-2 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-mono text-xs font-bold shadow-glow-cyan transition shrink-0"
        >
          <Key className={`w-3.5 h-3.5 ${isVerifying ? 'animate-spin' : ''}`} />
          <span>{isVerifying ? 'Verifying Hashes...' : 'Verify Ledger Integrity'}</span>
        </button>
      </div>

      {/* Verification Result Banner */}
      {verification && (
        <div className={`p-4 rounded-xl border flex items-center space-x-3 text-xs font-mono ${
          verification.verified
            ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
            : 'bg-rose-500/10 border-rose-500/30 text-rose-300'
        }`}>
          {verification.verified ? (
            <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
          ) : (
            <AlertOctagon className="w-5 h-5 text-rose-400 shrink-0" />
          )}
          <div>
            <div className="font-bold">
              {verification.verified 
                ? `LEDGER INTEGRITY VERIFIED: All ${verification.totalRecordsChecked} records cryptographically validated`
                : 'TAMPERING DETECTED: Cryptographic hash chain mismatch'}
            </div>
            <p className="text-[11px] text-slate-400 mt-0.5">
              {verification.error || 'All sequential SHA-256 hash hashes match the expected cryptographic anchors with zero discrepancies.'}
            </p>
          </div>
        </div>
      )}

      {/* Audit Log Table */}
      <div className="rounded-xl bg-navy-900 border border-slate-800 overflow-hidden font-mono text-xs">
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead className="bg-navy-950/80 border-b border-slate-800 text-slate-400 text-[11px] uppercase">
              <tr>
                <th className="py-3 px-4">Timestamp (UTC)</th>
                <th className="py-3 px-4">Actor</th>
                <th className="py-3 px-4">Action</th>
                <th className="py-3 px-4">Target Resource</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">SHA-256 Fingerprint</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {logs.map((record) => (
                <tr key={record.logId} className="hover:bg-slate-850/50">
                  <td className="py-3 px-4 text-slate-400 text-[11px] whitespace-nowrap">
                    {new Date(record.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="py-3 px-4 text-slate-200 font-semibold">{record.actor}</td>
                  <td className="py-3 px-4 text-cyan-400">{record.action}</td>
                  <td className="py-3 px-4 text-slate-300">{record.targetResource}</td>
                  <td className="py-3 px-4">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      record.result === 'SUCCESS' 
                        ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30' 
                        : 'bg-rose-500/10 text-rose-400 border border-rose-500/30'
                    }`}>
                      {record.result}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <span className="text-[10px] text-slate-500 hover:text-cyan-accent font-mono truncate block max-w-xs cursor-pointer" title={`Full Hash: ${record.integrityHash}\nPrevious: ${record.previousHash}`}>
                      {record.integrityHash.slice(0, 16)}...{record.integrityHash.slice(-8)}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
