import React from 'react';
import { ResponseExecution } from '../types/index.js';
import { Zap, ShieldAlert, CheckCircle2, RotateCcw, ShieldCheck, Clock } from 'lucide-react';

interface ResponseCenterProps {
  pendingApprovals: ResponseExecution[];
  activeBlockedIps: string[];
  suspendedUsers: string[];
  responseHistory: ResponseExecution[];
  onApprove: (executionId: string) => void;
  onRollback: (executionId: string) => void;
}

export const ResponseCenter: React.FC<ResponseCenterProps> = ({
  pendingApprovals,
  activeBlockedIps,
  suspendedUsers,
  responseHistory,
  onApprove,
  onRollback,
}) => {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-base font-semibold text-white font-mono flex items-center space-x-2">
          <span>SECURITY ORCHESTRATION, AUTOMATION & RESPONSE (SOAR) CENTER</span>
          {pendingApprovals.length > 0 && (
            <span className="text-xs px-2 py-0.5 rounded bg-amber-500/20 text-amber-400 border border-amber-500/30 animate-pulse font-bold">
              {pendingApprovals.length} Approval Required
            </span>
          )}
        </h2>
        <p className="text-xs text-slate-400">
          Controlled defensive execution workflows with mandatory human-in-the-loop approval gates for high-impact containment actions.
        </p>
      </div>

      {/* Human Approval Queue */}
      <div className="p-5 rounded-xl bg-navy-900 border border-amber-500/40 space-y-4 shadow-glow-amber">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <ShieldAlert className="w-5 h-5 text-amber-400" />
            <h3 className="text-xs font-mono font-bold text-white uppercase">
              Human-in-the-Loop Containment Approval Queue
            </h3>
          </div>
          <span className="text-[11px] font-mono text-slate-400">
            {pendingApprovals.length} Actions Pending Sign-Off
          </span>
        </div>

        {pendingApprovals.length === 0 ? (
          <div className="p-4 rounded-lg bg-navy-950 border border-slate-800 text-xs text-slate-400 text-center font-mono">
            No disruptive defensive actions pending approval. Critical incidents requiring IP blocks or account suspensions will queue here for analyst verification.
          </div>
        ) : (
          <div className="space-y-3">
            {pendingApprovals.map((req) => (
              <div
                key={req.executionId}
                className="p-4 rounded-lg bg-navy-950 border border-amber-500/30 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4"
              >
                <div className="space-y-1 text-xs font-mono">
                  <div className="flex items-center space-x-2">
                    <span className="font-bold text-amber-400">{req.action}</span>
                    <span className="text-slate-500">&rarr;</span>
                    <span className="text-cyan-accent font-bold">{req.targetEntity}</span>
                    <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-400">
                      Incident: {req.incidentId}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400">{req.details}</p>
                </div>

                <div className="flex items-center space-x-2 shrink-0">
                  <button
                    onClick={() => onApprove(req.executionId)}
                    className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-amber-500 hover:bg-amber-400 text-slate-950 font-mono text-xs font-bold transition shadow-glow-amber"
                  >
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>Approve & Execute</span>
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Active Containment Registries */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Active Blocked IPs */}
        <div className="p-5 rounded-xl bg-navy-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono font-semibold text-slate-300 uppercase flex items-center space-x-2">
              <Zap className="w-4 h-4 text-cyan-accent" />
              <span>Active Firewall Blocklist</span>
            </span>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-cyan-400 font-bold">
              {activeBlockedIps.length} Active
            </span>
          </div>

          <div className="space-y-2 max-h-56 overflow-y-auto">
            {activeBlockedIps.length === 0 ? (
              <div className="py-8 text-center text-xs text-slate-500 font-mono">
                No IP addresses currently under active block policy.
              </div>
            ) : (
              activeBlockedIps.map((ip) => {
                const matchExec = responseHistory.find(
                  h => h.targetEntity === ip && h.action === 'BLOCK_IP' && h.status === 'SUCCESS'
                );
                return (
                  <div
                    key={ip}
                    className="p-3 rounded-lg bg-navy-950 border border-slate-800 flex items-center justify-between text-xs font-mono"
                  >
                    <div>
                      <span className="text-cyan-accent font-bold">{ip}</span>
                      <span className="text-[10px] text-slate-500 block">Firewall Policy: DROP ALL</span>
                    </div>

                    {matchExec && (
                      <button
                        onClick={() => onRollback(matchExec.executionId)}
                        className="flex items-center space-x-1 text-[11px] text-slate-400 hover:text-white px-2 py-1 rounded bg-slate-800 hover:bg-slate-700"
                        title="Rollback block policy"
                      >
                        <RotateCcw className="w-3 h-3" />
                        <span>Unblock</span>
                      </button>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Active Suspended Users */}
        <div className="p-5 rounded-xl bg-navy-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono font-semibold text-slate-300 uppercase flex items-center space-x-2">
              <ShieldCheck className="w-4 h-4 text-amber-400" />
              <span>Suspended Account Registry</span>
            </span>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-amber-400 font-bold">
              {suspendedUsers.length} Suspended
            </span>
          </div>

          <div className="space-y-2 max-h-56 overflow-y-auto">
            {suspendedUsers.length === 0 ? (
              <div className="py-8 text-center text-xs text-slate-500 font-mono">
                No user identities currently locked or suspended.
              </div>
            ) : (
              suspendedUsers.map((user) => {
                const matchExec = responseHistory.find(
                  h => h.targetEntity === user && h.action === 'SUSPEND_USER' && h.status === 'SUCCESS'
                );
                return (
                  <div
                    key={user}
                    className="p-3 rounded-lg bg-navy-950 border border-slate-800 flex items-center justify-between text-xs font-mono"
                  >
                    <div>
                      <span className="text-amber-300 font-bold">{user}</span>
                      <span className="text-[10px] text-slate-500 block">Directory Status: LOCKED</span>
                    </div>

                    {matchExec && (
                      <button
                        onClick={() => onRollback(matchExec.executionId)}
                        className="flex items-center space-x-1 text-[11px] text-slate-400 hover:text-white px-2 py-1 rounded bg-slate-800 hover:bg-slate-700"
                        title="Reinstate user account"
                      >
                        <RotateCcw className="w-3 h-3" />
                        <span>Reinstate</span>
                      </button>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </div>
      </div>

      {/* Response Audit Log */}
      <div className="rounded-xl bg-navy-900 border border-slate-800 overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <span className="text-xs font-mono font-semibold text-slate-300 uppercase">
            Defensive Orchestration Execution History
          </span>
          <span className="text-[11px] text-slate-500 font-mono">{responseHistory.length} Recorded Actions</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-navy-950/80 border-b border-slate-800 text-slate-400 text-[11px] uppercase">
              <tr>
                <th className="py-3 px-4">Time (UTC)</th>
                <th className="py-3 px-4">Action</th>
                <th className="py-3 px-4">Target Entity</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Executor / Approved By</th>
                <th className="py-3 px-4">Operational Summary</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {responseHistory.map((h) => (
                <tr key={h.executionId} className="hover:bg-slate-850/50">
                  <td className="py-3 px-4 text-slate-400 text-[11px]">
                    {h.executedAt ? new Date(h.executedAt).toLocaleTimeString() : 'Queued'}
                  </td>
                  <td className="py-3 px-4 font-bold text-white">{h.action}</td>
                  <td className="py-3 px-4 text-cyan-accent">{h.targetEntity}</td>
                  <td className="py-3 px-4">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      h.status === 'SUCCESS'
                        ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                        : h.status === 'ROLLED_BACK'
                          ? 'bg-slate-800 text-slate-300'
                          : 'bg-amber-500/10 text-amber-400'
                    }`}>
                      {h.status}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-slate-300">{h.approvedBy || h.requestedBy}</td>
                  <td className="py-3 px-4 text-slate-400 text-[11px] max-w-sm truncate">{h.details}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
