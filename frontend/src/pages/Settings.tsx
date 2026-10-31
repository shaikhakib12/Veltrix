import React from 'react';
import { Settings as SettingsIcon, Shield, Users, Server, Database, Lock } from 'lucide-react';

export const Settings: React.FC = () => {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-base font-semibold text-white font-mono flex items-center space-x-2">
          <span>PLATFORM CONFIGURATION & TENANT ISOLATION SETTINGS</span>
        </h2>
        <p className="text-xs text-slate-400">
          Organization-level multi-tenancy controls, role-based access permissions, and AWS serverless environment parameters.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Organization Tenancy */}
        <div className="p-5 rounded-xl bg-navy-900 border border-slate-800 space-y-4">
          <div className="flex items-center space-x-2">
            <Shield className="w-4 h-4 text-cyan-accent" />
            <h3 className="text-xs font-mono font-bold text-white uppercase">Active Organization Tenant</h3>
          </div>

          <div className="space-y-2 text-xs font-mono">
            <div className="flex justify-between py-1.5 border-b border-slate-800">
              <span className="text-slate-500">Tenant Name:</span>
              <span className="text-slate-200 font-bold">CyberDefend Corp Global</span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-slate-800">
              <span className="text-slate-500">Organization ID:</span>
              <span className="text-cyan-accent">org-enterprise-01</span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-slate-800">
              <span className="text-slate-500">Service Tier:</span>
              <span className="px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-accent border border-cyan-500/30 font-bold">
                ENTERPRISE
              </span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-slate-800">
              <span className="text-slate-500">Data Retention:</span>
              <span className="text-slate-300">90 Days (DynamoDB TTL Active)</span>
            </div>
            <div className="flex justify-between py-1.5">
              <span className="text-slate-500">MFA Policy:</span>
              <span className="text-emerald-400">ENFORCED (TOTP / FIDO2)</span>
            </div>
          </div>
        </div>

        {/* Cloud Infrastructure Status */}
        <div className="p-5 rounded-xl bg-navy-900 border border-slate-800 space-y-4">
          <div className="flex items-center space-x-2">
            <Server className="w-4 h-4 text-cyan-accent" />
            <h3 className="text-xs font-mono font-bold text-white uppercase">AWS Serverless Subsystems</h3>
          </div>

          <div className="space-y-2 text-xs font-mono">
            <div className="flex justify-between py-1.5 border-b border-slate-800">
              <span className="text-slate-500">Compute:</span>
              <span className="text-emerald-400 font-semibold">AWS Lambda (Node.js 20.x ARM64)</span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-slate-800">
              <span className="text-slate-500">Database:</span>
              <span className="text-emerald-400 font-semibold">Amazon DynamoDB (Pay-Per-Request)</span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-slate-800">
              <span className="text-slate-500">Event Router:</span>
              <span className="text-emerald-400 font-semibold">Amazon EventBridge (Custom Bus)</span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-slate-800">
              <span className="text-slate-500">SOAR Orchestration:</span>
              <span className="text-emerald-400 font-semibold">AWS Step Functions (Approval Task Tokens)</span>
            </div>
            <div className="flex justify-between py-1.5">
              <span className="text-slate-500">Identity:</span>
              <span className="text-emerald-400 font-semibold">Amazon Cognito User Pools</span>
            </div>
          </div>
        </div>
      </div>

      {/* RBAC Matrix */}
      <div className="p-5 rounded-xl bg-navy-900 border border-slate-800 space-y-3">
        <div className="flex items-center space-x-2">
          <Users className="w-4 h-4 text-cyan-accent" />
          <h3 className="text-xs font-mono font-bold text-white uppercase">Role-Based Access Control (RBAC) Matrix</h3>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-navy-950 text-slate-400 text-[11px] uppercase">
              <tr>
                <th className="py-2.5 px-4">Role</th>
                <th className="py-2.5 px-4">Telemetry Ingest</th>
                <th className="py-2.5 px-4">Incident Triage</th>
                <th className="py-2.5 px-4">SOAR Containment</th>
                <th className="py-2.5 px-4">Audit Ledger</th>
                <th className="py-2.5 px-4">Rule Configuration</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              <tr>
                <td className="py-2.5 px-4 text-white font-bold">SUPER_ADMIN</td>
                <td className="py-2.5 px-4 text-emerald-400">&check; Full</td>
                <td className="py-2.5 px-4 text-emerald-400">&check; Full</td>
                <td className="py-2.5 px-4 text-emerald-400">&check; Full</td>
                <td className="py-2.5 px-4 text-emerald-400">&check; Full</td>
                <td className="py-2.5 px-4 text-emerald-400">&check; Full</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 text-cyan-300 font-bold">ORG_ADMIN</td>
                <td className="py-2.5 px-4 text-emerald-400">&check; Org</td>
                <td className="py-2.5 px-4 text-emerald-400">&check; Org</td>
                <td className="py-2.5 px-4 text-emerald-400">&check; Authorize</td>
                <td className="py-2.5 px-4 text-emerald-400">&check; Export</td>
                <td className="py-2.5 px-4 text-emerald-400">&check; Edit</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 text-slate-200 font-bold">SECURITY_ANALYST</td>
                <td className="py-2.5 px-4 text-emerald-400">&check; View</td>
                <td className="py-2.5 px-4 text-emerald-400">&check; Investigate</td>
                <td className="py-2.5 px-4 text-amber-400">&check; With Approval</td>
                <td className="py-2.5 px-4 text-emerald-400">&check; Verify</td>
                <td className="py-2.5 px-4 text-slate-500">&minus; Read Only</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 text-slate-400 font-bold">READ_ONLY_VIEWER</td>
                <td className="py-2.5 px-4 text-slate-500">&minus; No Access</td>
                <td className="py-2.5 px-4 text-slate-400">&check; View Only</td>
                <td className="py-2.5 px-4 text-slate-500">&minus; No Access</td>
                <td className="py-2.5 px-4 text-slate-400">&check; View Only</td>
                <td className="py-2.5 px-4 text-slate-500">&minus; No Access</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
