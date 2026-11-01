import React, { useState, useEffect } from 'react';
import {
  Globe,
  Plus,
  CheckCircle2,
  AlertTriangle,
  Clock,
  ShieldCheck,
  ShieldX,
  Trash2,
  Copy,
  ExternalLink,
  RefreshCw,
  X,
  AlertCircle,
  Activity,
} from 'lucide-react';
import type { WebsiteAsset } from '@veltrix/shared';
import {
  fetchWebsites,
  createWebsite,
  verifyDomainOwnership,
  revokeDomainVerification,
  deleteWebsite,
} from '../api';

export function WebsiteInventory() {
  const [sites, setSites] = useState<WebsiteAsset[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Modals state
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [selectedSiteForVerify, setSelectedSiteForVerify] = useState<WebsiteAsset | null>(null);
  const [isVerifying, setIsVerifying] = useState(false);

  // Form state
  const [formData, setFormData] = useState({
    name: '',
    primaryDomain: '',
    subdomains: '',
    environment: 'PRODUCTION' as 'PRODUCTION' | 'STAGING' | 'DEVELOPMENT',
    riskTier: 'CRITICAL' as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW',
    tags: '',
  });

  const loadSites = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await fetchWebsites();
      setSites(data.sites);
    } catch (err: unknown) {
      setError((err as Error).message || 'Failed to load website inventory.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSites();
  }, []);

  const handleCreateSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setActionMessage(null);
      const subdomainsList = formData.subdomains
        .split(',')
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean);
      const tagsList = formData.tags
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);

      const created = await createWebsite({
        name: formData.name,
        primaryDomain: formData.primaryDomain.toLowerCase().trim(),
        approvedSubdomains: subdomainsList,
        environment: formData.environment,
        riskTier: formData.riskTier,
        tags: tagsList,
      });

      setIsAddModalOpen(false);
      setFormData({
        name: '',
        primaryDomain: '',
        subdomains: '',
        environment: 'PRODUCTION',
        riskTier: 'CRITICAL',
        tags: '',
      });
      setActionMessage({
        type: 'success',
        text: `Website '${created.name}' registered! Complete domain verification to enable vulnerability scanning.`,
      });
      await loadSites();
    } catch (err: unknown) {
      setActionMessage({
        type: 'error',
        text: (err as Error).message || 'Failed to register website.',
      });
    }
  };

  const handleVerify = async (method: 'DNS_TXT' | 'HTTP_CHALLENGE') => {
    if (!selectedSiteForVerify) return;
    setIsVerifying(true);
    setActionMessage(null);
    try {
      const res = await verifyDomainOwnership(selectedSiteForVerify.siteId, method);
      setActionMessage({
        type: 'success',
        text: res.message || `Domain '${selectedSiteForVerify.primaryDomain}' successfully verified!`,
      });
      setSelectedSiteForVerify(null);
      await loadSites();
    } catch (err: unknown) {
      setActionMessage({
        type: 'error',
        text: (err as Error).message || 'Verification attempt failed.',
      });
    } finally {
      setIsVerifying(false);
    }
  };

  const handleRevoke = async (site: WebsiteAsset) => {
    if (!window.confirm(`Revoke verification for '${site.primaryDomain}'? This will immediately place the asset in GRACE_PERIOD and freeze all active and scheduled vulnerability scans.`)) {
      return;
    }

    try {
      await revokeDomainVerification(site.siteId, 'Manual revocation from SOC Console');
      setActionMessage({
        type: 'success',
        text: `Domain verification revoked for '${site.primaryDomain}'. Asset placed in 7-day GRACE_PERIOD with immediate scan freeze.`,
      });
      await loadSites();
    } catch (err: unknown) {
      setActionMessage({
        type: 'error',
        text: (err as Error).message || 'Failed to revoke verification.',
      });
    }
  };

  const handleDelete = async (site: WebsiteAsset) => {
    if (!window.confirm(`Are you sure you want to delete website '${site.name}' (${site.primaryDomain})?`)) {
      return;
    }

    try {
      await deleteWebsite(site.siteId);
      setActionMessage({
        type: 'success',
        text: `Website '${site.name}' deleted.`,
      });
      await loadSites();
    } catch (err: unknown) {
      setActionMessage({
        type: 'error',
        text: (err as Error).message || 'Failed to delete website.',
      });
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    alert('Copied to clipboard!');
  };

  return (
    <div className="space-y-6">
      {/* Action Banner Message */}
      {actionMessage && (
        <div
          className={`p-4 rounded-lg border text-sm flex items-start justify-between ${
            actionMessage.type === 'success'
              ? 'bg-emerald-950/40 border-emerald-800/60 text-emerald-300'
              : 'bg-rose-950/40 border-rose-800/60 text-rose-300'
          }`}
        >
          <div className="flex items-center space-x-2">
            {actionMessage.type === 'success' ? (
              <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
            ) : (
              <AlertCircle className="w-5 h-5 text-rose-400 shrink-0" />
            )}
            <span>{actionMessage.text}</span>
          </div>
          <button
            onClick={() => setActionMessage(null)}
            className="text-slate-400 hover:text-white"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Header and Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-[#0D1527] border border-slate-800 p-5 rounded-xl shadow-lg">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center space-x-2">
            <Globe className="w-6 h-6 text-cyan-400" />
            <span>Website Asset Inventory & Domain Registry</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Registered web assets, domain ownership verification, and continuous vulnerability assessment readiness.
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={loadSites}
            disabled={loading}
            className="flex items-center space-x-1.5 px-3 py-2 text-xs font-medium text-slate-300 bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700 rounded-lg transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
          <button
            onClick={() => setIsAddModalOpen(true)}
            className="flex items-center space-x-2 px-4 py-2 text-xs font-semibold text-slate-950 bg-gradient-to-r from-cyan-400 to-blue-500 hover:from-cyan-300 hover:to-blue-400 rounded-lg shadow-md shadow-cyan-500/20 transition-all"
          >
            <Plus className="w-4 h-4" />
            <span>Register Website</span>
          </button>
        </div>
      </div>

      {/* Error View */}
      {error && (
        <div className="p-6 bg-rose-950/20 border border-rose-800/50 rounded-xl text-center space-y-3">
          <AlertTriangle className="w-8 h-8 text-rose-400 mx-auto" />
          <p className="text-sm text-rose-300 font-medium">{error}</p>
          <button
            onClick={loadSites}
            className="px-4 py-1.5 text-xs bg-rose-900/60 hover:bg-rose-800 text-white rounded border border-rose-700/60"
          >
            Retry Connection
          </button>
        </div>
      )}

      {/* Loading State */}
      {loading && !error && (
        <div className="p-12 text-center space-y-3 bg-[#0D1527] border border-slate-800 rounded-xl">
          <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin mx-auto" />
          <p className="text-sm text-slate-400">Loading website inventory from API Gateway...</p>
        </div>
      )}

      {/* Empty State */}
      {!loading && !error && sites.length === 0 && (
        <div className="p-12 text-center space-y-4 bg-[#0D1527] border border-slate-800 rounded-xl">
          <Globe className="w-12 h-12 text-slate-600 mx-auto" />
          <div className="space-y-1">
            <h3 className="text-base font-semibold text-white">No Website Assets Registered</h3>
            <p className="text-xs text-slate-400 max-w-md mx-auto">
              Register your primary domain to begin continuous attack monitoring and configure authorized vulnerability scanning.
            </p>
          </div>
          <button
            onClick={() => setIsAddModalOpen(true)}
            className="inline-flex items-center space-x-2 px-4 py-2 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-lg"
          >
            <Plus className="w-4 h-4" />
            <span>Add Your First Website</span>
          </button>
        </div>
      )}

      {/* Website Cards Grid */}
      {!loading && !error && sites.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {sites.map((site) => {
            const isVerified = site.status === 'VERIFIED';
            const isGrace = site.status === 'GRACE_PERIOD';

            return (
              <div
                key={site.siteId}
                className="bg-[#0D1527] border border-slate-800 hover:border-slate-700 rounded-xl p-5 space-y-4 transition-all shadow-md relative overflow-hidden"
              >
                {/* Header row */}
                <div className="flex items-start justify-between">
                  <div className="space-y-1">
                    <div className="flex items-center space-x-2">
                      <span className="font-bold text-base text-white">{site.name}</span>
                      <span
                        className={`text-[10px] font-semibold px-2 py-0.5 rounded border uppercase ${
                          site.environment === 'PRODUCTION'
                            ? 'bg-purple-950/60 text-purple-300 border-purple-800/60'
                            : 'bg-slate-800 text-slate-300 border-slate-700'
                        }`}
                      >
                        {site.environment}
                      </span>
                    </div>
                    <div className="flex items-center space-x-2 text-xs text-cyan-400 font-mono">
                      <span>{site.primaryDomain}</span>
                      <ExternalLink className="w-3 h-3 text-slate-500" />
                    </div>
                  </div>

                  {/* Verification Status Badge */}
                  <div className="flex flex-col items-end space-y-1">
                    <span
                      className={`inline-flex items-center space-x-1.5 text-xs font-medium px-2.5 py-1 rounded-full border ${
                        isVerified
                          ? 'bg-emerald-950/70 text-emerald-400 border-emerald-800/60'
                          : isGrace
                          ? 'bg-amber-950/70 text-amber-400 border-amber-800/60'
                          : 'bg-blue-950/70 text-blue-400 border-blue-800/60'
                      }`}
                    >
                      {isVerified ? (
                        <CheckCircle2 className="w-3.5 h-3.5" />
                      ) : isGrace ? (
                        <Clock className="w-3.5 h-3.5" />
                      ) : (
                        <AlertCircle className="w-3.5 h-3.5" />
                      )}
                      <span>{site.status.replace('_', ' ')}</span>
                    </span>

                    {/* Scan Eligibility Indicator */}
                    <div className="flex items-center space-x-1 text-[10px]">
                      {site.scanBlocked ? (
                        <span className="text-amber-400 flex items-center space-x-1">
                          <ShieldX className="w-3 h-3" />
                          <span>Scan Freeze Active</span>
                        </span>
                      ) : (
                        <span className="text-emerald-400 flex items-center space-x-1">
                          <ShieldCheck className="w-3 h-3" />
                          <span>Scan Eligible</span>
                        </span>
                      )}
                    </div>
                  </div>
                </div>

                {/* Metadata & Subdomains */}
                <div className="grid grid-cols-2 gap-3 text-xs bg-slate-900/50 p-3 rounded-lg border border-slate-800/60">
                  <div>
                    <span className="text-slate-500 block text-[10px] uppercase font-semibold">Risk Tier</span>
                    <span
                      className={`font-semibold ${
                        site.riskTier === 'CRITICAL'
                          ? 'text-rose-400'
                          : site.riskTier === 'HIGH'
                          ? 'text-orange-400'
                          : 'text-amber-400'
                      }`}
                    >
                      {site.riskTier}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[10px] uppercase font-semibold">Telemetry Status</span>
                    <span className="text-slate-300 flex items-center space-x-1">
                      <Activity className="w-3 h-3 text-cyan-400" />
                      <span>{site.health?.telemetryStatus || 'INACTIVE'}</span>
                    </span>
                  </div>

                  {site.approvedSubdomains && site.approvedSubdomains.length > 0 && (
                    <div className="col-span-2 pt-1 border-t border-slate-800/50">
                      <span className="text-slate-500 block text-[10px] uppercase font-semibold mb-1">
                        Approved Subdomains ({site.approvedSubdomains.length})
                      </span>
                      <div className="flex flex-wrap gap-1">
                        {site.approvedSubdomains.map((sub) => (
                          <span
                            key={sub}
                            className="bg-slate-800/80 text-slate-300 px-2 py-0.5 rounded text-[11px] font-mono border border-slate-700/50"
                          >
                            {sub}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                {/* Expiration and Timeline */}
                <div className="flex items-center justify-between text-[11px] text-slate-400">
                  {site.expiresAt && (
                    <span>
                      Verification valid until:{' '}
                      <strong className="text-slate-200">
                        {new Date(site.expiresAt).toLocaleDateString()}
                      </strong>
                    </span>
                  )}
                  {site.gracePeriodEndsAt && (
                    <span className="text-amber-400">
                      Grace period ends:{' '}
                      <strong>{new Date(site.gracePeriodEndsAt).toLocaleDateString()}</strong>
                    </span>
                  )}
                  <span className="text-slate-500">ID: {site.siteId.slice(0, 14)}...</span>
                </div>

                {/* Action buttons */}
                <div className="pt-2 border-t border-slate-800 flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    {(!isVerified || isGrace) && (
                      <button
                        onClick={() => setSelectedSiteForVerify(site)}
                        className="px-3 py-1.5 text-xs font-semibold rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 hover:bg-cyan-500/30 transition-colors"
                      >
                        Verify Domain
                      </button>
                    )}
                    {isVerified && (
                      <button
                        onClick={() => handleRevoke(site)}
                        className="px-2.5 py-1.5 text-xs font-medium rounded text-amber-400 hover:text-amber-300 hover:bg-amber-950/30 border border-transparent hover:border-amber-800/50 transition-colors"
                      >
                        Revoke
                      </button>
                    )}
                  </div>

                  <button
                    onClick={() => handleDelete(site)}
                    className="p-1.5 text-slate-500 hover:text-rose-400 rounded hover:bg-slate-800 transition-colors"
                    title="Delete Website Asset"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Modal: Register Website Asset */}
      {isAddModalOpen && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0D1527] border border-slate-800 rounded-xl max-w-lg w-full p-6 space-y-5 shadow-2xl relative">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-lg font-bold text-white flex items-center space-x-2">
                <Globe className="w-5 h-5 text-cyan-400" />
                <span>Register New Website Asset</span>
              </h3>
              <button
                onClick={() => setIsAddModalOpen(false)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleCreateSubmit} className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-300 font-medium mb-1">Asset Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Production Customer Portal"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-cyan-400"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  Primary Domain (FQDN only, no http://)
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. app.example.com"
                  value={formData.primaryDomain}
                  onChange={(e) => setFormData({ ...formData, primaryDomain: e.target.value })}
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white font-mono focus:outline-none focus:border-cyan-400"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  Approved Subdomains (comma-separated)
                </label>
                <input
                  type="text"
                  placeholder="e.g. api.example.com, auth.example.com"
                  value={formData.subdomains}
                  onChange={(e) => setFormData({ ...formData, subdomains: e.target.value })}
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white font-mono focus:outline-none focus:border-cyan-400"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 font-medium mb-1">Environment</label>
                  <select
                    value={formData.environment}
                    onChange={(e) => setFormData({ ...formData, environment: e.target.value as any })}
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-cyan-400"
                  >
                    <option value="PRODUCTION">PRODUCTION</option>
                    <option value="STAGING">STAGING</option>
                    <option value="DEVELOPMENT">DEVELOPMENT</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-300 font-medium mb-1">Criticality Risk Tier</label>
                  <select
                    value={formData.riskTier}
                    onChange={(e) => setFormData({ ...formData, riskTier: e.target.value as any })}
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-cyan-400"
                  >
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Tags (comma-separated)</label>
                <input
                  type="text"
                  placeholder="e.g. ecommerce, pci-dss, customer-facing"
                  value={formData.tags}
                  onChange={(e) => setFormData({ ...formData, tags: e.target.value })}
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-cyan-400"
                />
              </div>

              <div className="pt-3 border-t border-slate-800 flex items-center justify-end space-x-3">
                <button
                  type="button"
                  onClick={() => setIsAddModalOpen(false)}
                  className="px-4 py-2 text-slate-400 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-5 py-2 font-semibold bg-cyan-400 hover:bg-cyan-300 text-slate-950 rounded-lg shadow-md transition-all"
                >
                  Register Asset
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Domain Ownership Verification Details & Trigger */}
      {selectedSiteForVerify && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0D1527] border border-slate-800 rounded-xl max-w-xl w-full p-6 space-y-5 shadow-2xl relative">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-lg font-bold text-white flex items-center space-x-2">
                  <ShieldCheck className="w-5 h-5 text-cyan-400" />
                  <span>Verify Domain Ownership</span>
                </h3>
                <p className="text-xs text-slate-400 font-mono mt-0.5">
                  {selectedSiteForVerify.primaryDomain}
                </p>
              </div>
              <button
                onClick={() => setSelectedSiteForVerify(null)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <p className="text-xs text-slate-300">
              To guarantee zero-bypass authorization and protect third-party websites, you must prove control of this domain using one of the two challenge methods below:
            </p>

            {/* Method A: DNS TXT */}
            <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-lg space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-cyan-400 uppercase tracking-wider">
                  Option 1: DNS TXT Record (Recommended)
                </span>
                <span className="text-[10px] bg-cyan-950 text-cyan-300 border border-cyan-800/60 px-2 py-0.5 rounded">
                  90-Day Validity
                </span>
              </div>
              <div className="space-y-2 text-xs">
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase font-semibold">Host / Name</span>
                  <div className="flex items-center justify-between bg-slate-950 px-3 py-1.5 rounded font-mono text-slate-200 border border-slate-800">
                    <span className="truncate">{selectedSiteForVerify.dnsTxtRecord?.host}</span>
                    <button
                      onClick={() => copyToClipboard(selectedSiteForVerify.dnsTxtRecord?.host || '')}
                      className="text-slate-400 hover:text-cyan-400 ml-2"
                    >
                      <Copy className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase font-semibold">Value / Target</span>
                  <div className="flex items-center justify-between bg-slate-950 px-3 py-1.5 rounded font-mono text-slate-200 border border-slate-800">
                    <span className="truncate">{selectedSiteForVerify.dnsTxtRecord?.value}</span>
                    <button
                      onClick={() => copyToClipboard(selectedSiteForVerify.dnsTxtRecord?.value || '')}
                      className="text-slate-400 hover:text-cyan-400 ml-2"
                    >
                      <Copy className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              </div>
              <button
                disabled={isVerifying}
                onClick={() => handleVerify('DNS_TXT')}
                className="w-full mt-2 py-2 text-xs font-semibold rounded bg-cyan-500 hover:bg-cyan-400 text-slate-950 transition-colors flex items-center justify-center space-x-1.5"
              >
                {isVerifying && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
                <span>Check & Verify DNS TXT Record</span>
              </button>
            </div>

            {/* Method B: HTTP Challenge */}
            <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-lg space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-blue-400 uppercase tracking-wider">
                  Option 2: Well-Known HTTP Challenge
                </span>
              </div>
              <div className="space-y-2 text-xs">
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase font-semibold">Endpoint URL</span>
                  <div className="flex items-center justify-between bg-slate-950 px-3 py-1.5 rounded font-mono text-slate-200 border border-slate-800">
                    <span className="truncate">{selectedSiteForVerify.httpChallenge?.url}</span>
                    <button
                      onClick={() => copyToClipboard(selectedSiteForVerify.httpChallenge?.url || '')}
                      className="text-slate-400 hover:text-blue-400 ml-2"
                    >
                      <Copy className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase font-semibold">Expected JSON Body</span>
                  <div className="flex items-center justify-between bg-slate-950 px-3 py-1.5 rounded font-mono text-slate-200 border border-slate-800">
                    <span className="truncate">{JSON.stringify(selectedSiteForVerify.httpChallenge?.expectedBody)}</span>
                    <button
                      onClick={() =>
                        copyToClipboard(JSON.stringify(selectedSiteForVerify.httpChallenge?.expectedBody, null, 2))
                      }
                      className="text-slate-400 hover:text-blue-400 ml-2"
                    >
                      <Copy className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              </div>
              <button
                disabled={isVerifying}
                onClick={() => handleVerify('HTTP_CHALLENGE')}
                className="w-full mt-2 py-2 text-xs font-semibold rounded bg-blue-600 hover:bg-blue-500 text-white transition-colors flex items-center justify-center space-x-1.5"
              >
                {isVerifying && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
                <span>Check & Verify HTTP Endpoint</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
