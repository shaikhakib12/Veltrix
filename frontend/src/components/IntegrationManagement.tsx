import React, { useState, useEffect } from 'react';
import {
  Layers,
  Plus,
  Key,
  RotateCw,
  Ban,
  Trash2,
  Copy,
  CheckCircle2,
  AlertCircle,
  RefreshCw,
  X,
  Server,
  Cloud,
  Code2,
  Activity,
  AlertTriangle,
} from 'lucide-react';
import type { Integration, WebsiteAsset } from '@veltrix/shared';
import {
  fetchIntegrations,
  fetchWebsites,
  createIntegration,
  rotateIntegrationKey,
  revokeIntegration,
  deleteIntegration,
} from '../api';

export function IntegrationManagement() {
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [websites, setWebsites] = useState<WebsiteAsset[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Modal states
  const [isRegisterModalOpen, setIsRegisterModalOpen] = useState(false);
  const [newSecretReveal, setNewSecretReveal] = useState<{ name: string; secretKey: string } | null>(null);

  // Form state
  const [formData, setFormData] = useState({
    name: '',
    type: 'EXPRESS',
    siteId: '',
    description: '',
  });

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);
      const [intData, siteData] = await Promise.all([
        fetchIntegrations(),
        fetchWebsites().catch(() => ({ total: 0, sites: [] })),
      ]);
      setIntegrations(intData.integrations);
      setWebsites(siteData.sites);
    } catch (err: unknown) {
      setError((err as Error).message || 'Failed to load integrations.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleRegisterSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setActionMessage(null);
      const res = await createIntegration({
        name: formData.name,
        type: formData.type,
        siteId: formData.siteId || undefined,
        description: formData.description || undefined,
      });

      setIsRegisterModalOpen(false);
      setFormData({
        name: '',
        type: 'EXPRESS',
        siteId: '',
        description: '',
      });

      setNewSecretReveal({
        name: res.integration.name,
        secretKey: res.secretKey,
      });

      await loadData();
    } catch (err: unknown) {
      setActionMessage({
        type: 'error',
        text: (err as Error).message || 'Failed to create integration.',
      });
    }
  };

  const handleRotateKey = async (integration: Integration) => {
    if (
      !window.confirm(
        `Rotate API key for '${integration.name}'? The existing key will be invalidated immediately.`
      )
    ) {
      return;
    }

    try {
      const res = await rotateIntegrationKey(integration.integrationId);
      setNewSecretReveal({
        name: integration.name,
        secretKey: res.secretKey,
      });
      await loadData();
    } catch (err: unknown) {
      setActionMessage({
        type: 'error',
        text: (err as Error).message || 'Key rotation failed.',
      });
    }
  };

  const handleRevoke = async (integration: Integration) => {
    if (
      !window.confirm(
        `Revoke integration '${integration.name}'? All further telemetry dispatched using its key will be rejected.`
      )
    ) {
      return;
    }

    try {
      await revokeIntegration(integration.integrationId);
      setActionMessage({
        type: 'success',
        text: `Integration '${integration.name}' revoked.`,
      });
      await loadData();
    } catch (err: unknown) {
      setActionMessage({
        type: 'error',
        text: (err as Error).message || 'Failed to revoke integration.',
      });
    }
  };

  const handleDelete = async (integration: Integration) => {
    if (!window.confirm(`Delete integration '${integration.name}'?`)) {
      return;
    }

    try {
      await deleteIntegration(integration.integrationId);
      setActionMessage({
        type: 'success',
        text: `Integration '${integration.name}' deleted.`,
      });
      await loadData();
    } catch (err: unknown) {
      setActionMessage({
        type: 'error',
        text: (err as Error).message || 'Failed to delete integration.',
      });
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    alert('Secret API key copied to clipboard!');
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'SDK_NODE':
      case 'EXPRESS':
        return <Code2 className="w-4 h-4 text-cyan-400" />;
      case 'NGINX':
      case 'APACHE':
        return <Server className="w-4 h-4 text-emerald-400" />;
      case 'CLOUDFLARE':
      case 'AWS_WAF':
      case 'AWS_CLOUDTRAIL':
        return <Cloud className="w-4 h-4 text-blue-400" />;
      default:
        return <Layers className="w-4 h-4 text-slate-400" />;
    }
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

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-[#0D1527] border border-slate-800 p-5 rounded-xl shadow-lg">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center space-x-2">
            <Layers className="w-6 h-6 text-cyan-400" />
            <span>Telemetry Integrations & Ingestion Clients</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Registered Node.js Express SDKs, Nginx/Apache log forwarders, and cloud connectors streaming real-time web attack telemetry.
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={loadData}
            disabled={loading}
            className="flex items-center space-x-1.5 px-3 py-2 text-xs font-medium text-slate-300 bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700 rounded-lg transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
          <button
            onClick={() => setIsRegisterModalOpen(true)}
            className="flex items-center space-x-2 px-4 py-2 text-xs font-semibold text-slate-950 bg-gradient-to-r from-cyan-400 to-blue-500 hover:from-cyan-300 hover:to-blue-400 rounded-lg shadow-md shadow-cyan-500/20 transition-all"
          >
            <Plus className="w-4 h-4" />
            <span>Register Integration</span>
          </button>
        </div>
      </div>

      {/* Error View */}
      {error && (
        <div className="p-6 bg-rose-950/20 border border-rose-800/50 rounded-xl text-center space-y-3">
          <AlertTriangle className="w-8 h-8 text-rose-400 mx-auto" />
          <p className="text-sm text-rose-300 font-medium">{error}</p>
          <button
            onClick={loadData}
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
          <p className="text-sm text-slate-400">Loading integrations from API Gateway...</p>
        </div>
      )}

      {/* Empty State */}
      {!loading && !error && integrations.length === 0 && (
        <div className="p-12 text-center space-y-4 bg-[#0D1527] border border-slate-800 rounded-xl">
          <Layers className="w-12 h-12 text-slate-600 mx-auto" />
          <div className="space-y-1">
            <h3 className="text-base font-semibold text-white">No Telemetry Integrations Connected</h3>
            <p className="text-xs text-slate-400 max-w-md mx-auto">
              Create an integration to generate an API key for `@veltrix/sdk-node` or your Nginx/Apache log collector.
            </p>
          </div>
          <button
            onClick={() => setIsRegisterModalOpen(true)}
            className="inline-flex items-center space-x-2 px-4 py-2 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-lg"
          >
            <Plus className="w-4 h-4" />
            <span>Register First Integration</span>
          </button>
        </div>
      )}

      {/* Integrations Table / List */}
      {!loading && !error && integrations.length > 0 && (
        <div className="bg-[#0D1527] border border-slate-800 rounded-xl overflow-hidden shadow-lg">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-900/80 border-b border-slate-800 text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                <tr>
                  <th className="px-5 py-3.5">Integration Name</th>
                  <th className="px-4 py-3.5">Type</th>
                  <th className="px-4 py-3.5">Status</th>
                  <th className="px-4 py-3.5">API Key Prefix</th>
                  <th className="px-4 py-3.5">Telemetry Health</th>
                  <th className="px-4 py-3.5">Last Seen</th>
                  <th className="px-5 py-3.5 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {integrations.map((intItem) => {
                  const isActive = intItem.status === 'ACTIVE';
                  const isRevoked = intItem.status === 'REVOKED';

                  return (
                    <tr key={intItem.integrationId} className="hover:bg-slate-800/30 transition-colors">
                      <td className="px-5 py-4">
                        <div className="font-semibold text-white">{intItem.name}</div>
                        {intItem.description && (
                          <div className="text-[11px] text-slate-500">{intItem.description}</div>
                        )}
                        <div className="text-[10px] font-mono text-slate-600 mt-0.5">
                          {intItem.integrationId}
                        </div>
                      </td>

                      <td className="px-4 py-4">
                        <span className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-md bg-slate-800 border border-slate-700 font-medium text-slate-200">
                          {getTypeIcon(intItem.type)}
                          <span>{intItem.type}</span>
                        </span>
                      </td>

                      <td className="px-4 py-4">
                        <span
                          className={`inline-flex items-center space-x-1 text-[11px] px-2 py-0.5 rounded border uppercase font-semibold ${
                            isActive
                              ? 'bg-emerald-950/60 text-emerald-400 border-emerald-800/60'
                              : isRevoked
                              ? 'bg-rose-950/60 text-rose-400 border-rose-800/60'
                              : 'bg-slate-800 text-slate-400 border-slate-700'
                          }`}
                        >
                          <span>{intItem.status}</span>
                        </span>
                      </td>

                      <td className="px-4 py-4 font-mono text-slate-300">
                        {intItem.apiKeyPrefix}••••••••
                      </td>

                      <td className="px-4 py-4">
                        <div className="flex items-center space-x-2">
                          <Activity className="w-3.5 h-3.5 text-cyan-400" />
                          <span className="font-semibold text-slate-200">
                            {intItem.health?.eventsReceived || 0}
                          </span>
                          <span className="text-[10px] text-slate-500">events</span>
                        </div>
                        <div className="text-[10px] text-slate-500">
                          Status: {intItem.health?.status || 'INACTIVE'}
                        </div>
                      </td>

                      <td className="px-4 py-4 text-slate-400">
                        {intItem.lastSeenAt
                          ? new Date(intItem.lastSeenAt).toLocaleString()
                          : 'Never'}
                      </td>

                      <td className="px-5 py-4 text-right">
                        <div className="flex items-center justify-end space-x-2">
                          {isActive && (
                            <>
                              <button
                                onClick={() => handleRotateKey(intItem)}
                                className="p-1.5 text-slate-400 hover:text-cyan-400 hover:bg-slate-800 rounded transition-colors"
                                title="Rotate API Key"
                              >
                                <RotateCw className="w-3.5 h-3.5" />
                              </button>
                              <button
                                onClick={() => handleRevoke(intItem)}
                                className="p-1.5 text-slate-400 hover:text-amber-400 hover:bg-slate-800 rounded transition-colors"
                                title="Revoke Integration"
                              >
                                <Ban className="w-3.5 h-3.5" />
                              </button>
                            </>
                          )}
                          <button
                            onClick={() => handleDelete(intItem)}
                            className="p-1.5 text-slate-500 hover:text-rose-400 hover:bg-slate-800 rounded transition-colors"
                            title="Delete Integration"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Modal: Register Integration */}
      {isRegisterModalOpen && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0D1527] border border-slate-800 rounded-xl max-w-lg w-full p-6 space-y-5 shadow-2xl relative">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-lg font-bold text-white flex items-center space-x-2">
                <Layers className="w-5 h-5 text-cyan-400" />
                <span>Register New Telemetry Integration</span>
              </h3>
              <button
                onClick={() => setIsRegisterModalOpen(false)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleRegisterSubmit} className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-300 font-medium mb-1">Integration Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Production Node API"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-cyan-400"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Integration Type</label>
                <select
                  value={formData.type}
                  onChange={(e) => setFormData({ ...formData, type: e.target.value })}
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-cyan-400"
                >
                  <option value="EXPRESS">Express Middleware (@veltrix/sdk-node)</option>
                  <option value="SDK_NODE">Node.js Custom Client (@veltrix/sdk-node)</option>
                  <option value="NGINX">Nginx Log Collector (FluentBit)</option>
                  <option value="APACHE">Apache Log Collector (FluentBit)</option>
                  <option value="GENERIC_HTTP">Generic HTTP Webhook</option>
                  <option value="CLOUDFLARE">Cloudflare Worker (Edge)</option>
                  <option value="AWS_WAF">AWS WAF v2 Stream</option>
                </select>
              </div>

              {websites.length > 0 && (
                <div>
                  <label className="block text-slate-300 font-medium mb-1">
                    Associated Website (Optional)
                  </label>
                  <select
                    value={formData.siteId}
                    onChange={(e) => setFormData({ ...formData, siteId: e.target.value })}
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-cyan-400"
                  >
                    <option value="">-- No specific website bound --</option>
                    {websites.map((w) => (
                      <option key={w.siteId} value={w.siteId}>
                        {w.name} ({w.primaryDomain})
                      </option>
                    ))}
                  </select>
                </div>
              )}

              <div>
                <label className="block text-slate-300 font-medium mb-1">Description (Optional)</label>
                <input
                  type="text"
                  placeholder="e.g. Telemetry forwarder running on ECS Fargate"
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-cyan-400"
                />
              </div>

              <div className="pt-3 border-t border-slate-800 flex items-center justify-end space-x-3">
                <button
                  type="button"
                  onClick={() => setIsRegisterModalOpen(false)}
                  className="px-4 py-2 text-slate-400 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-5 py-2 font-semibold bg-cyan-400 hover:bg-cyan-300 text-slate-950 rounded-lg shadow-md transition-all"
                >
                  Create Integration
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Secret API Key Reveal Dialog */}
      {newSecretReveal && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0D1527] border border-amber-600/60 rounded-xl max-w-lg w-full p-6 space-y-4 shadow-2xl relative">
            <div className="flex items-center space-x-3">
              <div className="w-10 h-10 rounded-full bg-amber-500/20 flex items-center justify-center shrink-0">
                <Key className="w-5 h-5 text-amber-400" />
              </div>
              <div>
                <h3 className="text-base font-bold text-white">New API Key Generated</h3>
                <p className="text-xs text-slate-400">{newSecretReveal.name}</p>
              </div>
            </div>

            <div className="p-3 bg-amber-950/30 border border-amber-800/50 rounded-lg text-xs text-amber-300 space-y-1">
              <p className="font-semibold">Important Security Notice:</p>
              <p>
                This secret API key will <strong>never be shown again</strong>. Store it immediately in your application environment or secret manager (e.g. AWS Secrets Manager, Vault).
              </p>
            </div>

            <div className="space-y-1">
              <span className="text-[10px] font-semibold uppercase text-slate-400">Secret API Key</span>
              <div className="flex items-center justify-between bg-slate-950 border border-slate-700 px-3 py-2 rounded-lg font-mono text-xs text-cyan-300">
                <span className="truncate select-all">{newSecretReveal.secretKey}</span>
                <button
                  onClick={() => copyToClipboard(newSecretReveal.secretKey)}
                  className="p-1 hover:text-white text-slate-400 ml-2"
                  title="Copy to clipboard"
                >
                  <Copy className="w-4 h-4" />
                </button>
              </div>
            </div>

            <div className="pt-2 flex justify-end">
              <button
                onClick={() => setNewSecretReveal(null)}
                className="px-5 py-2 text-xs font-semibold bg-cyan-400 hover:bg-cyan-300 text-slate-950 rounded-lg"
              >
                I have securely saved this key
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
