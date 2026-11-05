import { useState } from 'react';
import {
  ShieldCheck,
  Globe,
  Copy,
  Check,
  AlertTriangle,
  FileCode,
  Radio,
  X,
  RefreshCw,
  Lock,
} from 'lucide-react';
import type { WebsiteAsset } from '@veltrix/shared';
import { verifyDomain } from '../lib/api/endpoints';
import { Button, Badge } from './ui/primitives';

export interface DomainVerificationModalProps {
  isOpen: boolean;
  onClose: () => void;
  site: WebsiteAsset;
  onSuccess?: () => void;
}

export function DomainVerificationModal({
  isOpen,
  onClose,
  site,
  onSuccess,
}: DomainVerificationModalProps) {
  const [selectedMethod, setSelectedMethod] = useState<'DNS_TXT' | 'HTTP_CHALLENGE' | 'META_TAG'>('DNS_TXT');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  if (!isOpen) return null;

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard?.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const dnsTxtRecordValue = typeof site.dnsTxtRecord === 'object' && site.dnsTxtRecord !== null
    ? site.dnsTxtRecord.value
    : typeof (site.dnsTxtRecord as any) === 'string'
    ? (site.dnsTxtRecord as any)
    : `veltrix-domain-verification=${site.verificationToken || 'token'}`;

  const dnsTxtHost = typeof site.dnsTxtRecord === 'object' && site.dnsTxtRecord !== null && site.dnsTxtRecord.host
    ? site.dnsTxtRecord.host
    : `_veltrix-challenge.${site.primaryDomain}`;

  const httpUrl = site.httpChallenge?.url || `https://${site.primaryDomain}/.well-known/veltrix-challenge.txt`;

  const httpExpectedBody = typeof site.httpChallenge?.expectedBody === 'object' && site.httpChallenge.expectedBody !== null
    ? JSON.stringify(site.httpChallenge.expectedBody, null, 2)
    : typeof (site.httpChallenge?.expectedBody as any) === 'string'
    ? (site.httpChallenge.expectedBody as any)
    : site.verificationToken || 'token';

  const metaTagContent = typeof site.metaTag === 'object' && site.metaTag !== null
    ? site.metaTag.tag
    : typeof (site.metaTag as any) === 'string'
    ? (site.metaTag as any)
    : `<meta name="veltrix-domain-verification" content="${site.verificationToken || 'token'}">`;

  const handleVerify = async () => {
    try {
      setIsSubmitting(true);
      setErrorMessage(null);
      setSuccessMessage(null);

      const res = await verifyDomain(site.siteId, selectedMethod);
      if (res.verified) {
        setSuccessMessage(res.message || 'Domain ownership verified successfully! Active scanning is now authorized.');
        if (onSuccess) {
          setTimeout(() => {
            onSuccess();
            onClose();
          }, 1500);
        }
      } else {
        setErrorMessage(res.message || 'Verification could not confirm domain ownership.');
      }
    } catch (err: unknown) {
      setErrorMessage((err as Error)?.message || 'Failed to complete verification request.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
      <div className="w-full max-w-2xl rounded-2xl border border-slate-800 bg-slate-900 shadow-2xl flex flex-col max-h-[90vh] overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 px-6 py-4">
          <div className="flex items-center gap-3">
            <div className="grid h-10 w-10 place-items-center rounded-xl bg-cyan-500/10 text-cyan-400">
              <ShieldCheck className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                Verify Domain Ownership
                <Badge tone="info">{site.primaryDomain}</Badge>
              </h2>
              <p className="text-xs text-slate-400">
                Prove domain administrative ownership to unlock automated crawling and active security probes.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-800 hover:text-white"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-6 overflow-y-auto">
          {/* Method selector tabs */}
          <div className="grid grid-cols-3 gap-2">
            {[
              {
                id: 'DNS_TXT',
                label: 'DNS TXT Record',
                desc: 'Add TXT record to domain DNS',
                icon: Globe,
              },
              {
                id: 'HTTP_CHALLENGE',
                label: 'HTTP Challenge',
                desc: 'Place challenge JSON file on web server',
                icon: FileCode,
              },
              {
                id: 'META_TAG',
                label: 'HTML Meta Tag',
                desc: 'Insert meta tag into homepage head',
                icon: Radio,
              },
            ].map((m) => {
              const Icon = m.icon;
              const active = selectedMethod === m.id;
              return (
                <button
                  type="button"
                  key={m.id}
                  onClick={() => {
                    setSelectedMethod(m.id as any);
                    setErrorMessage(null);
                  }}
                  className={`flex flex-col items-start gap-1 p-3 rounded-xl border text-left transition ${
                    active
                      ? 'border-cyan-500 bg-cyan-500/10 text-cyan-300'
                      : 'border-slate-800 bg-slate-950/40 text-slate-400 hover:border-slate-700 hover:text-slate-200'
                  }`}
                >
                  <div className="flex items-center gap-2 font-semibold text-xs text-white">
                    <Icon className={`h-4 w-4 ${active ? 'text-cyan-400' : 'text-slate-500'}`} />
                    <span>{m.label}</span>
                  </div>
                  <span className="text-[11px] text-slate-500 leading-tight">{m.desc}</span>
                </button>
              );
            })}
          </div>

          {/* Instructions Box */}
          <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4 space-y-3">
            {selectedMethod === 'DNS_TXT' && (
              <>
                <p className="text-xs text-slate-300">
                  Add the following <code className="text-cyan-400 font-mono">TXT</code> record with your DNS provider (Cloudflare, Route53, Namecheap, etc.):
                </p>

                <div>
                  <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block mb-1">Host / Name</span>
                  <div className="flex items-center justify-between rounded-lg bg-slate-900 border border-slate-800 px-3 py-2 font-mono text-xs text-white">
                    <span className="truncate">{dnsTxtHost}</span>
                    <button
                      type="button"
                      onClick={() => copyToClipboard(dnsTxtHost, 'host')}
                      className="ml-2 text-slate-400 hover:text-white"
                      title="Copy Host"
                    >
                      {copiedKey === 'host' ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                    </button>
                  </div>
                </div>

                <div>
                  <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block mb-1">TXT Record Value</span>
                  <div className="flex items-center justify-between rounded-lg bg-slate-900 border border-slate-800 px-3 py-2 font-mono text-xs text-cyan-300">
                    <span className="truncate">{dnsTxtRecordValue}</span>
                    <button
                      type="button"
                      onClick={() => copyToClipboard(dnsTxtRecordValue, 'txtval')}
                      className="ml-2 text-slate-400 hover:text-white"
                      title="Copy Value"
                    >
                      {copiedKey === 'txtval' ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                    </button>
                  </div>
                </div>
              </>
            )}

            {selectedMethod === 'HTTP_CHALLENGE' && (
              <>
                <p className="text-xs text-slate-300">
                  Upload a plain text or JSON file accessible via public HTTP(S) at:
                </p>

                <div>
                  <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block mb-1">File URL</span>
                  <div className="flex items-center justify-between rounded-lg bg-slate-900 border border-slate-800 px-3 py-2 font-mono text-xs text-white">
                    <span className="truncate">{httpUrl}</span>
                    <button
                      type="button"
                      onClick={() => copyToClipboard(httpUrl, 'httppath')}
                      className="ml-2 text-slate-400 hover:text-white"
                      title="Copy Path"
                    >
                      {copiedKey === 'httppath' ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                    </button>
                  </div>
                </div>

                <div>
                  <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block mb-1">Expected File Body</span>
                  <div className="flex items-center justify-between rounded-lg bg-slate-900 border border-slate-800 px-3 py-2 font-mono text-xs text-cyan-300">
                    <span className="truncate">{httpExpectedBody}</span>
                    <button
                      type="button"
                      onClick={() => copyToClipboard(httpExpectedBody, 'httpbody')}
                      className="ml-2 text-slate-400 hover:text-white"
                      title="Copy Body"
                    >
                      {copiedKey === 'httpbody' ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                    </button>
                  </div>
                </div>
              </>
            )}

            {selectedMethod === 'META_TAG' && (
              <>
                <p className="text-xs text-slate-300">
                  Add the following meta tag inside the <code className="text-cyan-400 font-mono">&lt;head&gt;</code> element of your homepage (<code className="text-slate-400 font-mono">/</code>):
                </p>

                <div>
                  <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block mb-1">HTML Tag</span>
                  <div className="flex items-center justify-between rounded-lg bg-slate-900 border border-slate-800 px-3 py-2 font-mono text-xs text-cyan-300">
                    <span className="truncate">{metaTagContent}</span>
                    <button
                      type="button"
                      onClick={() => copyToClipboard(metaTagContent, 'metatag')}
                      className="ml-2 text-slate-400 hover:text-white"
                      title="Copy Tag"
                    >
                      {copiedKey === 'metatag' ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                    </button>
                  </div>
                </div>
              </>
            )}
          </div>

          {/* Feedback messages */}
          {errorMessage && (
            <div className="flex items-start gap-2.5 rounded-xl border border-rose-500/40 bg-rose-500/10 p-3 text-xs text-rose-300">
              <AlertTriangle className="h-4 w-4 shrink-0 text-rose-400 mt-0.5" />
              <span>{errorMessage}</span>
            </div>
          )}

          {successMessage && (
            <div className="flex items-start gap-2.5 rounded-xl border border-emerald-500/40 bg-emerald-500/10 p-3 text-xs text-emerald-300">
              <Check className="h-4 w-4 shrink-0 text-emerald-400 mt-0.5" />
              <span>{successMessage}</span>
            </div>
          )}

          {/* Verification Scope Gate Note */}
          <div className="flex items-start gap-2 rounded-lg bg-slate-950 p-3 text-[11px] text-slate-400 border border-slate-800">
            <Lock className="h-4 w-4 shrink-0 text-cyan-400 mt-0.5" />
            <span>
              <strong>Zero-Trust Gate:</strong> Active vulnerability probes and depth crawlers require confirmed domain ownership. Verification expires automatically after 90 days.
            </span>
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-3 border-t border-slate-800 bg-slate-900/60 px-6 py-4">
          <Button variant="ghost" size="sm" onClick={onClose} disabled={isSubmitting}>
            Cancel
          </Button>
          <Button
            variant="primary"
            size="sm"
            icon={isSubmitting ? RefreshCw : ShieldCheck}
            onClick={handleVerify}
            disabled={isSubmitting}
          >
            {isSubmitting ? 'Verifying Challenge...' : 'Verify Ownership Now'}
          </Button>
        </div>
      </div>
    </div>
  );
}
