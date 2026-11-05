import { useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Crosshair, PlayCircle, Radar, RefreshCw, ShieldAlert, X } from 'lucide-react';
import type { Detection, Severity } from '@veltrix/shared';
import {
  fetchDetectionEvidence,
  fetchDetections,
  fetchWebsites,
  runDetections,
} from '../lib/api/endpoints';
import {
  Badge,
  Button,
  Card,
  ConfidenceBadge,
  Drawer,
  EmptyState,
  ErrorState,
  KpiTile,
  LoadingPanel,
  PageHeader,
  Select,
  SeverityBadge,
  StatusBadge,
} from '../components/ui/primitives';
import { formatDateTime, formatNumber, timeAgo, titleCase } from '../lib/format';
import { useAuth } from '../features/auth/AuthProvider';

const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

function EvidencePanel({ detectionId }: { detectionId: string }) {
  const evidence = useQuery({
    queryKey: ['detections', 'evidence', detectionId],
    queryFn: () => fetchDetectionEvidence(detectionId),
  });

  if (evidence.isLoading) return <LoadingPanel rows={3} />;
  if (evidence.isError) {
    return (
      <ErrorState
        message={evidence.error instanceof Error ? evidence.error.message : undefined}
        onRetry={() => evidence.refetch()}
      />
    );
  }

  const payload = evidence.data?.data;
  if (!payload) return null;
  const details = (payload.evidence?.details || {}) as Record<string, unknown>;
  const patterns = Array.isArray(details.matchedPatterns)
    ? (details.matchedPatterns as string[])
    : [];
  const signals = Array.isArray(details.corroboratingSignals)
    ? (details.corroboratingSignals as string[])
    : [];

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3">
        <div className="rounded-lg border border-veltrix-border bg-veltrix-chrome/50 p-3">
          <div className="vx-label">Confidence</div>
          <div className="mt-1 font-mono text-lg font-bold text-white">{payload.confidence}</div>
        </div>
        <div className="rounded-lg border border-veltrix-border bg-veltrix-chrome/50 p-3">
          <div className="vx-label">Threshold</div>
          <div className="mt-1 font-mono text-lg font-bold text-white">
            {payload.evidence?.matchedThreshold ?? '—'}
          </div>
        </div>
      </div>

      {patterns.length > 0 ? (
        <div>
          <div className="vx-label mb-1.5">Matched signatures</div>
          <div className="flex flex-wrap gap-1.5">
            {patterns.map((pattern) => (
              <Badge key={pattern} tone="high">
                {pattern.replaceAll('_', ' ')}
              </Badge>
            ))}
          </div>
        </div>
      ) : null}

      {signals.length > 0 ? (
        <div>
          <div className="vx-label mb-1.5">Corroborating signals</div>
          <ul className="space-y-1">
            {signals.map((signal) => (
              <li
                key={signal}
                className="rounded-md border border-veltrix-border/70 bg-veltrix-chrome/40 px-2.5 py-1.5 font-mono text-[10px] text-cyan-200/90"
              >
                {signal}
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      <div>
        <div className="vx-label mb-1.5">Triggering events</div>
        <div className="flex flex-wrap gap-1.5">
          {(payload.evidence?.triggeringEvents || []).map((eventId) => (
            <Link
              key={eventId}
              to={`/events?focus=${eventId}`}
              className="rounded-md border border-veltrix-border bg-veltrix-surface/70 px-2 py-1 font-mono text-[10px] text-slate-300 hover:border-cyan-500/40 hover:text-cyan-200"
            >
              {eventId.slice(0, 12)}
            </Link>
          ))}
        </div>
      </div>

      <div>
        <div className="vx-label mb-1.5">Evidence detail</div>
        <pre className="max-h-80 overflow-auto rounded-lg border border-veltrix-border bg-veltrix-chrome/80 p-3 font-mono text-[10px] leading-relaxed text-slate-400 vx-scroll">
          {JSON.stringify(details, null, 2)}
        </pre>
      </div>
    </div>
  );
}

export function DetectionsPage() {
  const [params] = useSearchParams();
  const [severity, setSeverity] = useState('');
  const [ruleId, setRuleId] = useState('');
  const [siteId, setSiteId] = useState('');
  const [selected, setSelected] = useState<Detection | null>(
    null
  );
  const [focused, setFocused] = useState<string | null>(params.get('focus'));
  const queryClient = useQueryClient();
  const { can } = useAuth();

  const detections = useQuery({
    queryKey: ['detections', { severity, ruleId, siteId }],
    queryFn: () =>
      fetchDetections({
        limit: 100,
        severity: (severity || undefined) as Severity | undefined,
        ruleId: ruleId || undefined,
        siteId: siteId || undefined,
      }),
    refetchInterval: 30_000,
  });

  const sites = useQuery({
    queryKey: ['websites', 'list'],
    queryFn: fetchWebsites,
  });

  const run = useMutation({
    mutationFn: () =>
      runDetections({
        startTime: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
        endTime: new Date().toISOString(),
        persistDetections: true,
        limit: 1000,
      }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['detections'] }),
  });

  const items = detections.data?.data.items || [];

  const stats = useMemo(() => {
    const critical = items.filter((item) => item.severity === 'CRITICAL').length;
    const high = items.filter((item) => item.severity === 'HIGH').length;
    const confirmed = items.filter(
      (item) =>
        (item.evidence?.details as Record<string, unknown> | undefined)?.confidenceLevel ===
        'CONFIRMED_EXPLOITATION'
    ).length;
    return { critical, high, confirmed, total: items.length };
  }, [items]);

  const activeDetection = selected || items.find((item) => item.detectionId === focused) || null;

  const runResult = run.data?.data as
    | { persisted?: number; detections?: Detection[]; totalDetections?: number }
    | undefined;

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow="Detect"
        title="Detection findings"
        description="Rule-engine output with confidence tiers, matched signatures and retained evidence."
        actions={
          <>
            <Button
              size="sm"
              variant="secondary"
              icon={RefreshCw}
              onClick={() => detections.refetch()}
              disabled={detections.isFetching}
            >
              Refresh
            </Button>
            {can(['ORG_ADMIN', 'SUPER_ADMIN', 'SECURITY_ANALYST']) ? (
              <Button
                size="sm"
                variant="primary"
                icon={PlayCircle}
                disabled={run.isPending}
                onClick={() => run.mutate()}
              >
                {run.isPending ? 'Running…' : 'Run rules (24h)'}
              </Button>
            ) : null}
          </>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiTile label="Findings" value={formatNumber(stats.total)} icon={Radar} tone="info" />
        <KpiTile
          label="Confirmed exploitation"
          value={formatNumber(stats.confirmed)}
          icon={ShieldAlert}
          tone="critical"
          hint="highest confidence tier"
        />
        <KpiTile label="Critical" value={formatNumber(stats.critical)} tone="critical" />
        <KpiTile label="High" value={formatNumber(stats.high)} tone="high" />
      </div>

      {run.data ? (
        <div className="flex items-center justify-between gap-3 rounded-xl border border-cyan-500/25 bg-cyan-500/[0.07] px-4 py-2.5 text-[11px] text-cyan-200">
          <span>
            Rule run complete —{' '}
            {runResult?.persisted ??
              runResult?.totalDetections ??
              (Array.isArray(runResult?.detections) ? runResult?.detections.length : 0)}{' '}
            detections persisted from the last 24 hours of telemetry.
          </span>
          <button type="button" onClick={() => run.reset()} aria-label="Dismiss">
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
      ) : null}
      {run.error ? (
        <div className="rounded-xl border border-rose-500/25 bg-rose-500/[0.07] px-4 py-2.5 text-[11px] text-rose-200">
          {run.error instanceof Error ? run.error.message : 'Rule execution failed.'}
        </div>
      ) : null}

      <Card className="p-4">
        <div className="flex flex-wrap items-end gap-3">
          <label className="space-y-1.5">
            <span className="vx-label">Severity</span>
            <Select value={severity} onChange={(event) => setSeverity(event.target.value)}>
              <option value="">Any</option>
              {SEVERITIES.map((value) => (
                <option key={value} value={value}>
                  {titleCase(value)}
                </option>
              ))}
            </Select>
          </label>
          <label className="space-y-1.5">
            <span className="vx-label">Rule</span>
            <Select value={ruleId} onChange={(event) => setRuleId(event.target.value)}>
              <option value="">Any rule</option>
              <option value="RULE-101">RULE-101 · SQL injection</option>
              <option value="RULE-102">RULE-102 · XSS</option>
              <option value="RULE-103">RULE-103 · Path traversal</option>
              <option value="RULE-104">RULE-104 · Bot activity</option>
              <option value="RULE-105">RULE-105 · Auth tampering</option>
            </Select>
          </label>
          <label className="min-w-[200px] flex-1 space-y-1.5">
            <span className="vx-label">Asset</span>
            <Select value={siteId} onChange={(event) => setSiteId(event.target.value)}>
              <option value="">All assets</option>
              {(sites.data?.sites || []).map((site) => (
                <option key={site.siteId} value={site.siteId}>
                  {site.name} · {site.primaryDomain}
                </option>
              ))}
            </Select>
          </label>
          <Badge tone="neutral">{formatNumber(items.length)} shown</Badge>
        </div>
      </Card>

      <Card className="overflow-hidden">
        {detections.isError ? (
          <ErrorState
            message={
              detections.error instanceof Error ? detections.error.message : undefined
            }
            onRetry={() => detections.refetch()}
          />
        ) : detections.isLoading ? (
          <LoadingPanel rows={6} />
        ) : items.length === 0 ? (
          <EmptyState
            icon={Crosshair}
            title="No detections yet"
            description="Run the detection engine over the last 24 hours, or ingest attack telemetry through an integration."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="vx-table">
              <thead>
                <tr>
                  <th className="w-24">Severity</th>
                  <th>Detection</th>
                  <th className="w-28">Rule</th>
                  <th className="w-32">Confidence</th>
                  <th className="w-32">Observed</th>
                  <th className="w-24">Status</th>
                </tr>
              </thead>
              <tbody>
                {items.map((detection) => {
                  const details = (detection.evidence?.details || {}) as Record<string, unknown>;
                  return (
                    <tr
                      key={detection.detectionId}
                      className="cursor-pointer"
                      onClick={() => {
                        setSelected(detection);
                        setFocused(detection.detectionId);
                      }}
                    >
                      <td>
                        <SeverityBadge severity={detection.severity} />
                      </td>
                      <td>
                        <div className="font-medium text-slate-100">{detection.title}</div>
                        <div className="mt-0.5 truncate font-mono text-[10px] text-slate-500">
                          {String(details.domain || '—')} · {String(details.attackType || 'n/a')}
                        </div>
                      </td>
                      <td className="font-mono text-[11px] text-slate-400">{detection.ruleId}</td>
                      <td>
                        <div className="flex items-center gap-1.5">
                          <ConfidenceBadge confidence={String(details.confidenceLevel || '')} />
                        </div>
                        <div className="mt-1 font-mono text-[10px] text-slate-500">
                          score {detection.confidence}
                        </div>
                      </td>
                      <td>
                        <div className="text-[11px] text-slate-300">
                          {timeAgo(detection.detectedAt)}
                        </div>
                        <div className="text-[10px] text-slate-600">
                          {formatDateTime(detection.detectedAt)}
                        </div>
                      </td>
                      <td>
                        <StatusBadge status={detection.status || 'ACTIVE'} />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Drawer
        open={Boolean(activeDetection)}
        onClose={() => {
          setSelected(null);
          setFocused(null);
        }}
        title={activeDetection?.title || 'Detection'}
        subtitle={
          activeDetection
            ? `${activeDetection.ruleId} · ${formatDateTime(activeDetection.detectedAt)}`
            : undefined
        }
        footer={
          activeDetection ? (
            <div className="flex items-center justify-between text-[10px] text-slate-500">
              <span className="font-mono">{activeDetection.detectionId}</span>
              {activeDetection.mitreAttack ? (
                <Badge tone="info">
                  {activeDetection.mitreAttack.techniqueId} · {activeDetection.mitreAttack.tactic}
                </Badge>
              ) : null}
            </div>
          ) : null
        }
      >
        {activeDetection ? (
          <div className="space-y-4">
            <p className="text-[12px] leading-relaxed text-slate-300">
              {activeDetection.description}
            </p>
            <EvidencePanel detectionId={activeDetection.detectionId} />
          </div>
        ) : null}
      </Drawer>
    </div>
  );
}
