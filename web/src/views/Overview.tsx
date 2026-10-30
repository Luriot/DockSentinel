import { useEffect, useState } from 'react';
import { api, type FindingView, type OverviewData } from '../api.ts';
import { useApi, navigate } from '../hooks.ts';
import {
  EmptyState,
  ErrorPanel,
  ExposureBadge,
  FixBadge,
  IconActivity,
  IconAlert,
  IconBell,
  IconCheck,
  IconPlus,
  IconRefresh,
  IconServer,
  IconShield,
  KevBadge,
  PriorityBadge,
  SeverityBadge,
  TableSkeleton,
  useToast,
} from '../components/ui.tsx';
import { exposureShortLabel, relativeTime, shortImageId } from '../format.ts';

const PRIORITY_LABELS: Record<string, string> = {
  P1: 'Fix today',
  P2: 'This week',
  P3: 'Scheduled',
  P4: 'Backlog',
};

/**
 * The action word must be feasible: a finding with no listed fix cannot be "fixed today".
 * The tier still carries the rank; this word carries what the operator can actually do.
 */
const NO_FIX_LONG = 'No fix — accept and watch';

function actionWord(finding: FindingView, compact = false): string {
  const label = PRIORITY_LABELS[finding.priority.tier] ?? finding.priority.tier;
  if (finding.fixedVersion) return label;
  return compact ? 'No fix' : NO_FIX_LONG;
}

function CoverageRow({
  tone,
  label,
  value,
  detail,
  onClick,
}: {
  tone: 'online' | 'pending' | 'offline' | 'unknown' | 'running';
  label: string;
  value?: string;
  detail?: string;
  onClick?: () => void;
}) {
  const content = (
    <>
      <span className={`status-dot ${tone}`} aria-hidden="true" />
      <span className="ops-coverage-label">{label}</span>
      {value ? <span className="ops-coverage-value">{value}</span> : null}
      {detail ? <span className="ops-coverage-detail">{detail}</span> : null}
    </>
  );

  return onClick ? (
    <button type="button" className="ops-coverage-row" onClick={onClick}>
      {content}
    </button>
  ) : (
    <div className="ops-coverage-row">{content}</div>
  );
}

function ActivityIcon({ kind }: { kind: string }) {
  if (kind === 'resolved') return <IconCheck width={12} height={12} />;
  if (kind === 'changed') return <IconRefresh width={12} height={12} />;
  if (kind === 'reappeared') return <IconBell width={12} height={12} />;
  return <IconAlert width={12} height={12} />;
}

function eventDescription(kind: string): string {
  if (kind === 'resolved') return 'Finding no longer reported';
  if (kind === 'changed') return 'Finding updated';
  if (kind === 'reappeared') return 'Finding reappeared';
  return 'New finding detected';
}

function workloadSummary(finding: FindingView): string {
  if (finding.containers.length === 0) {
    return finding.containerCount > 0
      ? `${finding.containerCount} container${finding.containerCount === 1 ? '' : 's'}`
      : 'Image only';
  }
  const names = finding.containers.slice(0, 2).map((container) => container.name).join(', ');
  const extra = finding.containers.length > 2 ? ` +${finding.containers.length - 2}` : '';
  return `${names}${extra}`;
}

function workloadDetail(finding: FindingView): string {
  const counts =
    finding.containerCount > 0
      ? `${finding.containerCount} container${finding.containerCount === 1 ? '' : 's'}${
          finding.runningContainerCount > 0 ? `, ${finding.runningContainerCount} running` : ''
        }${
          finding.containerCount > finding.runningContainerCount
            ? `, ${finding.containerCount - finding.runningContainerCount} stopped`
            : ''
        }`
      : 'Image only';
  return finding.environmentNames.length > 0
    ? `${counts} · ${finding.environmentNames.join(', ')}`
    : counts;
}

function scanOutcome(scan: OverviewData['scans']['recent'][number]): {
  text: string;
  error: boolean;
  title: string;
} {
  if (scan.status === 'failed') {
    const text = scan.errorCode
      ? scan.errorCode.replace(/_/g, ' ').replace(/^./, (character) => character.toUpperCase())
      : 'Scan failed';
    return {
      text,
      error: true,
      title: [scan.errorCode, scan.errorMessage].filter(Boolean).join(' — ') || text,
    };
  }
  if (scan.status === 'success') {
    const parts = [
      scan.critical > 0 ? `${scan.critical} critical` : null,
      scan.high > 0 ? `${scan.high} high` : null,
      scan.medium > 0 ? `${scan.medium} medium` : null,
    ].filter((part): part is string => part !== null);
    // A scan with only low/unknown findings is not clean: never reduce it to "No findings".
    if (parts.length === 0) {
      if (scan.low > 0) parts.push(`${scan.low} low`);
      if (scan.unknown > 0) parts.push(`${scan.unknown} unknown`);
    }
    const titleParts = [
      scan.critical > 0 ? `${scan.critical} critical` : null,
      scan.high > 0 ? `${scan.high} high` : null,
      scan.medium > 0 ? `${scan.medium} medium` : null,
      scan.low > 0 ? `${scan.low} low` : null,
      scan.unknown > 0 ? `${scan.unknown} unknown` : null,
    ].filter((part): part is string => part !== null);
    return {
      text:
        parts.length > 0
          ? parts.join(' · ')
          : scan.total > 0
            ? `${scan.total} finding${scan.total === 1 ? '' : 's'}`
            : 'No findings',
      error: false,
      title: titleParts.length > 0 ? titleParts.join(' · ') : 'No findings',
    };
  }
  if (scan.status === 'cancelled') return { text: 'Cancelled', error: false, title: 'Scan cancelled' };
  if (scan.status === 'running') return { text: 'Running', error: false, title: 'Scan running' };
  if (scan.status === 'queued') return { text: 'Queued', error: false, title: 'Scan queued' };
  return { text: scan.status, error: false, title: scan.status };
}

export function Overview() {
  const { data, error, loading, refresh } = useApi<OverviewData>('/overview', { intervalMs: 15_000 });
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [updatedAt, setUpdatedAt] = useState<string | null>(null);
  const [acknowledging, setAcknowledging] = useState<number | null>(null);
  const toast = useToast();

  useEffect(() => {
    if (data && !error) setUpdatedAt(new Date().toISOString());
  }, [data, error]);

  if (loading && !data) {
    return (
      <div className="ops-page ops-loading" aria-busy="true" aria-label="Loading overview">
        <div className="ops-loading-stats">
          {[0, 1, 2, 3].map((index) => (
            <div key={index} className="ops-loading-stat">
              <div className="skeleton" style={{ width: 92, height: 9 }} />
              <div className="skeleton" style={{ width: 52, height: 30, marginTop: 8 }} />
              <div className="skeleton" style={{ width: 140, height: 9, marginTop: 8 }} />
            </div>
          ))}
        </div>
        <div className="ops-loading-grid">
          <div className="ops-loading-panel ops-loading-table">
            <div className="ops-loading-head" />
            <TableSkeleton rows={6} columns={6} />
          </div>
          <div className="ops-side">
            <div className="ops-loading-panel">
              <div className="skeleton" style={{ width: 120, height: 11 }} />
              <div className="skeleton" style={{ width: '82%', height: 22, marginTop: 12 }} />
              <div className="skeleton" style={{ width: '64%', height: 10, marginTop: 8 }} />
              <div className="skeleton" style={{ width: '92%', height: 10, marginTop: 18 }} />
              <div className="skeleton" style={{ width: '76%', height: 10, marginTop: 8 }} />
            </div>
            <div className="ops-loading-panel">
              <div className="skeleton" style={{ width: 150, height: 11 }} />
              <div className="skeleton" style={{ width: '88%', height: 10, marginTop: 12 }} />
              <div className="skeleton" style={{ width: '68%', height: 10, marginTop: 8 }} />
              <div className="skeleton" style={{ width: '80%', height: 10, marginTop: 8 }} />
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (error && !data) {
    return <ErrorPanel error={error} onRetry={refresh} />;
  }

  if (!data) return null;

  if (data.environments.length === 0) {
    return (
      <div className="ops-page">
        <section className="card ops-empty-page" aria-label="Connect your first Docker environment">
          <EmptyState
            icon={<IconShield width={30} height={30} />}
            title="Connect your first Docker environment"
            action={
              <div className="hstack" style={{ marginTop: 6 }}>
                <button type="button" className="btn primary" onClick={() => navigate('/environments')}>
                  <IconPlus width={14} height={14} /> Add environment
                </button>
                <button type="button" className="btn ghost" onClick={() => navigate('/settings')}>
                  Review scan policy
                </button>
              </div>
            }
          >
            DockSentinel discovers containers and images from a Docker Engine, then scans their images with Trivy.
            Start with the local socket on this host, or a secure remote endpoint.
          </EmptyState>
          <p className="ops-empty-note">
            Docker socket access is effectively privileged. Prefer local sockets or TLS-protected endpoints, and never
            expose an unauthenticated Docker TCP API.
          </p>
        </section>
      </div>
    );
  }

  const neverScanned = data.scans.lastSuccessfulAt === null;
  const scansInFlight = data.scans.queued + data.scans.running;
  // The API orders by severity; the tier also weighs exploitation, fixes, running state and
  // exposure, so rank here and let the row position agree with the badge.
  const ranked = [...data.findings.top]
    .sort((a, b) => b.priority.score - a.priority.score || a.priority.tier.localeCompare(b.priority.tier))
    .slice(0, 8);
  const focus = ranked[0] ?? null;
  const selected = ranked.find((finding) => finding.id === selectedId) ?? focus;
  const selectedRank = selected ? ranked.findIndex((finding) => finding.id === selected.id) + 1 : 0;

  const offline = data.environments.filter((environment) => environment.status === 'offline');
  const online = data.environments.filter((environment) => environment.status === 'online').length;
  const unreachable = data.environments.filter(
    (environment) => environment.enabled && environment.status === 'unknown',
  );
  const attention: {
    label: string;
    detail: string;
    path: string;
    tone: 'danger' | 'warn' | 'neutral';
    value?: string;
  }[] = [];
  if (offline.length > 0) {
    attention.push({
      label: 'Unavailable environments',
      detail: offline.map((environment) => environment.name).join(', '),
      value: String(offline.length),
      path: '/environments',
      tone: 'danger',
    });
  }
  if (unreachable.length > 0) {
    attention.push({
      label: 'Environments never contacted',
      detail: `${unreachable.map((environment) => environment.name).join(', ')}. Unknown is not healthy — no inventory was read from them.`,
      value: String(unreachable.length),
      path: '/environments',
      tone: 'neutral',
    });
  }
  if (data.scans.failed24h > 0) {
    attention.push({
      label: 'Scans failed in the last 24h',
      detail: 'Previous findings stay in place; no clean result is assumed.',
      value: String(data.scans.failed24h),
      path: '/scans?status=failed',
      tone: 'danger',
    });
  }
  if (!neverScanned && data.scans.success24h === 0) {
    attention.push({
      label: 'No successful scan in 24h',
      detail: `Last success ${relativeTime(data.scans.lastSuccessfulAt)}. The findings shown are kept, not freshly confirmed.`,
      path: '/scans',
      tone: 'warn',
    });
  }
  if (data.workloads.staleImages > 0) {
    attention.push({
      label: 'Stale scan results',
      detail: `In-use images not successfully scanned within ${data.freshnessHours}h.`,
      value: String(data.workloads.staleImages),
      path: '/images?stale=true',
      tone: 'warn',
    });
  }
  if (data.alerts.failed24h > 0) {
    attention.push({
      label: 'Alert delivery failures',
      detail: 'Notification attempts failed. Alerts are retried with backoff.',
      value: String(data.alerts.failed24h),
      path: '/notifications?status=failed',
      tone: 'warn',
    });
  }
  if (data.alerts.pending > 0) {
    attention.push({
      label: 'Alerts waiting for delivery',
      detail: 'Queued for delivery. Check the ntfy configuration if this grows.',
      value: String(data.alerts.pending),
      path: '/notifications?status=pending',
      tone: 'neutral',
    });
  }
  if (data.kev.status === 'error') {
    const fallback = data.kev.available
      ? `The last catalog, synced ${relativeTime(data.kev.syncedAt)}, is still being used.`
      : 'No catalog is available, so findings are not ranked for known exploitation.';
    attention.push({
      label: 'Known-exploited data could not be refreshed',
      detail: `${data.kev.error ?? 'The CISA KEV feed could not be refreshed.'} ${fallback}`,
      path: '/settings',
      tone: 'warn',
    });
  } else if (data.kev.available && data.kev.stale) {
    attention.push({
      label: 'Known-exploited data is stale',
      detail: `Catalog last synced ${relativeTime(data.kev.syncedAt)}. Findings added to KEV since then are not flagged.`,
      path: '/settings',
      tone: 'warn',
    });
  }
  if (data.workloads.runningContainers === 0) {
    attention.push({
      label: 'No running containers discovered',
      detail: 'DockSentinel only alerts for images used by monitored containers.',
      path: '/containers',
      tone: 'neutral',
    });
  }

  const recentScans = data.scans.recent.slice(0, 3);
  const recentEvents = data.events.slice(0, 4);
  const latestSuccess = data.scans.recent.find((scan) => scan.status === 'success');
  const scanTone = data.scans.running > 0 ? 'running' : data.scans.queued > 0 ? 'pending' : 'online';
  const segments: { key: 'critical' | 'high' | 'medium' | 'low' | 'unknown'; label: string; count: number }[] = [
    { key: 'critical', label: 'Critical', count: data.counts.critical },
    { key: 'high', label: 'High', count: data.counts.high },
    { key: 'medium', label: 'Medium', count: data.counts.medium },
    { key: 'low', label: 'Low', count: data.counts.low },
    { key: 'unknown', label: 'Unknown', count: data.counts.unknown },
  ];

  function openFinding(finding: FindingView): void {
    // Keep the image: the same CVE can exist on several images and the list is not filtered by it.
    navigate(
      `/vulnerabilities?q=${encodeURIComponent(finding.vulnId)}&image=${encodeURIComponent(finding.imageId)}`,
    );
  }

  async function acknowledge(finding: FindingView): Promise<void> {
    setAcknowledging(finding.id);
    try {
      await api.patch(`/findings/${finding.id}/triage`, {
        status: 'acknowledged',
        note: finding.triageNote ?? null,
      });
      toast('Finding acknowledged', 'success');
      refresh();
    } catch (caught) {
      toast(caught instanceof Error ? caught.message : 'Unable to acknowledge this finding', 'error');
    } finally {
      setAcknowledging(null);
    }
  }

  function attentionTone(tone: 'danger' | 'warn' | 'neutral'): 'offline' | 'pending' | 'unknown' {
    if (tone === 'danger') return 'offline';
    if (tone === 'warn') return 'pending';
    return 'unknown';
  }


  return (
    <div className="ops-page">
      {error && data ? (
        <section className="ops-banner is-stale" role="status" aria-label="Showing stored data">
          <span className="ops-banner-icon" aria-hidden="true">
            <IconAlert width={15} height={15} />
          </span>
          <div className="ops-banner-copy">
            <strong>Live updates are paused</strong>
            <span>
              This page last refreshed {updatedAt ? relativeTime(updatedAt) : 'before it opened'}. {error.message}
            </span>
          </div>
          <div className="ops-banner-actions">
            <button type="button" className="btn small ghost" onClick={refresh}>
              Retry now
            </button>
          </div>
        </section>
      ) : null}

      {neverScanned ? (
        <section className="ops-banner" aria-label="Getting started">
          <span className="ops-banner-icon" aria-hidden="true">
            <IconActivity width={15} height={15} />
          </span>
          <div className="ops-banner-copy">
            <strong>{scansInFlight > 0 ? 'Scanning your images…' : 'Your Docker host is connected'}</strong>
            <span>
              {scansInFlight > 0
                ? `${scansInFlight} scan${scansInFlight === 1 ? '' : 's'} queued or running. Results appear as each image finishes.`
                : 'Discovery is complete, but no scan has finished yet. Open Images to queue a scan or check the host status.'}
            </span>
          </div>
          <div className="ops-banner-actions">
            <button type="button" className="btn small ghost" onClick={() => navigate('/images')}>
              <IconServer width={12} height={12} /> Images
            </button>
            <button type="button" className="btn small ghost" onClick={() => navigate('/notifications')}>
              <IconBell width={12} height={12} /> Set up alerts
            </button>
          </div>
        </section>
      ) : null}

      {selected ? (
        <section className="ops-lead" aria-labelledby="lead-title">
          <div className="ops-lead-body">
            <div className="ops-lead-kicker">
              <SeverityBadge severity={selected.severity} />
              <PriorityBadge
                tier={selected.priority.tier}
                factors={selected.priority.factors}
                label={actionWord(selected)}
                rank={selectedRank > 0 ? selectedRank : undefined}
              />
              <KevBadge kev={selected.kev} />
              <FixBadge fixedVersion={selected.fixedVersion} />
              {selected.triageStatus === 'acknowledged' ? (
                <span className="badge neutral">Acknowledged</span>
              ) : null}
            </div>
            <p className="sr-only" role="status" aria-live="polite">
              {selectedRank > 0
                ? `Showing finding ${selectedRank} of ${ranked.length}: ${selected.vulnId}, ${selected.severity.toLowerCase()} severity, ${actionWord(selected)}.`
                : ''}
            </p>
            <h2 id="lead-title">{selected.vulnId}</h2>
            <p className="ops-lead-title">{selected.title ?? `${selected.pkgName} requires review`}</p>
            <dl className="ops-lead-meta">
              <div>
                <dt>Package</dt>
                <dd>
                  {selected.pkgName} · {selected.installedVersion || 'unknown'}
                </dd>
              </div>
              <div>
                <dt>Fixed in</dt>
                <dd className={selected.fixedVersion ? 'is-ok' : 'is-dim'}>
                  {selected.fixedVersion ?? 'No fix listed'}
                </dd>
              </div>
              <div>
                <dt>Workload</dt>
                <dd>{selected.containers[0]?.imageRef ?? shortImageId(selected.imageId)}</dd>
              </div>
              <div>
                <dt>Exposure</dt>
                <dd>{exposureShortLabel(selected.exposure)}</dd>
              </div>
              <div>
                <dt>First seen</dt>
                <dd>{relativeTime(selected.firstSeenAt)}</dd>
              </div>
            </dl>
            <div className="ops-factors">
              {selected.priority.factors.map((factor) => (
                <span className="ops-factor" key={factor}>
                  {factor}
                </span>
              ))}
            </div>
          </div>
          <div className="ops-lead-actions">
            <button type="button" className="btn primary" onClick={() => openFinding(selected)}>
              Review finding
            </button>
            {selected.triageStatus === 'acknowledged' ? null : (
              <button
                type="button"
                className="btn ghost"
                disabled={acknowledging === selected.id}
                onClick={() => void acknowledge(selected)}
              >
                {acknowledging === selected.id ? 'Acknowledging…' : 'Acknowledge'}
              </button>
            )}
            <button
              type="button"
              className="ops-text-link"
              onClick={() => navigate(`/images?image=${encodeURIComponent(selected.imageId)}`)}
            >
              Image &amp; containers
            </button>
          </div>
        </section>
      ) : null}

      <section className="risk" aria-label="Open findings">
        <div className="risk-main">
          <div className="risk-total">
            <span className="risk-label">Open findings</span>
            <span className="risk-value">{data.counts.total}</span>
            <span className="risk-sub">{data.counts.fixable} with a fix</span>
          </div>
          <div className="risk-chart">
            <div
              className={`risk-bar${data.counts.total === 0 ? ' is-empty' : ''}`}
              role="img"
              aria-label={`${data.counts.critical} critical, ${data.counts.high} high, ${data.counts.medium} medium, ${data.counts.low} low and ${data.counts.unknown} unknown open findings`}
            >
              {segments
                .filter((segment) => segment.count > 0)
                .map((segment) => (
                  <span
                    key={segment.key}
                    className={`risk-seg is-${segment.key}`}
                    style={{ flexGrow: segment.count, minWidth: 6 }}
                  />
                ))}
            </div>
            <div className="risk-legend">
              {segments.map((segment) => (
                <button
                  key={segment.key}
                  type="button"
                  className="risk-legend-item"
                  aria-label={`${segment.count} ${segment.label.toLowerCase()} open findings`}
                  onClick={() => navigate(`/vulnerabilities?severity=${segment.key.toUpperCase()}`)}
                >
                  <span className={`risk-mark is-${segment.key}`} aria-hidden="true" />
                  <span className="risk-legend-value">{segment.count}</span>
                  <span className="risk-legend-label">{segment.label}</span>
                </button>
              ))}
            </div>
            <p className="risk-note">
              {data.counts.total === 0
                ? `Nothing is open. ${data.changes.newFindings24h} appeared and ${data.changes.resolvedFindings24h} resolved in the last 24h.`
                : `${data.changes.newFindings24h} appeared · ${data.changes.resolvedFindings24h} resolved in the last 24h`}
            </p>
          </div>
        </div>
        <div className="risk-side">
          <button
            type="button"
            className="risk-side-item"
            onClick={() => navigate('/vulnerabilities?kev=true')}
          >
            <span className="risk-side-label">Known exploited</span>
            <span className="risk-side-value">{data.kev.available ? data.counts.kev : '—'}</span>
            <span className="risk-side-meta">
              {!data.kev.available
                ? 'Catalog not loaded'
                : data.kev.stale
                  ? `CISA KEV · stale, synced ${relativeTime(data.kev.syncedAt)}`
                  : `CISA KEV · synced ${relativeTime(data.kev.syncedAt)}`}
            </span>
          </button>
          <button
            type="button"
            className="risk-side-item"
            onClick={() => navigate('/containers?status=running')}
          >
            <span className="risk-side-label">Affected workloads</span>
            <span className="risk-side-value">{data.workloads.affectedRunningContainers}</span>
            <span className="risk-side-meta">
              {data.workloads.affectedImages} of {data.workloads.totalImages} images affected
            </span>
          </button>
        </div>
      </section>

      <div className="ops-grid">
        <div className="ops-primary">
          <section className="card ops-panel" aria-labelledby="priority-queue-title">
            <div className="ops-panel-head">
              <div className="ops-panel-heading">
                <h2 className="ops-panel-title" id="priority-queue-title">
                  Action queue
                </h2>
                <span className="ops-panel-sub">Critical and high, ordered by what to fix first</span>
              </div>
              <div className="ops-panel-actions">
                <button type="button" className="btn small ghost" onClick={refresh} aria-label="Refresh overview">
                  <IconRefresh width={13} height={13} />
                </button>
                <button type="button" className="btn small ghost" onClick={() => navigate('/vulnerabilities')}>
                  All findings
                </button>
              </div>
            </div>
            {ranked.length === 0 ? (
              <EmptyState
                icon={<IconCheck width={24} height={24} />}
                title="No critical or high findings"
                action={
                  <button type="button" className="btn small ghost" onClick={() => navigate('/images')}>
                    Review image coverage
                  </button>
                }
              >
                {data.counts.total === 0
                  ? 'Scans have not reported vulnerabilities for the current images. Check scan activity to confirm freshness.'
                  : 'No critical or high severities are currently open.'}
              </EmptyState>
            ) : (
              <div className="ops-table-wrap">
                <table className="ops-table">
                  <caption className="sr-only">Highest priority open findings</caption>
                  <thead>
                    <tr>
                      <th scope="col">Priority</th>
                      <th scope="col">Vulnerability</th>
                      <th scope="col">Package</th>
                      <th scope="col">Workload</th>
                      <th scope="col">Signals</th>
                      <th scope="col">First seen</th>
                    </tr>
                  </thead>
                  <tbody>
                    {ranked.map((finding, index) => (
                      <tr
                        key={finding.id}
                        className={selected?.id === finding.id ? 'is-selected' : undefined}
                        aria-current={selected?.id === finding.id ? 'true' : undefined}
                        onClick={() => openFinding(finding)}
                        onFocus={() => setSelectedId(finding.id)}
                      >
                        <td>
                          <div className="ops-cell-prio">
                            <PriorityBadge
                              tier={finding.priority.tier}
                              factors={finding.priority.factors}
                              label={actionWord(finding, true)}
                              rank={index + 1}
                            />
                            <SeverityBadge severity={finding.severity} />
                          </div>
                        </td>
                        <td>
                          <div className="ops-vuln-id">
                            <a
                              className="ops-vuln-link"
                              href={`/vulnerabilities?q=${encodeURIComponent(finding.vulnId)}&image=${encodeURIComponent(finding.imageId)}`}
                              onClick={(event) => {
                                event.preventDefault();
                                event.stopPropagation();
                                openFinding(finding);
                              }}
                            >
                              {finding.vulnId}
                            </a>
                          </div>
                          <div className="ops-vuln-title" title={finding.title ?? undefined}>
                            {finding.title ?? `${finding.pkgName} requires review`}
                          </div>
                          <div className="ops-mobile-signals">
                            <span className="ops-mobile-workload">
                              {finding.containers[0]?.imageRef ?? shortImageId(finding.imageId)}
                            </span>
                            {finding.triageStatus === 'acknowledged' ? (
                              <span className="badge neutral">Acknowledged</span>
                            ) : null}
                            <KevBadge kev={finding.kev} />
                            {finding.exposure ? (
                              <ExposureBadge state={finding.exposure} reason={finding.containers[0]?.exposureReason} />
                            ) : null}
                          </div>
                        </td>
                        <td>
                          <div className="ops-mono" title={finding.pkgName}>
                            {finding.pkgName}
                          </div>
                          <div className="ops-sub" title={`Fix available: ${finding.fixedVersion}`}>
                            {finding.installedVersion || 'unknown'}
                            {finding.fixedVersion ? ` → ${finding.fixedVersion}` : ' · no fix'}
                          </div>
                        </td>
                        <td>
                          <div className="ops-workload" title={finding.containers[0]?.imageRef ?? undefined}>
                            {finding.containers[0]?.imageRef ?? shortImageId(finding.imageId)}
                          </div>
                          <div className="ops-sub" title={workloadDetail(finding)}>
                            {workloadSummary(finding)}
                          </div>
                        </td>
                        <td>
                          <div className="ops-signals">
                            {finding.triageStatus === 'acknowledged' ? (
                              <span className="badge neutral">Acknowledged</span>
                            ) : null}
                            <KevBadge kev={finding.kev} />
                            {finding.exposure ? (
                              <ExposureBadge state={finding.exposure} reason={finding.containers[0]?.exposureReason} />
                            ) : null}
                            {data.environments.length > 1 && finding.environmentNames[0] ? (
                              <span
                                className="ops-signal-env"
                                title={`Environment: ${finding.environmentNames[0]}`}
                              >
                                {finding.environmentNames[0]}
                              </span>
                            ) : null}
                          </div>
                        </td>
                        <td className="ops-age">{relativeTime(finding.firstSeenAt)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          <section className="card ops-panel" aria-labelledby="recent-activity-title">
            <div className="ops-panel-head">
              <div className="ops-panel-heading">
                <h2 className="ops-panel-title" id="recent-activity-title">
                  Recent activity
                </h2>
                <span className="ops-panel-sub">Latest scans and finding changes</span>
              </div>
              <div className="ops-panel-actions">
                <button
                  type="button"
                  className="btn small ghost"
                  onClick={() => navigate('/vulnerabilities?state=resolved')}
                >
                  Resolved findings
                </button>
              </div>
            </div>

            <div className="ops-activity-section">
              <div className="ops-subhead">
                <span>Recent scans</span>
                <button type="button" className="ops-link" onClick={() => navigate('/scans')}>
                  View scans
                </button>
              </div>
              {recentScans.length === 0 ? (
                <div className="ops-scan-empty">
                  No scans recorded yet.{' '}
                  <button type="button" className="ops-link" onClick={() => navigate('/images')}>
                    Open images
                  </button>
                </div>
              ) : (
                recentScans.map((scan) => {
                  const outcome = scanOutcome(scan);
                  return (
                    <button
                      key={scan.id}
                      type="button"
                      className="ops-scan-row"
                      onClick={() => navigate('/scans')}
                      aria-label={`Open scans for ${scan.imageRef}: ${outcome.text}`}
                    >
                      <span className={`status-dot ${scan.status}`} aria-hidden="true" />
                      <span className="ops-scan-image" title={scan.imageRef}>
                        {scan.imageRef}
                      </span>
                      <span className="ops-scan-meta">
                        {scan.profile} · {relativeTime(scan.finishedAt ?? scan.startedAt ?? scan.queuedAt)}
                      </span>
                      <span className={`ops-scan-result ${outcome.error ? 'is-error' : ''}`} title={outcome.title}>
                        {outcome.text}
                      </span>
                    </button>
                  );
                })
              )}
            </div>

            <div className="ops-activity-section">
              <div className="ops-subhead">
                <span>Finding activity</span>
                <button type="button" className="ops-link" onClick={() => navigate('/vulnerabilities')}>
                  All findings
                </button>
              </div>
              {recentEvents.length === 0 ? (
                <div className="ops-scan-empty">
                  No finding changes recorded yet.{' '}
                  <button type="button" className="ops-link" onClick={() => navigate('/images')}>
                    Review scanning
                  </button>
                </div>
              ) : (
                <div className="ops-activity-list">
                  {recentEvents.map((event) => (
                    <div className="ops-activity-item" key={event.id}>
                      <span className={`ops-activity-icon is-${event.kind}`} aria-hidden="true">
                        <ActivityIcon kind={event.kind} />
                      </span>
                      <div>
                        <div className="ops-activity-copy">
                          {eventDescription(event.kind)} <span className="mono">{event.vulnId}</span> in {event.pkgName}
                        </div>
                        <div className="ops-activity-meta">
                          {event.imageRef ?? shortImageId(event.imageId)} · severity {event.severity.toLowerCase()} ·{' '}
                          {relativeTime(event.createdAt)}
                        </div>
                      </div>
                      <button
                        type="button"
                        className="ops-activity-open"
                        onClick={() =>
                          navigate(
                            `/vulnerabilities?q=${encodeURIComponent(event.vulnId)}&image=${encodeURIComponent(event.imageId)}`,
                          )
                        }
                      >
                        Open
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </section>
        </div>
        <div className="ops-side">
          <section className="card ops-panel" aria-labelledby="coverage-title">
            <div className="ops-panel-head">
              <div className="ops-panel-heading">
                <h2 className="ops-panel-title" id="coverage-title">
                  Coverage &amp; trust
                </h2>
                <span className="ops-panel-sub">
                  {attention.length === 0 ? 'All integrations healthy' : `${attention.length} item${attention.length === 1 ? '' : 's'} need attention`}
                </span>
              </div>
              <button
                type="button"
                className="ops-panel-link"
                onClick={() => navigate('/environments')}
                title="Manage Docker hosts"
              >
                {online}/{data.environments.length} hosts
              </button>
            </div>
            <CoverageRow
              tone={scanTone}
              label="Scan queue"
              value={`${data.scans.running + data.scans.queued} active`}
              detail={`${data.scans.running} running · ${data.scans.queued} queued · ${data.scans.success24h} succeeded / ${data.scans.failed24h} failed in 24h`}
              onClick={() => navigate('/scans')}
            />
            <CoverageRow
              tone={data.scans.lastSuccessfulAt ? 'online' : 'pending'}
              label="Last successful scan"
              value={data.scans.lastSuccessfulAt ? relativeTime(data.scans.lastSuccessfulAt) : 'Never'}
              detail={latestSuccess?.imageRef ?? `${data.scans.success24h} succeeded in 24h`}
              onClick={() => navigate('/scans')}
            />
            <CoverageRow
              tone={data.workloads.staleImages > 0 ? 'pending' : 'online'}
              label="Inventory"
              value={`${online}/${data.environments.length} hosts`}
              detail={`${data.workloads.runningContainers} running · ${data.workloads.totalImages} images · ${data.workloads.staleImages} stale`}
              onClick={() => navigate('/containers?status=running')}
            />
            {attention.map((item) => (
              <CoverageRow
                key={item.label}
                tone={attentionTone(item.tone)}
                label={item.label}
                value={item.value}
                detail={item.detail}
                onClick={() => navigate(item.path)}
              />
            ))}
            {attention.length === 0 ? (
              <div className="ops-all-clear">
                <IconCheck width={14} height={14} />
                <span>Every enabled environment was contacted, scans are recent and alerts are delivered.</span>
              </div>
            ) : null}
          </section>
        </div>
      </div>


    </div>
  );
}
