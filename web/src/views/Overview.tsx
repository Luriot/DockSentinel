import { type OverviewData } from '../api.ts';
import { useApi, navigate } from '../hooks.ts';
import {
  EmptyState,
  ErrorPanel,
  ExposureBadge,
  FixBadge,
  IconActivity,
  IconAlert,
  IconBell,
  IconBug,
  IconCheck,
  IconClock,
  IconPlus,
  IconRefresh,
  IconServer,
  IconShield,
  KevBadge,
  PriorityBadge,
  ScanStatusBadge,
  SeverityBadge,
  TableSkeleton,
  IconPlay,
} from '../components/ui.tsx';
import { relativeTime, shortImageId } from '../format.ts';

export function Overview() {
  const { data, error, loading, refresh } = useApi<OverviewData>('/overview', { intervalMs: 15_000 });

  if (loading && !data) {
    return (
      <div className="vstack" style={{ gap: 16 }}>
        <div className="kpi-grid">
          {[0, 1, 2, 3].map((index) => (
            <div key={index} className="kpi">
              <div className="skeleton" style={{ width: 110 }} />
              <div className="skeleton" style={{ width: 64, height: 28, marginTop: 10 }} />
              <div className="skeleton" style={{ width: 150, marginTop: 10 }} />
            </div>
          ))}
        </div>
        <div className="card">
          <TableSkeleton rows={5} columns={5} />
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
      <div className="card">
        <div className="empty" style={{ padding: '56px 24px' }}>
          <IconShield width={34} height={34} />
          <h3>Connect your first Docker environment</h3>
          <p>
            DockSentinel discovers containers and images from a Docker Engine, then scans their images with Trivy.
            Start with the local socket on this host, or a secure remote endpoint.
          </p>
          <div className="hstack" style={{ marginTop: 6 }}>
            <button type="button" className="btn primary" onClick={() => navigate('/environments')}>
              <IconPlus width={15} height={15} /> Add environment
            </button>
            <button type="button" className="btn ghost" onClick={() => navigate('/settings')}>
              Review scan policy
            </button>
          </div>
          <p className="tiny dim" style={{ marginTop: 18, maxWidth: 560 }}>
            Docker socket access is effectively privileged. Prefer local sockets or TLS-protected endpoints, and never
            expose an unauthenticated Docker TCP API.
          </p>
        </div>
      </div>
    );
  }

  const offline = data.environments.filter((environment) => environment.status === 'offline');
  const attention: { label: string; detail: string; path: string; tone: 'danger' | 'warn' | 'neutral' }[] = [];
  if (offline.length > 0) {
    attention.push({
      label: 'Unavailable environments',
      detail: offline.map((environment) => environment.name).join(', '),
      path: '/environments',
      tone: 'danger',
    });
  }
  if (data.scans.failed24h > 0) {
    attention.push({
      label: 'Scans failed in the last 24h',
      detail: `${data.scans.failed24h} failed. Previous findings stay in place; no clean result is assumed.`,
      path: '/scans?status=failed',
      tone: 'danger',
    });
  }
  if (data.workloads.staleImages > 0) {
    attention.push({
      label: 'Stale scan results',
      detail: `${data.workloads.staleImages} in-use images were not successfully scanned within ${data.freshnessHours}h.`,
      path: '/images?stale=true',
      tone: 'warn',
    });
  }
  if (data.alerts.failed24h > 0) {
    attention.push({
      label: 'Alert delivery failures',
      detail: `${data.alerts.failed24h} notification attempts failed. Alerts are retried with backoff.`,
      path: '/notifications?status=failed',
      tone: 'warn',
    });
  }
  if (data.alerts.pending > 0) {
    attention.push({
      label: 'Alerts waiting for delivery',
      detail: `${data.alerts.pending} queued. Check the ntfy configuration if this grows.`,
      path: '/notifications?status=pending',
      tone: 'neutral',
    });
  }
  if (data.kev.status === 'error') {
    attention.push({
      label: 'Known-exploited data is unavailable or stale',
      detail: data.kev.error ?? 'The CISA KEV feed could not be refreshed.',
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

  return (
    <div className="vstack" style={{ gap: 18 }}>
      <div className="kpi-grid">
        <button type="button" className="kpi critical" onClick={() => navigate('/vulnerabilities?severity=CRITICAL')} style={{ textAlign: 'left', cursor: 'pointer' }}>
          <div className="kpi-label">
            <IconAlert width={13} height={13} /> Critical open
          </div>
          <div className="kpi-value">{data.counts.critical}</div>
          <div className="kpi-foot">
            {data.counts.fixable > 0 ? `${data.counts.fixable} fixable findings overall` : 'No fixes listed yet'} ·{' '}
            {data.counts.total} open findings
          </div>
        </button>
        <button type="button" className="kpi high" onClick={() => navigate('/vulnerabilities?severity=HIGH')} style={{ textAlign: 'left', cursor: 'pointer' }}>
          <div className="kpi-label">
            <IconBug width={13} height={13} /> High open
          </div>
          <div className="kpi-value">{data.counts.high}</div>
          <div className="kpi-foot">
            {data.changes.newFindings24h} new in 24h · {data.counts.kev} known-exploited overall
          </div>
        </button>
        <button type="button" className="kpi kev" onClick={() => navigate('/vulnerabilities?kev=true')} style={{ textAlign: 'left', cursor: 'pointer' }}>
          <div className="kpi-label">
            <IconShield width={13} height={13} /> Known exploited
          </div>
          <div className="kpi-value">{data.counts.kev}</div>
          <div className="kpi-foot">
            {data.kev.available
              ? `CISA KEV · ${data.kev.entryCount} ${data.kev.entryCount === 1 ? 'entry' : 'entries'} · synced ${relativeTime(data.kev.syncedAt)}`
              : 'KEV catalog not synchronised yet'}
          </div>
        </button>
        <button
          type="button"
          className="kpi workloads"
          onClick={() => navigate('/containers?status=running')}
          style={{ textAlign: 'left', cursor: 'pointer' }}
        >
          <div className="kpi-label">
            <IconServer width={13} height={13} /> Affected workloads
          </div>
          <div className="kpi-value">{data.workloads.affectedRunningContainers}</div>
          <div className="kpi-foot">
            running containers with critical/high findings · {data.workloads.affectedImages} of{' '}
            {data.workloads.totalImages} images affected
          </div>
        </button>
      </div>

      <div className="grid-2">
        <section className="card" aria-labelledby="priority-queue-title">
          <div className="card-header">
            <div className="vstack">
              <h2 className="section-title" id="priority-queue-title">
                Priority queue
              </h2>
              <span className="section-subtitle">
                Ranked by severity, known exploitation, fixes and exposure — not a risk score.
              </span>
            </div>
            <div className="hstack">
              <button type="button" className="btn small ghost" onClick={refresh} aria-label="Refresh overview">
                <IconRefresh width={14} height={14} />
              </button>
              <button type="button" className="btn small ghost" onClick={() => navigate('/vulnerabilities')}>
                View all
              </button>
            </div>
          </div>
          {data.findings.top.length === 0 ? (
            <EmptyState
              icon={<IconCheck width={26} height={26} />}
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
            <div className="table-wrap">
              <table className="table">
                <caption className="sr-only">Highest priority open findings</caption>
                <thead>
                  <tr>
                    <th scope="col">Priority</th>
                    <th scope="col">Severity</th>
                    <th scope="col">Vulnerability</th>
                    <th scope="col">Image / workload</th>
                    <th scope="col">Signals</th>
                  </tr>
                </thead>
                <tbody>
                  {data.findings.top.map((finding) => (
                    <tr
                      key={finding.id}
                      className="clickable"
                      onClick={() => navigate(`/vulnerabilities?q=${encodeURIComponent(finding.vulnId)}`)}
                    >
                      <td>
                        <PriorityBadge tier={finding.priority.tier} factors={finding.priority.factors} />
                      </td>
                      <td>
                        <SeverityBadge severity={finding.severity} />
                      </td>
                      <td>
                        <div className="cell-main mono id">{finding.vulnId}</div>
                        <div className="cell-sub truncate" title={finding.title ?? undefined}>
                          {finding.pkgName} {finding.installedVersion ? `· ${finding.installedVersion}` : ''}
                        </div>
                      </td>
                      <td>
                        <div className="cell-main truncate" title={finding.containers[0]?.imageRef}>
                          {finding.containers[0]?.imageRef ?? shortImageId(finding.imageId)}
                        </div>
                        <div className="cell-sub">
                          {finding.containerCount > 0
                            ? `${finding.containerCount} container${finding.containerCount === 1 ? '' : 's'}${
                                finding.runningContainerCount > 0 ? ` · ${finding.runningContainerCount} running` : ''
                              }`
                            : 'Image only'}
                          {finding.environmentNames.length > 0 ? ` · ${finding.environmentNames.join(', ')}` : ''}
                        </div>
                      </td>
                      <td>
                        <div className="hstack" style={{ flexWrap: 'wrap', gap: 4 }}>
                          <KevBadge kev={finding.kev} />
                          {finding.fixedVersion ? <FixBadge fixedVersion={finding.fixedVersion} /> : null}
                          {finding.exposure ? <ExposureBadge state={finding.exposure} /> : null}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <div className="vstack" style={{ gap: 16 }}>
          <section className="card" aria-labelledby="attention-title">
            <div className="card-header">
              <h2 className="section-title" id="attention-title">
                Needs attention
              </h2>
              <span className={`badge ${attention.length > 0 ? 'warn' : 'ok'}`}>
                {attention.length > 0 ? `${attention.length} item${attention.length === 1 ? '' : 's'}` : 'All clear'}
              </span>
            </div>
            <div className="card-body" style={{ padding: '6px 16px' }}>
              {attention.length === 0 ? (
                <div className="empty" style={{ padding: '24px 4px' }}>
                  <IconCheck width={22} height={22} />
                  <p style={{ maxWidth: 320 }}>
                    Integrations are healthy: every environment was contacted, scans are recent and alerts are
                    delivered.
                  </p>
                </div>
              ) : (
                attention.map((item) => (
                  <button
                    key={item.label}
                    type="button"
                    className="attr-row"
                    style={{ width: '100%', background: 'none', border: 'none', textAlign: 'left', cursor: 'pointer' }}
                    onClick={() => navigate(item.path)}
                  >
                    <span
                      className={`status-dot ${item.tone === 'danger' ? 'offline' : item.tone === 'warn' ? 'pending' : 'unknown'}`}
                      aria-hidden="true"
                    />
                    <span className="vstack" style={{ gap: 0 }}>
                      <span style={{ fontWeight: 550 }}>{item.label}</span>
                      <span className="cell-sub" style={{ whiteSpace: 'normal' }}>
                        {item.detail}
                      </span>
                    </span>
                  </button>
                ))
              )}
            </div>
          </section>

          <section className="card" aria-labelledby="environments-title">
            <div className="card-header">
              <h2 className="section-title" id="environments-title">
                Environments
              </h2>
              <button type="button" className="btn small ghost" onClick={() => navigate('/environments')}>
                Manage
              </button>
            </div>
            <div className="card-body" style={{ padding: '8px 16px' }}>
              {data.environments.map((environment) => (
                <div className="attr-row" key={environment.id}>
                  <span
                    className={`status-dot ${
                      environment.status === 'online' ? 'online' : environment.status === 'offline' ? 'offline' : 'unknown'
                    }`}
                    aria-hidden="true"
                  />
                  <span className="vstack" style={{ gap: 0, flex: 1 }}>
                    <span style={{ fontWeight: 550 }}>{environment.name}</span>
                    <span className="cell-sub">
                      {environment.containers} containers · {environment.images} images · contacted{' '}
                      {relativeTime(environment.lastContactAt)}
                    </span>
                  </span>
                  <span className="cell-sub">{environment.status}</span>
                </div>
              ))}
            </div>
          </section>

          <section className="card" aria-labelledby="scan-summary-title">
            <div className="card-header">
              <h2 className="section-title" id="scan-summary-title">
                Scan activity
              </h2>
              {data.scans.running > 0 ? (
                <ScanStatusBadge status="running" />
              ) : (
                <span className="badge neutral">Idle</span>
              )}
            </div>
            <div className="card-body" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
              <div className="env-stat">
                <strong>{data.scans.running}</strong>
                <span>Running</span>
              </div>
              <div className="env-stat">
                <strong>{data.scans.queued}</strong>
                <span>Queued</span>
              </div>
              <div className="env-stat">
                <strong>{data.scans.success24h}</strong>
                <span>Succeeded 24h</span>
              </div>
              <div className="env-stat">
                <strong>{data.scans.failed24h}</strong>
                <span>Failed 24h</span>
              </div>
              <div className="env-stat" style={{ gridColumn: '1 / -1' }}>
                <span>Last successful scan</span>
                <strong style={{ fontSize: 13 }}>{relativeTime(data.scans.lastSuccessfulAt)}</strong>
              </div>
              <div className="hstack" style={{ gridColumn: '1 / -1', gap: 6 }}>
                <button type="button" className="btn small ghost" onClick={() => navigate('/scans')}>
                  <IconActivity width={14} height={14} /> Scan activity
                </button>
                <button type="button" className="btn small ghost" onClick={() => navigate('/images')}>
                  <IconPlay width={13} height={13} /> Scan images
                </button>
              </div>
            </div>
          </section>
        </div>
      </div>

      <section className="card" aria-labelledby="recent-title">
        <div className="card-header">
          <div className="vstack">
            <h2 className="section-title" id="recent-title">
              Recent findings activity
            </h2>
            <span className="section-subtitle">
              {data.changes.newFindings24h} new · {data.changes.resolvedFindings24h} resolved in the last 24 hours
            </span>
          </div>
          <button type="button" className="btn small ghost" onClick={() => navigate('/vulnerabilities?state=resolved')}>
            Resolved findings
          </button>
        </div>
        {data.events.length === 0 ? (
          <EmptyState
            icon={<IconClock width={24} height={24} />}
            title="No finding changes recorded yet"
            action={
              <button type="button" className="btn small ghost" onClick={() => navigate('/images')}>
                Review scanning
              </button>
            }
          >
            Changes appear here after a successful scan identifies, resolves or re-classifies a vulnerability.
          </EmptyState>
        ) : (
          <div className="recent-list">
            {data.events.map((event) => (
              <div className="recent-item" key={event.id}>
                <span className={`recent-icon ${event.kind}`} aria-hidden="true">
                  {event.kind === 'resolved' ? (
                    <IconCheck width={13} height={13} />
                  ) : event.kind === 'changed' ? (
                    <IconRefresh width={13} height={13} />
                  ) : event.kind === 'appeared' ? (
                    <IconAlert width={13} height={13} />
                  ) : (
                    <IconBell width={13} height={13} />
                  )}
                </span>
                <div className="vstack" style={{ gap: 1, flex: 1, minWidth: 0 }}>
                  <span className="small">
                    {event.kind === 'resolved'
                      ? 'Finding no longer reported'
                      : event.kind === 'changed'
                        ? 'Finding updated'
                        : event.kind === 'reappeared'
                          ? 'Finding reappeared'
                          : 'New finding detected'}{' '}
                    <span className="mono">{event.vulnId}</span> in {event.pkgName}
                  </span>
                  <span className="cell-sub truncate">
                    {event.imageRef ?? shortImageId(event.imageId)} · severity {event.severity.toLowerCase()} ·{' '}
                    {relativeTime(event.createdAt)}
                  </span>
                </div>
                <button
                  type="button"
                  className="btn small ghost"
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
      </section>
    </div>
  );
}
