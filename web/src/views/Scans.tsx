import { useEffect, useState } from 'react';
import { api, type EnvironmentSummary, type ScanRecord, type ScanStatus } from '../api.ts';
import { useApi, useRoute } from '../hooks.ts';
import {
  Drawer,
  EmptyState,
  ErrorPanel,
  IconActivity,
  IconClock,
  IconPlay,
  IconRefresh,
  InlineLoading,
  Pagination,
  ScanStatusBadge,
  TableSkeleton,
  useToast,
} from '../components/ui.tsx';
import { formatDate, formatDuration, relativeTime, titleCase } from '../format.ts';

interface SystemActivity {
  activity: { queued: number; running: number; success: number; failed: number; cancelled: number };
  limits: { scanConcurrency: number; scanTimeoutMs: number; maxOutputBytes: number };
}

interface ScansResponse {
  items: ScanRecord[];
  total: number;
  page: number;
  pageSize: number;
}

export function Scans() {
  const route = useRoute();
  const toast = useToast();
  const [status, setStatus] = useState<ScanStatus | ''>(() => {
    const value = route.params.get('status');
    return value === 'queued' || value === 'running' || value === 'success' || value === 'failed' || value === 'cancelled'
      ? value
      : '';
  });
  const [environmentId, setEnvironmentId] = useState(route.params.get('envId') ?? '');
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<number | null>(null);

  const query = new URLSearchParams();
  if (status) query.set('status', status);
  if (environmentId) query.set('envId', environmentId);
  query.set('page', String(page));
  query.set('pageSize', '25');

  const { data, error, loading, refresh } = useApi<ScansResponse>(`/scans?${query.toString()}`, {
    intervalMs: 5_000,
  });
  const system = useApi<SystemActivity>('/system', { intervalMs: 15_000 });
  const environments = useApi<{ items: EnvironmentSummary[] }>('/environments');
  const environmentNames = new Map((environments.data?.items ?? []).map((environment) => [environment.id, environment.name]));

  useEffect(() => {
    setPage(1);
  }, [status, environmentId]);

  async function cancel(scan: ScanRecord): Promise<void> {
    try {
      await api.post(`/scans/${scan.id}/cancel`);
      toast(`Scan #${scan.id} cancelled`, 'success');
      refresh();
    } catch (cancelError) {
      toast(cancelError instanceof Error ? cancelError.message : 'Unable to cancel scan', 'error');
    }
  }

  async function rescan(scan: ScanRecord): Promise<void> {
    try {
      await api.post('/scans', { imageId: scan.imageId, profile: scan.profile, kind: scan.kind });
      toast(`Scan queued for ${scan.imageRef}`, 'success');
      refresh();
    } catch (scanError) {
      toast(scanError instanceof Error ? scanError.message : 'Unable to queue scan', 'error');
    }
  }

  const activity = system.data?.activity;

  return (
    <div className="page-stack">
      <div className="scan-summary" aria-label="Scan activity summary">
        <div className="scan-summary-item">
          <span className="scan-summary-label">
            <IconActivity width={12} height={12} /> Active now
          </span>
          <span className="scan-summary-value">{(activity?.running ?? 0) + (activity?.queued ?? 0)}</span>
          <span className="scan-summary-meta">
            {activity?.running ?? 0} running · {activity?.queued ?? 0} queued · concurrency{' '}
            {system.data?.limits.scanConcurrency ?? '—'}
          </span>
        </div>
        <div className="scan-summary-item">
          <span className="scan-summary-label">Succeeded (24h)</span>
          <span className="scan-summary-value">{activity?.success ?? 0}</span>
          <span className="scan-summary-meta">Scans completed and findings recorded</span>
        </div>
        <div className="scan-summary-item">
          <span className="scan-summary-label">Failed (24h)</span>
          <span className="scan-summary-value">{activity?.failed ?? 0}</span>
          <span className="scan-summary-meta">Failures keep previous findings; never treated as clean</span>
        </div>
      </div>

      <section className="card">
        <div className="page-list-head">
          <div>
            <h2>Scan history</h2>
            <span className="sub">Running, scheduled, successful and failed scans. Auto-refreshes every 5 seconds.</span>
          </div>
          <span className="meta">{data ? `${data.total} scans` : ''}</span>
        </div>
        <div className="filters">
          <select
            className="select"
            value={status}
            onChange={(event) => setStatus(event.target.value as ScanStatus | '')}
            aria-label="Filter by status"
          >
            <option value="">All statuses</option>
            <option value="queued">Queued</option>
            <option value="running">Running</option>
            <option value="success">Succeeded</option>
            <option value="failed">Failed</option>
            <option value="cancelled">Cancelled</option>
          </select>
          <select
            className="select"
            value={environmentId}
            onChange={(event) => setEnvironmentId(event.target.value)}
            aria-label="Filter by environment"
          >
            <option value="">All environments</option>
            {(environments.data?.items ?? []).map((environment) => (
              <option key={environment.id} value={environment.id}>
                {environment.name}
              </option>
            ))}
          </select>
          <button type="button" className="btn small ghost" onClick={refresh} aria-label="Refresh">
            <IconRefresh width={14} height={14} />
          </button>
        </div>

        {error && !data ? <ErrorPanel error={error} onRetry={refresh} /> : null}
        {loading && !data ? <TableSkeleton rows={6} columns={7} /> : null}

        {data && data.items.length === 0 ? (
          <EmptyState icon={<IconClock width={26} height={26} />} title="No scans match">
            Scans are queued by the scheduler for in-use images, or manually from an image or container.
          </EmptyState>
        ) : null}

        {data && data.items.length > 0 ? (
          <>
            <div className="table-wrap">
              <table className="table">
                <caption className="sr-only">Scan history</caption>
                <thead>
                  <tr>
                    <th scope="col">Status</th>
                    <th scope="col">Image</th>
                    <th scope="col">Environment</th>
                    <th scope="col">Profile</th>
                    <th scope="col">Trigger</th>
                    <th scope="col">Started</th>
                    <th scope="col">Findings</th>
                    <th scope="col">
                      <span className="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((scan) => (
                    <tr key={scan.id} className="clickable" onClick={() => setSelected(scan.id)}>
                      <td>
                        <ScanStatusBadge status={scan.status} />
                        <div className="cell-sub">{formatDuration(scan.durationMs)}</div>
                      </td>
                      <td>
                        <div className="cell-main mono truncate" style={{ maxWidth: 250 }} title={scan.imageRef}>
                          {scan.imageRef}
                        </div>
                        <div className="cell-sub mono">{scan.imageId.slice(0, 19)}…</div>
                      </td>
                      <td>
                        {scan.environmentId ? (environmentNames.get(scan.environmentId) ?? `#${scan.environmentId}`) : '—'}
                      </td>
                      <td>{scan.kind === 'content' ? 'Config & secrets' : titleCase(scan.profile)}</td>
                      <td>{titleCase(scan.trigger)}</td>
                      <td>
                        <span className="small">{relativeTime(scan.startedAt ?? scan.queuedAt)}</span>
                        <div className="cell-sub">{scan.finishedAt ? formatDate(scan.finishedAt) : '—'}</div>
                      </td>
                      <td>
                        {scan.status === 'success' ? (
                          <span className="hstack" style={{ gap: 4, flexWrap: 'wrap' }}>
                            {scan.critical > 0 ? <span className="badge sev-CRITICAL">C {scan.critical}</span> : null}
                            {scan.high > 0 ? <span className="badge sev-HIGH">H {scan.high}</span> : null}
                            {scan.total === 0 ? <span className="badge ok">No findings</span> : null}
                            {scan.fixable > 0 ? <span className="badge neutral">{scan.fixable} fixable</span> : null}
                          </span>
                        ) : scan.status === 'failed' ? (
                          <span className="cell-sub" style={{ whiteSpace: 'normal' }}>
                            <span className="mono">{scan.errorCode}</span>
                            <br />
                            {scan.errorMessage?.slice(0, 90)}
                          </span>
                        ) : (
                          <span className="dim tiny">—</span>
                        )}
                      </td>
                      <td onClick={(event) => event.stopPropagation()}>
                        {scan.status === 'queued' || scan.status === 'running' ? (
                          <button type="button" className="btn xs danger" onClick={() => void cancel(scan)}>
                            Cancel
                          </button>
                        ) : (
                          <button type="button" className="btn xs ghost" onClick={() => void rescan(scan)}>
                            <IconPlay width={11} height={11} /> Scan again
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination page={data.page} pageSize={data.pageSize} total={data.total} onChange={setPage} />
          </>
        ) : null}
      </section>

      {selected !== null ? <ScanDrawer scanId={selected} onClose={() => setSelected(null)} /> : null}
    </div>
  );
}

function ScanDrawer({ scanId, onClose }: { scanId: number; onClose: () => void }) {
  const { data, error, loading, refresh } = useApi<{
    scan: ScanRecord;
    environment: { id: number; name: string; status: string } | null;
    image: { imageId: string; displayRef: string };
  }>(`/scans/${scanId}`, { intervalMs: 5_000 });

  return (
    <Drawer
      title={data ? `Scan #${data.scan.id}` : 'Scan'}
      subtitle={data ? data.scan.imageRef : 'Loading scan'}
      onClose={onClose}
      footer={
        data ? (
          <button type="button" className="btn ghost" onClick={onClose}>
            Close
          </button>
        ) : null
      }
    >
      {loading && !data ? <InlineLoading label="Loading scan…" /> : null}
      {error && !data ? <ErrorPanel error={error} onRetry={refresh} /> : null}
      {data ? (
        <>
          <section className="drawer-section">
            <div className="hstack" style={{ marginBottom: 10 }}>
              <ScanStatusBadge status={data.scan.status} />
              <span className="badge neutral">{data.scan.kind === 'content' ? 'Config & secrets' : titleCase(data.scan.profile)}</span>
              <span className="badge neutral">{titleCase(data.scan.trigger)}</span>
            </div>
            <dl className="detail-list">
              <dt>Image</dt>
              <dd className="mono">{data.scan.imageRef}</dd>
              <dt>Image ID</dt>
              <dd className="mono" style={{ wordBreak: 'break-all' }}>
                {data.scan.imageId}
              </dd>
              <dt>Environment</dt>
              <dd>{data.environment?.name ?? '—'}</dd>
              <dt>Queued</dt>
              <dd>{formatDate(data.scan.queuedAt)}</dd>
              <dt>Started</dt>
              <dd>{formatDate(data.scan.startedAt)}</dd>
              <dt>Finished</dt>
              <dd>{formatDate(data.scan.finishedAt)}</dd>
              <dt>Duration</dt>
              <dd>{formatDuration(data.scan.durationMs)}</dd>
              <dt>Attempt</dt>
              <dd>{data.scan.attempts}</dd>
              <dt>Scanner</dt>
              <dd>
                {data.scan.scanner} {data.scan.scannerVersion ?? 'version unknown'}
              </dd>
              <dt>Vulnerability DB</dt>
              <dd>
                {data.scan.dbVersion ? `schema ${data.scan.dbVersion}` : 'unknown'} · updated{' '}
                {data.scan.dbUpdatedAt ? formatDate(data.scan.dbUpdatedAt) : 'unknown'}
              </dd>
              <dt>Exit code</dt>
              <dd>{data.scan.exitCode ?? '—'}</dd>
            </dl>
            {data.scan.status === 'success' ? (
              <div className="pill-row" style={{ marginTop: 10 }}>
                <span className="badge sev-CRITICAL">Critical {data.scan.critical}</span>
                <span className="badge sev-HIGH">High {data.scan.high}</span>
                <span className="badge sev-MEDIUM">Medium {data.scan.medium}</span>
                <span className="badge sev-LOW">Low {data.scan.low}</span>
                <span className="badge sev-UNKNOWN">Unknown {data.scan.unknown}</span>
                <span className="badge neutral">{data.scan.fixable} fixable</span>
              </div>
            ) : null}
          </section>

          {data.scan.status === 'failed' || data.scan.status === 'cancelled' ? (
            <section className="drawer-section">
              <h3>Failure</h3>
              <div className="note danger">
                <strong className="mono">{data.scan.errorCode}</strong>
                <br />
                {data.scan.errorMessage}
                <br />
                Previous findings were preserved. This failed scan is not a clean result.
              </div>
            </section>
          ) : null}

          {data.scan.warnings.length > 0 ? (
            <section className="drawer-section">
              <h3>Warnings</h3>
              <ul className="vstack" style={{ gap: 4, paddingLeft: 18, margin: 0, fontSize: 12.5 }}>
                {data.scan.warnings.map((warning, index) => (
                  <li key={index}>{warning}</li>
                ))}
              </ul>
            </section>
          ) : null}

          <section className="drawer-section">
            <h3>Profile coverage</h3>
            <p className="small muted" style={{ lineHeight: 1.6 }}>
              {data.scan.profile === 'quick'
                ? 'Quick scans inspect operating-system packages only and skip the Java index. Application dependencies are not covered.'
                : 'Standard scans inspect operating-system and language packages (npm, Python, PHP, Java, Ruby, Go and more). They take longer and may download a Java index on first use.'}
            </p>
            <p className="tiny dim" style={{ marginTop: 6 }}>
              Image scans detect known vulnerabilities in packages the scanner can inspect. They do not detect runtime
              compromise, misconfiguration or secrets.
            </p>
          </section>
        </>
      ) : null}
    </Drawer>
  );
}
