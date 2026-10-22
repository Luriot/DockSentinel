import { useCallback, useEffect, useState } from 'react';
import {
  api,
  type EnvironmentSummary,
  type FindingView,
  type ImageSummary,
  type ScanRecord,
  type Severity,
  type SeverityCounts,
} from '../api.ts';
import { useApi, useDebounced, navigate, useRoute } from '../hooks.ts';
import {
  Drawer,
  EmptyState,
  ErrorPanel,
  ExposureBadge,
  FixBadge,
  IconBug,
  IconClock,
  IconExternal,
  IconPlay,
  IconRefresh,
  IconSearch,
  InlineLoading,
  KevBadge,
  Pagination,
  PriorityBadge,
  ScanStatusBadge,
  SeverityBadge,
  TableSkeleton,
  useToast,
} from '../components/ui.tsx';
import { formatDate, relativeTime, shortImageId } from '../format.ts';

const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];

interface FindingsResponse {
  items: FindingView[];
  total: number;
  counts: SeverityCounts;
  page: number;
  pageSize: number;
}

interface FindingDetail {
  finding: FindingView;
  image: ImageSummary | null;
  events: {
    id: number;
    kind: string;
    detail: string | null;
    createdAt: string;
    vulnId: string;
    pkgName: string;
    severity: string;
  }[];
  scans: ScanRecord[];
}

function parseSeverityList(raw: string | null): Severity[] {
  if (!raw) return [];
  return raw
    .split(',')
    .map((value) => value.trim().toUpperCase())
    .filter((value): value is Severity => SEVERITIES.includes(value as Severity));
}

export function Vulnerabilities() {
  const route = useRoute();
  const toast = useToast();

  const [search, setSearch] = useState(route.params.get('q') ?? '');
  const debouncedSearch = useDebounced(search);
  const [severities, setSeverities] = useState<Severity[]>(parseSeverityList(route.params.get('severity')));
  const [imageId, setImageId] = useState(route.params.get('image') ?? '');
  const [kevOnly, setKevOnly] = useState(route.params.get('kev') === 'true');
  const [fixableOnly, setFixableOnly] = useState(route.params.get('fixable') === 'true');
  const [runningOnly, setRunningOnly] = useState(route.params.get('running') === 'true');
  const [environmentId, setEnvironmentId] = useState(route.params.get('envId') ?? '');
  const [state, setState] = useState<'open' | 'resolved' | 'all'>(
    (route.params.get('state') as 'open' | 'resolved' | 'all' | null) ?? 'open',
  );
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<number | null>(null);

  useEffect(() => {
    setPage(1);
  }, [debouncedSearch, severities, imageId, kevOnly, fixableOnly, runningOnly, environmentId, state]);

  const query = new URLSearchParams();
  if (debouncedSearch) query.set('q', debouncedSearch);
  if (severities.length > 0) query.set('severity', severities.join(','));
  if (imageId) query.set('image', imageId);
  if (kevOnly) query.set('kev', 'true');
  if (fixableOnly) query.set('fixable', 'true');
  if (runningOnly) query.set('running', 'true');
  if (environmentId) query.set('envId', environmentId);
  if (state !== 'open') query.set('state', state);
  query.set('page', String(page));
  query.set('pageSize', '25');

  // Keep the address bar shareable without triggering a route re-render on every keystroke.
  useEffect(() => {
    const next = new URLSearchParams(query);
    next.delete('page');
    next.delete('pageSize');
    const text = next.toString();
    window.history.replaceState(null, '', `${window.location.pathname}${text ? `?${text}` : ''}`);
  }, [debouncedSearch, severities, imageId, kevOnly, fixableOnly, runningOnly, environmentId, state]);

  const { data, error, loading, refresh } = useApi<FindingsResponse>(`/findings?${query.toString()}`, {
    intervalMs: 30_000,
  });
  const environments = useApi<{ items: EnvironmentSummary[] }>('/environments');

  const toggleSeverity = useCallback((severity: Severity) => {
    setSeverities((current) =>
      current.includes(severity) ? current.filter((entry) => entry !== severity) : [...current, severity],
    );
  }, []);

  async function scanImage(finding: FindingView, profile: 'quick' | 'standard'): Promise<void> {
    try {
      await api.post(`/images/${encodeURIComponent(finding.imageId)}/scan`, { profile });
      toast(`${profile === 'quick' ? 'Quick' : 'Standard'} scan queued`, 'success');
    } catch (scanError) {
      toast(scanError instanceof Error ? scanError.message : 'Unable to queue scan', 'error');
    }
  }

  const hasFilters =
    Boolean(debouncedSearch) ||
    severities.length > 0 ||
    Boolean(imageId) ||
    kevOnly ||
    fixableOnly ||
    runningOnly ||
    Boolean(environmentId) ||
    state !== 'open';

  return (
    <div className="vstack" style={{ gap: 14 }}>
      <section className="card">
        <div className="filters" role="search" aria-label="Filter findings">
          <div style={{ position: 'relative', flex: '1 1 220px', maxWidth: 300 }}>
            <IconSearch width={14} height={14} style={{ position: 'absolute', left: 10, top: 11, color: 'var(--text-dim)' }} />
            <input
              className="input"
              placeholder="CVE, package, title or image"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              aria-label="Search findings"
              style={{ paddingLeft: 32, width: '100%' }}
            />
          </div>
          <div className="hstack" style={{ gap: 4, flexWrap: 'wrap' }} role="group" aria-label="Severity filter">
            {SEVERITIES.map((severity) => (
              <button
                key={severity}
                type="button"
                className={`chip-toggle sev-${severity}`}
                aria-pressed={severities.includes(severity)}
                onClick={() => toggleSeverity(severity)}
              >
                <span className="dot" aria-hidden="true" />
                {severity === 'CRITICAL' ? 'Critical' : severity === 'HIGH' ? 'High' : severity === 'MEDIUM' ? 'Medium' : severity === 'LOW' ? 'Low' : 'Unknown'}
              </button>
            ))}
          </div>
          <button type="button" className="chip-toggle" aria-pressed={kevOnly} onClick={() => setKevOnly((value) => !value)}>
            Known exploited
          </button>
          <button type="button" className="chip-toggle" aria-pressed={fixableOnly} onClick={() => setFixableOnly((value) => !value)}>
            Fix available
          </button>
          <button type="button" className="chip-toggle" aria-pressed={runningOnly} onClick={() => setRunningOnly((value) => !value)}>
            Running only
          </button>
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
          <select
            className="select"
            value={state}
            onChange={(event) => setState(event.target.value as 'open' | 'resolved' | 'all')}
            aria-label="Filter by state"
          >
            <option value="open">Open</option>
            <option value="resolved">Resolved</option>
            <option value="all">All states</option>
          </select>
          <button type="button" className="btn small ghost" onClick={refresh} aria-label="Refresh">
            <IconRefresh width={14} height={14} />
          </button>
          {hasFilters ? (
            <button
              type="button"
              className="btn small ghost"
              onClick={() => {
                setSearch('');
                setSeverities([]);
                setImageId('');
                setKevOnly(false);
                setFixableOnly(false);
                setRunningOnly(false);
                setEnvironmentId('');
                setState('open');
              }}
            >
              Clear filters
            </button>
          ) : null}
        </div>

        {imageId ? (
          <div className="filters" style={{ borderBottom: '1px solid var(--border)', paddingTop: 8, paddingBottom: 8 }}>
            <span className="badge accent">
              Image filter: <span className="mono">{shortImageId(imageId)}</span>
              <button
                type="button"
                className="link-button"
                style={{ color: 'inherit', marginLeft: 4 }}
                onClick={() => setImageId('')}
                aria-label="Remove image filter"
              >
                ✕
              </button>
            </span>
          </div>
        ) : null}

        {data ? (
          <div className="filters" style={{ borderBottom: '1px solid var(--border)', paddingTop: 8, paddingBottom: 8 }}>
            <span className="tiny dim">
              {data.total} matching {state === 'resolved' ? 'resolved' : 'open'}{' '}
              {data.total === 1 ? 'finding' : 'findings'}
            </span>
            <span className="hstack" style={{ marginLeft: 'auto', gap: 4 }}>
              <span className="badge sev-CRITICAL">C {data.counts.CRITICAL}</span>
              <span className="badge sev-HIGH">H {data.counts.HIGH}</span>
              <span className="badge sev-MEDIUM">M {data.counts.MEDIUM}</span>
              <span className="badge sev-LOW">L {data.counts.LOW}</span>
              <span className="badge sev-UNKNOWN">? {data.counts.UNKNOWN}</span>
            </span>
          </div>
        ) : null}

        {error && !data ? <ErrorPanel error={error} onRetry={refresh} /> : null}
        {loading && !data ? <TableSkeleton rows={8} columns={6} /> : null}

        {data && data.items.length === 0 ? (
          <EmptyState
            icon={<IconBug width={26} height={26} />}
            title={state === 'resolved' ? 'No resolved findings match' : 'No findings match'}
            action={
              hasFilters ? (
                <button
                  type="button"
                  className="btn small ghost"
                  onClick={() => {
                    setSearch('');
                    setSeverities([]);
                    setImageId('');
                    setKevOnly(false);
                    setFixableOnly(false);
                    setRunningOnly(false);
                    setEnvironmentId('');
                    setState('open');
                  }}
                >
                  Clear filters
                </button>
              ) : (
                <button type="button" className="btn small ghost" onClick={() => navigate('/images')}>
                  Check scan coverage
                </button>
              )
            }
          >
            {state === 'resolved'
              ? 'Resolved findings appear here after a later successful scan no longer reports them.'
              : 'Either your images are clean according to the last successful scans, or scans have not run yet. Check scan activity to confirm.'}
          </EmptyState>
        ) : null}

        {data && data.items.length > 0 ? (
          <>
            <div className="table-wrap">
              <table className="table">
                <caption className="sr-only">Vulnerability findings</caption>
                <thead>
                  <tr>
                    <th scope="col">Priority</th>
                    <th scope="col">Severity</th>
                    <th scope="col">Vulnerability</th>
                    <th scope="col">Package</th>
                    <th scope="col">Affected workloads</th>
                    <th scope="col">Signals</th>
                    <th scope="col">First seen</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((finding) => (
                    <tr key={finding.id} className="clickable" onClick={() => setSelected(finding.id)}>
                      <td>
                        <PriorityBadge tier={finding.priority.tier} factors={finding.priority.factors} />
                      </td>
                      <td>
                        <SeverityBadge severity={finding.severity} />
                      </td>
                      <td>
                        <div className="cell-main mono id">{finding.vulnId}</div>
                        <div className="cell-sub truncate" style={{ maxWidth: 300 }} title={finding.title ?? undefined}>
                          {finding.title ?? 'No title reported'}
                        </div>
                      </td>
                      <td>
                        <div className="cell-main truncate" style={{ maxWidth: 190 }} title={finding.pkgName}>
                          {finding.pkgName}
                        </div>
                        <div className="cell-sub mono">
                          {finding.installedVersion || 'unknown'} {finding.fixedVersion ? `→ ${finding.fixedVersion}` : ''}
                        </div>
                      </td>
                      <td>
                        <div className="cell-main truncate" style={{ maxWidth: 240 }} title={finding.containers[0]?.imageRef}>
                          {finding.containers[0]?.imageRef ?? shortImageId(finding.imageId)}
                        </div>
                        <div className="cell-sub">
                          {finding.containerCount > 0
                            ? `${finding.containerCount} container${finding.containerCount === 1 ? '' : 's'}${
                                finding.runningContainerCount > 0 ? ` · ${finding.runningContainerCount} running` : ''
                              }`
                            : 'No container'}
                          {finding.environmentNames.length > 0
                            ? ` · ${finding.environmentNames.join(', ')}`
                            : ''}
                        </div>
                      </td>
                      <td>
                        <div className="hstack" style={{ flexWrap: 'wrap', gap: 4 }}>
                          {finding.kev === 1 ? <KevBadge kev={1} /> : null}
                          {finding.fixedVersion ? <FixBadge fixedVersion={finding.fixedVersion} /> : null}
                          {finding.exposure ? <ExposureBadge state={finding.exposure} /> : null}
                          {finding.resolvedAt ? <span className="badge ok">Resolved</span> : null}
                        </div>
                      </td>
                      <td>
                        <span className="small">{relativeTime(finding.firstSeenAt)}</span>
                        <div className="cell-sub">{finding.episode > 1 ? `episode ${finding.episode}` : ''}</div>
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

      {selected !== null ? (
        <FindingDrawer
          findingId={selected}
          onClose={() => setSelected(null)}
          onScan={(finding, profile) => void scanImage(finding, profile)}
        />
      ) : null}
    </div>
  );
}

function FindingDrawer({
  findingId,
  onClose,
  onScan,
}: {
  findingId: number;
  onClose: () => void;
  onScan: (finding: FindingView, profile: 'quick' | 'standard') => void;
}) {
  const { data, error, loading, refresh } = useApi<FindingDetail>(`/findings/${findingId}`);

  return (
    <Drawer
      title={data ? data.finding.vulnId : 'Finding'}
      subtitle={data ? `${data.finding.pkgName} ${data.finding.installedVersion}` : 'Loading finding'}
      onClose={onClose}
      footer={
        data ? (
          <>
            <button type="button" className="btn ghost" onClick={onClose}>
              Close
            </button>
            <button type="button" className="btn ghost" onClick={() => onScan(data.finding, 'quick')}>
              <IconPlay width={13} height={13} /> Quick scan
            </button>
            <button type="button" className="btn primary" onClick={() => onScan(data.finding, 'standard')}>
              <IconPlay width={13} height={13} /> Standard scan
            </button>
          </>
        ) : null
      }
    >
      {loading && !data ? <InlineLoading label="Loading finding…" /> : null}
      {error && !data ? <ErrorPanel error={error} onRetry={refresh} /> : null}
      {data ? (
        <>
          <section className="drawer-section">
            <div className="pill-row" style={{ marginBottom: 10 }}>
              <SeverityBadge severity={data.finding.severity} />
              <PriorityBadge tier={data.finding.priority.tier} factors={data.finding.priority.factors} />
              {data.finding.kev === 1 ? <KevBadge kev={1} /> : null}
              {data.finding.fixedVersion ? <FixBadge fixedVersion={data.finding.fixedVersion} /> : null}
              {data.finding.exposure ? <ExposureBadge state={data.finding.exposure} /> : null}
              {data.finding.resolvedAt ? <span className="badge ok">Resolved {relativeTime(data.finding.resolvedAt)}</span> : null}
            </div>
            <h3>{data.finding.title ?? 'No title reported by the scanner'}</h3>
            <dl className="detail-list" style={{ marginTop: 10 }}>
              <dt>Vulnerability ID</dt>
              <dd className="mono">{data.finding.vulnId}</dd>
              <dt>Package</dt>
              <dd>
                <span className="mono">{data.finding.pkgName}</span> · installed{' '}
                <span className="mono">{data.finding.installedVersion || 'unknown'}</span>
                {data.finding.fixedVersion ? (
                  <>
                    {' '}· fixed <span className="mono">{data.finding.fixedVersion}</span>
                  </>
                ) : (
                  ' · no fix listed'
                )}
              </dd>
              <dt>Scanner status</dt>
              <dd>{data.finding.status ?? 'unknown'}</dd>
              <dt>CVSS</dt>
              <dd>
                {data.finding.cvssScore !== null
                  ? `${data.finding.cvssScore.toFixed(1)}${data.finding.cvssSource ? ` (${data.finding.cvssSource})` : ''}`
                  : 'Not reported'}
              </dd>
              <dt>Target</dt>
              <dd className="mono">{data.finding.target}</dd>
              <dt>Class</dt>
              <dd>{data.finding.class ?? '—'}{data.finding.type ? ` (${data.finding.type})` : ''}</dd>
              <dt>Published</dt>
              <dd>{data.finding.publishedAt ? formatDate(data.finding.publishedAt) : '—'}</dd>
              <dt>First seen</dt>
              <dd>{formatDate(data.finding.firstSeenAt)}</dd>
              <dt>Last seen</dt>
              <dd>{relativeTime(data.finding.lastSeenAt)}</dd>
              {data.finding.kev === 1 ? (
                <>
                  <dt>Known exploited since</dt>
                  <dd>{data.finding.kevAddedAt ?? 'unknown'}</dd>
                </>
              ) : null}
            </dl>
            {data.finding.primaryUrl ? (
              <a
                className="btn small ghost"
                style={{ marginTop: 10 }}
                href={data.finding.primaryUrl}
                target="_blank"
                rel="noopener noreferrer"
              >
                <IconExternal width={13} height={13} /> Authoritative advisory
              </a>
            ) : null}
            <div className="note" style={{ marginTop: 10 }}>
              Severity is scanner-provided. Internet exposure is inferred from Docker metadata or explicitly declared
              with the <code className="kv-code">docksentinel.exposure</code> label; it is not proof of public
              reachability.
            </div>
          </section>

          <section className="drawer-section">
            <h3>Why this priority</h3>
            <div className="factor-list">
              {data.finding.priority.factors.map((factor) => (
                <span className="factor" key={factor}>
                  {factor}
                </span>
              ))}
            </div>
            <p className="tiny dim" style={{ marginTop: 8 }}>
              Priority {data.finding.priority.tier} · transparent rule-based ranking (score{' '}
              {data.finding.priority.score}). No proprietary risk score is implied.
            </p>
          </section>

          <section className="drawer-section">
            <h3>Affected containers ({data.finding.containers.length})</h3>
            {data.finding.containers.length === 0 ? (
              <div className="note">No container currently uses this image. The finding still describes the image.</div>
            ) : (
              <div className="vstack" style={{ gap: 8 }}>
                {data.finding.containers.map((container) => (
                  <div className="card" style={{ padding: 10, background: 'var(--panel-2)' }} key={`${container.environmentId}:${container.id}`}>
                    <div className="spread">
                      <span className="small">
                        <strong>{container.name}</strong>{' '}
                        <span className="dim">· {container.environmentName} · {container.state}</span>
                      </span>
                      <ExposureBadge state={container.exposure} reason={container.exposureReason} />
                    </div>
                    <div className="cell-sub mono" style={{ marginTop: 3 }}>
                      {container.imageRef}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </section>

          <section className="drawer-section">
            <h3>Finding history</h3>
            {data.events.length === 0 ? (
              <div className="note">No lifecycle events recorded yet.</div>
            ) : (
              <div className="vstack" style={{ gap: 6 }}>
                {data.events.map((event) => (
                  <div className="spread" key={event.id}>
                    <span className="small">
                      {event.kind === 'appeared'
                        ? 'Detected'
                        : event.kind === 'resolved'
                          ? 'No longer reported'
                          : event.kind === 'reappeared'
                            ? 'Reappeared'
                            : 'Updated'}{' '}
                      {event.detail ? <span className="dim mono tiny">{event.detail}</span> : null}
                    </span>
                    <span className="tiny dim">{relativeTime(event.createdAt)}</span>
                  </div>
                ))}
              </div>
            )}
          </section>

          <section className="drawer-section">
            <h3>Image scan history</h3>
            {data.scans.length === 0 ? (
              <div className="note">This image has not been scanned.</div>
            ) : (
              <div className="vstack" style={{ gap: 6 }}>
                {data.scans.map((scan) => (
                  <div className="spread" key={scan.id}>
                    <span className="small">
                      <ScanStatusBadge status={scan.status} /> {scan.profile} · {scan.total} findings
                    </span>
                    <span className="tiny dim">{relativeTime(scan.finishedAt ?? scan.queuedAt)}</span>
                  </div>
                ))}
              </div>
            )}
            {data.image ? (
              <button
                type="button"
                className="link-button small"
                style={{ marginTop: 10 }}
                onClick={() => navigate(`/images?image=${encodeURIComponent(data.image!.imageId)}`)}
              >
                <IconClock width={12} height={12} style={{ verticalAlign: -2 }} /> Open image details
              </button>
            ) : null}
          </section>
        </>
      ) : null}
    </Drawer>
  );
}

export type { FindingsResponse };
