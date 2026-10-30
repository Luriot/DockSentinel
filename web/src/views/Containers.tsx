import { useEffect, useState } from 'react';
import {
  api,
  type ContainerSummary,
  type EnvironmentSummary,
  type FindingView,
  type ImageSummary,
  type ScanRecord,
  type SeverityCounts,
} from '../api.ts';
import { useApi, useDebounced, navigate, useRoute } from '../hooks.ts';
import {
  Drawer,
  EmptyState,
  ErrorPanel,
  ExposureBadge,
  FixBadge,
  IconBox,
  IconExternal,
  IconPlay,
  IconRefresh,
  IconSearch,
  InlineLoading,
  KevBadge,
  Pagination,
  ScanStatusBadge,
  SeverityBadge,
  SeverityPills,
  TableSkeleton,
  useToast,
} from '../components/ui.tsx';
import { formatDate, relativeTime, titleCase } from '../format.ts';

interface ContainerDetail {
  container: ContainerSummary;
  image: ImageSummary | null;
  findings: FindingView[];
  findingCounts: SeverityCounts;
  totalFindings: number;
  scans: ScanRecord[];
}

export function Containers() {
  const route = useRoute();
  const [search, setSearch] = useState(route.params.get('q') ?? '');
  const debouncedSearch = useDebounced(search);
  const [environmentId, setEnvironmentId] = useState(route.params.get('envId') ?? '');
  const [status, setStatus] = useState<'running' | 'stopped' | 'all'>(() => {
    const value = route.params.get('status');
    return value === 'running' || value === 'stopped' ? value : 'all';
  });
  const [exposure, setExposure] = useState('');
  const [includeRemoved, setIncludeRemoved] = useState(false);
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<{ environmentId: number; id: string } | null>(null);
  const toast = useToast();

  useEffect(() => {
    setPage(1);
  }, [debouncedSearch, environmentId, status, exposure, includeRemoved]);

  const query = new URLSearchParams();
  if (debouncedSearch) query.set('q', debouncedSearch);
  if (environmentId) query.set('envId', environmentId);
  if (status !== 'all') query.set('status', status);
  if (exposure) query.set('exposure', exposure);
  if (includeRemoved) query.set('includeRemoved', 'true');
  query.set('page', String(page));
  query.set('pageSize', '25');

  const { data, error, loading, refresh } = useApi<{
    items: ContainerSummary[];
    total: number;
    page: number;
    pageSize: number;
  }>(`/containers?${query.toString()}`, { intervalMs: 30_000 });
  const environments = useApi<{ items: EnvironmentSummary[] }>('/environments');

  async function scanImage(container: ContainerSummary, profile: 'quick' | 'standard'): Promise<void> {
    if (!container.imageId) {
      toast('This container has no resolvable image ID', 'error');
      return;
    }
    try {
      await api.post(`/images/${encodeURIComponent(container.imageId)}/scan`, { profile });
      toast(`${titleCase(profile)} scan queued for ${container.imageRef}`, 'success');
    } catch (scanError) {
      toast(scanError instanceof Error ? scanError.message : 'Unable to queue scan', 'error');
    }
  }

  return (
    <div className="page-stack">
      <section className="card">
        <div className="filters" role="search" aria-label="Filter containers">
          <div className="toolbar-search">
            <IconSearch width={14} height={14} aria-hidden="true" />
            <input
              className="input"
              placeholder="Search containers"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              aria-label="Search containers"
            />
          </div>
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
            value={status}
            onChange={(event) => setStatus(event.target.value as 'running' | 'stopped' | 'all')}
            aria-label="Filter by state"
          >
            <option value="all">Any state</option>
            <option value="running">Running</option>
            <option value="stopped">Stopped</option>
          </select>
          <select
            className="select"
            value={exposure}
            onChange={(event) => setExposure(event.target.value)}
            aria-label="Filter by exposure"
          >
            <option value="">Any exposure</option>
            <option value="confirmed">Internet exposure declared</option>
            <option value="potential">Potentially exposed</option>
            <option value="internal">No published ports</option>
            <option value="unknown">Unknown</option>
          </select>
          <label className="chip-toggle" style={{ gap: 7 }}>
            <input
              type="checkbox"
              checked={includeRemoved}
              onChange={(event) => setIncludeRemoved(event.target.checked)}
            />
            Include removed
          </label>
          <button type="button" className="btn small ghost" onClick={refresh} aria-label="Refresh">
            <IconRefresh width={14} height={14} />
          </button>
          <span className="list-meta-count">{data ? `${data.total} containers` : ''}</span>
        </div>

        {error && !data ? <ErrorPanel error={error} onRetry={refresh} /> : null}
        {loading && !data ? <TableSkeleton rows={6} columns={6} /> : null}

        {data && data.items.length === 0 ? (
          <EmptyState
            icon={<IconBox width={26} height={26} />}
            title="No containers match"
            action={
              <button type="button" className="btn small ghost" onClick={() => navigate('/environments')}>
                Check environments
              </button>
            }
          >
            Containers appear after a successful discovery of an environment. Removed containers are hidden unless
            explicitly included.
          </EmptyState>
        ) : null}

        {data && data.items.length > 0 ? (
          <>
            <div className="table-wrap">
              <table className="table">
                <caption className="sr-only">Discovered containers</caption>
                <thead>
                  <tr>
                    <th scope="col">Container</th>
                    <th scope="col">Environment</th>
                    <th scope="col">State</th>
                    <th scope="col">Image</th>
                    <th scope="col">Exposure</th>
                    <th scope="col">Findings</th>
                    <th scope="col">Last scan</th>
                    <th scope="col">
                      <span className="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((container) => (
                    <tr
                      key={`${container.environmentId}:${container.id}`}
                      className="clickable"
                      onClick={() => setSelected({ environmentId: container.environmentId, id: container.id })}
                    >
                      <td>
                        <div className="cell-main">{container.name}</div>
                        <div className="cell-sub mono truncate" title={container.id}>
                          {container.id.slice(0, 12)}
                        </div>
                      </td>
                      <td>{container.environmentName}</td>
                      <td>
                        <span className="status-line">
                          <span className={`status-dot ${container.running ? 'online' : 'unknown'}`} aria-hidden="true" />
                          {container.present ? titleCase(container.state) : 'Removed'}
                        </span>
                      </td>
                      <td>
                        <div className="truncate mono" style={{ maxWidth: 260 }} title={container.imageRef}>
                          {container.imageRef}
                        </div>
                        <div className="cell-sub">{container.imageId ? container.imageId.slice(0, 19) : 'unknown ID'}</div>
                      </td>
                      <td>
                        <ExposureBadge state={container.exposure} reason={container.exposureReason} />
                      </td>
                      <td>
                        <SeverityPills counts={{ critical: container.critical, high: container.high }} />
                      </td>
                      <td>
                        <ScanStatusBadge status={container.lastScanStatus} />
                        <div className="cell-sub">{relativeTime(container.lastSuccessAt)}</div>
                      </td>
                      <td onClick={(event) => event.stopPropagation()}>
                        <div className="hstack" style={{ gap: 4 }}>
                          <button
                            type="button"
                            className="btn xs ghost"
                            onClick={() => void scanImage(container, 'quick')}
                            disabled={!container.imageId}
                            title="Queue a quick OS-only scan"
                          >
                            <IconPlay width={11} height={11} /> Quick
                          </button>
                          <button
                            type="button"
                            className="btn xs ghost"
                            onClick={() => void scanImage(container, 'standard')}
                            disabled={!container.imageId}
                            title="Queue a standard scan (OS + language packages)"
                          >
                            Standard
                          </button>
                        </div>
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

      {selected ? (
        <ContainerDrawer
          environmentId={selected.environmentId}
          id={selected.id}
          onClose={() => setSelected(null)}
          onScan={(container, profile) => void scanImage(container, profile)}
        />
      ) : null}
    </div>
  );
}

function ContainerDrawer({
  environmentId,
  id,
  onClose,
  onScan,
}: {
  environmentId: number;
  id: string;
  onClose: () => void;
  onScan: (container: ContainerSummary, profile: 'quick' | 'standard') => void;
}) {
  const { data, error, loading } = useApi<ContainerDetail>(
    `/containers/${environmentId}/${encodeURIComponent(id)}`,
  );

  return (
    <Drawer
      title={data?.container.name ?? 'Container'}
      subtitle={data ? `${data.container.environmentName} · ${data.container.state}` : 'Loading container'}
      onClose={onClose}
      footer={
        data ? (
          <>
            <button type="button" className="btn ghost" onClick={onClose}>
              Close
            </button>
            {data.image ? (
              <button
                type="button"
                className="btn ghost"
                onClick={() => navigate(`/images?image=${encodeURIComponent(data.image!.imageId)}`)}
              >
                <IconExternal width={14} height={14} /> Open image
              </button>
            ) : null}
            <button type="button" className="btn primary" onClick={() => onScan(data.container, 'standard')} disabled={!data.container.imageId}>
              <IconPlay width={14} height={14} /> Scan standard
            </button>
          </>
        ) : null
      }
    >
      {loading && !data ? <InlineLoading label="Loading container…" /> : null}
      {error && !data ? <ErrorPanel error={error} /> : null}
      {data ? (
        <>
          <section className="drawer-section">
            <h3>Workload</h3>
            <div className="pill-row" style={{ marginBottom: 10 }}>
              <ExposureBadge state={data.container.exposure} reason={data.container.exposureReason} />
              <SeverityPills counts={{ critical: data.container.critical, high: data.container.high }} />
              <ScanStatusBadge status={data.container.lastScanStatus} />
              {!data.container.present ? <span className="badge neutral">Removed from host</span> : null}
            </div>
            <dl className="detail-list">
              <dt>Image</dt>
              <dd className="mono">{data.container.imageRef}</dd>
              <dt>Image ID</dt>
              <dd className="mono">{data.container.imageId ?? '—'}</dd>
              <dt>Exposure evidence</dt>
              <dd>{data.container.exposureReason ?? 'Not determined'}</dd>
              <dt>Network mode</dt>
              <dd>{data.container.networkMode ?? '—'}</dd>
              <dt>Ports</dt>
              <dd>
                {data.container.ports.length === 0
                  ? 'No published ports'
                  : data.container.ports
                      .map(
                        (port) =>
                          `${port.publicPort ?? '—'}→${port.privatePort ?? '—'}/${port.type ?? 'tcp'}${
                            port.ip ? ` on ${port.ip}` : ''
                          }`,
                      )
                      .join(', ')}
              </dd>
              <dt>Created</dt>
              <dd>{formatDate(data.container.createdTs)}</dd>
              <dt>First seen</dt>
              <dd>{formatDate(data.container.firstSeenAt)}</dd>
              <dt>Last seen</dt>
              <dd>{relativeTime(data.container.lastSeenAt)}</dd>
            </dl>
            {Object.keys(data.container.labels).length > 0 ? (
              <div className="tag-list" style={{ marginTop: 10 }}>
                {Object.entries(data.container.labels).map(([key, value]) => (
                  <span className="tag" key={key} title={`${key}=${value}`}>
                    {key}={value}
                  </span>
                ))}
              </div>
            ) : null}
          </section>

          <section className="drawer-section">
            <h3>
              Findings ({data.totalFindings}) · {data.findingCounts.CRITICAL} critical, {data.findingCounts.HIGH} high
            </h3>
            {data.findings.length === 0 ? (
              <div className="note">
                No open findings for this image. Confirm the last successful scan is recent before treating this as
                clean.
              </div>
            ) : (
              <div className="vstack" style={{ gap: 8 }}>
                {data.findings.map((finding) => (
                  <div key={finding.id} className="drawer-finding">
                    <div className="hstack" style={{ flexWrap: 'wrap', gap: 6 }}>
                      <SeverityBadge severity={finding.severity} />
                      <span className="mono small">{finding.vulnId}</span>
                      {finding.kev === 1 ? <KevBadge kev={1} /> : null}
                      <FixBadge fixedVersion={finding.fixedVersion} />
                    </div>
                    <div className="small" style={{ marginTop: 6 }}>
                      {finding.title ?? `${finding.pkgName} ${finding.installedVersion}`}
                    </div>
                    <div className="cell-sub">
                      {finding.pkgName} {finding.installedVersion} · priority {finding.priority.tier}
                    </div>
                  </div>
                ))}
              </div>
            )}
            {data.image ? (
              <button
                type="button"
                className="link-button small"
                style={{ marginTop: 8 }}
                onClick={() => navigate(`/vulnerabilities?image=${encodeURIComponent(data.image!.imageId)}`)}
              >
                Open all findings for this image
              </button>
            ) : null}
          </section>

          <section className="drawer-section">
            <h3>Recent scans</h3>
            {data.scans.length === 0 ? (
              <div className="note">This image has not been scanned yet.</div>
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
          </section>
        </>
      ) : null}
    </Drawer>
  );
}
