import { useEffect, useState } from 'react';
import {
  api,
  type ContainerSummary,
  type EnvironmentSummary,
  type FindingView,
  type ImageSummary,
  type OverviewData,
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
  IconAlert,
  IconClock,
  IconExternal,
  IconLayers,
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
import { formatBytes, formatDate, relativeTime, shortImageId, titleCase } from '../format.ts';

interface ImagesResponse {
  items: ImageSummary[];
  total: number;
  page: number;
  pageSize: number;
}

interface ImageDetail {
  image: ImageSummary;
  containers: ContainerSummary[];
  findings: FindingView[];
  findingCounts: SeverityCounts;
  totalFindings: number;
  scans: ScanRecord[];
  events: { id: number; kind: string; detail: string | null; createdAt: string; vulnId: string; pkgName: string; severity: string }[];
}

export function Images() {
  const route = useRoute();
  const toast = useToast();
  const [search, setSearch] = useState('');
  const debouncedSearch = useDebounced(search);
  const [environmentId, setEnvironmentId] = useState('');
  const [minSeverity, setMinSeverity] = useState('');
  const [neverScanned, setNeverScanned] = useState(false);
  const [stale, setStale] = useState(route.params.get('stale') === 'true');
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<string | null>(route.params.get('image'));

  useEffect(() => {
    setPage(1);
  }, [debouncedSearch, environmentId, minSeverity, neverScanned, stale]);

  const query = new URLSearchParams();
  if (debouncedSearch) query.set('q', debouncedSearch);
  if (environmentId) query.set('envId', environmentId);
  if (minSeverity) query.set('minSeverity', minSeverity);
  if (neverScanned) query.set('neverScanned', 'true');
  if (stale) query.set('stale', 'true');
  query.set('page', String(page));
  query.set('pageSize', '25');

  const { data, error, loading, refresh } = useApi<ImagesResponse>(`/images?${query.toString()}`, {
    intervalMs: 30_000,
  });
  const environments = useApi<{ items: EnvironmentSummary[] }>('/environments');
  const overview = useApi<OverviewData>('/overview', { intervalMs: 60_000 });
  const freshnessHours = overview.data?.freshnessHours ?? 48;

  async function scan(imageId: string, profile: 'quick' | 'standard'): Promise<void> {
    try {
      await api.post(`/images/${encodeURIComponent(imageId)}/scan`, { profile });
      toast(`${titleCase(profile)} scan queued`, 'success');
    } catch (scanError) {
      toast(scanError instanceof Error ? scanError.message : 'Unable to queue scan', 'error');
    }
  }

  function isStale(image: ImageSummary): boolean {
    if (!image.lastSuccessAt) return true;
    const age = Date.now() - Date.parse(image.lastSuccessAt);
    return Number.isFinite(age) && age > freshnessHours * 3_600_000;
  }

  return (
    <div className="vstack" style={{ gap: 14 }}>
      <section className="card">
        <div className="filters" role="search" aria-label="Filter images">
          <div style={{ position: 'relative', flex: '1 1 220px', maxWidth: 320 }}>
            <IconSearch width={14} height={14} style={{ position: 'absolute', left: 10, top: 11, color: 'var(--text-dim)' }} />
            <input
              className="input"
              placeholder="Search repository, tag or image ID"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              aria-label="Search images"
              style={{ paddingLeft: 32, width: '100%' }}
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
            value={minSeverity}
            onChange={(event) => setMinSeverity(event.target.value)}
            aria-label="Filter by findings"
          >
            <option value="">Any findings</option>
            <option value="critical">Has critical</option>
            <option value="high">Has high</option>
          </select>
          <button
            type="button"
            className={`chip-toggle${neverScanned ? ' ' : ''}`}
            aria-pressed={neverScanned}
            onClick={() => setNeverScanned((value) => !value)}
          >
            Never scanned
          </button>
          <button
            type="button"
            className="chip-toggle"
            aria-pressed={stale}
            onClick={() => setStale((value) => !value)}
            title={`Older than ${freshnessHours}h`}
          >
            <IconClock width={12} height={12} /> Stale
          </button>
          <button type="button" className="btn small ghost" onClick={refresh} aria-label="Refresh">
            <IconRefresh width={14} height={14} />
          </button>
          <span className="tiny dim" style={{ marginLeft: 'auto' }}>
            {data ? `${data.total} images` : ''}
          </span>
        </div>

        {error && !data ? <ErrorPanel error={error} onRetry={refresh} /> : null}
        {loading && !data ? <TableSkeleton rows={6} columns={7} /> : null}

        {data && data.items.length === 0 ? (
          <EmptyState
            icon={<IconLayers width={26} height={26} />}
            title="No images match"
            action={
              <button type="button" className="btn small ghost" onClick={() => navigate('/environments')}>
                Check discovery
              </button>
            }
          >
            Images are deduplicated by immutable image ID. Run discovery on an environment to populate the inventory.
          </EmptyState>
        ) : null}

        {data && data.items.length > 0 ? (
          <>
            <div className="table-wrap">
              <table className="table">
                <caption className="sr-only">Image inventory</caption>
                <thead>
                  <tr>
                    <th scope="col">Image</th>
                    <th scope="col">Environments</th>
                    <th scope="col">Containers</th>
                    <th scope="col">Findings</th>
                    <th scope="col">Fixes</th>
                    <th scope="col">Last successful scan</th>
                    <th scope="col">
                      <span className="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((image) => {
                    const stale = isStale(image);
                    const displayRef =
                      image.references.find((reference) => reference.tag)?.tag ??
                      image.references[0]?.reference ??
                      shortImageId(image.imageId);
                    return (
                      <tr key={image.imageId} className="clickable" onClick={() => setSelected(image.imageId)}>
                        <td>
                          <div className="cell-main mono truncate" style={{ maxWidth: 300 }} title={image.imageId}>
                            {displayRef}
                          </div>
                          <div className="cell-sub mono">{shortImageId(image.imageId)} · {formatBytes(image.sizeBytes)}</div>
                        </td>
                        <td>
                          <div className="hstack" style={{ gap: 4, flexWrap: 'wrap' }}>
                            {[...new Set(image.references.map((reference) => reference.environmentName))].map((name) => (
                              <span className="tag" key={name}>
                                {name}
                              </span>
                            ))}
                          </div>
                        </td>
                        <td>
                          {image.containerCount}
                          {image.runningContainerCount > 0 ? (
                            <div className="cell-sub">{image.runningContainerCount} running</div>
                          ) : null}
                        </td>
                        <td>
                          <SeverityPills
                            counts={{
                              critical: image.critical,
                              high: image.high,
                              medium: image.medium,
                              low: image.low,
                              unknown: image.unknown,
                            }}
                          />
                        </td>
                        <td>{image.fixable > 0 ? <span className="badge ok">{image.fixable} fixable</span> : <span className="dim tiny">—</span>}</td>
                        <td>
                          {image.lastSuccessAt ? (
                            <span className="status-line">
                              <span className="status-dot success" aria-hidden="true" />
                              Succeeded
                            </span>
                          ) : (
                            <span className="status-line">
                              <span className="status-dot unknown" aria-hidden="true" />
                              Never scanned
                            </span>
                          )}
                          <div className="cell-sub">
                            {relativeTime(image.lastSuccessAt)}
                            {stale ? ' · stale' : ''}
                          </div>
                          {image.lastScanStatus === 'failed' ? (
                            <div className="cell-sub" style={{ color: 'var(--critical)' }}>
                              last attempt failed
                            </div>
                          ) : null}
                        </td>
                        <td onClick={(event) => event.stopPropagation()}>
                          <div className="hstack" style={{ gap: 4 }}>
                            <button
                              type="button"
                              className="btn xs ghost"
                              onClick={() => void scan(image.imageId, 'quick')}
                              title="Queue quick scan (OS packages)"
                            >
                              <IconPlay width={11} height={11} /> Quick
                            </button>
                            <button
                              type="button"
                              className="btn xs ghost"
                              onClick={() => void scan(image.imageId, 'standard')}
                              title="Queue standard scan (OS + language packages)"
                            >
                              Standard
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            <Pagination page={data.page} pageSize={data.pageSize} total={data.total} onChange={setPage} />
          </>
        ) : null}
      </section>

      {selected ? (
        <ImageDrawer
          imageId={selected}
          freshnessHours={freshnessHours}
          onClose={() => setSelected(null)}
          onScan={(imageId, profile) => void scan(imageId, profile)}
        />
      ) : null}
    </div>
  );
}

function ImageDrawer({
  imageId,
  freshnessHours,
  onClose,
  onScan,
}: {
  imageId: string;
  freshnessHours: number;
  onClose: () => void;
  onScan: (imageId: string, profile: 'quick' | 'standard') => void;
}) {
  const { data, error, loading, refresh } = useApi<ImageDetail>(`/images/${encodeURIComponent(imageId)}`);
  const stale =
    !data?.image.lastSuccessAt ||
    Date.now() - Date.parse(data.image.lastSuccessAt) > freshnessHours * 3_600_000;

  return (
    <Drawer
      title={data ? (data.image.references.find((reference) => reference.tag)?.tag ?? shortImageId(data.image.imageId)) : 'Image'}
      subtitle={data ? `Image ID ${data.image.imageId.slice(0, 23)}…` : 'Loading image'}
      onClose={onClose}
      footer={
        data ? (
          <>
            <button type="button" className="btn ghost" onClick={onClose}>
              Close
            </button>
            <button type="button" className="btn ghost" onClick={() => onScan(data.image.imageId, 'quick')}>
              <IconPlay width={13} height={13} /> Quick scan
            </button>
            <button type="button" className="btn primary" onClick={() => onScan(data.image.imageId, 'standard')}>
              <IconPlay width={13} height={13} /> Standard scan
            </button>
          </>
        ) : null
      }
    >
      {loading && !data ? <InlineLoading label="Loading image…" /> : null}
      {error && !data ? <ErrorPanel error={error} onRetry={refresh} /> : null}
      {data ? (
        <>
          <section className="drawer-section">
            <div className="pill-row" style={{ marginBottom: 10 }}>
              <SeverityPills
                counts={{
                  critical: data.image.critical,
                  high: data.image.high,
                  medium: data.image.medium,
                  low: data.image.low,
                  unknown: data.image.unknown,
                }}
              />
              {data.image.fixable > 0 ? <span className="badge ok">{data.image.fixable} fixable</span> : null}
              <ScanStatusBadge status={data.image.lastScanStatus} />
              {stale ? <span className="badge stale">Stale results</span> : null}
            </div>
            {stale ? (
              <div className="note warn">
                <IconAlert width={14} height={14} style={{ verticalAlign: -2 }} /> Last successful scan is older than{' '}
                {freshnessHours}h. Vulnerability intelligence changes even when the image digest does not.
              </div>
            ) : null}
            <dl className="detail-list">
              <dt>Image ID</dt>
              <dd className="mono" style={{ wordBreak: 'break-all' }}>
                {data.image.imageId}
              </dd>
              <dt>Operating system</dt>
              <dd>{data.image.osFamily ? `${data.image.osFamily} ${data.image.osVersion ?? ''}` : 'Not reported'}</dd>
              <dt>Size</dt>
              <dd>{formatBytes(data.image.sizeBytes)}</dd>
              <dt>First seen</dt>
              <dd>{formatDate(data.image.firstSeenAt)}</dd>
              <dt>Last successful scan</dt>
              <dd>{relativeTime(data.image.lastSuccessAt)}</dd>
              <dt>Last scan attempt</dt>
              <dd>
                {relativeTime(data.image.lastScanAt)} · {data.image.lastScanStatus ?? 'never'}
              </dd>
              <dt>References</dt>
              <dd>
                <div className="tag-list">
                  {data.image.references.map((reference) => (
                    <span className="tag" key={`${reference.environmentId}:${reference.reference}`}>
                      {reference.environmentName}: {reference.reference}
                    </span>
                  ))}
                </div>
              </dd>
            </dl>
          </section>

          <section className="drawer-section">
            <h3>Containers using this image ({data.containers.length})</h3>
            {data.containers.length === 0 ? (
              <div className="note">No container currently uses this image version.</div>
            ) : (
              <div className="vstack" style={{ gap: 6 }}>
                {data.containers.map((container) => (
                  <div className="spread" key={`${container.environmentId}:${container.id}`}>
                    <span className="small">
                      {container.name} <span className="dim">· {container.environmentName} · {container.state}</span>
                    </span>
                    <ExposureBadge state={container.exposure} reason={container.exposureReason} />
                  </div>
                ))}
              </div>
            )}
          </section>

          <section className="drawer-section">
            <div className="spread" style={{ marginBottom: 8 }}>
              <h3 style={{ margin: 0 }}>Open findings ({data.totalFindings})</h3>
              <button
                type="button"
                className="link-button small"
                onClick={() => navigate(`/vulnerabilities?image=${encodeURIComponent(data.image.imageId)}`)}
              >
                Open in Vulnerabilities
              </button>
            </div>
            {data.findings.length === 0 ? (
              <div className="note">
                No open findings were reported by the last successful scan. Confirm that scan is recent and that its
                profile covers the packages you use.
              </div>
            ) : (
              <div className="vstack" style={{ gap: 8 }}>
                {data.findings.map((finding) => (
                  <div key={finding.id} className="card" style={{ padding: 10, background: 'var(--panel-2)' }}>
                    <div className="hstack" style={{ flexWrap: 'wrap', gap: 6 }}>
                      <SeverityBadge severity={finding.severity} />
                      <span className="mono small">{finding.vulnId}</span>
                      {finding.kev === 1 ? <KevBadge kev={1} /> : null}
                      <FixBadge fixedVersion={finding.fixedVersion} />
                    </div>
                    <div className="cell-sub" style={{ marginTop: 4 }}>
                      {finding.pkgName} {finding.installedVersion} · priority {finding.priority.tier}
                    </div>
                  </div>
                ))}
              </div>
            )}
            {data.events.length > 0 ? (
              <button
                type="button"
                className="link-button small"
                style={{ marginTop: 10 }}
                onClick={() => navigate(`/vulnerabilities?image=${encodeURIComponent(data.image.imageId)}&state=resolved`)}
              >
                <IconExternal width={12} height={12} style={{ verticalAlign: -2 }} /> View resolved findings
              </button>
            ) : null}
          </section>

          <section className="drawer-section">
            <h3>Recent scans</h3>
            {data.scans.length === 0 ? (
              <div className="note">Never scanned.</div>
            ) : (
              <div className="vstack" style={{ gap: 6 }}>
                {data.scans.map((scan) => (
                  <div className="spread" key={scan.id}>
                    <span className="small">
                      <ScanStatusBadge status={scan.status} /> {scan.profile} · {scan.total} findings ·{' '}
                      {scan.scannerVersion ?? 'scanner unknown'}
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
