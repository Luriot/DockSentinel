import { useEffect, useState } from 'react';
import {
  type ContentFinding,
  type ContentFindingsResponse,
  type ContentKind,
  type PublicSettings,
  type Severity,
} from '../api.ts';
import { navigate, useApi, useDebounced } from '../hooks.ts';
import {
  Drawer,
  EmptyState,
  ErrorPanel,
  IconAlert,
  IconExternal,
  IconKey,
  IconRefresh,
  IconSearch,
  Pagination,
  SeverityBadge,
  TableSkeleton,
} from '../components/ui.tsx';
import { formatDate, relativeTime } from '../format.ts';

const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];

export function Content() {
  const [search, setSearch] = useState('');
  const debouncedSearch = useDebounced(search);
  const [kind, setKind] = useState<'' | ContentKind>('');
  const [severity, setSeverity] = useState<'' | Severity>('');
  const [state, setState] = useState<'open' | 'resolved' | 'all'>('open');
  const [page, setPage] = useState(1);
  const [selectedId, setSelectedId] = useState<number | null>(null);

  useEffect(() => setPage(1), [debouncedSearch, kind, severity, state]);

  const query = new URLSearchParams();
  if (debouncedSearch) query.set('q', debouncedSearch);
  if (kind) query.set('kind', kind);
  if (severity) query.set('severity', severity);
  if (state !== 'open') query.set('state', state);
  query.set('page', String(page));
  query.set('pageSize', '25');

  const { data, error, loading, refresh } = useApi<ContentFindingsResponse>(
    `/content-findings?${query.toString()}`,
    { intervalMs: 30_000 },
  );
  const settings = useApi<{ settings: PublicSettings }>('/settings');
  const contentEnabled =
    Boolean(settings.data?.settings.misconfigScanEnabled) || Boolean(settings.data?.settings.secretScanEnabled);
  const selected = data?.items.find((item) => item.id === selectedId) ?? null;
  const hasFilters = Boolean(debouncedSearch) || Boolean(kind) || Boolean(severity) || state !== 'open';

  return (
    <div className="page-stack">
      <div className="vstack" style={{ gap: 10 }}>
        <div className="note warn">
          <IconAlert width={14} height={14} style={{ verticalAlign: -2 }} /> Secret values are never stored, returned by
          the API, logged or shown here. Only rule, location, category and severity are kept. Secret matches can be
          false positives.
        </div>
        {!contentEnabled && settings.data ? (
          <div className="note info">
            Content scanning is disabled. Enable misconfiguration and/or secret scanning in{' '}
            <button type="button" className="link-button" onClick={() => navigate('/settings')}>
              Settings
            </button>
            , then run a content scan from an image.
          </div>
        ) : null}
      </div>

      <section className="card">
        <div className="filters" role="search" aria-label="Filter configuration and secret findings">
          <div className="toolbar-search">
            <IconSearch width={14} height={14} aria-hidden="true" />
            <input
              className="input"
              placeholder="Rule, title or path"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              aria-label="Search content findings"
            />
          </div>
          <select
            className="select"
            value={kind}
            onChange={(event) => setKind(event.target.value as '' | ContentKind)}
            aria-label="Finding type"
          >
            <option value="">All types</option>
            <option value="misconfiguration">Misconfigurations</option>
            <option value="secret">Secrets</option>
          </select>
          <select
            className="select"
            value={severity}
            onChange={(event) => setSeverity(event.target.value as '' | Severity)}
            aria-label="Severity"
          >
            <option value="">All severities</option>
            {SEVERITIES.map((entry) => (
              <option key={entry} value={entry}>
                {entry}
              </option>
            ))}
          </select>
          <select
            className="select"
            value={state}
            onChange={(event) => setState(event.target.value as 'open' | 'resolved' | 'all')}
            aria-label="State"
          >
            <option value="open">Open</option>
            <option value="resolved">Resolved</option>
            <option value="all">All</option>
          </select>
          <button type="button" className="btn small ghost" onClick={refresh} aria-label="Refresh" disabled={loading}>
            <IconRefresh width={13} height={13} />
          </button>
        </div>
        <div className="list-meta">
          <span className="badge neutral">
            {data?.byKind.misconfiguration ?? 0} misconfiguration{(data?.byKind.misconfiguration ?? 0) === 1 ? '' : 's'}
          </span>
          <span className="badge neutral">
            {data?.byKind.secret ?? 0} secret{(data?.byKind.secret ?? 0) === 1 ? '' : 's'}
          </span>
          <span className="badge neutral">{data?.total ?? 0} matching</span>
          {hasFilters ? (
            <button
              type="button"
              className="link-button"
              onClick={() => {
                setSearch('');
                setKind('');
                setSeverity('');
                setState('open');
              }}
            >
              Clear filters
            </button>
          ) : null}
        </div>
      </section>

      <section className="card">
        {error && !data ? <ErrorPanel error={error} onRetry={refresh} /> : null}
        {loading && !data ? <TableSkeleton columns={5} rows={6} /> : null}
        {data && data.items.length === 0 ? (
          <EmptyState icon={<IconKey width={22} height={22} />} title="No configuration or secret findings">
            <p>
              {contentEnabled
                ? 'Run a content scan from an image. Successful scans resolve absent findings; failed scans never do.'
                : 'Enable content scanning in Settings, then run a content scan from an image.'}
            </p>
          </EmptyState>
        ) : null}
        {data && data.items.length > 0 ? (
          <div className="table-wrap">
            <table className="table content-table">
              <caption className="sr-only">Configuration and secret findings</caption>
              <thead>
                <tr>
                  <th scope="col">Severity</th>
                  <th scope="col">Type</th>
                  <th scope="col">Finding</th>
                  <th scope="col">Location</th>
                  <th scope="col">Image</th>
                  <th scope="col">Last seen</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((item) => (
                  <tr key={item.id} className="clickable" onClick={() => setSelectedId(item.id)}>
                    <td>
                      <SeverityBadge severity={item.severity} />
                    </td>
                    <td>
                      <span className={`badge ${item.kind === 'secret' ? 'warn' : 'neutral'}`}>
                        {item.kind === 'secret' ? 'Secret' : 'Misconfig'}
                      </span>
                      <div className="cell-sub">{item.scope === 'image-config' ? 'Image config' : 'Image files'}</div>
                    </td>
                    <td>
                      <div className="cell-main">{item.title}</div>
                      <div className="cell-sub mono">{item.ruleId}</div>
                    </td>
                    <td>
                      <div className="cell-main mono truncate" style={{ maxWidth: 280 }} title={item.target}>
                        {item.target}
                      </div>
                      <div className="cell-sub">
                        {item.startLine ? `line ${item.startLine}${item.endLine && item.endLine !== item.startLine ? `-${item.endLine}` : ''}` : '—'}
                      </div>
                    </td>
                    <td>
                      <div className="cell-main truncate" style={{ maxWidth: 220 }} title={item.imageRef}>
                        {item.imageRef}
                      </div>
                      <div className="cell-sub mono">{item.imageId.slice(0, 19)}…</div>
                    </td>
                    <td>
                      <span className="small">{relativeTime(item.lastSeenAt)}</span>
                      {item.resolvedAt ? <div className="cell-sub">Resolved</div> : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
        {data ? (
          <Pagination page={data.page} pageSize={data.pageSize} total={data.total} onChange={setPage} />
        ) : null}
      </section>

      {selected ? <ContentDrawer finding={selected} onClose={() => setSelectedId(null)} /> : null}
    </div>
  );
}

function ContentDrawer({ finding, onClose }: { finding: ContentFinding; onClose: () => void }) {
  return (
    <Drawer
      title={finding.title}
      subtitle={`${finding.kind === 'secret' ? 'Secret' : 'Misconfiguration'} · ${finding.ruleId}`}
      onClose={onClose}
      footer={
        <button type="button" className="btn ghost" onClick={onClose}>
          Close
        </button>
      }
    >
      <section className="drawer-section">
        <div className="pill-row">
          <SeverityBadge severity={finding.severity} />
          <span className="badge neutral">{finding.scope === 'image-config' ? 'Image config' : 'Image files'}</span>
          {finding.category ? <span className="badge neutral">{finding.category}</span> : null}
        </div>
        <dl className="detail-list">
          <dt>Image</dt>
          <dd className="mono">{finding.imageRef}</dd>
          <dt>Rule</dt>
          <dd className="mono">{finding.ruleId}</dd>
          <dt>Location</dt>
          <dd className="mono">
            {finding.target}
            {finding.startLine ? `:${finding.startLine}${finding.endLine && finding.endLine !== finding.startLine ? `-${finding.endLine}` : ''}` : ''}
          </dd>
          <dt>First seen</dt>
          <dd>{formatDate(finding.firstSeenAt)}</dd>
          <dt>Last seen</dt>
          <dd>{formatDate(finding.lastSeenAt)}</dd>
          <dt>Episode</dt>
          <dd>{finding.episode}</dd>
          {finding.primaryUrl ? (
            <>
              <dt>Reference</dt>
              <dd>
                <a href={finding.primaryUrl} target="_blank" rel="noreferrer noopener" className="link-button">
                  <IconExternal width={12} height={12} /> {finding.primaryUrl}
                </a>
              </dd>
            </>
          ) : null}
        </dl>
      </section>
      {finding.message ? (
        <section className="drawer-section">
          <h3>Message</h3>
          <div className="note">{finding.message}</div>
        </section>
      ) : null}
      {finding.resolution ? (
        <section className="drawer-section">
          <h3>Resolution</h3>
          <div className="note info">{finding.resolution}</div>
        </section>
      ) : null}
      {finding.kind === 'secret' ? (
        <section className="drawer-section">
          <div className="note warn">
            <IconAlert width={14} height={14} style={{ verticalAlign: -2 }} /> The matched secret value is not stored or
            displayed. Rotate the credential if this finding is real, then rebuild the image without the secret.
          </div>
        </section>
      ) : null}
    </Drawer>
  );
}
