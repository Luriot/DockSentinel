import { useCallback, useEffect, useState, type KeyboardEvent } from 'react';
import {
  api,
  type EnvironmentSummary,
  type FindingView,
  type ImageSummary,
  type ScanRecord,
  type Severity,
  type SeverityCounts,
  type TriageStatus,
} from '../api.ts';
import { useApi, useDebounced, navigate, useRoute } from '../hooks.ts';
import {
  Drawer,
  EmptyState,
  ErrorPanel,
  ExposureBadge,
  IconBug,
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
const PAGE_SIZES = [25, 50, 100];
const STATE_LABELS: Record<'open' | 'resolved' | 'all', string> = {
  open: 'open',
  resolved: 'resolved',
  all: 'open or resolved',
};

interface FindingsResponse {
  items: FindingView[];
  total: number;
  counts: SeverityCounts;
  page: number;
  pageSize: number;
}

interface GroupedFinding {
  vulnId: string;
  pkgName: string;
  severity: Severity;
  title: string | null;
  primaryUrl: string | null;
  kev: number;
  fixable: number;
  images: number;
  targets: number;
  findings: number;
  lastSeenAt: string;
}

interface GroupedResponse {
  items: GroupedFinding[];
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

type FindingStatusTone = 'open' | 'acknowledged' | 'ignored' | 'false-positive' | 'resolved';

function parseSeverityList(raw: string | null): Severity[] {
  if (!raw) return [];
  return raw
    .split(',')
    .map((value) => value.trim().toUpperCase())
    .filter((value): value is Severity => SEVERITIES.includes(value as Severity));
}

function findingStatus(finding: FindingView): { label: string; tone: FindingStatusTone } {
  if (finding.resolvedAt) return { label: 'Resolved', tone: 'resolved' };
  if (finding.triageStatus === 'acknowledged') return { label: 'Acknowledged', tone: 'acknowledged' };
  if (finding.triageStatus === 'ignored') return { label: 'Ignored', tone: 'ignored' };
  if (finding.triageStatus === 'false_positive') return { label: 'False positive', tone: 'false-positive' };
  return { label: 'Open', tone: 'open' };
}

function triageLabel(status: TriageStatus): string {
  if (status === 'acknowledged') return 'Acknowledged';
  if (status === 'ignored') return 'Ignored';
  if (status === 'false_positive') return 'False positive';
  return 'Not triaged';
}

function triageTone(status: TriageStatus): FindingStatusTone {
  if (status === 'acknowledged') return 'acknowledged';
  if (status === 'ignored') return 'ignored';
  if (status === 'false_positive') return 'false-positive';
  return 'open';
}

function scannerPackageState(status: string | null): string {
  switch ((status ?? '').toLowerCase()) {
    case 'fixed':
      return 'Fix version available';
    case 'affected':
      return 'Affected';
    case 'unknown':
      return 'Unknown';
    default:
      return status || 'Not reported';
  }
}

function initialPageSize(route: ReturnType<typeof useRoute>): number {
  const value = Number(route.params.get('pageSize'));
  return PAGE_SIZES.includes(value) ? value : 25;
}

function initialFinding(route: ReturnType<typeof useRoute>): number | null {
  const value = Number(route.params.get('finding'));
  return Number.isInteger(value) && value > 0 ? value : null;
}

function openGroup(
  group: GroupedFinding,
  setGrouped: (value: boolean) => void,
  setSearch: (value: string) => void,
  setPage: (value: number) => void,
): void {
  setGrouped(false);
  setSearch(group.vulnId);
  setPage(1);
}

function rowKey(event: KeyboardEvent<HTMLTableRowElement>, action: () => void): void {
  if (event.key === 'Enter' || event.key === ' ') {
    event.preventDefault();
    action();
  }
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
  const [includeSuppressed, setIncludeSuppressed] = useState(route.params.get('suppressed') === 'true');
  const [includeKernel, setIncludeKernel] = useState(route.params.get('includeKernel') === 'true');
  const [grouped, setGrouped] = useState(route.params.get('grouped') !== 'false');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(() => initialPageSize(route));
  const [selected, setSelected] = useState<number | null>(() => initialFinding(route));

  useEffect(() => {
    setPage(1);
  }, [
    debouncedSearch,
    severities,
    imageId,
    kevOnly,
    fixableOnly,
    runningOnly,
    environmentId,
    state,
    includeSuppressed,
    includeKernel,
    grouped,
    pageSize,
  ]);

  const query = new URLSearchParams();
  if (debouncedSearch) query.set('q', debouncedSearch);
  if (severities.length > 0) query.set('severity', severities.join(','));
  if (imageId) query.set('image', imageId);
  if (kevOnly) query.set('kev', 'true');
  if (fixableOnly) query.set('fixable', 'true');
  if (runningOnly) query.set('running', 'true');
  if (environmentId) query.set('envId', environmentId);
  if (state !== 'open') query.set('state', state);
  if (includeSuppressed) query.set('includeSuppressed', 'true');
  if (includeKernel) query.set('includeKernel', 'true');
  query.set('grouped', grouped ? 'true' : 'false');
  query.set('page', String(page));
  query.set('pageSize', String(pageSize));

  // Keep the address bar shareable without triggering a route re-render on every keystroke.
  useEffect(() => {
    const next = new URLSearchParams(query);
    next.delete('page');
    if (pageSize === 25) next.delete('pageSize');
    if (selected !== null) next.set('finding', String(selected));
    else next.delete('finding');
    const text = next.toString();
    window.history.replaceState(null, '', `${window.location.pathname}${text ? `?${text}` : ''}`);
  }, [
    debouncedSearch,
    severities,
    imageId,
    kevOnly,
    fixableOnly,
    runningOnly,
    environmentId,
    state,
    includeSuppressed,
    includeKernel,
    grouped,
    pageSize,
    selected,
  ]);

  const { data, error, loading, refresh } = useApi<FindingsResponse>(`/findings?${query.toString()}`, {
    intervalMs: 30_000,
  });
  const groupedResults = useApi<GroupedResponse>(grouped ? `/findings/grouped?${query.toString()}` : null, {
    intervalMs: 30_000,
  });
  const environments = useApi<{ items: EnvironmentSummary[] }>('/environments');

  const toggleSeverity = useCallback((severity: Severity) => {
    setSeverities((current) =>
      current.includes(severity) ? current.filter((entry) => entry !== severity) : [...current, severity],
    );
  }, []);

  function exportFindings(format: 'csv' | 'json'): void {
    const params = new URLSearchParams(query);
    params.delete('page');
    params.delete('pageSize');
    params.set('format', format);
    window.location.href = `/api/findings/export?${params.toString()}`;
  }

  async function scanImage(finding: FindingView, profile: 'quick' | 'standard'): Promise<void> {
    try {
      await api.post(`/images/${encodeURIComponent(finding.imageId)}/scan`, { profile });
      toast(`${profile === 'quick' ? 'Quick' : 'Standard'} scan queued`, 'success');
    } catch (scanError) {
      toast(scanError instanceof Error ? scanError.message : 'Unable to queue scan', 'error');
    }
  }

  function clearFilters(): void {
    setSearch('');
    setSeverities([]);
    setImageId('');
    setKevOnly(false);
    setFixableOnly(false);
    setRunningOnly(false);
    setEnvironmentId('');
    setIncludeSuppressed(false);
    setIncludeKernel(false);
    setState('open');
    setPage(1);
  }

  const advancedCount =
    (runningOnly ? 1 : 0) +
    (includeSuppressed ? 1 : 0) +
    (includeKernel ? 1 : 0) +
    (environmentId ? 1 : 0) +
    (state !== 'open' ? 1 : 0);

  const hasFilters =
    Boolean(debouncedSearch) ||
    severities.length > 0 ||
    Boolean(imageId) ||
    kevOnly ||
    fixableOnly ||
    advancedCount > 0;

  const stateWord = STATE_LABELS[state];
  const summary = grouped
    ? groupedResults.data
      ? `${groupedResults.data.total} ${groupedResults.data.total === 1 ? 'vulnerability' : 'vulnerabilities'} · ${data?.total ?? 0} ${stateWord} findings`
      : 'Loading grouped findings…'
    : data
      ? `${data.total} matching ${stateWord} ${data.total === 1 ? 'finding' : 'findings'}`
      : 'Loading findings…';

  const isEmpty = grouped ? groupedResults.data?.items.length === 0 : data?.items.length === 0;
  const tableLoading = grouped ? groupedResults.loading && !groupedResults.data : loading && !data;
  const tableError = grouped ? groupedResults.error && !groupedResults.data : error && !data;
  const retry = grouped ? groupedResults.refresh : refresh;

  return (
    <div className="vuln-page">
      <section className="card vuln-toolbar" aria-label="Filter findings">
        <div className="vuln-toolbar-main">
          <div className="vuln-search">
            <IconSearch width={14} height={14} aria-hidden="true" />
            <input
              className="input"
              placeholder="CVE, package, title or image"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              aria-label="Search findings"
            />
          </div>

          <div className="vuln-severity" role="group" aria-label="Severity filter">
            {SEVERITIES.map((severity) => (
              <button
                key={severity}
                type="button"
                className={`chip-toggle sev-${severity}`}
                aria-pressed={severities.includes(severity)}
                onClick={() => toggleSeverity(severity)}
              >
                <span className="dot" aria-hidden="true" />
                {severity === 'CRITICAL'
                  ? 'Critical'
                  : severity === 'HIGH'
                    ? 'High'
                    : severity === 'MEDIUM'
                      ? 'Medium'
                      : severity === 'LOW'
                        ? 'Low'
                        : 'Unknown'}
              </button>
            ))}
          </div>

          <button
            type="button"
            className="chip-toggle"
            aria-pressed={grouped}
            onClick={() => setGrouped((value) => !value)}
            title="One row per vulnerability and package across images"
          >
            Group by CVE
          </button>
          <button
            type="button"
            className="chip-toggle"
            aria-pressed={kevOnly}
            onClick={() => setKevOnly((value) => !value)}
          >
            Known exploited
          </button>
          <button
            type="button"
            className="chip-toggle"
            aria-pressed={fixableOnly}
            onClick={() => setFixableOnly((value) => !value)}
          >
            Fix available
          </button>

          <details className="vuln-advanced">
            <summary>
              More filters
              {advancedCount > 0 ? <span className="vuln-advanced-count">{advancedCount}</span> : null}
            </summary>
            <div className="vuln-advanced-body">
              <label className="vuln-field">
                <span>State</span>
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
              </label>
              <label className="vuln-field">
                <span>Environment</span>
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
              </label>
              <label className="checkbox vuln-check">
                <input
                  type="checkbox"
                  checked={runningOnly}
                  onChange={(event) => setRunningOnly(event.target.checked)}
                />
                Running only
              </label>
              <label className="checkbox vuln-check">
                <input
                  type="checkbox"
                  checked={includeSuppressed}
                  onChange={(event) => setIncludeSuppressed(event.target.checked)}
                />
                Show ignored
              </label>
              <label className="checkbox vuln-check">
                <input
                  type="checkbox"
                  checked={includeKernel}
                  onChange={(event) => setIncludeKernel(event.target.checked)}
                />
                Kernel packages
              </label>
            </div>
          </details>

          {hasFilters ? (
            <button type="button" className="btn small ghost" onClick={clearFilters}>
              Clear filters
            </button>
          ) : null}
        </div>

        <div className="vuln-toolbar-meta">
          <span className="vuln-summary">{summary}</span>
          <span className="vuln-severity-counts" aria-label="Findings by severity">
            <span className="badge sev-CRITICAL">{data?.counts.CRITICAL ?? 0} critical</span>
            <span className="badge sev-HIGH">{data?.counts.HIGH ?? 0} high</span>
            <span className="badge sev-MEDIUM">{data?.counts.MEDIUM ?? 0} medium</span>
            <span className="badge sev-LOW">{data?.counts.LOW ?? 0} low</span>
            <span className="badge sev-UNKNOWN">{data?.counts.UNKNOWN ?? 0} unknown</span>
          </span>
          <label className="vuln-page-size">
            Rows
            <select
              className="select"
              value={pageSize}
              onChange={(event) => setPageSize(Number(event.target.value))}
              aria-label="Findings per page"
            >
              {PAGE_SIZES.map((size) => (
                <option key={size} value={size}>
                  {size}
                </option>
              ))}
            </select>
          </label>
          <div className="vuln-toolbar-actions">
            <button type="button" className="btn small ghost" onClick={() => exportFindings('csv')}>
              Export CSV
            </button>
            <button type="button" className="btn small ghost" onClick={() => exportFindings('json')}>
              Export JSON
            </button>
            <button type="button" className="btn small ghost" onClick={refresh} aria-label="Refresh">
              <IconRefresh width={13} height={13} />
            </button>
          </div>
        </div>

        {imageId ? (
          <div className="vuln-image-filter">
            <span className="badge accent">
              Image filter: <span className="mono">{shortImageId(imageId)}</span>
              <button
                type="button"
                className="link-button"
                onClick={() => setImageId('')}
                aria-label="Remove image filter"
              >
                ✕
              </button>
            </span>
          </div>
        ) : null}
      </section>

      <section className="card vuln-list" aria-labelledby="vuln-list-title">
        <div className="vuln-list-head">
          <div>
            <h2 id="vuln-list-title">{grouped ? 'Grouped findings' : 'Individual findings'}</h2>
            <span className="vuln-list-sub">
              {grouped
                ? 'One row per CVE and package. Switch to individual findings for per-finding versions, CVSS, status and triage.'
                : 'Every row is a finding attached to an image.'}
            </span>
          </div>
          <span className="vuln-rank-note">
            Server order: severity, KEV, fix availability, running state, last seen
          </span>
        </div>

        {tableError ? <ErrorPanel error={grouped ? groupedResults.error! : error!} onRetry={retry} /> : null}
        {tableLoading ? (
          <TableSkeleton rows={8} columns={grouped ? 7 : 7} />
        ) : null}

        {isEmpty ? (
          <EmptyState
            icon={<IconBug width={24} height={24} />}
            title={state === 'resolved' ? 'No resolved findings match' : 'No findings match'}
            action={
              hasFilters ? (
                <button type="button" className="btn small ghost" onClick={clearFilters}>
                  Reset filters
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

        {grouped && groupedResults.data && groupedResults.data.items.length > 0 ? (
          <>
            <div className="vuln-table-wrap">
              <table className="table vuln-table vuln-table-grouped">
                <caption className="sr-only">Vulnerabilities grouped by CVE and package</caption>
                <thead>
                  <tr>
                    <th scope="col">Severity</th>
                    <th scope="col">Vulnerability</th>
                    <th scope="col">Package</th>
                    <th scope="col">Images</th>
                    <th scope="col">Findings</th>
                    <th scope="col">Signals</th>
                    <th scope="col">Last seen</th>
                  </tr>
                </thead>
                <tbody>
                  {groupedResults.data.items.map((group) => (
                    <tr
                      key={`${group.vulnId}:${group.pkgName}`}
                      tabIndex={0}
                      title="Open individual findings"
                      onClick={() => openGroup(group, setGrouped, setSearch, setPage)}
                      onKeyDown={(event) =>
                        rowKey(event, () => openGroup(group, setGrouped, setSearch, setPage))
                      }
                    >
                      <td>
                        <SeverityBadge severity={group.severity} />
                      </td>
                      <td>
                        <div className="vuln-id">{group.vulnId}</div>
                        <div className="vuln-title">{group.title ?? 'No title reported'}</div>
                      </td>
                      <td>
                        <span className="vuln-pkg mono">{group.pkgName}</span>
                      </td>
                      <td className="vuln-num">{group.images}</td>
                      <td className="vuln-num">{group.findings}</td>
                      <td>
                        <div className="vuln-signals">
                          {group.kev === 1 ? <KevBadge kev={1} /> : null}
                          {group.fixable > 0 ? (
                            <span className="vuln-signal-text">{group.fixable} with fix</span>
                          ) : (
                            <span className="vuln-signal-text">No fix listed</span>
                          )}
                        </div>
                      </td>
                      <td className="vuln-age">{relativeTime(group.lastSeenAt)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="vuln-mobile-list" aria-label="Grouped vulnerabilities">
              {groupedResults.data.items.map((group) => (
                <button
                  key={`${group.vulnId}:${group.pkgName}`}
                  type="button"
                  className="vuln-mobile-card"
                  onClick={() => openGroup(group, setGrouped, setSearch, setPage)}
                >
                  <span className="vuln-mobile-top">
                    <SeverityBadge severity={group.severity} />
                    <span className="vuln-mobile-id">{group.vulnId}</span>
                  </span>
                  <span className="vuln-mobile-title">{group.title ?? 'No title reported'}</span>
                  <span className="vuln-mobile-line">
                    <span className="mono">{group.pkgName}</span> · {group.images} image
                    {group.images === 1 ? '' : 's'} · {group.findings} finding
                    {group.findings === 1 ? '' : 's'}
                  </span>
                  <span className="vuln-mobile-foot">
                    <span className="vuln-signals">
                      {group.kev === 1 ? <KevBadge kev={1} /> : null}
                      {group.fixable > 0 ? <span className="vuln-signal-text">{group.fixable} with fix</span> : null}
                    </span>
                    <span className="vuln-age">{relativeTime(group.lastSeenAt)}</span>
                  </span>
                </button>
              ))}
            </div>

            <Pagination
              page={groupedResults.data.page}
              pageSize={groupedResults.data.pageSize}
              total={groupedResults.data.total}
              onChange={setPage}
            />
          </>
        ) : null}

        {!grouped && data && data.items.length > 0 ? (
          <>
            <div className="vuln-table-wrap">
              <table className="table vuln-table vuln-table-individual">
                <caption className="sr-only">Vulnerability findings</caption>
                <thead>
                  <tr>
                    <th scope="col">Severity</th>
                    <th scope="col">Vulnerability</th>
                    <th scope="col">Package / fix</th>
                    <th scope="col">Affected workload</th>
                    <th scope="col">Status</th>
                    <th scope="col">Signals</th>
                    <th scope="col">First seen</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((finding) => {
                    const status = findingStatus(finding);
                    return (
                      <tr
                        key={finding.id}
                        tabIndex={0}
                        title="Open finding details"
                        onClick={() => setSelected(finding.id)}
                        onKeyDown={(event) => rowKey(event, () => setSelected(finding.id))}
                      >
                        <td>
                          <SeverityBadge severity={finding.severity} />
                          <div className="vuln-cvss" title={finding.cvssSource ? `Source: ${finding.cvssSource}` : undefined}>
                            {finding.cvssScore !== null ? `CVSS ${finding.cvssScore.toFixed(1)}` : 'CVSS —'}
                          </div>
                        </td>
                        <td>
                          <div className="vuln-id">{finding.vulnId}</div>
                          <div className="vuln-title">{finding.title ?? 'No title reported'}</div>
                        </td>
                        <td>
                          <div className="vuln-pkg mono" title={finding.pkgName}>
                            {finding.pkgName}
                          </div>
                          <div className="vuln-versions">
                            <span className="mono">{finding.installedVersion || 'unknown'}</span>
                            {finding.fixedVersion ? (
                              <span
                                className="vuln-fix"
                                title="Fixed version listed by the scanner. Not applied until the image is rebuilt and rescanned."
                              >
                                → {finding.fixedVersion}
                              </span>
                            ) : (
                              <span className="vuln-nofix">No fix listed</span>
                            )}
                          </div>
                        </td>
                        <td>
                          <div className="vuln-workload" title={finding.containers[0]?.imageRef ?? undefined}>
                            {finding.containers[0]?.imageRef ?? shortImageId(finding.imageId)}
                          </div>
                          <div className="vuln-workload-meta">
                            {finding.containerCount > 0
                              ? `${finding.containerCount} container${finding.containerCount === 1 ? '' : 's'}${
                                  finding.runningContainerCount > 0
                                    ? ` · ${finding.runningContainerCount} running`
                                    : ''
                                }`
                              : 'Image only'}
                            {finding.environmentNames.length > 0
                              ? ` · ${finding.environmentNames.join(', ')}`
                              : ''}
                          </div>
                        </td>
                        <td>
                          <span className={`vuln-status is-${status.tone}`}>
                            <span className="vuln-status-dot" aria-hidden="true" />
                            {status.label}
                          </span>
                        </td>
                        <td>
                          <div className="vuln-signals">
                            <KevBadge kev={finding.kev} />
                            {finding.exposure ? <ExposureBadge state={finding.exposure} /> : null}
                          </div>
                        </td>
                        <td className="vuln-age">
                          {relativeTime(finding.firstSeenAt)}
                          {finding.episode > 1 ? <div className="vuln-episode">episode {finding.episode}</div> : null}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            <div className="vuln-mobile-list" aria-label="Vulnerability findings">
              {data.items.map((finding) => {
                const status = findingStatus(finding);
                return (
                  <button
                    key={finding.id}
                    type="button"
                    className="vuln-mobile-card"
                    onClick={() => setSelected(finding.id)}
                  >
                    <span className="vuln-mobile-top">
                      <SeverityBadge severity={finding.severity} />
                      <span className="vuln-mobile-id">{finding.vulnId}</span>
                      <span className="vuln-cvss">
                        {finding.cvssScore !== null ? `CVSS ${finding.cvssScore.toFixed(1)}` : 'CVSS —'}
                      </span>
                    </span>
                    <span className="vuln-mobile-title">{finding.title ?? 'No title reported'}</span>
                    <span className="vuln-mobile-line">
                      <span className="mono">{finding.pkgName}</span> · {finding.installedVersion || 'unknown'}
                      {finding.fixedVersion ? ` → ${finding.fixedVersion}` : ' · no fix listed'}
                    </span>
                    <span className="vuln-mobile-line">
                      {finding.containers[0]?.imageRef ?? shortImageId(finding.imageId)} ·{' '}
                      {finding.containerCount} container{finding.containerCount === 1 ? '' : 's'}
                    </span>
                    <span className="vuln-mobile-foot">
                      <span className={`vuln-status is-${status.tone}`}>
                        <span className="vuln-status-dot" aria-hidden="true" />
                        {status.label}
                      </span>
                      <span className="vuln-signals">
                        <KevBadge kev={finding.kev} />
                        {finding.exposure ? <ExposureBadge state={finding.exposure} /> : null}
                      </span>
                    </span>
                  </button>
                );
              })}
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
          onChanged={refresh}
          onToast={toast}
        />
      ) : null}
    </div>
  );
}

function FindingDrawer({
  findingId,
  onClose,
  onScan,
  onChanged,
  onToast,
}: {
  findingId: number;
  onClose: () => void;
  onScan: (finding: FindingView, profile: 'quick' | 'standard') => void;
  onChanged: () => void;
  onToast: ReturnType<typeof useToast>;
}) {
  const { data, error, loading, refresh } = useApi<FindingDetail>(`/findings/${findingId}`);
  const [triageNote, setTriageNote] = useState('');
  const [triageBusy, setTriageBusy] = useState(false);

  useEffect(() => {
    if (data) setTriageNote(data.finding.triageNote ?? '');
  }, [data]);

  async function triage(status: TriageStatus): Promise<void> {
    setTriageBusy(true);
    try {
      await api.patch(`/findings/${findingId}/triage`, {
        status,
        note: triageNote.trim() || null,
      });
      onToast(
        status === 'none'
          ? 'Triage cleared'
          : status === 'acknowledged'
            ? 'Finding acknowledged'
            : status === 'ignored'
              ? 'Finding ignored and hidden from default views'
              : 'Finding marked as a false positive',
        'success',
      );
      refresh();
      onChanged();
    } catch (triageError) {
      onToast(triageError instanceof Error ? triageError.message : 'Unable to update triage', 'error');
    } finally {
      setTriageBusy(false);
    }
  }

  const finding = data?.finding;
  const image = data?.image;
  const scanExcluded = image?.scanExcluded === true;
  const scanDisabled = loading || scanExcluded;
  const resolved = Boolean(finding?.resolvedAt);

  return (
    <Drawer
      title={finding ? finding.vulnId : 'Finding'}
      subtitle={finding ? `${finding.pkgName} ${finding.installedVersion || ''}`.trim() : 'Loading finding'}
      onClose={onClose}
      footer={
        finding ? (
          <>
            <button type="button" className="btn ghost" onClick={onClose}>
              Close
            </button>
            <button
              type="button"
              className="btn ghost"
              disabled={scanDisabled}
              title={scanExcluded ? 'This image is excluded from scans' : undefined}
              onClick={() => onScan(finding, 'quick')}
            >
              <IconPlay width={13} height={13} /> Quick scan
            </button>
            <button
              type="button"
              className="btn primary"
              disabled={scanDisabled}
              title={scanExcluded ? 'This image is excluded from scans' : undefined}
              onClick={() => onScan(finding, 'standard')}
            >
              <IconPlay width={13} height={13} /> Standard scan
            </button>
          </>
        ) : null
      }
    >
      {loading && !data ? <InlineLoading label="Loading finding…" /> : null}
      {error && !data ? <ErrorPanel error={error} onRetry={refresh} /> : null}
      {finding ? (
        <div className="finding-detail">
          <div className="finding-title-block">
            <div className="finding-tags">
              <SeverityBadge severity={finding.severity} />
              <span className="finding-cvss" title={finding.cvssSource ? `Source: ${finding.cvssSource}` : undefined}>
                {finding.cvssScore !== null ? `CVSS ${finding.cvssScore.toFixed(1)}` : 'CVSS not reported'}
              </span>
              <PriorityBadge tier={finding.priority.tier} factors={finding.priority.factors} />
              <KevBadge kev={finding.kev} />
              {finding.exposure ? <ExposureBadge state={finding.exposure} /> : null}
              {finding.resolvedAt ? <span className="badge ok">Resolved</span> : null}
            </div>
            <h2>{finding.title ?? 'No title reported by the scanner'}</h2>
            <p className="finding-subtitle">
              <span className="mono">{finding.pkgName}</span> {finding.installedVersion || ''} ·{' '}
              <span className="mono">{finding.target}</span>
            </p>
          </div>

          <section className="finding-section">
            <h3>Fix availability</h3>
            {resolved ? (
              <div className="finding-callout is-neutral">
                <p>
                  This finding is resolved by the latest successful scan.
                  {finding.fixedVersion
                    ? ` The listed fixed version (${finding.fixedVersion}) is informational; verify the deployed image.`
                    : ' No fixed version is listed.'}
                </p>
              </div>
            ) : finding.fixedVersion ? (
              <div className="finding-callout">
                <div className="finding-callout-head">
                  <span className="finding-callout-label">Fixed version listed</span>
                  <span className="finding-callout-version mono">{finding.fixedVersion}</span>
                </div>
                <p>
                  This finding is still open. A listed fixed version is an upgrade target, not an applied remediation:
                  rebuild the image and rescan to confirm the finding is gone.
                </p>
              </div>
            ) : (
              <div className="finding-callout is-neutral">
                <p>No fixed version is listed by the scanner. This finding is still open; do not treat it as resolved.</p>
              </div>
            )}
          </section>

          <section className="finding-section">
            <h3>Finding data</h3>
            <dl className="finding-meta">
              <dt>Vulnerability ID</dt>
              <dd className="mono">{finding.vulnId}</dd>
              <dt>Package</dt>
              <dd className="mono">{finding.pkgName}</dd>
              <dt>Installed</dt>
              <dd className="mono">{finding.installedVersion || 'unknown'}</dd>
              <dt>Fix version</dt>
              <dd className="mono">{finding.fixedVersion ?? 'No fix listed'}</dd>
              <dt>Scanner package state</dt>
              <dd>{scannerPackageState(finding.status)}</dd>
              <dt>CVSS</dt>
              <dd>
                {finding.cvssScore !== null
                  ? `${finding.cvssScore.toFixed(1)}${finding.cvssSource ? ` · ${finding.cvssSource}` : ''}`
                  : 'Not reported'}
              </dd>
              {finding.cvssVector ? (
                <>
                  <dt>CVSS vector</dt>
                  <dd className="mono">{finding.cvssVector}</dd>
                </>
              ) : null}
              <dt>Target</dt>
              <dd className="mono">{finding.target}</dd>
              <dt>Class / type</dt>
              <dd>
                {finding.class ?? '—'}
                {finding.type ? ` · ${finding.type}` : ''}
              </dd>
              <dt>Published</dt>
              <dd>{finding.publishedAt ? formatDate(finding.publishedAt) : '—'}</dd>
              <dt>Modified</dt>
              <dd>{finding.modifiedAt ? formatDate(finding.modifiedAt) : '—'}</dd>
              <dt>First seen</dt>
              <dd>{formatDate(finding.firstSeenAt)}</dd>
              <dt>Last seen</dt>
              <dd>{relativeTime(finding.lastSeenAt)}</dd>
              {finding.episode > 1 ? (
                <>
                  <dt>Episode</dt>
                  <dd>{finding.episode}</dd>
                </>
              ) : null}
              {finding.kev === 1 ? (
                <>
                  <dt>Known exploited since</dt>
                  <dd>{finding.kevAddedAt ? formatDate(finding.kevAddedAt) : 'Unknown'}</dd>
                </>
              ) : null}
            </dl>
            <p className="finding-hint">
              Scanner package state describes the package reported by Trivy. It does not mean the finding has been
              remediated.
            </p>
          </section>

          <section className="finding-section">
            <div className="finding-section-head">
              <h3>Affected workloads ({finding.containers.length})</h3>
              {image ? (
                <button
                  type="button"
                  className="ops-link"
                  onClick={() => navigate(`/images?image=${encodeURIComponent(image.imageId)}`)}
                >
                  Open image
                </button>
              ) : null}
            </div>
            {finding.containers.length === 0 ? (
              <p className="finding-empty">No container currently uses this image. The finding still describes the image.</p>
            ) : (
              <div className="finding-workloads">
                {finding.containers.map((container) => (
                  <div className="finding-workload" key={`${container.environmentId}:${container.id}`}>
                    <div className="finding-workload-main">
                      <strong>{container.name}</strong>
                      <span className="finding-workload-meta">
                        {container.environmentName} · {container.state} · {container.imageRef}
                      </span>
                    </div>
                    <ExposureBadge state={container.exposure} reason={container.exposureReason} />
                  </div>
                ))}
              </div>
            )}
            <p className="finding-hint">
              Exposure is inferred from Docker metadata or declared with the <code className="kv-code">docksentinel.exposure</code>{' '}
              label; it is not proof of public reachability.
            </p>
          </section>

          <section className="finding-section">
            <h3>Why this priority</h3>
            <div className="factor-list">
              {finding.priority.factors.map((factor) => (
                <span className="factor" key={factor}>
                  {factor}
                </span>
              ))}
            </div>
            <p className="finding-hint">
              Priority {finding.priority.tier} · transparent rule-based ranking (score {finding.priority.score}). No
              proprietary risk score is implied.
            </p>
          </section>

          <section className="finding-section">
            <h3>Triage</h3>
            <div className="finding-triage-status">
              <span className={`vuln-status is-${triageTone(finding.triageStatus)}`}>
                <span className="vuln-status-dot" aria-hidden="true" />
                {triageLabel(finding.triageStatus)}
              </span>
              {finding.triagedAt ? (
                <span className="finding-hint">updated {relativeTime(finding.triagedAt)}</span>
              ) : null}
            </div>
            <textarea
              className="input"
              rows={2}
              maxLength={500}
              placeholder="Optional note (why is this acknowledged or ignored?)"
              value={triageNote}
              onChange={(event) => setTriageNote(event.target.value)}
              aria-label="Triage note"
            />
            <div className="finding-actions">
              <button type="button" className="btn small ghost" disabled={triageBusy} onClick={() => void triage('acknowledged')}>
                Acknowledge
              </button>
              <button type="button" className="btn small ghost" disabled={triageBusy} onClick={() => void triage('ignored')}>
                Ignore
              </button>
              <button type="button" className="btn small ghost" disabled={triageBusy} onClick={() => void triage('false_positive')}>
                False positive
              </button>
              <button type="button" className="btn small ghost" disabled={triageBusy} onClick={() => void triage('none')}>
                Clear
              </button>
            </div>
            <p className="finding-hint">
              Ignored and false-positive findings are hidden from default views, counts and alerts. They remain in scan
              history and can be restored here.
            </p>
          </section>

          <section className="finding-section">
            <h3>Lifecycle</h3>
            {data.events.length === 0 ? (
              <p className="finding-empty">No lifecycle events recorded yet.</p>
            ) : (
              <div className="finding-timeline">
                {data.events.map((event) => (
                  <div className="finding-timeline-row" key={event.id}>
                    <span className="finding-timeline-kind">
                      {event.kind === 'appeared'
                        ? 'Detected'
                        : event.kind === 'resolved'
                          ? 'No longer reported'
                          : event.kind === 'reappeared'
                            ? 'Reappeared'
                            : 'Updated'}
                    </span>
                    {event.detail ? <span className="finding-timeline-detail">{event.detail}</span> : null}
                    <span className="finding-timeline-time">{relativeTime(event.createdAt)}</span>
                  </div>
                ))}
              </div>
            )}
          </section>

          <section className="finding-section">
            <div className="finding-section-head">
              <h3>Image scan history</h3>
              {image ? (
                <button
                  type="button"
                  className="ops-link"
                  onClick={() => navigate(`/images?image=${encodeURIComponent(image.imageId)}`)}
                >
                  Open image details
                </button>
              ) : null}
            </div>
            {scanExcluded ? (
              <p className="finding-callout is-neutral">
                This image is excluded from scans. Existing findings remain visible, but new scans will be refused.
              </p>
            ) : null}
            {data.scans.length === 0 ? (
              <p className="finding-empty">This image has not been scanned.</p>
            ) : (
              <div className="finding-scans">
                {data.scans.map((scan) => (
                  <div className="finding-scan-row" key={scan.id}>
                    <span>
                      <ScanStatusBadge status={scan.status} /> {scan.profile}
                    </span>
                    <span className="finding-scan-meta">
                      {scan.total} finding{scan.total === 1 ? '' : 's'} · {relativeTime(scan.finishedAt ?? scan.queuedAt)}
                    </span>
                  </div>
                ))}
              </div>
            )}
            {image ? (
              <dl className="finding-meta finding-image-meta">
                <dt>Image</dt>
                <dd className="mono">{image.references[0]?.reference ?? image.imageId}</dd>
                <dt>Operating system</dt>
                <dd>{[image.osFamily, image.osVersion].filter(Boolean).join(' ') || 'Not reported'}</dd>
                <dt>Last successful scan</dt>
                <dd>{relativeTime(image.lastSuccessAt)}</dd>
                <dt>Scanning</dt>
                <dd>{image.scanExcluded ? 'Excluded' : 'Enabled'}</dd>
              </dl>
            ) : null}
          </section>

          <section className="finding-section">
            <h3>References</h3>
            {finding.primaryUrl ? (
              <a
                className="btn small ghost finding-advisory"
                href={finding.primaryUrl}
                target="_blank"
                rel="noopener noreferrer"
              >
                <IconExternal width={13} height={13} /> Authoritative advisory
              </a>
            ) : (
              <p className="finding-empty">No external advisory URL was reported by the scanner.</p>
            )}
            <p className="finding-hint">
              Severity and identifiers are scanner-provided. DockSentinel does not infer a fix, a CVSS change or a
              remediation step from the advisory.
            </p>
          </section>
        </div>
      ) : null}
    </Drawer>
  );
}
