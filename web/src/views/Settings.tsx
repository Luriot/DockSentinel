import { useEffect, useState } from 'react';
import { api, type KevStatus, type PublicSettings, type ScannerInfo, type Severity } from '../api.ts';
import { useApi } from '../hooks.ts';
import { applyTheme, getInitialTheme, type Theme } from '../theme.ts';
import {
  ErrorPanel,
  Field,
  IconAlert,
  IconCheck,
  IconRefresh,
  InlineLoading,
  useToast,
} from '../components/ui.tsx';
import { formatDate, formatBytes, formatDuration, relativeTime } from '../format.ts';

interface SettingsResponse {
  settings: PublicSettings;
  kev: KevStatus;
  scanner: ScannerInfo;
}

interface SystemResponse {
  version: string;
  nodeVersion: string;
  uptimeSeconds: number;
  schemaVersion: number;
  scanner: ScannerInfo;
  kev: KevStatus;
  scans: { active: number };
  activity: { queued: number; running: number; success: number; failed: number };
  limits: { scanConcurrency: number; scanTimeoutMs: number; maxOutputBytes: number; maxImageExportBytes: number };
}

const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];

export function Settings() {
  const toast = useToast();
  const { data, error, loading, refresh } = useApi<SettingsResponse>('/settings');
  const system = useApi<SystemResponse>('/system');
  const [form, setForm] = useState<PublicSettings | null>(null);
  const [ignoredText, setIgnoredText] = useState('');
  const [theme, setTheme] = useState<Theme>(() => getInitialTheme());
  const [savingSection, setSavingSection] = useState<string | null>(null);
  const [syncing, setSyncing] = useState(false);

  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  useEffect(() => {
    if (data && !form) {
      setForm(data.settings);
      setIgnoredText(data.settings.ignoredPackages.join(', '));
    }
  }, [data, form]);

  async function save(section: string, patch: Record<string, unknown>): Promise<void> {
    setSavingSection(section);
    try {
      await api.patch('/settings', patch);
      toast('Settings saved', 'success');
      await refresh();
      await system.refresh();
    } catch (saveError) {
      toast(saveError instanceof Error ? saveError.message : 'Unable to save settings', 'error');
    } finally {
      setSavingSection(null);
    }
  }

  async function syncKev(): Promise<void> {
    setSyncing(true);
    try {
      const result = await api.post<{ ok: boolean; entryCount: number; error: string | null }>('/kev/sync');
      if (result.ok) toast(`CISA KEV synced: ${result.entryCount} entries`, 'success');
      else toast(`KEV sync failed: ${result.error ?? 'unknown error'}`, 'error');
      await refresh();
    } catch (syncError) {
      toast(syncError instanceof Error ? syncError.message : 'KEV sync failed', 'error');
    } finally {
      setSyncing(false);
    }
  }

  if (loading && !data) return <InlineLoading label="Loading settings…" />;
  if (error && !data) return <ErrorPanel error={error} onRetry={refresh} />;
  if (!data || !form) return null;

  const kev = data.kev;
  const scanner = data.scanner;

  return (
    <div className="page-stack">
      <nav className="settings-nav" aria-label="Settings sections">
        <a href="#settings-appearance">Appearance</a>
        <a href="#settings-scanning">Scanning</a>
        <a href="#settings-alerting">Alerting</a>
        <a href="#settings-retention">Retention</a>
        <a href="#settings-kev">Known exploited</a>
        <a href="#settings-system">System and security</a>
      </nav>
      <section className="card settings-section" id="settings-appearance">
        <div className="card-header">
          <div className="vstack">
            <h2 className="section-title">Appearance</h2>
            <span className="section-subtitle">
              Theme for this browser. Changes apply immediately and survive a reload.
            </span>
          </div>
        </div>
        <div className="card-body">
          <div className="hstack" role="group" aria-label="Theme">
            <button
              type="button"
              className={`btn small ${theme === 'dark' ? 'primary' : 'ghost'}`}
              aria-pressed={theme === 'dark'}
              onClick={() => setTheme('dark')}
            >
              Dark theme
            </button>
            <button
              type="button"
              className={`btn small ${theme === 'light' ? 'primary' : 'ghost'}`}
              aria-pressed={theme === 'light'}
              onClick={() => setTheme('light')}
            >
              Light theme
            </button>
          </div>
          <p className="tiny dim" style={{ marginTop: 10 }}>
            Dark is the default. The choice is stored in this browser only, not on the server.
          </p>
        </div>
      </section>

      <section className="card settings-section" id="settings-scanning">
        <div className="card-header">
          <div className="vstack">
            <h2 className="section-title">Scanning</h2>
            <span className="section-subtitle">
              Global defaults. Per-environment intervals override the schedule for images on that endpoint.
            </span>
          </div>
          <button
            type="button"
            className="btn small"
            disabled={savingSection !== null}
            onClick={() =>
              void save('scanning', {
                scanConcurrency: form.scanConcurrency,
                discoveryIntervalMinutes: form.discoveryIntervalMinutes,
                defaultQuickIntervalHours: form.defaultQuickIntervalHours,
                defaultStandardIntervalHours: form.defaultStandardIntervalHours,
                scanOnDiscovery: form.scanOnDiscovery,
                scanFailureRetries: form.scanFailureRetries,
                misconfigScanEnabled: form.misconfigScanEnabled,
                secretScanEnabled: form.secretScanEnabled,
                ignoredPackages: ignoredText
                  .split(/[,\n]/)
                  .map((name) => name.trim())
                  .filter(Boolean),
              })
            }
          >
            {savingSection === 'scanning' ? <span className="spinner" aria-hidden="true" /> : null}
            Save
          </button>
        </div>
        <div className="card-body">
          <div className="form-grid">
            <Field
              label="Concurrent scans"
              htmlFor="scanConcurrency"
              hint={`Current runtime ceiling: ${system.data?.limits.scanConcurrency ?? form.scanConcurrency}. Scans run in parallel, including several against the same host.`}
            >
              <input
                id="scanConcurrency"
                className="input"
                type="number"
                min={1}
                max={8}
                value={form.scanConcurrency}
                onChange={(event) => setForm({ ...form, scanConcurrency: Number(event.target.value) })}
              />
            </Field>
            <Field
              label="Discovery interval (minutes)"
              htmlFor="discoveryIntervalMinutes"
              hint="How often container and image inventory is refreshed."
            >
              <input
                id="discoveryIntervalMinutes"
                className="input"
                type="number"
                min={1}
                max={1440}
                value={form.discoveryIntervalMinutes}
                onChange={(event) => setForm({ ...form, discoveryIntervalMinutes: Number(event.target.value) })}
              />
            </Field>
            <Field
              label="Default quick interval (hours)"
              htmlFor="defaultQuick"
              hint="Applied to new environments. OS packages only."
            >
              <input
                id="defaultQuick"
                className="input"
                type="number"
                min={0}
                max={2160}
                value={form.defaultQuickIntervalHours}
                onChange={(event) => setForm({ ...form, defaultQuickIntervalHours: Number(event.target.value) })}
              />
            </Field>
            <Field
              label="Default standard interval (hours)"
              htmlFor="defaultStandard"
              hint="OS and language packages. 168 hours = weekly."
            >
              <input
                id="defaultStandard"
                className="input"
                type="number"
                min={0}
                max={8760}
                value={form.defaultStandardIntervalHours}
                onChange={(event) => setForm({ ...form, defaultStandardIntervalHours: Number(event.target.value) })}
              />
            </Field>
            <Field
              label="Retry budget for transient scan failures"
              htmlFor="scanFailureRetries"
              hint="Each failure is requeued with exponential backoff. 0 disables retries."
            >
              <input
                id="scanFailureRetries"
                className="input"
                type="number"
                min={0}
                max={5}
                value={form.scanFailureRetries}
                onChange={(event) => setForm({ ...form, scanFailureRetries: Number(event.target.value) })}
              />
            </Field>
            <Field
              label="Ignored packages"
              htmlFor="ignoredPackages"
              hint="Exact package names, separated by commas. Their findings are deleted now and skipped by future scans (case-insensitive). Use for packages you do not intend to patch."
            >
              <input
                id="ignoredPackages"
                className="input"
                value={ignoredText}
                placeholder="chromium, chromium-common, chromium-driver"
                onChange={(event) => setIgnoredText(event.target.value)}
              />
            </Field>
            <div className="vstack" style={{ gap: 10, justifyContent: 'end', paddingBottom: 4 }}>
              <label className="checkbox">
                <input
                  type="checkbox"
                  checked={form.scanOnDiscovery}
                  onChange={(event) => setForm({ ...form, scanOnDiscovery: event.target.checked })}
                />
                <span>
                  Scan newly discovered images automatically
                  <span className="hint" style={{ display: 'block' }}>
                    A standard scan is queued for images that have never completed a successful scan.
                  </span>
                </span>
              </label>
              <label className="checkbox">
                <input
                  type="checkbox"
                  checked={form.misconfigScanEnabled}
                  onChange={(event) => setForm({ ...form, misconfigScanEnabled: event.target.checked })}
                />
                <span>
                  Enable misconfiguration scans (opt-in)
                  <span className="hint" style={{ display: 'block' }}>
                    Scans Dockerfile-converted image config and IaC files inside the image. It is not a host or daemon audit.
                  </span>
                </span>
              </label>
              <label className="checkbox">
                <input
                  type="checkbox"
                  checked={form.secretScanEnabled}
                  onChange={(event) => setForm({ ...form, secretScanEnabled: event.target.checked })}
                />
                <span>
                  Enable secret scans (opt-in)
                  <span className="hint" style={{ display: 'block' }}>
                    Stores only rule, location, category and severity; never the matched value. False positives are possible.
                  </span>
                </span>
              </label>
            </div>
          </div>
        </div>
      </section>

      <section className="card settings-section" id="settings-alerting">
        <div className="card-header">
          <div className="vstack">
            <h2 className="section-title">Alerting</h2>
            <span className="section-subtitle">Severity thresholds and the changes that are worth notifying.</span>
          </div>
          <button
            type="button"
            className="btn small"
            disabled={savingSection !== null}
            onClick={() =>
              void save('alerting', {
                minAlertSeverity: form.minAlertSeverity,
                freshnessHours: form.freshnessHours,
                alertOnNew: form.alertOnNew,
                alertOnResolved: form.alertOnResolved,
                alertOnKev: form.alertOnKev,
                alertOnScanFailure: form.alertOnScanFailure,
                alertOnStale: form.alertOnStale,
              })
            }
          >
            {savingSection === 'alerting' ? <span className="spinner" aria-hidden="true" /> : null}
            Save
          </button>
        </div>
        <div className="card-body">
          <div className="form-grid">
            <Field
              label="Minimum alert severity"
              htmlFor="minAlertSeverity"
              hint="Per-environment and per-container labels can be stricter or override this."
            >
              <select
                id="minAlertSeverity"
                className="select"
                value={form.minAlertSeverity}
                onChange={(event) => setForm({ ...form, minAlertSeverity: event.target.value as Severity })}
              >
                {SEVERITIES.map((severity) => (
                  <option key={severity} value={severity}>
                    {severity}
                  </option>
                ))}
              </select>
            </Field>
            <Field
              label="Freshness window (hours)"
              htmlFor="freshnessHours"
              hint="Results older than this are marked stale in the UI; with stale alerts enabled they notify once per day."
            >
              <input
                id="freshnessHours"
                className="input"
                type="number"
                min={1}
                max={720}
                value={form.freshnessHours}
                onChange={(event) => setForm({ ...form, freshnessHours: Number(event.target.value) })}
              />
            </Field>
            <div className="span-2 vstack" style={{ gap: 10 }}>
              {(
                [
                  ['alertOnNew', 'Notify on new findings at or above the threshold'],
                  ['alertOnResolved', 'Notify when a successful scan confirms findings are resolved'],
                  ['alertOnKev', 'Notify when a finding becomes listed in CISA KEV'],
                  ['alertOnScanFailure', 'Notify when a scan fails after all retries'],
                  ['alertOnStale', 'Notify about stale results (at most once per image per day)'],
                ] as const
              ).map(([key, label]) => (
                <label className="checkbox" key={key}>
                  <input
                    type="checkbox"
                    checked={form[key]}
                    onChange={(event) => setForm({ ...form, [key]: event.target.checked })}
                  />
                  <span>{label}</span>
                </label>
              ))}
            </div>
          </div>
          <div className="note" style={{ marginTop: 12 }}>
            Notifications are deduplicated per finding lifecycle and grouped per image and scan. The public base URL for
            notification links is configured on the Alerts page.
          </div>
        </div>
      </section>

      <section className="card settings-section" id="settings-retention">
        <div className="card-header">
          <div className="vstack">
            <h2 className="section-title">Retention</h2>
            <span className="section-subtitle">
              The most recent scan per image is always kept so the current state can be explained.
            </span>
          </div>
          <button
            type="button"
            className="btn small"
            disabled={savingSection !== null}
            onClick={() =>
              void save('retention', {
                retentionScansDays: form.retentionScansDays,
                retentionAlertsDays: form.retentionAlertsDays,
                retentionResolvedFindingsDays: form.retentionResolvedFindingsDays,
                retentionEventsDays: form.retentionEventsDays,
              })
            }
          >
            {savingSection === 'retention' ? <span className="spinner" aria-hidden="true" /> : null}
            Save
          </button>
        </div>
        <div className="card-body">
          <div className="form-grid">
            <Field label="Scan history (days)" htmlFor="retentionScansDays">
              <input
                id="retentionScansDays"
                className="input"
                type="number"
                min={7}
                max={3650}
                value={form.retentionScansDays}
                onChange={(event) => setForm({ ...form, retentionScansDays: Number(event.target.value) })}
              />
            </Field>
            <Field label="Alert history (days)" htmlFor="retentionAlertsDays">
              <input
                id="retentionAlertsDays"
                className="input"
                type="number"
                min={7}
                max={3650}
                value={form.retentionAlertsDays}
                onChange={(event) => setForm({ ...form, retentionAlertsDays: Number(event.target.value) })}
              />
            </Field>
            <Field
              label="Resolved findings (days)"
              htmlFor="retentionResolvedFindingsDays"
              hint="Only findings whose image is no longer used by a container are pruned."
            >
              <input
                id="retentionResolvedFindingsDays"
                className="input"
                type="number"
                min={30}
                max={3650}
                value={form.retentionResolvedFindingsDays}
                onChange={(event) => setForm({ ...form, retentionResolvedFindingsDays: Number(event.target.value) })}
              />
            </Field>
            <Field label="Finding events (days)" htmlFor="retentionEventsDays">
              <input
                id="retentionEventsDays"
                className="input"
                type="number"
                min={30}
                max={3650}
                value={form.retentionEventsDays}
                onChange={(event) => setForm({ ...form, retentionEventsDays: Number(event.target.value) })}
              />
            </Field>
          </div>
        </div>
      </section>

      <section className="card settings-section" id="settings-kev">
        <div className="card-header">
          <div className="vstack">
            <h2 className="section-title">Known exploited intelligence</h2>
            <span className="section-subtitle">
              CISA&apos;s Known Exploited Vulnerabilities catalog enriches findings with exploitation evidence.
            </span>
          </div>
          <div className="hstack">
            <span className={`badge ${kev.available ? (kev.stale ? 'warn' : 'ok') : 'neutral'}`}>
              {kev.available ? (kev.stale ? 'Stale data' : 'Available') : 'Unavailable'}
            </span>
            <button type="button" className="btn small" onClick={() => void syncKev()} disabled={syncing}>
              {syncing ? <span className="spinner" aria-hidden="true" /> : <IconRefresh width={14} height={14} />}
              Sync now
            </button>
          </div>
        </div>
        <div className="card-body">
          <div className="form-grid">
            <div className="vstack" style={{ gap: 10 }}>
              <label className="checkbox">
                <input
                  type="checkbox"
                  checked={form.kevEnabled}
                  onChange={(event) => setForm({ ...form, kevEnabled: event.target.checked })}
                />
                <span>Synchronise the CISA KEV catalog daily (requires outbound HTTPS)</span>
              </label>
              <button
                type="button"
                className="btn small"
                style={{ alignSelf: 'flex-start' }}
                disabled={savingSection !== null}
                onClick={() => void save('kev', { kevEnabled: form.kevEnabled })}
              >
                Save KEV setting
              </button>
            </div>
            <dl className="detail-list">
              <dt>Entries</dt>
              <dd>{kev.entryCount}</dd>
              <dt>Catalog version</dt>
              <dd>{kev.catalogVersion ?? '—'}</dd>
              <dt>Last successful sync</dt>
              <dd>{kev.syncedAt ? `${formatDate(kev.syncedAt)} (${relativeTime(kev.syncedAt)})` : 'Never'}</dd>
              <dt>Last error</dt>
              <dd style={{ color: kev.error ? 'var(--critical)' : undefined }}>{kev.error ?? 'None'}</dd>
            </dl>
          </div>
          <div className="note info" style={{ marginTop: 12 }}>
            KEV membership is a prioritisation signal, not proof that a specific deployment is exploitable. If the feed
            is unavailable, existing KEV data is kept and findings report <span className="mono">KEV unknown</span> until
            a sync succeeds.
          </div>
        </div>
      </section>

      <section className="card settings-section" id="settings-system">
        <div className="card-header">
          <div className="vstack">
            <h2 className="section-title">System and security</h2>
            <span className="section-subtitle">Runtime facts and the limits that protect this host.</span>
          </div>
        </div>
        <div className="card-body">
          <div className="grid-2" style={{ gap: 20 }}>
            <div>
              <h3 className="section-title" style={{ marginBottom: 8 }}>
                Scanner
              </h3>
              <dl className="detail-list">
                <dt>Trivy</dt>
                <dd>
                  {scanner.available ? (
                    <span className="badge ok">
                      <IconCheck width={12} height={12} /> {scanner.version ?? 'available'}
                    </span>
                  ) : (
                    <span className="badge danger">
                      <IconAlert width={12} height={12} /> Unavailable
                    </span>
                  )}
                </dd>
                <dt>Vulnerability DB</dt>
                <dd>
                  {scanner.dbUpdatedAt
                    ? `${formatDate(scanner.dbUpdatedAt)} (${relativeTime(scanner.dbUpdatedAt)})`
                    : 'No database in the scanner cache yet — the first scan downloads one'}
                </dd>
                <dt>DB schema</dt>
                <dd>{scanner.dbSchema ?? 'unknown'}</dd>
                <dt>Scanner error</dt>
                <dd style={{ color: scanner.error ? 'var(--critical)' : undefined }}>{scanner.error ?? 'None'}</dd>
              </dl>
            </div>
            <div>
              <h3 className="section-title" style={{ marginBottom: 8 }}>
                Instance
              </h3>
              <dl className="detail-list">
                <dt>Version</dt>
                <dd>{system.data?.version ?? '—'}</dd>
                <dt>Node.js</dt>
                <dd>{system.data?.nodeVersion ?? '—'}</dd>
                <dt>Database schema</dt>
                <dd>{system.data?.schemaVersion ?? '—'}</dd>
                <dt>Uptime</dt>
                <dd>{system.data ? formatDuration(system.data.uptimeSeconds * 1000) : '—'}</dd>
                <dt>Scan timeout</dt>
                <dd>{system.data ? formatDuration(system.data.limits.scanTimeoutMs) : '—'}</dd>
                <dt>Report limit</dt>
                <dd>{system.data ? formatBytes(system.data.limits.maxOutputBytes) : '—'}</dd>
                <dt>Image export limit</dt>
                <dd>{system.data ? formatBytes(system.data.limits.maxImageExportBytes) : '—'}</dd>
              </dl>
            </div>
          </div>

          <div className="note warn" style={{ marginTop: 14 }}>
            <strong>Docker socket access is effectively host-root.</strong> Mount the socket read-write only if you
            accept that privilege; DockSentinel itself performs GET requests only, but anyone who can reach this UI or
            modify its data volume can influence what Docker endpoints are contacted. Keep DockSentinel on a trusted
            network, use TLS for remote endpoints, and never publish the Docker API without authentication.
          </div>
          <div className="note" style={{ marginTop: 10 }}>
            Secrets (TLS keys, ntfy tokens, notification passwords) are encrypted at rest with a key in the data
            directory. Back up <span className="mono">docksentinel.db</span> and{' '}
            <span className="mono">secret.key</span> together. Losing the key only invalidates stored secrets, not
            findings or history.
          </div>
          <div className="note" style={{ marginTop: 10 }}>
            This release performs image vulnerability scanning. It does not provide runtime intrusion detection, web
            application firewall behaviour, or guaranteed Internet exposure detection. Published Docker ports are
            evidence, not proof of reachability.
          </div>
        </div>
      </section>
    </div>
  );
}
