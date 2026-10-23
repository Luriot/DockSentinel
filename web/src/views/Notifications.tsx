import { useEffect, useState } from 'react';
import { api, type AlertRecord, type PublicSettings, type Severity } from '../api.ts';
import { useApi, navigate } from '../hooks.ts';
import {
  Drawer,
  EmptyState,
  ErrorPanel,
  Field,
  IconAlert,
  IconBell,
  IconCheck,
  IconRefresh,
  InlineLoading,
  Pagination,
  TableSkeleton,
  useToast,
  AlertStatusBadge,
} from '../components/ui.tsx';
import { formatDate, relativeTime, titleCase } from '../format.ts';

interface NotificationsResponse {
  ntfy: PublicSettings['ntfy'];
  publicUrl: string;
  alerts: { items: AlertRecord[]; total: number; page: number; pageSize: number };
  counts: { pending: number; sent: number; failed: number; total: number };
}

export function Notifications() {
  const toast = useToast();
  const [status, setStatus] = useState('');
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<AlertRecord | null>(null);
  const [form, setForm] = useState<{
    enabled: boolean;
    baseUrl: string;
    topic: string;
    authType: 'none' | 'basic' | 'token';
    username: string;
    priority: PublicSettings['ntfy']['priority'];
    tags: string;
    publicUrl: string;
    token: string;
    password: string;
    clearToken: boolean;
    clearPassword: boolean;
  } | null>(null);
  const [hasToken, setHasToken] = useState(false);
  const [hasPassword, setHasPassword] = useState(false);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; message: string } | null>(null);
  const [formError, setFormError] = useState<string | null>(null);

  const query = new URLSearchParams();
  if (status) query.set('status', status);
  query.set('page', String(page));
  query.set('pageSize', '25');

  const { data, error, loading, refresh } = useApi<NotificationsResponse>(`/notifications?${query.toString()}`, {
    intervalMs: 30_000,
  });
  const settings = useApi<{ settings: PublicSettings }>('/settings');

  useEffect(() => {
    if (!data || form) return;
    setHasToken(data.ntfy.hasToken);
    setHasPassword(data.ntfy.hasPassword);
    setForm({
      enabled: data.ntfy.enabled,
      baseUrl: data.ntfy.baseUrl,
      topic: data.ntfy.topic,
      authType: data.ntfy.authType,
      username: data.ntfy.username,
      priority: data.ntfy.priority,
      tags: data.ntfy.tags,
      publicUrl: data.publicUrl,
      token: '',
      password: '',
      clearToken: false,
      clearPassword: false,
    });
  }, [data, form]);

  useEffect(() => {
    setPage(1);
  }, [status]);

  if (loading && !data) {
    return (
      <div className="vstack" style={{ gap: 14 }}>
        <div className="card">
          <TableSkeleton rows={5} columns={4} />
        </div>
      </div>
    );
  }

  if (error && !data) return <ErrorPanel error={error} onRetry={refresh} />;

  async function save(): Promise<void> {
    if (!form) return;
    setSaving(true);
    setFormError(null);
    try {
      const ntfy: Record<string, unknown> = {
        enabled: form.enabled,
        baseUrl: form.baseUrl.trim(),
        topic: form.topic.trim(),
        authType: form.authType,
        username: form.username.trim(),
        priority: form.priority,
        tags: form.tags,
      };
      if (form.token) ntfy.token = form.token;
      if (form.password) ntfy.password = form.password;
      if (form.clearToken) ntfy.token = null;
      if (form.clearPassword) ntfy.password = null;
      await api.patch('/settings', { ntfy, publicUrl: form.publicUrl.trim() });
      toast('Notification settings saved', 'success');
      setForm((current) =>
        current ? { ...current, token: '', password: '', clearToken: false, clearPassword: false } : current,
      );
      await refresh();
      await settings.refresh();
    } catch (saveError) {
      setFormError(saveError instanceof Error ? saveError.message : 'Unable to save notification settings');
    } finally {
      setSaving(false);
    }
  }

  async function test(): Promise<void> {
    setTesting(true);
    setTestResult(null);
    try {
      const result = await api.post<{ ok: boolean; message: string }>('/notifications/test');
      setTestResult(result);
      await refresh();
    } catch (testError) {
      setTestResult({ ok: false, message: testError instanceof Error ? testError.message : 'Test delivery failed' });
    } finally {
      setTesting(false);
    }
  }

  const policy = settings.data?.settings;
  const severity: Severity = policy?.minAlertSeverity ?? 'HIGH';
  const dirty =
    Boolean(form && data) &&
    Boolean(
      form &&
        data &&
        (form.enabled !== data.ntfy.enabled ||
          form.baseUrl !== data.ntfy.baseUrl ||
          form.topic !== data.ntfy.topic ||
          form.authType !== data.ntfy.authType ||
          form.username !== data.ntfy.username ||
          form.priority !== data.ntfy.priority ||
          form.tags !== data.ntfy.tags ||
          form.publicUrl !== data.publicUrl ||
          form.token.length > 0 ||
          form.password.length > 0 ||
          form.clearToken ||
          form.clearPassword),
    );

  return (
    <div className="vstack" style={{ gap: 16 }}>
      <div className="grid-2">
        <section className="card" aria-labelledby="ntfy-config-title">
          <div className="card-header">
            <div className="vstack">
              <h2 className="section-title" id="ntfy-config-title">
                ntfy delivery
              </h2>
              <span className="section-subtitle">
                Self-hosted or ntfy.sh. Credentials are encrypted at rest and never returned by the API.
              </span>
            </div>
            <div className="hstack">
              {dirty ? <span className="badge warn">Unsaved changes</span> : null}
              <span className={`badge ${data?.ntfy.enabled ? 'ok' : 'neutral'}`}>
                {data?.ntfy.enabled ? 'Enabled' : 'Disabled'}
              </span>
            </div>
          </div>
          {form ? (
            <form
              className="card-body vstack"
              style={{ gap: 14 }}
              onSubmit={(event) => {
                event.preventDefault();
                void save();
              }}
            >
              <label className="checkbox">
                <input
                  type="checkbox"
                  checked={form.enabled}
                  onChange={(event) => setForm({ ...form, enabled: event.target.checked })}
                />
                <span>Send notifications through ntfy</span>
              </label>
              <div className="form-grid">
                <Field label="Base URL" htmlFor="ntfy-base" hint="Example: https://ntfy.example.com">
                  <input
                    id="ntfy-base"
                    className="input"
                    value={form.baseUrl}
                    onChange={(event) => setForm({ ...form, baseUrl: event.target.value })}
                    placeholder="https://ntfy.sh"
                  />
                </Field>
                <Field label="Topic" htmlFor="ntfy-topic" hint="The topic is effectively the shared secret.">
                  <input
                    id="ntfy-topic"
                    className="input mono"
                    value={form.topic}
                    onChange={(event) => setForm({ ...form, topic: event.target.value })}
                    placeholder="docksentinel-alerts"
                  />
                </Field>
                <Field label="Authentication" htmlFor="ntfy-auth">
                  <select
                    id="ntfy-auth"
                    className="select"
                    value={form.authType}
                    onChange={(event) =>
                      setForm({ ...form, authType: event.target.value as 'none' | 'basic' | 'token' })
                    }
                  >
                    <option value="none">None</option>
                    <option value="token">Access token (Bearer)</option>
                    <option value="basic">Username and password</option>
                  </select>
                </Field>
                <Field label="Minimum priority" htmlFor="ntfy-priority" hint="Leave on default to use computed priority.">
                  <select
                    id="ntfy-priority"
                    className="select"
                    value={form.priority}
                    onChange={(event) =>
                      setForm({ ...form, priority: event.target.value as PublicSettings['ntfy']['priority'] })
                    }
                  >
                    <option value="default">Computed</option>
                    <option value="low">Low</option>
                    <option value="high">High</option>
                    <option value="urgent">Urgent</option>
                    <option value="max">Maximum</option>
                  </select>
                </Field>

                {form.authType === 'basic' ? (
                  <>
                    <Field label="Username" htmlFor="ntfy-username">
                      <input
                        id="ntfy-username"
                        className="input"
                        value={form.username}
                        onChange={(event) => setForm({ ...form, username: event.target.value })}
                        autoComplete="off"
                      />
                    </Field>
                    <Field label="Password" htmlFor="ntfy-password" hint={hasPassword && !form.password ? 'Stored password is kept unless you replace or clear it.' : undefined}>
                      <input
                        id="ntfy-password"
                        className="input"
                        type="password"
                        value={form.password}
                        onChange={(event) => setForm({ ...form, password: event.target.value, clearPassword: false })}
                        placeholder={hasPassword ? '•••••••• (stored)' : ''}
                        autoComplete="new-password"
                      />
                      {hasPassword ? (
                        <button
                          type="button"
                          className="link-button tiny"
                          onClick={() => setForm({ ...form, password: '', clearPassword: true })}
                        >
                          {form.clearPassword ? 'Password will be cleared on save' : 'Clear stored password'}
                        </button>
                      ) : null}
                    </Field>
                  </>
                ) : null}

                {form.authType === 'token' ? (
                  <Field
                    className="span-2"
                    label="Access token"
                    htmlFor="ntfy-token"
                    hint={hasToken && !form.token ? 'A token is stored. Leave blank to keep it.' : 'Sent as an Authorization: Bearer header.'}
                  >
                    <input
                      id="ntfy-token"
                      className="input"
                      type="password"
                      value={form.token}
                      onChange={(event) => setForm({ ...form, token: event.target.value, clearToken: false })}
                      placeholder={hasToken ? '•••••••• (stored)' : ''}
                      autoComplete="new-password"
                    />
                    {hasToken ? (
                      <button
                        type="button"
                        className="link-button tiny"
                        onClick={() => setForm({ ...form, token: '', clearToken: true })}
                      >
                        {form.clearToken ? 'Token will be cleared on save' : 'Clear stored token'}
                      </button>
                    ) : null}
                  </Field>
                ) : null}

                <Field label="Tags" htmlFor="ntfy-tags" hint="Comma-separated ntfy tags, e.g. shield, docker.">
                  <input
                    id="ntfy-tags"
                    className="input"
                    value={form.tags}
                    onChange={(event) => setForm({ ...form, tags: event.target.value })}
                  />
                </Field>
                <Field
                  className="span-2"
                  label="Public base URL for links"
                  htmlFor="ntfy-public-url"
                  hint="Used in notifications so links open this DockSentinel instance, e.g. http://192.168.1.10:8080"
                >
                  <input
                    id="ntfy-public-url"
                    className="input"
                    value={form.publicUrl}
                    onChange={(event) => setForm({ ...form, publicUrl: event.target.value })}
                    placeholder="http://docksentinel.local:8080"
                  />
                </Field>
              </div>

              {formError ? (
                <div className="form-error" role="alert">
                  <IconAlert width={16} height={16} /> {formError}
                </div>
              ) : null}
              {testResult ? (
                <div className={`${testResult.ok ? 'form-success' : 'form-error'}`} role="status">
                  {testResult.ok ? <IconCheck width={16} height={16} /> : <IconAlert width={16} height={16} />}
                  {testResult.message}
                </div>
              ) : null}

              <div className="hstack" style={{ flexWrap: 'wrap' }}>
                <button type="submit" className="btn primary" disabled={saving}>
                  {saving ? <span className="spinner" aria-hidden="true" /> : null}
                  Save notification settings
                </button>
                <button type="button" className="btn ghost" onClick={() => void test()} disabled={testing || !form.enabled}>
                  {testing ? <span className="spinner" aria-hidden="true" /> : <IconBell width={14} height={14} />}
                  Send test
                </button>
              </div>
              <p className="tiny dim">
                Test delivery uses the saved configuration. Save changes first. Notification failures never affect
                scanning or finding history.
              </p>
            </form>
          ) : (
            <InlineLoading />
          )}
        </section>

        <div className="vstack" style={{ gap: 16 }}>
          <section className="card">
            <div className="card-header">
              <h2 className="section-title">Alert policy</h2>
              <button type="button" className="btn small ghost" onClick={() => navigate('/settings')}>
                Edit in settings
              </button>
            </div>
            <div className="card-body">
              {policy ? (
                <div className="vstack" style={{ gap: 8, fontSize: 12.5 }}>
                  <div className="spread">
                    <span className="muted">Minimum severity</span>
                    <span className={`badge sev-${severity}`}>{severity}</span>
                  </div>
                  {[
                    ['New findings', policy.alertOnNew],
                    ['Resolved findings', policy.alertOnResolved],
                    ['Known exploited', policy.alertOnKev],
                    ['Fix availability', true],
                    ['Scan failures', policy.alertOnScanFailure],
                    ['Stale results', policy.alertOnStale],
                  ].map(([label, enabled]) => (
                    <div className="spread" key={String(label)}>
                      <span className="muted">{label}</span>
                      <span className={`badge ${enabled ? 'ok' : 'neutral'}`}>{enabled ? 'On' : 'Off'}</span>
                    </div>
                  ))}
                  <p className="tiny dim" style={{ marginTop: 4 }}>
                    Alerts are grouped per image and scan, deduplicated by finding lifecycle, and retried with backoff.
                    Retries stop after five attempts and the failure is shown here.
                  </p>
                </div>
              ) : (
                <InlineLoading />
              )}
            </div>
          </section>

          <section className="card">
            <div className="card-header">
              <h2 className="section-title">Delivery summary</h2>
            </div>
            <div className="card-body" style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 12 }}>
              <div className="env-stat">
                <strong>{data?.counts.sent ?? 0}</strong>
                <span>Sent (90d)</span>
              </div>
              <div className="env-stat">
                <strong>{data?.counts.pending ?? 0}</strong>
                <span>Queued</span>
              </div>
              <div className="env-stat">
                <strong style={{ color: (data?.counts.failed ?? 0) > 0 ? 'var(--critical)' : undefined }}>
                  {data?.counts.failed ?? 0}
                </strong>
                <span>Failed (90d)</span>
              </div>
              <div className="env-stat">
                <strong>{data?.counts.total ?? 0}</strong>
                <span>Total (90d)</span>
              </div>
            </div>
          </section>
        </div>
      </div>

      <section className="card">
        <div className="card-header">
          <div className="vstack">
            <h2 className="section-title">Alert history</h2>
            <span className="section-subtitle">Every notification attempt is recorded with its error, if any.</span>
          </div>
          <div className="hstack">
            <select
              className="select"
              value={status}
              onChange={(event) => setStatus(event.target.value)}
              aria-label="Filter alerts by status"
              style={{ width: 'auto' }}
            >
              <option value="">All statuses</option>
              <option value="pending">Queued</option>
              <option value="sent">Sent</option>
              <option value="failed">Failed</option>
            </select>
            <button type="button" className="btn small ghost" onClick={refresh} aria-label="Refresh">
              <IconRefresh width={14} height={14} />
            </button>
          </div>
        </div>

        {data && data.alerts.items.length === 0 ? (
          <EmptyState icon={<IconBell width={26} height={26} />} title="No alerts recorded">
            Alerts appear here once findings change and notifications are enabled. Delivery errors are stored and shown
            with the alert.
          </EmptyState>
        ) : null}

        {data && data.alerts.items.length > 0 ? (
          <>
            <div className="table-wrap">
              <table className="table">
                <caption className="sr-only">Notification history</caption>
                <thead>
                  <tr>
                    <th scope="col">Status</th>
                    <th scope="col">Kind</th>
                    <th scope="col">Title</th>
                    <th scope="col">Attempts</th>
                    <th scope="col">Created</th>
                    <th scope="col">Sent</th>
                  </tr>
                </thead>
                <tbody>
                  {data.alerts.items.map((alert) => (
                    <tr key={alert.id} className="clickable" onClick={() => setSelected(alert)}>
                      <td>
                        <AlertStatusBadge status={alert.status} />
                      </td>
                      <td>{titleCase(alert.kind)}</td>
                      <td>
                        <div className="cell-main truncate" style={{ maxWidth: 420 }} title={alert.title}>
                          {alert.title}
                        </div>
                        {alert.lastError ? (
                          <div className="cell-sub truncate" style={{ maxWidth: 420, color: 'var(--critical)' }}>
                            {alert.lastError}
                          </div>
                        ) : null}
                      </td>
                      <td>{alert.attempts}</td>
                      <td>{relativeTime(alert.createdAt)}</td>
                      <td>{alert.sentAt ? relativeTime(alert.sentAt) : alert.nextAttemptAt ? `retry ${relativeTime(alert.nextAttemptAt)}` : '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination
              page={data.alerts.page}
              pageSize={data.alerts.pageSize}
              total={data.alerts.total}
              onChange={setPage}
            />
          </>
        ) : null}
      </section>

      {selected ? (
        <Drawer title={selected.title} subtitle={`${titleCase(selected.kind)} · ${selected.status}`} onClose={() => setSelected(null)}>
          <section className="drawer-section">
            <div className="pill-row">
              <AlertStatusBadge status={selected.status} />
              <span className="badge neutral">intent priority {selected.priority}</span>
              {selected.tags ? <span className="badge neutral">{selected.tags}</span> : null}
            </div>
            <dl className="detail-list" style={{ marginTop: 10 }}>
              <dt>Created</dt>
              <dd>{formatDate(selected.createdAt)}</dd>
              <dt>Attempts</dt>
              <dd>{selected.attempts}</dd>
              <dt>Sent</dt>
              <dd>{formatDate(selected.sentAt)}</dd>
              <dt>Next attempt</dt>
              <dd>{selected.nextAttemptAt ? formatDate(selected.nextAttemptAt) : '—'}</dd>
              <dt>Dedupe key</dt>
              <dd className="mono" style={{ wordBreak: 'break-all' }}>
                {selected.dedupeKey}
              </dd>
              {selected.lastError ? (
                <>
                  <dt>Last error</dt>
                  <dd style={{ color: 'var(--critical)' }}>{selected.lastError}</dd>
                </>
              ) : null}
            </dl>
          </section>
          <section className="drawer-section">
            <h3>Message</h3>
            <div className="code-block">{selected.body}</div>
          </section>
        </Drawer>
      ) : null}
    </div>
  );
}
