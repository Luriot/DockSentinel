import { useEffect, useState, type FormEvent } from 'react';
import { api, type EnvironmentSummary, type LocalEnvironmentResult, type Severity } from '../api.ts';
import { useApi, useRoute } from '../hooks.ts';
import {
  ConfirmDialog,
  EmptyState,
  EnvStatusBadge,
  ErrorPanel,
  Field,
  IconAlert,
  IconEdit,
  IconPlus,
  IconRefresh,
  IconServer,
  IconTrash,
  Modal,
  TableSkeleton,
  useToast,
} from '../components/ui.tsx';
import { formatDate, relativeTime } from '../format.ts';

const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];

export function Environments() {
  const { data, error, loading, refresh } = useApi<{ items: EnvironmentSummary[] }>('/environments', {
    intervalMs: 30_000,
  });
  const toast = useToast();
  const route = useRoute();
  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<EnvironmentSummary | null>(null);
  const [deleting, setDeleting] = useState<EnvironmentSummary | null>(null);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [deleteBusy, setDeleteBusy] = useState(false);
  const [localBusy, setLocalBusy] = useState(false);

  useEffect(() => {
    if (route.params.get('new') === '1') {
      setEditing(null);
      setFormOpen(true);
    }
  }, [route.params]);

  async function connectLocal(): Promise<void> {
    setLocalBusy(true);
    try {
      const result = await api.post<LocalEnvironmentResult>('/environments/local', {});
      toast(
        result.created
          ? `Connected to ${result.environment.name}. Discovery found ${result.discovery?.containers ?? 0} containers and ${result.discovery?.images ?? 0} images.`
          : `${result.environment.name} is already connected.`,
        'success',
      );
      await refresh();
    } catch (connectError) {
      toast(connectError instanceof Error ? connectError.message : 'Could not find Docker on this computer', 'error');
    } finally {
      setLocalBusy(false);
    }
  }

  async function testEnvironment(environment: EnvironmentSummary): Promise<void> {
    setBusyId(environment.id);
    try {
      const result = await api.post<{ ok: boolean; message: string; containers: number; images: number }>(
        `/environments/${environment.id}/test`,
      );
      toast(
        result.ok
          ? `Connected. ${result.containers} containers, ${result.images} images visible.`
          : `Connection failed: ${result.message}`,
        result.ok ? 'success' : 'error',
      );
      await refresh();
    } catch (testError) {
      toast(testError instanceof Error ? testError.message : 'Connection test failed', 'error');
    } finally {
      setBusyId(null);
    }
  }

  async function discover(environment: EnvironmentSummary): Promise<void> {
    setBusyId(environment.id);
    try {
      const result = await api.post<{ containers: number; images: number; warnings: string[] }>(
        `/environments/${environment.id}/discover`,
      );
      toast(
        `Discovered ${result.containers} containers and ${result.images} images${
          result.warnings.length > 0 ? ` (${result.warnings[0]})` : ''
        }`,
        result.warnings.length > 0 ? 'info' : 'success',
      );
      await refresh();
    } catch (discoverError) {
      toast(discoverError instanceof Error ? discoverError.message : 'Discovery failed', 'error');
      await refresh();
    } finally {
      setBusyId(null);
    }
  }

  async function toggle(environment: EnvironmentSummary, field: 'enabled' | 'scanEnabled'): Promise<void> {
    try {
      await api.patch(`/environments/${environment.id}`, { [field]: !environment[field] });
      await refresh();
      toast(
        field === 'enabled'
          ? `${environment.name} ${environment.enabled ? 'disabled' : 'enabled'}`
          : `Scanning ${environment.scanEnabled ? 'disabled' : 'enabled'} for ${environment.name}`,
        'success',
      );
    } catch (toggleError) {
      toast(toggleError instanceof Error ? toggleError.message : 'Update failed', 'error');
    }
  }

  async function confirmDelete(): Promise<void> {
    if (!deleting) return;
    setDeleteBusy(true);
    try {
      await api.delete(`/environments/${deleting.id}`);
      toast(`${deleting.name} removed`, 'success');
      setDeleting(null);
      await refresh();
    } catch (deleteError) {
      toast(deleteError instanceof Error ? deleteError.message : 'Delete failed', 'error');
    } finally {
      setDeleteBusy(false);
    }
  }

  return (
    <div className="page-stack">
      <div className="note info">
        <strong>Docker access is privileged.</strong> DockSentinel only reads container and image metadata and never
        starts, stops or modifies containers. Prefer a local socket or a TLS-protected remote host.
      </div>

      <div className="spread">
        <div>
          <h2 className="section-title">Watched hosts</h2>
          <p className="section-subtitle">
            DockSentinel can watch several Docker hosts. One unavailable host never blocks the others.
          </p>
        </div>
        <div className="hstack">
          <button type="button" className="btn ghost" onClick={refresh} disabled={loading}>
            <IconRefresh width={14} height={14} /> Refresh
          </button>
          <button type="button" className="btn primary" onClick={() => void connectLocal()} disabled={localBusy}>
            {localBusy ? <span className="spinner" aria-hidden="true" /> : <IconServer width={15} height={15} />}
            Use Docker on this computer
          </button>
          <button
            type="button"
            className="btn ghost"
            onClick={() => {
              setEditing(null);
              setFormOpen(true);
            }}
          >
            <IconPlus width={15} height={15} /> Connect remote host
          </button>
        </div>
      </div>

      {error && !data ? <ErrorPanel error={error} onRetry={refresh} /> : null}

      {loading && !data ? (
        <div className="card">
          <TableSkeleton rows={3} columns={4} />
        </div>
      ) : null}

      {data && data.items.length === 0 ? (
        <div className="card">
          <EmptyState
            icon={<IconServer width={28} height={28} />}
            title="No Docker host connected yet"
            action={
              <div className="hstack">
                <button type="button" className="btn primary" onClick={() => void connectLocal()} disabled={localBusy}>
                  {localBusy ? <span className="spinner" aria-hidden="true" /> : <IconServer width={15} height={15} />}
                  Use Docker on this computer
                </button>
                <button
                  type="button"
                  className="btn ghost"
                  onClick={() => {
                    setEditing(null);
                    setFormOpen(true);
                  }}
                >
                  <IconPlus width={15} height={15} /> Connect remote host
                </button>
              </div>
            }
          >
            Start Docker Desktop (or the Docker service), then use the one-click option. You can also connect a remote
            host with TCP or mutual TLS.
          </EmptyState>
        </div>
      ) : null}

      {data && data.items.length > 0 ? (
        <div className="grid-auto">
          {data.items.map((environment) => {
            const busy = busyId === environment.id;
            return (
              <article className="card env-card" key={environment.id} aria-label={environment.name}>
                <div className="env-card-head">
                  <span className="vstack" style={{ gap: 3, flex: 1 }}>
                    <h3>{environment.name}</h3>
                    <span className="addr">
                      {environment.kind === 'unix' ? environment.address : `${environment.kind}://${environment.address}`}
                    </span>
                  </span>
                  <EnvStatusBadge status={environment.status} message={environment.statusMessage} />
                </div>

                {environment.statusMessage ? (
                  <div className={`note ${environment.status === 'offline' ? 'danger' : ''}`}>
                    {environment.statusMessage}
                  </div>
                ) : null}

                <div className="env-stats">
                  <div className="env-stat">
                    <strong>{environment.counts.containers}</strong>
                    <span>Containers</span>
                  </div>
                  <div className="env-stat">
                    <strong>{environment.counts.runningContainers}</strong>
                    <span>Running</span>
                  </div>
                  <div className="env-stat">
                    <strong>{environment.counts.images}</strong>
                    <span>Images</span>
                  </div>
                  <div className="env-stat">
                    <strong style={{ color: environment.counts.critical > 0 ? 'var(--critical)' : undefined }}>
                      {environment.counts.critical}
                    </strong>
                    <span>Critical</span>
                  </div>
                  <div className="env-stat">
                    <strong style={{ color: environment.counts.high > 0 ? 'var(--high)' : undefined }}>
                      {environment.counts.high}
                    </strong>
                    <span>High</span>
                  </div>
                </div>

                <div className="tiny dim">
                  Last contact {relativeTime(environment.lastContactAt)} · last discovery{' '}
                  {relativeTime(environment.lastDiscoveryAt)} · created {formatDate(environment.createdAt)}
                </div>
                <div className="tiny dim">
                  Policy: {environment.enabled ? 'enabled' : 'disabled'} · scanning{' '}
                  {environment.scanEnabled ? 'on' : 'off'} · quick every{' '}
                  {environment.quickIntervalHours === 0 ? '—' : `${environment.quickIntervalHours}h`} · standard every{' '}
                  {environment.standardIntervalHours === 0 ? '—' : `${environment.standardIntervalHours}h`} · minimum
                  alert severity {environment.minAlertSeverity}
                </div>
                {environment.tlsSkipVerify ? (
                  <div className="note warn">
                    <IconAlert width={14} height={14} style={{ verticalAlign: -2 }} /> TLS certificate verification is
                    disabled for this endpoint. Use it only on a trusted network.
                  </div>
                ) : null}

                <div className="env-card-actions">
                  <button
                    type="button"
                    className="btn small"
                    onClick={() => void discover(environment)}
                    disabled={busy || !environment.enabled}
                  >
                    {busy ? <span className="spinner" aria-hidden="true" /> : <IconRefresh width={13} height={13} />}
                    Discover
                  </button>
                  <button
                    type="button"
                    className="btn small ghost"
                    onClick={() => void testEnvironment(environment)}
                    disabled={busy}
                  >
                    Test connection
                  </button>
                  <button
                    type="button"
                    className="btn small ghost"
                    onClick={() => {
                      setEditing(environment);
                      setFormOpen(true);
                    }}
                  >
                    <IconEdit width={13} height={13} /> Edit
                  </button>
                  <button
                    type="button"
                    className="btn small ghost"
                    onClick={() => void toggle(environment, 'enabled')}
                    aria-pressed={environment.enabled}
                  >
                    {environment.enabled ? 'Disable' : 'Enable'}
                  </button>
                  <button
                    type="button"
                    className="btn small danger"
                    onClick={() => setDeleting(environment)}
                    aria-label={`Remove ${environment.name}`}
                  >
                    <IconTrash width={13} height={13} />
                  </button>
                </div>
              </article>
            );
          })}
        </div>
      ) : null}

      {formOpen ? (
        <EnvironmentForm
          environment={editing}
          onClose={() => setFormOpen(false)}
          onSaved={async () => {
            setFormOpen(false);
            await refresh();
          }}
        />
      ) : null}

      {deleting ? (
        <ConfirmDialog
          title={`Remove ${deleting.name}?`}
          message={
            <>
              The endpoint, its container inventory and image locations are removed. Historical findings for images are
              retained. Any queued or running scan for this environment must be cancelled first.
            </>
          }
          confirmLabel="Remove environment"
          danger
          busy={deleteBusy}
          onCancel={() => setDeleting(null)}
          onConfirm={() => void confirmDelete()}
        />
      ) : null}
    </div>
  );
}

function EnvironmentForm({
  environment,
  onClose,
  onSaved,
}: {
  environment: EnvironmentSummary | null;
  onClose: () => void;
  onSaved: () => Promise<void>;
}) {
  const editing = Boolean(environment);
  const [name, setName] = useState(environment?.name ?? '');
  const [kind, setKind] = useState<'unix' | 'tcp' | 'tls'>(environment?.kind ?? 'unix');
  const [address, setAddress] = useState(
    environment?.address ?? (environment?.kind === 'unix' || !environment ? '/var/run/docker.sock' : ''),
  );
  const [tlsCa, setTlsCa] = useState('');
  const [tlsCert, setTlsCert] = useState('');
  const [tlsKey, setTlsKey] = useState('');
  const [tlsSkipVerify, setTlsSkipVerify] = useState(environment?.tlsSkipVerify ?? false);
  const [enabled, setEnabled] = useState(environment?.enabled ?? true);
  const [scanEnabled, setScanEnabled] = useState(environment?.scanEnabled ?? true);
  const [quickHours, setQuickHours] = useState(environment?.quickIntervalHours ?? 24);
  const [standardHours, setStandardHours] = useState(environment?.standardIntervalHours ?? 168);
  const [minSeverity, setMinSeverity] = useState<Severity>(environment?.minAlertSeverity ?? 'HIGH');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent): Promise<void> {
    event.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const payload: Record<string, unknown> = {
        name: name.trim(),
        kind,
        address: address.trim(),
        enabled,
        scanEnabled,
        quickIntervalHours: quickHours,
        standardIntervalHours: standardHours,
        minAlertSeverity: minSeverity,
      };
      if (kind === 'tls') {
        payload.tlsSkipVerify = tlsSkipVerify;
        if (tlsCa.trim()) payload.tlsCa = tlsCa;
        if (tlsCert.trim()) payload.tlsCert = tlsCert;
        if (tlsKey.trim()) payload.tlsKey = tlsKey;
      }
      if (editing && environment) await api.patch(`/environments/${environment.id}`, payload);
      else await api.post('/environments', payload);
      await onSaved();
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : 'Unable to save environment');
    } finally {
      setBusy(false);
    }
  }

  const placeholder =
    kind === 'unix' ? '/var/run/docker.sock' : kind === 'tcp' ? '10.0.0.5:2375' : '10.0.0.5:2376';

  return (
    <Modal
      title={editing ? `Edit ${environment?.name}` : 'Connect a Docker host'}
      subtitle="DockSentinel only performs read-only Docker API calls."
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn ghost" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button type="submit" form="environment-form" className="btn primary" disabled={busy}>
            {busy ? <span className="spinner" aria-hidden="true" /> : null}
            {editing ? 'Save changes' : 'Connect host'}
          </button>
        </>
      }
    >
      <form id="environment-form" onSubmit={(event) => void submit(event)} className="vstack" style={{ gap: 16 }}>
        <div className="form-grid">
          <Field label="Name" htmlFor="env-name" hint="A short label, e.g. Unraid or Office Docker.">
            <input
              id="env-name"
              className="input"
              value={name}
              onChange={(event) => setName(event.target.value)}
              maxLength={100}
              required
            />
          </Field>
          <Field label="Connection type" htmlFor="env-kind">
            <select
              id="env-kind"
              className="select"
              value={kind}
              onChange={(event) => {
                const next = event.target.value as 'unix' | 'tcp' | 'tls';
                setKind(next);
                if (next === 'unix' && !address.startsWith('/')) setAddress('/var/run/docker.sock');
                if (next === 'tcp' && address.startsWith('/')) setAddress('');
              }}
            >
              <option value="unix">Local Unix socket</option>
              <option value="tcp">TCP (trusted network only)</option>
              <option value="tls">TCP with TLS and client certificates</option>
            </select>
          </Field>
          <Field
            className="span-2"
            label={kind === 'unix' ? 'Socket path' : 'Host and port'}
            htmlFor="env-address"
            hint={
              kind === 'unix'
                ? 'The path inside this container. Mount /var/run/docker.sock when deploying.'
                : kind === 'tcp'
                  ? 'Only use plain TCP on a trusted private network. Prefer TLS for anything remote.'
                  : 'Example: 10.0.0.5:2376. Provide the client certificate, key and CA below or TLS will fail closed.'
            }
          >
            <input
              id="env-address"
              className="input mono"
              value={address}
              onChange={(event) => setAddress(event.target.value)}
              placeholder={placeholder}
              required
            />
          </Field>

          {kind === 'tls' ? (
            <>
              <Field className="span-2" label="CA certificate (PEM)" htmlFor="env-ca">
                <textarea
                  id="env-ca"
                  className="textarea"
                  value={tlsCa}
                  onChange={(event) => setTlsCa(event.target.value)}
                  placeholder="-----BEGIN CERTIFICATE-----"
                  spellCheck={false}
                />
              </Field>
              <Field className="span-2" label="Client certificate (PEM)" htmlFor="env-cert">
                <textarea
                  id="env-cert"
                  className="textarea"
                  value={tlsCert}
                  onChange={(event) => setTlsCert(event.target.value)}
                  placeholder="-----BEGIN CERTIFICATE-----"
                  spellCheck={false}
                />
              </Field>
              <Field className="span-2" label="Client key (PEM)" htmlFor="env-key">
                <textarea
                  id="env-key"
                  className="textarea"
                  value={tlsKey}
                  onChange={(event) => setTlsKey(event.target.value)}
                  placeholder="-----BEGIN PRIVATE KEY-----"
                  spellCheck={false}
                />
              </Field>
              <label className="checkbox span-2">
                <input
                  type="checkbox"
                  checked={tlsSkipVerify}
                  onChange={(event) => setTlsSkipVerify(event.target.checked)}
                />
                <span>
                  Skip TLS certificate verification
                  <span className="hint" style={{ display: 'block' }}>
                    Strongly discouraged. Only for a self-signed endpoint on a trusted private network.
                  </span>
                </span>
              </label>
              {editing && environment?.hasTls ? (
                <div className="note span-2">
                  Leave certificate fields blank to keep the stored material. Pasting any field replaces all new TLS
                  values together.
                </div>
              ) : null}
            </>
          ) : null}
        </div>

        <hr className="divider" />

        <div className="form-grid">
          <Field label="Quick scan every (hours)" htmlFor="env-quick" hint="OS packages only. 0 disables quick scans.">
            <input
              id="env-quick"
              className="input"
              type="number"
              min={0}
              max={2160}
              value={quickHours}
              onChange={(event) => setQuickHours(Number(event.target.value))}
            />
          </Field>
          <Field
            label="Standard scan every (hours)"
            htmlFor="env-standard"
            hint="OS and language packages. 0 disables scheduled standard scans."
          >
            <input
              id="env-standard"
              className="input"
              type="number"
              min={0}
              max={8760}
              value={standardHours}
              onChange={(event) => setStandardHours(Number(event.target.value))}
            />
          </Field>
          <Field label="Minimum alert severity" htmlFor="env-severity">
            <select
              id="env-severity"
              className="select"
              value={minSeverity}
              onChange={(event) => setMinSeverity(event.target.value as Severity)}
            >
              {SEVERITIES.map((severity) => (
                <option key={severity} value={severity}>
                  {severity}
                </option>
              ))}
            </select>
          </Field>
          <div className="vstack" style={{ gap: 10, justifyContent: 'end', paddingBottom: 4 }}>
            <label className="checkbox">
              <input type="checkbox" checked={enabled} onChange={(event) => setEnabled(event.target.checked)} />
              <span>Environment enabled (discovery and alerting)</span>
            </label>
            <label className="checkbox">
              <input
                type="checkbox"
                checked={scanEnabled}
                onChange={(event) => setScanEnabled(event.target.checked)}
              />
              <span>Scanning enabled for images on this endpoint</span>
            </label>
          </div>
        </div>

        {error ? (
          <div className="form-error" role="alert">
            <IconAlert width={16} height={16} /> {error}
          </div>
        ) : null}
      </form>
    </Modal>
  );
}
