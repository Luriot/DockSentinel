import { useState } from 'react';
import { api, type BackupInfo, type SystemStatusData, type UpdateStatus } from '../api.ts';
import { useApi } from '../hooks.ts';
import {
  ConfirmDialog,
  EmptyState,
  ErrorPanel,
  IconCheck,
  IconExternal,
  IconRefresh,
  IconServer,
  InlineLoading,
  useToast,
} from '../components/ui.tsx';
import { formatBytes, formatDate, relativeTime, titleCase } from '../format.ts';

export function Status() {
  const { data, error, loading, refresh } = useApi<SystemStatusData>('/system/status');
  const toast = useToast();
  const [busy, setBusy] = useState<'backup' | 'update' | null>(null);
  const [update, setUpdate] = useState<UpdateStatus | null>(null);
  const [restoring, setRestoring] = useState<BackupInfo | null>(null);
  const [restoreBusy, setRestoreBusy] = useState(false);

  async function createBackup(): Promise<void> {
    setBusy('backup');
    try {
      await api.post('/system/backup');
      toast('Backup created', 'success');
      await refresh();
    } catch (backupError) {
      toast(backupError instanceof Error ? backupError.message : 'Backup failed', 'error');
    } finally {
      setBusy(null);
    }
  }

  async function checkUpdates(): Promise<void> {
    setBusy('update');
    try {
      const result = await api.post<UpdateStatus>('/system/update-check');
      setUpdate(result);
      toast(result.message, result.state === 'available' ? 'info' : 'success');
    } catch (updateError) {
      toast(updateError instanceof Error ? updateError.message : 'Update check failed', 'error');
    } finally {
      setBusy(null);
    }
  }

  async function restore(): Promise<void> {
    if (!restoring) return;
    setRestoreBusy(true);
    try {
      await api.post('/system/restore', { name: restoring.name });
      toast('Restore staged. Restart DockSentinel to apply it.', 'success');
      setRestoring(null);
    } catch (restoreError) {
      toast(restoreError instanceof Error ? restoreError.message : 'Restore failed', 'error');
    } finally {
      setRestoreBusy(false);
    }
  }

  if (loading && !data) return <InlineLoading label="Loading system status…" />;
  if (error && !data) return <ErrorPanel error={error} onRetry={refresh} />;
  if (!data) return null;
  const dataDisk = data.disk.data;
  const cacheDisk = data.disk.scannerCache;
  const diskPercent = dataDisk && dataDisk.totalBytes > 0 ? Math.round((dataDisk.usedBytes / dataDisk.totalBytes) * 100) : null;
  const currentUpdate = update ?? data.update;

  return (
    <div className="page-stack">
      <div className="grid-auto">
        <section className="card" aria-label="Application">
          <div className="card-header">
            <div>
              <h2 className="section-title">Application</h2>
              <p className="section-subtitle">DockSentinel {data.version}</p>
            </div>
          </div>
          <div className="card-body">
            <dl className="detail-list">
              <dt>Version</dt><dd>{data.version}</dd>
              <dt>Node.js</dt><dd className="mono">{data.nodeVersion}</dd>
              <dt>Schema</dt><dd>{data.schemaVersion}</dd>
              <dt>Uptime</dt><dd>{relativeTime(new Date(Date.now() - data.uptimeSeconds * 1000).toISOString())}</dd>
            </dl>
            <div className="hstack" style={{ marginTop: 12 }}>
              <button type="button" className="btn small ghost" onClick={() => void checkUpdates()} disabled={busy === 'update'}>
                {busy === 'update' ? <span className="spinner" aria-hidden="true" /> : <IconRefresh width={13} height={13} />}
                Check for updates
              </button>
              {currentUpdate?.state === 'available' && currentUpdate.url ? (
                <a className="link-button" href={currentUpdate.url} target="_blank" rel="noreferrer noopener">
                  <IconExternal width={12} height={12} /> {currentUpdate.latestVersion}
                </a>
              ) : null}
            </div>
            {currentUpdate ? (
              <div className={`note ${currentUpdate.state === 'available' ? 'info' : currentUpdate.state === 'error' ? 'warn' : ''}`} style={{ marginTop: 10 }}>
                {currentUpdate.message}
              </div>
            ) : null}
            <p className="tiny dim" style={{ marginTop: 8 }}>
              Native installs: rerun the Windows installer or <code>npm run native:setup</code>. Docker installs:
              pull the latest image and recreate the container.
            </p>
          </div>
        </section>

        <section className="card" aria-label="Scanner">
          <div className="card-header"><div><h2 className="section-title">Scanner</h2><p className="section-subtitle">Trivy and intelligence</p></div></div>
          <div className="card-body">
            <dl className="detail-list">
              <dt>Trivy</dt><dd>{data.scanner.available ? data.scanner.version ?? 'available' : 'unavailable'}</dd>
              <dt>Database</dt><dd>{data.scanner.dbUpdatedAt ? relativeTime(data.scanner.dbUpdatedAt) : 'not downloaded'}</dd>
              <dt>KEV</dt><dd>{data.kev.status === 'ok' ? `${data.kev.entryCount} ${data.kev.entryCount === 1 ? 'entry' : 'entries'} · ${relativeTime(data.kev.syncedAt)}` : data.kev.status}</dd>
            </dl>
          </div>
        </section>

        <section className="card" aria-label="Storage">
          <div className="card-header"><div><h2 className="section-title">Storage</h2><p className="section-subtitle">Data directory</p></div></div>
          <div className="card-body">
            <div className="mono small" style={{ wordBreak: 'break-all' }}>{data.dataDir}</div>
            {dataDisk ? (
              <>
                <div className="spread" style={{ marginTop: 12 }}><span>Data volume · {formatBytes(dataDisk.usedBytes)} used</span><span className="dim">{diskPercent}%</span></div>
                <div className="disk-meter" style={{ marginTop: 6 }}><span style={{ width: `${Math.min(100, diskPercent ?? 0)}%` }} /></div>
                <div className="tiny dim" style={{ marginTop: 6 }}>{formatBytes(dataDisk.freeBytes)} free of {formatBytes(dataDisk.totalBytes)}</div>
                {cacheDisk ? <div className="tiny dim" style={{ marginTop: 6 }}>Trivy cache volume: {formatBytes(cacheDisk.freeBytes)} free of {formatBytes(cacheDisk.totalBytes)}</div> : null}
              </>
            ) : <p className="small dim">Disk usage is not available on this platform.</p>}
          </div>
        </section>
      </div>

      <section className="card" aria-label="Docker hosts">
        <div className="card-header"><div><h2 className="section-title">Docker hosts</h2><p className="section-subtitle">Connectivity at a glance</p></div></div>
        {data.environments.length === 0 ? <EmptyState title="No Docker hosts" icon={<IconServer width={22} height={22} />}><p>Connect a host from the welcome screen or Docker hosts page.</p></EmptyState> : (
          <div className="table-wrap"><table className="table"><caption className="sr-only">Docker host connectivity</caption><thead><tr><th scope="col">Host</th><th scope="col">Status</th><th scope="col">Last contact</th><th scope="col">Scanning</th></tr></thead><tbody>
            {data.environments.map((environment) => (
              <tr key={environment.id}>
                <td>{environment.name}</td>
                <td><span className={`status-dot ${environment.status === 'online' ? 'online' : environment.status === 'offline' ? 'offline' : 'unknown'}`} aria-hidden="true" /> {titleCase(environment.status)}{environment.statusMessage ? <div className="cell-sub">{environment.statusMessage}</div> : null}</td>
                <td>{relativeTime(environment.lastContactAt)}</td>
                <td>{environment.scanEnabled ? 'Enabled' : 'Disabled'}</td>
              </tr>
            ))}
          </tbody></table></div>
        )}
      </section>

      <section className="card" aria-label="Backups">
        <div className="card-header">
          <div><h2 className="section-title">Backups</h2><p className="section-subtitle">{data.backups.last ? `Last backup ${relativeTime(data.backups.last.createdAt)}` : 'No backups yet — snapshots include encrypted secrets and the key'}</p></div>
          <button type="button" className="btn small primary" onClick={() => void createBackup()} disabled={busy === 'backup'}>
            {busy === 'backup' ? <span className="spinner" aria-hidden="true" /> : <IconCheck width={13} height={13} />} Create backup
          </button>
        </div>
        <div className="card-body">
          {data.backups.items.length === 0 ? <div className="note">No backups yet. Create one before upgrading or making changes.</div> : (
            <div className="table-wrap"><table className="table"><caption className="sr-only">Database backups</caption><thead><tr><th scope="col">Backup</th><th scope="col">Created</th><th scope="col">Size</th><th scope="col">Restore</th></tr></thead><tbody>
              {data.backups.items.map((backup) => (
                <tr key={backup.name}>
                  <td className="mono small">{backup.name}</td>
                  <td>{formatDate(backup.createdAt)}</td>
                  <td>{formatBytes(backup.sizeBytes)}</td>
                  <td><button type="button" className="btn small ghost" onClick={() => setRestoring(backup)}><IconRefresh width={12} height={12} /> Restore</button></td>
                </tr>
              ))}
            </tbody></table></div>
          )}
          <p className="tiny dim" style={{ marginTop: 10 }}>Restores are staged and applied on the next restart. The current database is saved as a pre-restore backup. The encryption key is not replaced by a restore.</p>
        </div>
      </section>

      {restoring ? (
        <ConfirmDialog
          title={`Restore ${restoring.name}?`}
          message={<>The selected database will replace the live database after DockSentinel restarts. The current database is copied to a pre-restore backup first. Restart the app to finish.</>}
          confirmLabel="Stage restore"
          danger
          busy={restoreBusy}
          onCancel={() => setRestoring(null)}
          onConfirm={() => void restore()}
        />
      ) : null}
    </div>
  );
}
