import { useEffect, useState } from 'react';
import {
  api,
  type LocalEnvironmentResult,
  type OverviewData,
  type PublicSettings,
} from '../api.ts';
import { navigate, useApi } from '../hooks.ts';
import {
  IconAlert,
  IconBell,
  IconCheck,
  IconLayers,
  IconRefresh,
  IconSearch,
  IconServer,
  IconShield,
} from '../components/ui.tsx';

export function Welcome({ onConnected }: { onConnected: () => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<LocalEnvironmentResult | null>(null);
  const [scanBusy, setScanBusy] = useState(false);
  const [scanMessage, setScanMessage] = useState<string | null>(null);
  const [baseUrl, setBaseUrl] = useState('https://ntfy.sh');
  const [topic, setTopic] = useState('');
  const [token, setToken] = useState('');
  const [alertsBusy, setAlertsBusy] = useState(false);
  const [alertsMessage, setAlertsMessage] = useState<string | null>(null);
  const overview = useApi<OverviewData>('/overview', { intervalMs: 2_500 });
  const settings = useApi<{ settings: PublicSettings }>('/settings');

  useEffect(() => {
    const ntfy = settings.data?.settings.ntfy;
    if (!ntfy) return;
    setBaseUrl(ntfy.baseUrl || 'https://ntfy.sh');
    setTopic(ntfy.topic);
  }, [settings.data]);

  async function connectLocal(): Promise<void> {
    setBusy(true);
    setError(null);
    try {
      const connected = await api.post<LocalEnvironmentResult>('/environments/local', {});
      setResult(connected);
      overview.refresh();
    } catch (connectError) {
      setError(connectError instanceof Error ? connectError.message : 'Could not connect to Docker');
    } finally {
      setBusy(false);
    }
  }

  async function scanNow(): Promise<void> {
    setScanBusy(true);
    setScanMessage(null);
    try {
      let cursor: string | undefined;
      let queuedCount = 0;
      let skippedCount = 0;
      let total = 0;
      do {
        const batch = await api.post<{
          queued: number;
          skipped: number;
          total: number;
          nextCursor: string | null;
        }>('/scans/scan-all', { profile: 'standard', limit: 100, ...(cursor ? { cursor } : {}) });
        queuedCount += batch.queued;
        skippedCount += batch.skipped;
        total = batch.total;
        cursor = batch.nextCursor ?? undefined;
      } while (cursor);
      setScanMessage(
        queuedCount > 0
          ? `Queued ${queuedCount} of ${total} image scans. ${skippedCount ? `${skippedCount} were already queued or unavailable. ` : ''}Results will appear here.`
          : total === 0
            ? 'No images were found yet. Start a container and try again.'
            : 'Scans are already queued or none of these images has a connected Docker host.',
      );
      overview.refresh();
    } catch (scanError) {
      setScanMessage(scanError instanceof Error ? scanError.message : 'Could not queue scans');
    } finally {
      setScanBusy(false);
    }
  }

  async function saveAlerts(): Promise<void> {
    if (!topic.trim()) {
      setAlertsMessage('Enter an ntfy topic first, for example docksentinel-yourname.');
      return;
    }
    setAlertsBusy(true);
    setAlertsMessage(null);
    try {
      await api.patch('/settings', {
        ntfy: {
          enabled: true,
          baseUrl: baseUrl.trim() || 'https://ntfy.sh',
          topic: topic.trim(),
          ...(token.trim() ? { authType: 'token', token: token.trim() } : {}),
        },
      });
      await api.post('/notifications/test');
      setAlertsMessage('Alerts are enabled and a test notification was delivered.');
      setToken('');
    } catch (alertError) {
      setAlertsMessage(alertError instanceof Error ? alertError.message : 'Could not save alert settings');
    } finally {
      setAlertsBusy(false);
    }
  }

  if (result) {
    const dockerVersion = result.detection.version?.Version ?? result.detection.version?.ApiVersion;
    const dockerLabel = dockerVersion ? `Docker ${dockerVersion}` : 'Docker';
    const images = overview.data?.workloads.totalImages ?? result.discovery?.images ?? 0;
    const inFlight = (overview.data?.scans.queued ?? 0) + (overview.data?.scans.running ?? 0);
    const firstDone = (overview.data?.scans.success24h ?? 0) > 0;
    const findingCount = overview.data?.counts.total ?? 0;
    return (
      <div className="welcome">
        <section className="card welcome-hero">
          <span className="welcome-check" aria-hidden="true">
            <IconCheck width={28} height={28} />
          </span>
          <p className="eyebrow">CONNECTED</p>
          <h2>Docker is connected</h2>
          <p>
            Found <strong>{result.discovery?.containers ?? 0} containers</strong> and{' '}
            <strong>{images} images</strong> using {dockerLabel}.{' '}
            {images > 0
              ? 'DockSentinel is preparing the first image scans.'
              : 'When you start a container, DockSentinel will discover and scan its image.'}
          </p>
          {result.warning ? (
            <div className="note warn">
              <IconAlert width={14} height={14} style={{ verticalAlign: -2 }} /> {result.warning}
            </div>
          ) : null}
          <div className="welcome-actions">
            <button type="button" className="btn primary" onClick={onConnected}>
              Open dashboard
            </button>
            <button type="button" className="btn ghost" onClick={() => navigate('/notifications')}>
              <IconBell width={14} height={14} /> Advanced alert settings
            </button>
          </div>
        </section>

        <section className="card welcome-panel" aria-live="polite">
          <div className="card-header">
            <div>
              <h3 className="section-title">First scan</h3>
              <p className="section-subtitle">DockSentinel scans the images it found automatically.</p>
            </div>
            {images > 0 && !firstDone ? (
              <button type="button" className="btn small ghost" onClick={() => void scanNow()} disabled={scanBusy}>
                {scanBusy ? <span className="spinner" aria-hidden="true" /> : <IconRefresh width={13} height={13} />}
                Scan now
              </button>
            ) : null}
          </div>
          <div className="card-body">
            {images === 0 ? (
              <div className="note">No images are available yet. Start a container and DockSentinel will pick it up.</div>
            ) : firstDone ? (
              <div className="hstack" style={{ gap: 10 }}>
                <span className="welcome-check" style={{ width: 34, height: 34, margin: 0 }}>
                  <IconCheck width={18} height={18} />
                </span>
                <div>
                  <strong>First scan complete</strong>
                  <div className="small dim">
                    {findingCount} open finding{findingCount === 1 ? '' : 's'} recorded. Results are on the dashboard.
                  </div>
                </div>
              </div>
            ) : inFlight > 0 ? (
              <div className="hstack" style={{ gap: 10 }}>
                <span className="spinner" aria-hidden="true" />
                <div>
                  <strong>Scanning your images…</strong>
                  <div className="small dim">
                    {inFlight} scan{inFlight === 1 ? '' : 's'} queued or running. This can take a few minutes on the first run.
                  </div>
                </div>
              </div>
            ) : (
              <div className="vstack" style={{ gap: 8 }}>
                <div className="note">The first scan has not started yet. You can start it now.</div>
                <div>
                  <button type="button" className="btn small primary" onClick={() => void scanNow()} disabled={scanBusy}>
                    {scanBusy ? <span className="spinner" aria-hidden="true" /> : <IconLayers width={13} height={13} />}
                    Scan now
                  </button>
                </div>
              </div>
            )}
            {scanMessage ? <p className="tiny dim" style={{ marginTop: 10 }}>{scanMessage}</p> : null}
          </div>
        </section>

        <section className="card welcome-panel">
          <div className="card-header">
            <div>
              <h3 className="section-title">Get alerts</h3>
              <p className="section-subtitle">Optional: send new findings to your phone or desktop with ntfy.</p>
            </div>
            <IconBell width={18} height={18} />
          </div>
          <div className="card-body">
            <div className="form-grid">
              <label className="field">
                <span>ntfy topic</span>
                <input
                  className="input"
                  value={topic}
                  onChange={(event) => setTopic(event.target.value)}
                  placeholder="docksentinel-yourname"
                  maxLength={64}
                  autoComplete="off"
                />
                <span className="hint">Use the ntfy app and subscribe to this topic.</span>
              </label>
              <label className="field">
                <span>Server</span>
                <input
                  className="input"
                  value={baseUrl}
                  onChange={(event) => setBaseUrl(event.target.value)}
                  placeholder="https://ntfy.sh"
                  maxLength={500}
                />
                <span className="hint">Leave the default unless you self-host ntfy.</span>
              </label>
              <label className="field">
                <span>Access token (optional)</span>
                <input
                  className="input"
                  type="password"
                  value={token}
                  onChange={(event) => setToken(event.target.value)}
                  placeholder="Only for protected topics"
                  autoComplete="new-password"
                />
              </label>
            </div>
            <div className="hstack" style={{ marginTop: 12, flexWrap: 'wrap' }}>
              <button type="button" className="btn primary" onClick={() => void saveAlerts()} disabled={alertsBusy}>
                {alertsBusy ? <span className="spinner" aria-hidden="true" /> : <IconBell width={14} height={14} />}
                Save and send test
              </button>
              <button type="button" className="btn ghost" onClick={onConnected}>
                Skip for now
              </button>
            </div>
            {alertsMessage ? (
              <div className={`note ${alertsMessage.includes('delivered') ? 'info' : 'warn'}`} style={{ marginTop: 10 }}>
                {alertsMessage}
              </div>
            ) : null}
          </div>
        </section>

        <p className="tiny dim">
          You can add more Docker hosts or change scan policy later in Docker hosts and Settings.
        </p>
      </div>
    );
  }

  return (
    <div className="welcome">
      <section className="card welcome-hero">
        <p className="eyebrow">FIRST RUN</p>
        <h2>Let&apos;s connect Docker</h2>
        <p>
          DockSentinel watches the containers and images on a Docker host. It only reads Docker metadata and scans
          images; it never starts, stops or changes your containers.
        </p>
        <div className="welcome-actions">
          <button type="button" className="btn primary" onClick={() => void connectLocal()} disabled={busy}>
            {busy ? <span className="spinner" aria-hidden="true" /> : <IconServer width={15} height={15} />}
            {busy ? 'Looking for Docker…' : 'Use Docker on this computer'}
          </button>
          <button type="button" className="btn ghost" onClick={() => navigate('/environments?new=1')}>
            Connect a remote host
          </button>
        </div>
        {error ? (
          <div className="note danger" role="alert">
            <IconAlert width={14} height={14} style={{ verticalAlign: -2 }} /> {error}
            <div className="hstack" style={{ marginTop: 10 }}>
              <button type="button" className="btn small ghost" onClick={() => void connectLocal()} disabled={busy}>
                Try again
              </button>
              <button type="button" className="btn small ghost" onClick={() => navigate('/environments?new=1')}>
                Set up manually
              </button>
            </div>
          </div>
        ) : null}
        <p className="tiny dim">
          Docker Desktop must be running. If DockSentinel runs in a container, the Docker socket must be mounted into
          that container. Remote Docker hosts are supported through TCP or mutual TLS.
        </p>
      </section>

      <div className="welcome-steps">
        <article className="card welcome-step">
          <span className="welcome-step-icon">
            <IconServer width={18} height={18} />
          </span>
          <h3>1. Connect Docker</h3>
          <p>Use this computer for one click, or add a remote host with its address and certificates.</p>
        </article>
        <article className="card welcome-step">
          <span className="welcome-step-icon">
            <IconLayers width={18} height={18} />
          </span>
          <h3>2. Let it scan</h3>
          <p>Images are scanned automatically with Trivy. You get a clear history and no false “clean” failures.</p>
        </article>
        <article className="card welcome-step">
          <span className="welcome-step-icon">
            <IconBell width={18} height={18} />
          </span>
          <h3>3. Get alerts</h3>
          <p>Add ntfy when you want a phone or desktop notification for serious new findings. It is optional.</p>
        </article>
      </div>

      <section className="card welcome-security">
        <IconShield width={18} height={18} />
        <div>
          <strong>Docker access is privileged.</strong>
          <p>
            Prefer a local socket or a TLS-protected remote endpoint. DockSentinel never exposes a Docker TCP API and
            never modifies containers. See the security notes in the documentation for hardening.
          </p>
        </div>
        <button type="button" className="btn ghost small" onClick={() => navigate('/environments')}>
          <IconSearch width={13} height={13} /> Docker hosts
        </button>
      </section>
    </div>
  );
}
