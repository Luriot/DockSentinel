import { useState } from 'react';
import { api, type LocalEnvironmentResult } from '../api.ts';
import { navigate } from '../hooks.ts';
import { IconAlert, IconBell, IconCheck, IconLayers, IconSearch, IconServer, IconShield } from '../components/ui.tsx';

export function Welcome({ onConnected }: { onConnected: () => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<LocalEnvironmentResult | null>(null);

  async function connectLocal(): Promise<void> {
    setBusy(true);
    setError(null);
    try {
      const connected = await api.post<LocalEnvironmentResult>('/environments/local', {});
      setResult(connected);
    } catch (connectError) {
      setError(connectError instanceof Error ? connectError.message : 'Could not connect to Docker');
    } finally {
      setBusy(false);
    }
  }

  if (result) {
    const dockerVersion = result.detection.version?.Version ?? result.detection.version?.ApiVersion;
    const dockerLabel = dockerVersion ? `Docker ${dockerVersion}` : 'Docker';
    const images = result.discovery?.images ?? 0;
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
              ? 'DockSentinel is preparing the first image scans; results appear as they finish.'
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
              <IconBell width={14} height={14} /> Set up alerts
            </button>
          </div>
          <p className="tiny dim">
            You can add more Docker hosts or change scan policy later in Docker hosts and Settings.
          </p>
        </section>
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
