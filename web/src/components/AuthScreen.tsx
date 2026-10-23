import { useState, type FormEvent } from 'react';
import { api } from '../api.ts';
import { IconAlert, IconCheck, IconShield } from './ui.tsx';

interface AuthScreenProps {
  needsSetup: boolean;
  onAuthenticated: () => void | Promise<void>;
}

export function AuthScreen({ needsSetup, onAuthenticated }: AuthScreenProps) {
  const [setupToken, setSetupToken] = useState('');
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent): Promise<void> {
    event.preventDefault();
    setError(null);
    if (needsSetup && password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }
    setBusy(true);
    try {
      const payload = needsSetup
        ? { setupToken, username, password }
        : { username, password };
      await api.post<{ authenticated: boolean }>(needsSetup ? '/auth/setup' : '/auth/login', payload);
      await onAuthenticated();
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : 'Sign-in failed');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="auth">
      <section className="auth-brand" aria-label="About DockSentinel">
        <div>
          <div className="brand" style={{ padding: 0 }}>
            <span className="brand-mark">
              <IconShield width={19} height={19} />
            </span>
            <span className="brand-text">
              <span className="brand-name">DockSentinel</span>
              <span className="brand-tag">Docker vulnerability watch</span>
            </span>
          </div>
          <h1>Know what is exploitable in your containers, before someone else does.</h1>
          <p className="lede">
            DockSentinel orchestrates Trivy across your Docker environments, keeps a history of findings,
            and alerts you when a serious vulnerability appears in a workload you expose.
          </p>
          <div className="auth-points">
            <div className="auth-point">
              <IconCheck width={16} height={16} />
              <span>Scans images with Trivy and explains severity, fixes and exposure context.</span>
            </div>
            <div className="auth-point">
              <IconCheck width={16} height={16} />
              <span>Prioritises known-exploited and Internet-facing risks instead of dumping raw CVE lists.</span>
            </div>
            <div className="auth-point">
              <IconCheck width={16} height={16} />
              <span>Sends deduplicated ntfy alerts; failures and stale results are never shown as clean scans.</span>
            </div>
          </div>
        </div>
        <p className="auth-foot">
          DockSentinel monitors image vulnerabilities. It is not an intrusion detection system and cannot prove
          that a currently running service is safe.
        </p>
      </section>

      <section className="auth-form-side">
        <div className="auth-card">
          <div>
            <h2>{needsSetup ? 'Set up DockSentinel' : 'Sign in'}</h2>
            <p className="sub" style={{ marginTop: 6 }}>
              {needsSetup
                ? 'Create the administrator account. The setup token is printed once in the server logs.'
                : 'Enter the administrator credentials for this instance.'}
            </p>
          </div>

          <form onSubmit={(event) => void submit(event)}>
            {needsSetup ? (
              <>
                <div className="field">
                  <label htmlFor="setup-token">Setup token</label>
                  <input
                    id="setup-token"
                    className="input mono"
                    value={setupToken}
                    onChange={(event) => setSetupToken(event.target.value)}
                    autoComplete="off"
                    spellCheck={false}
                    required
                  />
                  <span className="hint">
                    Printed in the container logs on first start. Alternatively set <code>SETUP_TOKEN</code> before
                    launching.
                  </span>
                </div>
                <div className="field">
                  <label htmlFor="username">Username</label>
                  <input
                    id="username"
                    className="input"
                    value={username}
                    onChange={(event) => setUsername(event.target.value)}
                    autoComplete="username"
                    required
                    maxLength={64}
                  />
                </div>
                <div className="field">
                  <label htmlFor="password">Password</label>
                  <input
                    id="password"
                    className="input"
                    type="password"
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                    autoComplete="new-password"
                    required
                    minLength={12}
                  />
                  <span className="hint">At least 12 characters. Stored with scrypt.</span>
                </div>
                <div className="field">
                  <label htmlFor="confirm-password">Confirm password</label>
                  <input
                    id="confirm-password"
                    className="input"
                    type="password"
                    value={confirmPassword}
                    onChange={(event) => setConfirmPassword(event.target.value)}
                    autoComplete="new-password"
                    required
                    minLength={12}
                  />
                </div>
              </>
            ) : (
              <>
                <div className="field">
                  <label htmlFor="username">Username</label>
                  <input
                    id="username"
                    className="input"
                    value={username}
                    onChange={(event) => setUsername(event.target.value)}
                    autoComplete="username"
                    required
                  />
                </div>
                <div className="field">
                  <label htmlFor="password">Password</label>
                  <input
                    id="password"
                    className="input"
                    type="password"
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                    autoComplete="current-password"
                    required
                  />
                </div>
              </>
            )}

            {error ? (
              <div className="form-error" role="alert">
                <IconAlert width={16} height={16} /> {error}
              </div>
            ) : null}

            <button type="submit" className="btn primary" disabled={busy} style={{ marginTop: 4 }}>
              {busy ? <span className="spinner" aria-hidden="true" /> : null}
              {needsSetup ? 'Create account and continue' : 'Sign in'}
            </button>
          </form>

          <div className="auth-hint">
            {needsSetup
              ? 'No default password exists. DockSentinel refuses to expose an administrative interface without an explicit account.'
              : 'Sessions are stored in an HttpOnly, SameSite=Strict cookie. Sign in again if the session expires.'}
          </div>
          <p className="tiny dim">
            DockSentinel {needsSetup ? 'is protected by a first-run token' : 'is self-hosted and never sends telemetry'}
            .
          </p>
        </div>
      </section>
    </div>
  );
}
