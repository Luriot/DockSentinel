import { useState, type FormEvent } from 'react';
import { api } from '../api.ts';
import { IconAlert, IconShield } from './ui.tsx';

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
    <div className="auth-solo">
      <div className="auth-solo-inner">
        <div className="auth-solo-brand">
          <span className="brand-mark">
            <IconShield width={18} height={18} />
          </span>
          <span className="brand-text">
            <span className="brand-name">DockSentinel</span>
            <span className="brand-tag">Docker vulnerability watch</span>
          </span>
        </div>

        <section className="auth-card" aria-labelledby="auth-title">
          <div>
            <h1 id="auth-title">{needsSetup ? 'Create your admin account' : 'Sign in'}</h1>
            <p className="sub">
              {needsSetup
                ? 'One-time setup. You only need the setup code shown when DockSentinel started.'
                : 'Enter the administrator credentials for this instance.'}
            </p>
          </div>

          <form onSubmit={(event) => void submit(event)}>
            {needsSetup ? (
              <>
                <div className="field">
                  <label htmlFor="setup-token">Setup code</label>
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
                    Shown once in the DockSentinel window or terminal when it started. The Windows installer keeps that
                    window open. In Docker, check the container logs.
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
                  <span className="hint">At least 12 characters. Use a password manager if you can.</span>
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

            <button type="submit" className="btn primary" disabled={busy}>
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
            DockSentinel {needsSetup ? 'is protected by a first-run token' : 'is self-hosted and never sends telemetry'}.
          </p>
        </section>

        <p className="auth-solo-note">
          Image scanning only — not an intrusion detection system. Self-hosted; no telemetry.
        </p>
      </div>
    </div>
  );
}
