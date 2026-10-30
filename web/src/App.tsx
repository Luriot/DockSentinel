import { useCallback, useEffect, useState } from 'react';
import { api, setCsrfToken, setUnauthorizedHandler, type SessionInfo } from './api.ts';
import { ToastProvider, WatchMark } from './components/ui.tsx';
import { AuthScreen } from './components/AuthScreen.tsx';
import { AppShell } from './components/Layout.tsx';

type BootState =
  | { status: 'loading' }
  | { status: 'error'; message: string }
  | { status: 'ready'; session: SessionInfo };

export default function App() {
  const [boot, setBoot] = useState<BootState>({ status: 'loading' });

  const loadSession = useCallback(async (): Promise<void> => {
    try {
      const session = await api.get<SessionInfo>('/auth/session');
      setCsrfToken(session.csrfToken);
      setBoot({ status: 'ready', session });
    } catch (error) {
      setBoot({
        status: 'error',
        message: error instanceof Error ? error.message : 'Unable to reach DockSentinel',
      });
    }
  }, []);

  useEffect(() => {
    void loadSession();
  }, [loadSession]);

  useEffect(() => {
    setUnauthorizedHandler(() => {
      setCsrfToken(null);
      setBoot({
        status: 'ready',
        session: { needsSetup: false, authenticated: false, user: null, csrfToken: null },
      });
    });
    return () => setUnauthorizedHandler(null);
  }, []);

  const onAuthenticated = useCallback(async (): Promise<void> => {
    await loadSession();
  }, [loadSession]);

  const logout = useCallback(async (): Promise<void> => {
    try {
      await api.post('/auth/logout');
    } catch {
      // A failed logout still clears the local session; the server-side session expires on its own.
    }
    setCsrfToken(null);
    setBoot({
      status: 'ready',
      session: { needsSetup: false, authenticated: false, user: null, csrfToken: null },
    });
  }, []);

  if (boot.status === 'loading') {
    return (
      <div className="auth-solo">
        <div className="auth-solo-inner">
          <div className="auth-solo-brand">
            <span className="brand-mark">
              <WatchMark size={18} />
            </span>
            <span className="brand-text">
              <span className="brand-name">DockSentinel</span>
              <span className="brand-tag">Docker vulnerability watch</span>
            </span>
          </div>
          <div className="auth-card">
            <div className="inline-loading">
              <span className="spinner" aria-hidden="true" /> Loading DockSentinel…
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (boot.status === 'error') {
    return (
      <div className="auth-solo">
        <div className="auth-solo-inner">
          <div className="auth-solo-brand">
            <span className="brand-mark">
              <WatchMark size={18} />
            </span>
            <span className="brand-text">
              <span className="brand-name">DockSentinel</span>
              <span className="brand-tag">Docker vulnerability watch</span>
            </span>
          </div>
          <div className="auth-card" role="alert">
            <h1>DockSentinel is unreachable</h1>
            <p className="sub">{boot.message}</p>
            <button type="button" className="btn primary" onClick={() => void loadSession()}>
              Try again
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (!boot.session.authenticated) {
    return (
      <AuthScreen needsSetup={boot.session.needsSetup} onAuthenticated={onAuthenticated} />
    );
  }

  return (
    <ToastProvider>
      <AppShell username={boot.session.user?.username ?? 'admin'} onLogout={logout} onSessionRefresh={loadSession} />
    </ToastProvider>
  );
}
