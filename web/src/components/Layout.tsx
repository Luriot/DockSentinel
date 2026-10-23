import { useEffect, useRef, useState, type ComponentType } from 'react';
import { api, type OverviewData } from '../api.ts';
import { navigate, useApi, useRoute } from '../hooks.ts';
import {
  IconActivity,
  IconBell,
  IconBox,
  IconDashboard,
  IconLayers,
  IconLogout,
  IconBug,
  IconServer,
  IconSettings,
  IconShield,
  IconKey,
  IconAlert,
  useToast,
  Modal,
  Field,
} from './ui.tsx';
import { Overview } from '../views/Overview.tsx';
import { Environments } from '../views/Environments.tsx';
import { Containers } from '../views/Containers.tsx';
import { Images } from '../views/Images.tsx';
import { Vulnerabilities } from '../views/Vulnerabilities.tsx';
import { Content } from '../views/Content.tsx';
import { Welcome } from '../views/Welcome.tsx';
import { Status } from '../views/Status.tsx';
import { Scans } from '../views/Scans.tsx';
import { Notifications } from '../views/Notifications.tsx';
import { Settings } from '../views/Settings.tsx';

interface RouteDefinition {
  title: string;
  subtitle: string;
  component: ComponentType;
}

const ROUTES: Record<string, RouteDefinition> = {
  '/': {
    title: 'Overview',
    subtitle: 'Urgent vulnerabilities across your Docker workloads',
    component: Overview,
  },
  '/environments': {
    title: 'Docker hosts',
    subtitle: 'The Docker engines DockSentinel watches',
    component: Environments,
  },
  '/containers': {
    title: 'Containers',
    subtitle: 'Workloads, their images and exposure context',
    component: Containers,
  },
  '/images': {
    title: 'Images',
    subtitle: 'Deduplicated image inventory and scan freshness',
    component: Images,
  },
  '/vulnerabilities': {
    title: 'Vulnerabilities',
    subtitle: 'Findings with fixes, exploitation signals and affected workloads',
    component: Vulnerabilities,
  },
  '/content': {
    title: 'Configuration & secrets',
    subtitle: 'Opt-in image content and image config findings',
    component: Content,
  },
  '/scans': {
    title: 'Scans',
    subtitle: 'Running, scheduled, successful and failed scans',
    component: Scans,
  },
  '/notifications': {
    title: 'Alerts',
    subtitle: 'ntfy delivery, alert policy and history',
    component: Notifications,
  },
  '/status': {
    title: 'System status',
    subtitle: 'Health, storage, backups and updates',
    component: Status,
  },
  '/settings': {
    title: 'Settings',
    subtitle: 'Scanning, retention, intelligence and security',
    component: Settings,
  },
};

const NAV_GROUPS = [
  {
    label: 'Monitor',
    items: [
      { path: '/', label: 'Overview', icon: IconDashboard },
      { path: '/vulnerabilities', label: 'Vulnerabilities', icon: IconBug },
      { path: '/content', label: 'Config & secrets', icon: IconKey },
    ],
  },
  {
    label: 'Inventory',
    items: [
      { path: '/environments', label: 'Docker hosts', icon: IconServer },
      { path: '/containers', label: 'Containers', icon: IconBox },
      { path: '/images', label: 'Images', icon: IconLayers },
    ],
  },
  {
    label: 'Operations',
    items: [
      { path: '/scans', label: 'Scans', icon: IconActivity },
      { path: '/notifications', label: 'Alerts', icon: IconBell },
    ],
  },
  {
    label: 'System',
    items: [
      { path: '/status', label: 'System status', icon: IconActivity },
      { path: '/settings', label: 'Settings', icon: IconSettings },
    ],
  },
];

interface AppShellProps {
  username: string;
  onLogout: () => void | Promise<void>;
  onSessionRefresh: () => void | Promise<void>;
}

export function AppShell({ username, onLogout, onSessionRefresh }: AppShellProps) {
  const route = useRoute();
  const overview = useApi<OverviewData>('/overview', { intervalMs: 30_000 });
  const health = useApi<{ version: string }>('/health');
  const system = useApi<{ scanner: { available: boolean; version: string | null }; scans: { active: number } }>(
    '/system',
    { intervalMs: 60_000 },
  );
  const toast = useToast();
  const [menuOpen, setMenuOpen] = useState(false);
  const [passwordOpen, setPasswordOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!menuOpen) return;
    const onPointer = (event: MouseEvent): void => {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) setMenuOpen(false);
    };
    document.addEventListener('mousedown', onPointer);
    return () => document.removeEventListener('mousedown', onPointer);
  }, [menuOpen]);

  const definition = ROUTES[route.path] ?? {
    title: 'Not found',
    subtitle: 'This page does not exist',
    component: NotFound,
  };
  const welcome = route.path === '/' && overview.data !== null && (overview.data.environments.length === 0);
  const View = definition.component;
  const critical = overview.data?.counts.critical ?? 0;
  const high = overview.data?.counts.high ?? 0;
  const runningScans = overview.data?.scans.running ?? 0;
  const queuedScans = overview.data?.scans.queued ?? 0;
  const environments = overview.data?.environments ?? [];

  async function changePassword(currentPassword: string, newPassword: string): Promise<void> {
    await api.post('/auth/password', { currentPassword, newPassword });
    toast('Password changed. Other sessions were signed out.', 'success');
    setPasswordOpen(false);
    await onSessionRefresh();
  }

  return (
    <>
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <div className="app">
        <aside className="sidebar" aria-label="Primary navigation">
          <a
            className="brand"
            href="/"
            onClick={(event) => {
              event.preventDefault();
              navigate('/');
            }}
          >
            <span className="brand-mark">
              <IconShield width={19} height={19} />
            </span>
            <span className="brand-text">
              <span className="brand-name">DockSentinel</span>
              <span className="brand-tag">Vulnerability watch</span>
            </span>
          </a>

          <nav className="nav-group" aria-label="Sections">
            {NAV_GROUPS.map((group) => (
              <div key={group.label} className="nav-group" role="group" aria-label={group.label}>
                <span className="nav-label">{group.label}</span>
                {group.items.map((item) => {
                  const Icon = item.icon;
                  const active = route.path === item.path;
                  const badge =
                    item.path === '/vulnerabilities' && critical + high > 0
                      ? critical + high
                      : item.path === '/images' && (overview.data?.workloads.staleImages ?? 0) > 0
                        ? overview.data?.workloads.staleImages
                        : null;
                  return (
                    <a
                      key={item.path}
                      className="nav-item"
                      href={item.path}
                      aria-current={active ? 'page' : undefined}
                      onClick={(event) => {
                        event.preventDefault();
                        navigate(item.path);
                      }}
                    >
                      <Icon width={15} height={15} />
                      <span>{item.label}</span>
                      {badge ? <span className="nav-count">{badge}</span> : null}
                    </a>
                  );
                })}
              </div>
            ))}
          </nav>

          <div className="sidebar-footer">
            <div className="sidebar-status">
              <span className={`status-dot ${runningScans > 0 ? 'running' : 'online'}`} aria-hidden="true" />
              {runningScans > 0
                ? `${runningScans} scan${runningScans === 1 ? '' : 's'} running`
                : queuedScans > 0
                  ? `${queuedScans} queued`
                  : 'Scanner idle'}
            </div>
            <div className="sidebar-status">
              <span
                className={`status-dot ${system.data?.scanner.available ? 'online' : system.data ? 'offline' : 'unknown'}`}
                aria-hidden="true"
              />
              {system.data
                ? system.data.scanner.available
                  ? `Trivy ${system.data.scanner.version ?? 'ready'}`
                  : 'Trivy unavailable'
                : 'Checking scanner…'}
            </div>
            <span>DockSentinel {health.data?.version ?? ''}</span>
            <span className="dim">Image scanning only — not runtime IDS</span>
          </div>
        </aside>

        <div className="main">
          <header className="topbar">
            <div className="page-heading">
              <h1>{welcome ? 'Welcome' : definition.title}</h1>
              <p>{welcome ? 'A few steps to start watching your Docker images' : definition.subtitle}</p>
            </div>
            <div className="topbar-right">
              {environments.length > 0 ? (
                <div className="env-chips" aria-label="Environment status">
                  {environments.slice(0, 3).map((environment) => (
                    <span
                      key={environment.id}
                      className={`env-chip${environment.status === 'offline' ? ' offline' : ''}`}
                      title={environment.statusMessage ?? `Last contact ${environment.lastContactAt ?? 'never'}`}
                    >
                      <span
                        className={`status-dot ${
                          environment.status === 'online' ? 'online' : environment.status === 'offline' ? 'offline' : 'unknown'
                        }`}
                        aria-hidden="true"
                      />
                      {environment.name}
                    </span>
                  ))}
                  {environments.length > 3 ? (
                    <span className="env-chip">+{environments.length - 3}</span>
                  ) : null}
                </div>
              ) : null}
              {runningScans > 0 ? (
                <span className="env-chip">
                  <span className="spinner" aria-hidden="true" /> {runningScans} scanning
                </span>
              ) : null}
              <div className="relative" ref={menuRef}>
                <button
                  type="button"
                  className="user-button"
                  aria-haspopup="menu"
                  aria-expanded={menuOpen}
                  onClick={() => setMenuOpen((open) => !open)}
                >
                  <span className="avatar" aria-hidden="true">
                    {username.slice(0, 1).toUpperCase()}
                  </span>
                  {username}
                </button>
                {menuOpen ? (
                  <div className="menu" role="menu">
                    <button
                      type="button"
                      role="menuitem"
                      onClick={() => {
                        setMenuOpen(false);
                        setPasswordOpen(true);
                      }}
                    >
                      <IconKey width={14} height={14} /> Change password
                    </button>
                    <button
                      type="button"
                      role="menuitem"
                      onClick={() => {
                        setMenuOpen(false);
                        void onLogout();
                      }}
                    >
                      <IconLogout width={14} height={14} /> Sign out
                    </button>
                  </div>
                ) : null}
              </div>
            </div>
          </header>

          <main id="main" className="content">
            {welcome ? <Welcome onConnected={() => overview.refresh()} /> : <View />}
          </main>
        </div>
      </div>

      {passwordOpen ? (
        <PasswordModal onClose={() => setPasswordOpen(false)} onSubmit={changePassword} />
      ) : null}
    </>
  );
}

function PasswordModal({
  onClose,
  onSubmit,
}: {
  onClose: () => void;
  onSubmit: (current: string, next: string) => Promise<void>;
}) {
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(): Promise<void> {
    if (next !== confirm) {
      setError('New passwords do not match');
      return;
    }
    if (next.length < 12) {
      setError('Password must be at least 12 characters');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await onSubmit(current, next);
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : 'Unable to change password');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      title="Change password"
      subtitle="Other active sessions will be signed out."
      onClose={onClose}
      narrow
      footer={
        <>
          <button type="button" className="btn ghost" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button type="button" className="btn primary" onClick={() => void submit()} disabled={busy}>
            {busy ? <span className="spinner" aria-hidden="true" /> : null}
            Update password
          </button>
        </>
      }
    >
      <div className="form-grid" style={{ gridTemplateColumns: '1fr' }}>
        <Field label="Current password" htmlFor="current-password">
          <input
            id="current-password"
            className="input"
            type="password"
            autoComplete="current-password"
            value={current}
            onChange={(event) => setCurrent(event.target.value)}
          />
        </Field>
        <Field label="New password" htmlFor="new-password" hint="At least 12 characters.">
          <input
            id="new-password"
            className="input"
            type="password"
            autoComplete="new-password"
            value={next}
            onChange={(event) => setNext(event.target.value)}
          />
        </Field>
        <Field label="Confirm new password" htmlFor="confirm-new-password">
          <input
            id="confirm-new-password"
            className="input"
            type="password"
            autoComplete="new-password"
            value={confirm}
            onChange={(event) => setConfirm(event.target.value)}
          />
        </Field>
      </div>
      {error ? (
        <div className="form-error" role="alert" style={{ marginTop: 12 }}>
          <IconAlert width={16} height={16} /> {error}
        </div>
      ) : null}
    </Modal>
  );
}

function NotFound() {
  return (
    <div className="card">
      <div className="empty">
        <IconAlert width={26} height={26} />
        <h3>Page not found</h3>
        <p>The page you requested does not exist in this DockSentinel version.</p>
        <button type="button" className="btn primary" onClick={() => navigate('/')}>
          Back to overview
        </button>
      </div>
    </div>
  );
}
