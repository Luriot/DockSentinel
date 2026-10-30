import { useEffect, useRef, useState, type ComponentType } from 'react';
import { createPortal } from 'react-dom';
import { api, type OverviewData } from '../api.ts';
import { navigate, useApi, useRoute } from '../hooks.ts';
import { relativeTime } from '../format.ts';
import {
  IconAlert,
  IconKey,
  IconLogout,
  IconMenu,
  IconX,
  WatchMark,
  useDialogBehavior,
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
    subtitle: 'What to patch first',
    component: Overview,
  },
  '/vulnerabilities': {
    title: 'Vulnerabilities',
    subtitle: 'Open findings, ranked',
    component: Vulnerabilities,
  },
  '/content': {
    title: 'Configuration & secrets',
    subtitle: 'Image configuration and secret findings',
    component: Content,
  },
  '/environments': {
    title: 'Docker hosts',
    subtitle: 'The Docker engines DockSentinel watches',
    component: Environments,
  },
  '/containers': {
    title: 'Containers',
    subtitle: 'Workloads, images and exposure',
    component: Containers,
  },
  '/images': {
    title: 'Images',
    subtitle: 'Inventory and scan age',
    component: Images,
  },
  '/scans': {
    title: 'Scans',
    subtitle: 'Queue, history and failures',
    component: Scans,
  },
  '/notifications': {
    title: 'Alerts',
    subtitle: 'ntfy policy and delivery',
    component: Notifications,
  },
  '/status': {
    title: 'System status',
    subtitle: 'Hosts, storage, backups and updates',
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
      { path: '/', label: 'Overview' },
      { path: '/vulnerabilities', label: 'Vulnerabilities' },
      { path: '/content', label: 'Config & secrets' },
    ],
  },
  {
    label: 'Inventory',
    items: [
      { path: '/environments', label: 'Docker hosts' },
      { path: '/containers', label: 'Containers' },
      { path: '/images', label: 'Images' },
    ],
  },
  {
    label: 'Operations',
    items: [
      { path: '/scans', label: 'Scans' },
      { path: '/notifications', label: 'Alerts' },
    ],
  },
  {
    label: 'System',
    items: [
      { path: '/status', label: 'System status' },
      { path: '/settings', label: 'Settings' },
    ],
  },
];

const formatCount = (value: number): string => (value >= 1000 ? `${Math.round(value / 100) / 10}k` : String(value));

interface NavCounts {
  critical: number;
  high: number;
  staleImages: number;
}

function NavList({ path, counts, onNavigate }: { path: string; counts: NavCounts; onNavigate: (path: string) => void }) {
  return (
    <nav className="nav" aria-label="Sections">
      {NAV_GROUPS.map((group) => (
        <div key={group.label} className="nav-group" role="group" aria-label={group.label}>
          <span className="nav-label">{group.label}</span>
          {group.items.map((item) => {
            const badge =
              item.path === '/vulnerabilities' && counts.critical + counts.high > 0
                ? formatCount(counts.critical + counts.high)
                : item.path === '/images' && counts.staleImages > 0
                  ? formatCount(counts.staleImages)
                  : null;
            const badgeTitle =
              item.path === '/vulnerabilities'
                ? `${counts.critical} critical and ${counts.high} high findings`
                : `${counts.staleImages} images with stale results`;
            return (
              <a
                key={item.path}
                className="nav-item"
                href={item.path}
                aria-current={path === item.path ? 'page' : undefined}
                onClick={(event) => {
                  event.preventDefault();
                  onNavigate(item.path);
                }}
              >
                <span className="nav-title">{item.label}</span>
                {badge ? (
                  <span className="nav-count" title={badgeTitle} aria-label={badgeTitle}>
                    {badge}
                  </span>
                ) : null}
              </a>
            );
          })}
        </div>
      ))}
    </nav>
  );
}

interface ShellStatus {
  state: string;
  tone: string;
  trivyTone: string;
  trivyLabel: string;
}

function NavSheet({
  path,
  counts,
  status,
  onClose,
}: {
  path: string;
  counts: NavCounts;
  status: ShellStatus;
  onClose: () => void;
}) {
  const ref = useRef<HTMLDivElement>(null);
  useDialogBehavior(ref, onClose);
  return createPortal(
    <div
      className="nav-backdrop"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div ref={ref} className="nav-sheet" role="dialog" aria-modal="true" aria-label="Navigation">
        <div className="nav-sheet-head">
          <span className="brand">
            <span className="brand-mark">
              <WatchMark size={18} />
            </span>
            <span className="brand-text">
              <span className="brand-name">DockSentinel</span>
              <span className="brand-tag">Docker image watch</span>
            </span>
          </span>
          <button type="button" className="icon-btn" onClick={onClose} aria-label="Close navigation">
            <IconX />
          </button>
        </div>
        <NavList
          path={path}
          counts={counts}
          onNavigate={(target) => {
            onClose();
            navigate(target);
          }}
        />
        <div className="sidebar-footer nav-sheet-footer">
          <div className="sidebar-status">
            <span className={`status-dot ${status.tone}`} aria-hidden="true" />
            {status.state}
          </div>
          <div className="sidebar-status">
            <span className={`status-dot ${status.trivyTone}`} aria-hidden="true" />
            {status.trivyLabel}
          </div>
        </div>
      </div>
    </div>,
    document.body,
  );
}

interface AppShellProps {
  username: string;
  onLogout: () => void | Promise<void>;
  onSessionRefresh: () => void | Promise<void>;
}

export function AppShell({ username, onLogout, onSessionRefresh }: AppShellProps) {
  const route = useRoute();
  // Same cadence as the Overview view so the rail badge and the page cannot drift apart.
  const overview = useApi<OverviewData>('/overview', { intervalMs: 15_000 });
  const system = useApi<{ scanner: { available: boolean; version: string | null }; scans: { active: number } }>(
    '/system',
    { intervalMs: 60_000 },
  );
  const toast = useToast();
  const [menuOpen, setMenuOpen] = useState(false);
  const [navOpen, setNavOpen] = useState(false);
  const [passwordOpen, setPasswordOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    setNavOpen(false);
  }, [route.path]);

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
  const welcome = route.path === '/' && overview.data !== null && overview.data.environments.length === 0;
  const View = definition.component;

  useEffect(() => {
    const label = welcome ? 'Setup' : definition.title;
    document.title = label === 'Overview' ? 'DockSentinel' : `${label} · DockSentinel`;
  }, [definition.title, welcome]);
  const critical = overview.data?.counts.critical ?? 0;
  const high = overview.data?.counts.high ?? 0;
  const runningScans = overview.data?.scans.running ?? 0;
  const queuedScans = overview.data?.scans.queued ?? 0;
  const environments = overview.data?.environments ?? [];
  const lastSuccessfulAt = overview.data?.scans.lastSuccessfulAt ?? null;
  const lastSuccessAge = lastSuccessfulAt ? Date.parse(lastSuccessfulAt) : Number.NaN;
  const dataIsOld = overview.data !== null && (!Number.isFinite(lastSuccessAge) || Date.now() - lastSuccessAge > 24 * 3_600_000);
  const counts: NavCounts = {
    critical,
    high,
    staleImages: overview.data?.workloads.staleImages ?? 0,
  };
  const navCounts = counts;
  const scannerState = runningScans > 0 ? 'Scanning now' : queuedScans > 0 ? 'Scans queued' : 'Scanner idle';
  const shellStatus: ShellStatus = {
    state: scannerState,
    tone: runningScans > 0 ? 'running' : queuedScans > 0 ? 'pending' : 'online',
    trivyTone: system.data?.scanner.available ? 'online' : system.data ? 'offline' : 'unknown',
    trivyLabel: system.data
      ? system.data.scanner.available
        ? `Trivy ${system.data.scanner.version ?? 'ready'}`
        : 'Trivy unavailable'
      : 'Checking Trivy',
  };

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
              <WatchMark size={18} />
            </span>
            <span className="brand-text">
              <span className="brand-name">DockSentinel</span>
              <span className="brand-tag">Docker image watch</span>
            </span>
          </a>

          <NavList path={route.path} counts={navCounts} onNavigate={(path) => navigate(path)} />

          <div className="sidebar-footer">
            <div className="sidebar-status">
              <span className={`status-dot ${runningScans > 0 ? 'running' : queuedScans > 0 ? 'pending' : 'online'}`} aria-hidden="true" />
              {scannerState}
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
                : 'Checking Trivy'}
            </div>
          </div>
        </aside>

        <div className="main">
          <header className="topbar">
            <button
              type="button"
              className="nav-toggle"
              aria-label="Open navigation"
              aria-expanded={navOpen}
              onClick={() => setNavOpen(true)}
            >
              <IconMenu width={18} height={18} />
            </button>
            <a
              className="topbar-brand"
              href="/"
              onClick={(event) => {
                event.preventDefault();
                navigate('/');
              }}
            >
              <span className="brand-mark">
                <WatchMark size={16} />
              </span>
              <span>DockSentinel</span>
            </a>
            <div className="page-heading">
              <h1>{welcome ? 'Setup' : definition.title}</h1>
              <p>{welcome ? 'Connect Docker to start the watch' : definition.subtitle}</p>
            </div>
            <div className="topbar-watch">
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
                  {environments.length > 3 ? <span className="env-chip">+{environments.length - 3}</span> : null}
                </div>
              ) : null}
              {runningScans > 0 ? (
                <span className="env-chip">
                  <span className="spinner" aria-hidden="true" /> {runningScans} scanning
                </span>
              ) : null}
              {overview.data && environments.length > 0 ? (
                <span
                  className={`watch-age${dataIsOld ? ' is-attention' : ''}`}
                  title="Age of the vulnerability data on screen: the last successful scan"
                >
                  <span className="watch-tick" aria-hidden="true" />
                  {lastSuccessfulAt ? `Data ${relativeTime(lastSuccessfulAt)}` : 'No scan yet'}
                </span>
              ) : null}
            </div>
            <div className="topbar-account">
              <div className="relative" ref={menuRef}>
                <button
                  type="button"
                  className="user-button"
                  aria-haspopup="menu"
                  aria-expanded={menuOpen}
                  aria-label={`Account menu for ${username}`}
                  onClick={() => setMenuOpen((open) => !open)}
                >
                  <span className="avatar" aria-hidden="true">
                    {username.slice(0, 1).toUpperCase()}
                  </span>
                  <span className="user-name">{username}</span>
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

      {navOpen ? <NavSheet path={route.path} counts={navCounts} status={shellStatus} onClose={() => setNavOpen(false)} /> : null}
      {passwordOpen ? <PasswordModal onClose={() => setPasswordOpen(false)} onSubmit={changePassword} /> : null}
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
      subtitle="Other active sessions will be signed out"
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
        <Field label="New password" htmlFor="new-password" hint="At least 12 characters">
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
        <IconAlert width={24} height={24} />
        <h3>Page not found</h3>
        <p>The page you requested does not exist in this DockSentinel version.</p>
        <button type="button" className="btn primary" onClick={() => navigate('/')}>
          Back to overview
        </button>
      </div>
    </div>
  );
}
