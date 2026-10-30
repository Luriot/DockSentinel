import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
  type SVGProps,
} from 'react';
import { createPortal } from 'react-dom';
import type { ApiError, ExposureState, Severity } from '../api.ts';
import { exposureShortLabel } from '../format.ts';

const svgProps = {
  width: 16,
  height: 16,
  viewBox: '0 0 24 24',
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 1.5,
  strokeLinecap: 'round',
  strokeLinejoin: 'round',
  'aria-hidden': true,
} as const;

type IconProps = SVGProps<SVGSVGElement>;

/** Flat product mark: a container with one signal light. */
export function WatchMark({ size = 18 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <rect x="3.5" y="6" width="17" height="12" rx="2.5" stroke="currentColor" strokeWidth="1.5" />
      <path d="M7.5 12h6" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      <circle cx="17" cy="10" r="1.7" fill="var(--accent)" />
    </svg>
  );
}

export const IconMenu = (props: IconProps) => (
  <svg {...svgProps} {...props}>
    <path d="M4 7h16M4 12h16M4 17h16" />
  </svg>
);

export const IconShield = (props: IconProps) => (
  <svg {...svgProps} {...props}>
    <path d="M12 3l7 3v6c0 4.4-3 7.4-7 9-4-1.6-7-4.6-7-9V6z" />
    <path d="M9.5 12l1.8 1.8L15 10" />
  </svg>
);
export const IconServer = (props: IconProps) => (
  <svg {...svgProps} {...props}>
    <rect x="3" y="4" width="18" height="7" rx="2" />
    <rect x="3" y="13" width="18" height="7" rx="2" />
    <path d="M7 7.5h.01M7 16.5h.01" />
  </svg>
);
export const IconBox = (props: IconProps) => (
  <svg {...svgProps} {...props}>
    <path d="M21 8l-9-5-9 5 9 5 9-5z" />
    <path d="M3 8v8l9 5 9-5V8" />
    <path d="M12 13v8" />
  </svg>
);
export const IconLayers = (props: IconProps) => (
  <svg {...svgProps} {...props}>
    <path d="M12 3l9 5-9 5-9-5 9-5z" />
    <path d="M3 12l9 5 9-5" />
    <path d="M3 16l9 5 9-5" />
  </svg>
);
export const IconBug = (props: IconProps) => (
  <svg {...svgProps} {...props}>
    <path d="M8 6a4 4 0 118 0" />
    <rect x="6" y="8" width="12" height="10" rx="4" />
    <path d="M3 11h3M18 11h3M3 16h3M18 16h3M12 8v10" />
  </svg>
);
export const IconActivity = (props: IconProps) => (
  <svg {...svgProps} {...props}>
    <path d="M3 12h4l2.5-6 4 12 2.5-6H21" />
  </svg>
);
export const IconBell = (props: IconProps) => (
  <svg {...svgProps} {...props}>
    <path d="M18 9a6 6 0 10-12 0c0 6-2 7-2 7h16s-2-1-2-7" />
    <path d="M10 20a2 2 0 004 0" />
  </svg>
);
export const IconSearch = (props: IconProps) => (
  <svg {...svgProps} {...props}>
    <circle cx="11" cy="11" r="7" />
    <path d="M20 20l-3.5-3.5" />
  </svg>
);
export const IconRefresh = (props: IconProps) => (
  <svg {...svgProps} {...props}>
    <path d="M20 11a8 8 0 10-2.3 5.7" />
    <path d="M20 4v7h-7" />
  </svg>
);
export const IconPlus = (props: IconProps) => (
  <svg {...svgProps} {...props}>
    <path d="M12 5v14M5 12h14" />
  </svg>
);
export const IconX = (props: IconProps) => (
  <svg {...svgProps} {...props}>
    <path d="M6 6l12 12M18 6L6 18" />
  </svg>
);
export const IconAlert = (props: IconProps) => (
  <svg {...svgProps} {...props}>
    <path d="M12 3l9.5 17h-19z" />
    <path d="M12 9v5M12 17.5h.01" />
  </svg>
);
export const IconCheck = (props: IconProps) => (
  <svg {...svgProps} {...props}>
    <path d="M20 6L9 17l-5-5" />
  </svg>
);
export const IconClock = (props: IconProps) => (
  <svg {...svgProps} {...props}>
    <circle cx="12" cy="12" r="9" />
    <path d="M12 7v5l3.5 2" />
  </svg>
);
export const IconExternal = (props: IconProps) => (
  <svg {...svgProps} {...props}>
    <path d="M14 4h6v6" />
    <path d="M20 4l-9 9" />
    <path d="M20 14v5a1 1 0 01-1 1H5a1 1 0 01-1-1V5a1 1 0 011-1h5" />
  </svg>
);
export const IconPlay = (props: IconProps) => (
  <svg {...svgProps} {...props}>
    <path d="M7 4l13 8-13 8z" />
  </svg>
);
export const IconTrash = (props: IconProps) => (
  <svg {...svgProps} {...props}>
    <path d="M4 7h16M9 7V4h6v3M6 7l1 14h10l1-14" />
  </svg>
);
export const IconEdit = (props: IconProps) => (
  <svg {...svgProps} {...props}>
    <path d="M4 20h4L20 8l-4-4L4 16z" />
    <path d="M13.5 6.5l4 4" />
  </svg>
);
export const IconLogout = (props: IconProps) => (
  <svg {...svgProps} {...props}>
    <path d="M9 4H5a1 1 0 00-1 1v14a1 1 0 001 1h4" />
    <path d="M16 8l4 4-4 4M20 12H9" />
  </svg>
);
export const IconKey = (props: IconProps) => (
  <svg {...svgProps} {...props}>
    <circle cx="8" cy="15" r="4" />
    <path d="M10.8 12.2L20 3M16 3h4v4" />
  </svg>
);
export const IconChevronLeft = (props: IconProps) => (
  <svg {...svgProps} {...props}>
    <path d="M15 6l-6 6 6 6" />
  </svg>
);
export const IconChevronRight = (props: IconProps) => (
  <svg {...svgProps} {...props}>
    <path d="M9 6l6 6-6 6" />
  </svg>
);
export function SeverityBadge({ severity, count }: { severity: Severity | string; count?: number }) {
  return (
    <span className={`badge sev-${severity}`}>
      <span className="dot" aria-hidden="true" />
      {severity === 'UNKNOWN' ? 'Unknown' : severity.charAt(0) + severity.slice(1).toLowerCase()}
      {count !== undefined ? ` · ${count}` : ''}
    </span>
  );
}

export function PriorityBadge({
  tier,
  factors,
  label,
  rank,
}: {
  tier: string;
  factors?: string[];
  label?: string;
  /** Position in a ranked list. Replaces the tier code, which stops discriminating when every row ties. */
  rank?: number;
}) {
  return (
    <span
      className={`tier tier-${tier}`}
      title={factors?.join(' · ')}
      aria-label={`Priority ${tier}${rank === undefined ? '' : `, ranked ${rank}`}${label ? `: ${label}` : ''}`}
    >
      {rank === undefined ? tier : `#${rank}`}
      {label ? (
        <span className="tier-label">
          {' · '}
          {label}
        </span>
      ) : null}
    </span>
  );
}

export function KevBadge({ kev }: { kev: number }) {
  if (kev === 1) {
    return (
      <span className="badge kev" title="Listed in CISA's Known Exploited Vulnerabilities catalog">
        <span className="dot" aria-hidden="true" /> Known exploited
      </span>
    );
  }
  if (kev === -1) {
    return <span className="badge neutral" title="KEV catalog has not been synchronised">KEV unknown</span>;
  }
  return null;
}

export function FixBadge({ fixedVersion }: { fixedVersion: string | null }) {
  if (!fixedVersion) return <span className="badge neutral">No fix listed</span>;
  return (
    <span
      className="badge neutral"
      title={`Fixed version: ${fixedVersion}. Not applied until the image is rebuilt and rescanned.`}
    >
      Fix in {fixedVersion.length > 18 ? `${fixedVersion.slice(0, 16)}…` : fixedVersion}
    </span>
  );
}

export function ExposureBadge({ state, reason }: { state: ExposureState | null | undefined; reason?: string | null }) {
  const tone = state === 'confirmed' || state === 'potential' ? 'accent' : 'neutral';
  return (
    <span className={`badge ${tone}`} title={reason ?? undefined}>
      {exposureShortLabel(state)}
    </span>
  );
}

export function EnvStatusBadge({ status, message }: { status: string; message?: string | null }) {
  const dot = status === 'online' ? 'online' : status === 'offline' ? 'offline' : 'unknown';
  const label = status === 'online' ? 'Online' : status === 'offline' ? 'Offline' : 'Unknown';
  return (
    <span className="status-line" title={message ?? undefined}>
      <span className={`status-dot ${dot}`} aria-hidden="true" />
      {label}
    </span>
  );
}

export function ScanStatusBadge({ status }: { status: string | null | undefined }) {
  const known = status ?? 'never';
  const label =
    known === 'success'
      ? 'Succeeded'
      : known === 'failed'
        ? 'Failed'
        : known === 'running'
          ? 'Running'
          : known === 'queued'
            ? 'Queued'
            : known === 'cancelled'
              ? 'Cancelled'
              : 'Never scanned';
  return (
    <span className="status-line">
      <span className={`status-dot ${known}`} aria-hidden="true" />
      {label}
    </span>
  );
}

export function AlertStatusBadge({ status }: { status: string }) {
  return (
    <span className="status-line" style={{ textTransform: 'capitalize' }}>
      <span className={`status-dot ${status}`} aria-hidden="true" />
      {status}
    </span>
  );
}

export function SeverityPills({
  counts,
}: {
  counts: { critical: number; high: number; medium?: number; low?: number; unknown?: number };
}) {
  const entries: [string, Severity, number][] = [
    ['C', 'CRITICAL', counts.critical],
    ['H', 'HIGH', counts.high],
    ['M', 'MEDIUM', counts.medium ?? 0],
    ['L', 'LOW', counts.low ?? 0],
  ];
  const visible = entries.filter(([, , count]) => count > 0);
  if (visible.length === 0) return <span className="dim tiny">None</span>;
  return (
    <span className="hstack" style={{ gap: 4 }} aria-label="Open findings by severity">
      {visible.map(([letter, severity, count]) => (
        <span key={severity} className={`badge sev-${severity}`} title={`${severity}: ${count}`}>
          {letter} {count}
        </span>
      ))}
      {(counts.unknown ?? 0) > 0 && (
        <span className="badge sev-UNKNOWN" title={`UNKNOWN: ${counts.unknown}`}>
          ? {counts.unknown}
        </span>
      )}
    </span>
  );
}

export function EmptyState({
  icon,
  title,
  children,
  action,
}: {
  icon?: ReactNode;
  title: string;
  children?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="empty">
      {icon ?? <IconSearch width={26} height={26} />}
      <h3>{title}</h3>
      {children ? <p>{children}</p> : null}
      {action}
    </div>
  );
}

export function ErrorPanel({ error, onRetry }: { error: ApiError; onRetry?: () => void }) {
  return (
    <div className="error-panel" role="alert">
      <IconAlert width={17} height={17} />
      <span>
        {error.message}
        {error.code === 'unauthorized' ? ' Please sign in again.' : ''}
      </span>
      {onRetry ? (
        <button type="button" className="btn small ghost" style={{ marginLeft: 'auto' }} onClick={onRetry}>
          Retry
        </button>
      ) : null}
    </div>
  );
}

export function TableSkeleton({ rows = 6, columns = 5 }: { rows?: number; columns?: number }) {
  return (
    <div role="status" aria-live="polite" aria-label="Loading">
      {Array.from({ length: rows }).map((_, rowIndex) => (
        <div key={rowIndex} className="skeleton-row" style={{ gridTemplateColumns: `repeat(${columns}, 1fr)` }}>
          {Array.from({ length: columns }).map((__, columnIndex) => (
            <div key={columnIndex} className="skeleton" style={{ width: `${55 + ((rowIndex + columnIndex) % 4) * 10}%` }} />
          ))}
        </div>
      ))}
    </div>
  );
}

export function InlineLoading({ label = 'Loading…' }: { label?: string }) {
  return (
    <span className="inline-loading" role="status" aria-live="polite">
      <span className="spinner" aria-hidden="true" /> {label}
    </span>
  );
}

export function Pagination({
  page,
  pageSize,
  total,
  onChange,
}: {
  page: number;
  pageSize: number;
  total: number;
  onChange: (page: number) => void;
}) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  return (
    <div className="pagination">
      <span>
        {total === 0 ? 'No results' : `${(page - 1) * pageSize + 1}–${Math.min(page * pageSize, total)} of ${total}`}
      </span>
      <div className="hstack">
        <button
          type="button"
          className="btn small ghost"
          onClick={() => onChange(Math.max(1, page - 1))}
          disabled={page <= 1}
          aria-label="Previous page"
        >
          <IconChevronLeft width={14} height={14} />
        </button>
        <span className="tiny muted">
          Page {page} of {pages}
        </span>
        <button
          type="button"
          className="btn small ghost"
          onClick={() => onChange(Math.min(pages, page + 1))}
          disabled={page >= pages}
          aria-label="Next page"
        >
          <IconChevronRight width={14} height={14} />
        </button>
      </div>
    </div>
  );
}

export function Field({
  label,
  htmlFor,
  hint,
  children,
  className,
}: {
  label: string;
  htmlFor?: string;
  hint?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={`field ${className ?? ''}`}>
      <label htmlFor={htmlFor}>{label}</label>
      {children}
      {hint ? <span className="hint">{hint}</span> : null}
    </div>
  );
}

export function useDialogBehavior(ref: React.RefObject<HTMLElement | null>, onClose: () => void): void {
  const closeRef = useRef(onClose);
  closeRef.current = onClose;

  useEffect(() => {
    const node = ref.current;
    if (!node) return;
    const previous = document.activeElement as HTMLElement | null;
    const focusables = (): HTMLElement[] =>
      Array.from(
        node.querySelectorAll<HTMLElement>(
          'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])',
        ),
      ).filter((element) => element.offsetParent !== null || element === document.activeElement);

    const first = focusables()[0];
    first?.focus();

    const onKey = (event: KeyboardEvent): void => {
      if (event.key === 'Escape') {
        event.preventDefault();
        closeRef.current();
        return;
      }
      if (event.key !== 'Tab') return;
      const items = focusables();
      if (items.length === 0) return;
      const firstItem = items[0];
      const lastItem = items[items.length - 1];
      if (!firstItem || !lastItem) return;
      if (event.shiftKey && document.activeElement === firstItem) {
        event.preventDefault();
        lastItem.focus();
      } else if (!event.shiftKey && document.activeElement === lastItem) {
        event.preventDefault();
        firstItem.focus();
      }
    };

    document.addEventListener('keydown', onKey);
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.removeEventListener('keydown', onKey);
      document.body.style.overflow = previousOverflow;
      previous?.focus?.();
    };
    // Mount-only: the dialog must not steal focus on every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
}

export function Modal({
  title,
  subtitle,
  onClose,
  children,
  footer,
  narrow,
}: {
  title: string;
  subtitle?: string;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  narrow?: boolean;
}) {
  const ref = useRef<HTMLDivElement>(null);
  useDialogBehavior(ref, onClose);
  return createPortal(
    <div
      className="overlay center"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div
        ref={ref}
        className={`modal${narrow ? ' narrow' : ''}`}
        role="dialog"
        aria-modal="true"
        aria-label={title}
      >
        <div className="modal-header">
          <div className="vstack" style={{ flex: 1 }}>
            <h2>{title}</h2>
            {subtitle ? <p className="section-subtitle">{subtitle}</p> : null}
          </div>
          <button type="button" className="icon-btn" onClick={onClose} aria-label="Close dialog">
            <IconX />
          </button>
        </div>
        <div className="modal-body">{children}</div>
        {footer ? <div className="modal-footer">{footer}</div> : null}
      </div>
    </div>,
    document.body,
  );
}

export function Drawer({
  title,
  subtitle,
  onClose,
  children,
  footer,
}: {
  title: string;
  subtitle?: string;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
}) {
  const ref = useRef<HTMLDivElement>(null);
  useDialogBehavior(ref, onClose);
  return createPortal(
    <div
      className="overlay"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <aside ref={ref} className="drawer" role="dialog" aria-modal="true" aria-label={title}>
        <div className="drawer-header">
          <div className="vstack" style={{ flex: 1 }}>
            <h2>{title}</h2>
            {subtitle ? <p className="section-subtitle">{subtitle}</p> : null}
          </div>
          <button type="button" className="icon-btn" onClick={onClose} aria-label="Close panel">
            <IconX />
          </button>
        </div>
        <div className="drawer-body">{children}</div>
        {footer ? <div className="modal-footer">{footer}</div> : null}
      </aside>
    </div>,
    document.body,
  );
}

export function ConfirmDialog({
  title,
  message,
  confirmLabel = 'Confirm',
  danger,
  busy,
  onConfirm,
  onCancel,
}: {
  title: string;
  message: ReactNode;
  confirmLabel?: string;
  danger?: boolean;
  busy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  return (
    <Modal
      title={title}
      onClose={onCancel}
      narrow
      footer={
        <>
          <button type="button" className="btn ghost" onClick={onCancel} disabled={busy}>
            Cancel
          </button>
          <button type="button" className={`btn ${danger ? 'danger' : 'primary'}`} onClick={onConfirm} disabled={busy}>
            {busy ? <span className="spinner" aria-hidden="true" /> : null}
            {confirmLabel}
          </button>
        </>
      }
    >
      <div className={danger ? 'note danger' : 'note'}>{message}</div>
    </Modal>
  );
}

type ToastKind = 'info' | 'success' | 'error';
interface ToastEntry {
  id: number;
  message: string;
  kind: ToastKind;
}

const ToastContext = createContext<(message: string, kind?: ToastKind) => void>(() => undefined);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastEntry[]>([]);
  const counter = useRef(0);

  const push = useCallback((message: string, kind: ToastKind = 'info') => {
    counter.current += 1;
    const id = counter.current;
    setToasts((current) => [...current.slice(-3), { id, message, kind }]);
    setTimeout(() => {
      setToasts((current) => current.filter((toast) => toast.id !== id));
    }, 5200);
  }, []);

  const value = useMemo(() => push, [push]);
  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="toast-stack" aria-live="polite" aria-atomic="false">
        {toasts.map((toast) => (
          <div key={toast.id} className={`toast ${toast.kind}`} role={toast.kind === 'error' ? 'alert' : 'status'}>
            {toast.kind === 'success' ? <IconCheck width={15} height={15} /> : null}
            {toast.kind === 'error' ? <IconAlert width={15} height={15} /> : null}
            <span>{toast.message}</span>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast(): (message: string, kind?: ToastKind) => void {
  return useContext(ToastContext);
}



