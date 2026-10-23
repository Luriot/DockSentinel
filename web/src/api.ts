export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
export type PriorityTier = 'P1' | 'P2' | 'P3' | 'P4';
export type ExposureState = 'confirmed' | 'potential' | 'internal' | 'unknown';
export type ScanStatus = 'queued' | 'running' | 'success' | 'failed' | 'cancelled';

export interface ApiError extends Error {
  code: string;
  status: number;
  details?: unknown;
}

let csrfToken: string | null = null;
let unauthorizedHandler: (() => void) | null = null;

export function setCsrfToken(token: string | null): void {
  csrfToken = token;
}

export function setUnauthorizedHandler(handler: (() => void) | null): void {
  unauthorizedHandler = handler;
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (csrfToken && method !== 'GET' && method !== 'HEAD') headers['X-CSRF-Token'] = csrfToken;

  let response: Response;
  try {
    response = await fetch(`/api${path}`, {
      method,
      headers,
      credentials: 'same-origin',
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch (error) {
    const apiError = new Error('Unable to reach DockSentinel. Check that the server is running.') as ApiError;
    apiError.code = 'network_error';
    apiError.status = 0;
    throw apiError;
  }

  const text = await response.text();
  let payload: unknown = null;
  try {
    payload = text ? JSON.parse(text) : null;
  } catch {
    payload = null;
  }

  if (!response.ok) {
    const errorPayload = (payload as { error?: { code?: string; message?: string; details?: unknown } } | null)?.error;
    const error = new Error(errorPayload?.message ?? `Request failed with HTTP ${response.status}`) as ApiError;
    error.code = errorPayload?.code ?? 'request_failed';
    error.status = response.status;
    error.details = errorPayload?.details;
    if (response.status === 401 && !path.startsWith('/auth/')) unauthorizedHandler?.();
    throw error;
  }
  return payload as T;
}

export const api = {
  get: <T>(path: string) => request<T>('GET', path),
  post: <T>(path: string, body?: unknown) => request<T>('POST', path, body ?? {}),
  patch: <T>(path: string, body: unknown) => request<T>('PATCH', path, body),
  delete: <T>(path: string) => request<T>('DELETE', path),
};


export interface Priority {
  score: number;
  tier: PriorityTier;
  factors: string[];
}

export interface ContainerPort {
  ip: string | null;
  privatePort: number | null;
  publicPort: number | null;
  type: string | null;
}

export interface ContainerSummary {
  id: string;
  environmentId: number;
  environmentName: string;
  name: string;
  imageRef: string;
  imageId: string | null;
  state: string;
  running: boolean;
  present: boolean;
  exposure: ExposureState;
  exposureReason: string | null;
  labels: Record<string, string>;
  ports: ContainerPort[];
  networkMode: string | null;
  createdTs: string | null;
  firstSeenAt: string;
  lastSeenAt: string;
  critical: number;
  high: number;
  fixable: number;
  lastSuccessAt: string | null;
  lastScanStatus: string | null;
}

export interface FindingView {
  id: number;
  imageId: string;
  target: string;
  class: string | null;
  type: string | null;
  vulnId: string;
  pkgName: string;
  installedVersion: string;
  fixedVersion: string | null;
  severity: Severity;
  status: string | null;
  title: string | null;
  primaryUrl: string | null;
  cvssScore: number | null;
  cvssSource: string | null;
  cvssVector: string | null;
  publishedAt: string | null;
  modifiedAt: string | null;
  kev: -1 | 0 | 1;
  kevAddedAt: string | null;
  episode: number;
  firstSeenAt: string;
  lastSeenAt: string;
  lastScanId: number | null;
  resolvedAt: string | null;
  priority: Priority;
  containers: ContainerSummary[];
  containerCount: number;
  runningContainerCount: number;
  environmentNames: string[];
  exposure: ExposureState | null;
}

export interface SeverityCounts {
  CRITICAL: number;
  HIGH: number;
  MEDIUM: number;
  LOW: number;
  UNKNOWN: number;
}

export interface ImageReference {
  environmentId: number;
  environmentName: string;
  reference: string;
  tag: string | null;
}

export interface ImageSummary {
  imageId: string;
  repoDigests: string[];
  osFamily: string | null;
  osVersion: string | null;
  sizeBytes: number | null;
  createdTs: string | null;
  firstSeenAt: string;
  lastScanAt: string | null;
  lastScanStatus: string | null;
  lastSuccessAt: string | null;
  lastSuccessScanId: number | null;
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
  fixable: number;
  containerCount: number;
  runningContainerCount: number;
  environmentCount: number;
  references: ImageReference[];
}

export interface EnvironmentSummary {
  id: number;
  name: string;
  kind: 'unix' | 'tcp' | 'tls';
  address: string;
  status: 'unknown' | 'online' | 'offline';
  statusMessage: string | null;
  enabled: boolean;
  scanEnabled: boolean;
  quickIntervalHours: number;
  standardIntervalHours: number;
  minAlertSeverity: Severity;
  tlsSkipVerify: boolean;
  hasTls: boolean;
  createdAt: string;
  updatedAt: string;
  lastContactAt: string | null;
  lastDiscoveryAt: string | null;
  counts: {
    containers: number;
    runningContainers: number;
    images: number;
    critical: number;
    high: number;
  };
}

export interface ScanRecord {
  id: number;
  environmentId: number | null;
  imageId: string;
  imageRef: string;
  profile: 'quick' | 'standard';
  trigger: 'manual' | 'schedule' | 'new_image' | 'retry';
  status: ScanStatus;
  priority: number;
  queuedAt: string;
  runAfter: string | null;
  startedAt: string | null;
  finishedAt: string | null;
  durationMs: number | null;
  scanner: string;
  scannerVersion: string | null;
  dbVersion: string | null;
  dbUpdatedAt: string | null;
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
  total: number;
  fixable: number;
  errorCode: string | null;
  errorMessage: string | null;
  exitCode: number | null;
  attempts: number;
  warnings: string[];
}

export interface AlertRecord {
  id: number;
  dedupeKey: string;
  kind: string;
  severity: string | null;
  environmentId: number | null;
  imageId: string | null;
  title: string;
  body: string;
  priority: number;
  tags: string | null;
  status: 'pending' | 'sending' | 'sent' | 'failed';
  attempts: number;
  nextAttemptAt: string | null;
  lastError: string | null;
  createdAt: string;
  updatedAt: string;
  sentAt: string | null;
}

export interface KevStatus {
  status: 'idle' | 'ok' | 'error';
  syncedAt: string | null;
  catalogVersion: string | null;
  entryCount: number;
  error: string | null;
  available: boolean;
  stale: boolean;
}

export interface ScannerInfo {
  available: boolean;
  version: string | null;
  dbUpdatedAt: string | null;
  dbSchema: string | null;
  checkedAt: string;
  error: string | null;
}

export interface PublicSettings {
  scanConcurrency: number;
  discoveryIntervalMinutes: number;
  defaultQuickIntervalHours: number;
  defaultStandardIntervalHours: number;
  freshnessHours: number;
  minAlertSeverity: Severity;
  alertOnNew: boolean;
  alertOnResolved: boolean;
  alertOnKev: boolean;
  alertOnScanFailure: boolean;
  alertOnStale: boolean;
  scanFailureRetries: number;
  scanOnDiscovery: boolean;
  retentionScansDays: number;
  retentionAlertsDays: number;
  retentionResolvedFindingsDays: number;
  retentionEventsDays: number;
  publicUrl: string;
  kevEnabled: boolean;
  ntfy: {
    enabled: boolean;
    baseUrl: string;
    topic: string;
    priority: 'min' | 'low' | 'default' | 'high' | 'urgent' | 'max';
    tags: string;
    authType: 'none' | 'basic' | 'token';
    username: string;
    hasToken: boolean;
    hasPassword: boolean;
  };
}

export interface OverviewData {
  counts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    unknown: number;
    total: number;
    kev: number;
    fixable: number;
  };
  workloads: {
    runningContainers: number;
    affectedRunningContainers: number;
    affectedImages: number;
    totalImages: number;
    staleImages: number;
  };
  changes: { newFindings24h: number; resolvedFindings24h: number };
  environments: {
    id: number;
    name: string;
    kind: string;
    status: 'unknown' | 'online' | 'offline';
    statusMessage: string | null;
    enabled: boolean;
    scanEnabled: boolean;
    lastContactAt: string | null;
    lastDiscoveryAt: string | null;
    containers: number;
    runningContainers: number;
    images: number;
  }[];
  scans: {
    queued: number;
    running: number;
    success24h: number;
    failed24h: number;
    recent: ScanRecord[];
    lastSuccessfulAt: string | null;
  };
  alerts: { pending: number; sent24h: number; failed24h: number };
  findings: { top: FindingView[] };
  events: {
    id: number;
    kind: string;
    detail: string | null;
    createdAt: string;
    scanId: number | null;
    vulnId: string;
    pkgName: string;
    severity: string;
    imageId: string;
    imageRef: string | null;
  }[];
  kev: KevStatus;
  lastDiscoveryAt: string | null;
  freshnessHours: number;
}


export interface SessionInfo {
  needsSetup: boolean;
  authenticated: boolean;
  user: { username: string } | null;
  csrfToken: string | null;
}
