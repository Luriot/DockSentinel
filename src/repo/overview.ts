import type { Db } from '../db/index.ts';
import type { AppSettings } from './settings.ts';
import { listFindings } from './findings.ts';
import { recentFindingEvents } from './findings.ts';
import { recentScans, scanStatusCounts } from './scans.ts';
import { alertStatusCounts } from './alerts.ts';
import { getKevStatus, type KevStatus } from './kev.ts';

export interface EnvironmentSummary {
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
  changes: {
    newFindings24h: number;
    resolvedFindings24h: number;
  };
  environments: EnvironmentSummary[];
  scans: {
    queued: number;
    running: number;
    success24h: number;
    failed24h: number;
    recent: ReturnType<typeof recentScans>;
    lastSuccessfulAt: string | null;
  };
  alerts: {
    pending: number;
    sent24h: number;
    failed24h: number;
  };
  findings: {
    top: ReturnType<typeof listFindings>['items'];
  };
  events: ReturnType<typeof recentFindingEvents>;
  kev: KevStatus;
  lastDiscoveryAt: string | null;
  freshnessHours: number;
}

const AFFECTED_SEVERITIES = `('CRITICAL','HIGH')`;

export function buildOverview(db: Db, settings: AppSettings, now: Date = new Date()): OverviewData {
  const since24h = new Date(now.getTime() - 24 * 3_600_000).toISOString();
  const staleBefore = new Date(now.getTime() - settings.freshnessHours * 3_600_000).toISOString();

  const severityCounts = db.get<Record<string, number | null>>(
    `SELECT
       SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) AS critical,
       SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) AS high,
       SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END) AS medium,
       SUM(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END) AS low,
       SUM(CASE WHEN severity = 'UNKNOWN' THEN 1 ELSE 0 END) AS unknown,
       COUNT(*) AS total,
       SUM(CASE WHEN kev = 1 THEN 1 ELSE 0 END) AS kev,
       SUM(CASE WHEN fixed_version IS NOT NULL AND fixed_version <> '' THEN 1 ELSE 0 END) AS fixable
     FROM findings WHERE resolved_at IS NULL AND triage_status NOT IN ('ignored','false_positive')`,
  );

  const affectedRunning = db.get<{ count: number }>(
    `SELECT COUNT(DISTINCT c.id) AS count FROM containers c
     WHERE c.present = 1 AND c.state = 'running'
       AND EXISTS (SELECT 1 FROM findings f WHERE f.image_id = c.image_id AND f.resolved_at IS NULL
                   AND f.triage_status NOT IN ('ignored','false_positive')
                   AND f.severity IN ${AFFECTED_SEVERITIES})`,
  )?.count ?? 0;

  const runningContainers = db.get<{ count: number }>(
    `SELECT COUNT(*) AS count FROM containers WHERE present = 1 AND state = 'running'`,
  )?.count ?? 0;

  const affectedImages = db.get<{ count: number }>(
    `SELECT COUNT(*) AS count FROM images i
     WHERE EXISTS (SELECT 1 FROM findings f WHERE f.image_id = i.image_id AND f.resolved_at IS NULL
                   AND f.triage_status NOT IN ('ignored','false_positive')
                   AND f.severity IN ${AFFECTED_SEVERITIES})
       AND EXISTS (SELECT 1 FROM containers c WHERE c.image_id = i.image_id AND c.present = 1)`,
  )?.count ?? 0;

  const totalImages = db.get<{ count: number }>(
    `SELECT COUNT(*) AS count FROM images i
     WHERE EXISTS (SELECT 1 FROM containers c WHERE c.image_id = i.image_id AND c.present = 1)`,
  )?.count ?? 0;

  const staleImages = db.get<{ count: number }>(
    `SELECT COUNT(*) AS count FROM images i
     WHERE EXISTS (SELECT 1 FROM containers c WHERE c.image_id = i.image_id AND c.present = 1)
       AND (i.last_success_at IS NULL OR i.last_success_at < ?)`,
    [staleBefore],
  )?.count ?? 0;

  const newFindings24h = db.get<{ count: number }>(
    `SELECT COUNT(*) AS count FROM finding_events WHERE kind = 'appeared' AND created_at >= ?`,
    [since24h],
  )?.count ?? 0;
  const resolvedFindings24h = db.get<{ count: number }>(
    `SELECT COUNT(*) AS count FROM finding_events WHERE kind = 'resolved' AND created_at >= ?`,
    [since24h],
  )?.count ?? 0;

  const environments = db
    .all<{
      id: number;
      name: string;
      kind: string;
      status: 'unknown' | 'online' | 'offline';
      status_message: string | null;
      enabled: number;
      scan_enabled: number;
      last_contact_at: string | null;
      last_discovery_at: string | null;
      containers: number;
      running_containers: number;
      images: number;
    }>(
      `SELECT e.id, e.name, e.kind, e.status, e.status_message, e.enabled, e.scan_enabled,
              e.last_contact_at, e.last_discovery_at,
              (SELECT COUNT(*) FROM containers c WHERE c.environment_id = e.id AND c.present = 1) AS containers,
              (SELECT COUNT(*) FROM containers c WHERE c.environment_id = e.id AND c.present = 1 AND c.state = 'running') AS running_containers,
              (SELECT COUNT(*) FROM image_locations l WHERE l.environment_id = e.id) AS images
       FROM environments e ORDER BY e.name COLLATE NOCASE`,
    )
    .map((row) => ({
      id: row.id,
      name: row.name,
      kind: row.kind,
      status: row.status,
      statusMessage: row.status_message,
      enabled: row.enabled === 1,
      scanEnabled: row.scan_enabled === 1,
      lastContactAt: row.last_contact_at,
      lastDiscoveryAt: row.last_discovery_at,
      containers: row.containers,
      runningContainers: row.running_containers,
      images: row.images,
    }));

  const scanCounts = scanStatusCounts(db, since24h);
  const lastSuccessful = db.get<{ finished_at: string | null }>(
    `SELECT MAX(finished_at) AS finished_at FROM scans WHERE status = 'success'`,
  )?.finished_at ?? null;
  const alertCounts = alertStatusCounts(db, since24h);

  const findings = listFindings(db, {
    severities: ['CRITICAL', 'HIGH'],
    page: 1,
    pageSize: 8,
    state: 'open',
  });

  const lastDiscoveryAt =
    db.get<{ value: string | null }>('SELECT MAX(last_discovery_at) AS value FROM environments')?.value ?? null;

  return {
    counts: {
      critical: Number(severityCounts?.critical ?? 0),
      high: Number(severityCounts?.high ?? 0),
      medium: Number(severityCounts?.medium ?? 0),
      low: Number(severityCounts?.low ?? 0),
      unknown: Number(severityCounts?.unknown ?? 0),
      total: Number(severityCounts?.total ?? 0),
      kev: Number(severityCounts?.kev ?? 0),
      fixable: Number(severityCounts?.fixable ?? 0),
    },
    workloads: {
      runningContainers,
      affectedRunningContainers: affectedRunning,
      affectedImages,
      totalImages,
      staleImages,
    },
    changes: { newFindings24h, resolvedFindings24h },
    environments,
    scans: {
      queued: scanCounts.queued,
      running: scanCounts.running,
      success24h: scanCounts.success,
      failed24h: scanCounts.failed,
      recent: recentScans(db, 6),
      lastSuccessfulAt: lastSuccessful,
    },
    alerts: {
      pending: alertCounts.pending,
      sent24h: alertCounts.sent,
      failed24h: alertCounts.failed,
    },
    findings: { top: findings.items },
    events: recentFindingEvents(db, 10),
    kev: getKevStatus(db),
    lastDiscoveryAt,
    freshnessHours: settings.freshnessHours,
  };
}
