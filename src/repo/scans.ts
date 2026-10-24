import type { Db } from '../db/index.ts';
import { nowIso } from '../util/time.ts';
import type { ScanProfile } from '../scanner/trivy.ts';

export type ScanStatus = 'queued' | 'running' | 'success' | 'failed' | 'cancelled';
export type ScanKind = 'vulnerability' | 'content';
export type ScanTrigger = 'manual' | 'schedule' | 'new_image' | 'retry';

export interface ScanRecord {
  id: number;
  environmentId: number | null;
  imageId: string;
  imageRef: string;
  kind?: ScanKind;
  profile: ScanProfile;
  trigger: ScanTrigger;
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

interface ScanRow {
  id: number;
  environment_id: number | null;
  image_id: string;
  image_ref: string;
  kind: ScanKind;
  profile: ScanProfile;
  trigger: ScanTrigger;
  status: ScanStatus;
  priority: number;
  queued_at: string;
  run_after: string | null;
  started_at: string | null;
  finished_at: string | null;
  duration_ms: number | null;
  scanner: string;
  scanner_version: string | null;
  db_version: string | null;
  db_updated_at: string | null;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  unknown_count: number;
  total_count: number;
  fixable_count: number;
  error_code: string | null;
  error_message: string | null;
  exit_code: number | null;
  attempts: number;
  warnings: string;
}

function mapScan(row: ScanRow): ScanRecord {
  return {
    id: row.id,
    environmentId: row.environment_id,
    imageId: row.image_id,
    imageRef: row.image_ref,
    kind: row.kind,
    profile: row.profile,
    trigger: row.trigger,
    status: row.status,
    priority: row.priority,
    queuedAt: row.queued_at,
    runAfter: row.run_after,
    startedAt: row.started_at,
    finishedAt: row.finished_at,
    durationMs: row.duration_ms,
    scanner: row.scanner,
    scannerVersion: row.scanner_version,
    dbVersion: row.db_version,
    dbUpdatedAt: row.db_updated_at,
    critical: row.critical_count,
    high: row.high_count,
    medium: row.medium_count,
    low: row.low_count,
    unknown: row.unknown_count,
    total: row.total_count,
    fixable: row.fixable_count,
    errorCode: row.error_code,
    errorMessage: row.error_message,
    exitCode: row.exit_code,
    attempts: row.attempts,
    warnings: safeParseArray(row.warnings),
  };
}

function safeParseArray(raw: string | null): string[] {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw) as unknown;
    return Array.isArray(parsed) ? parsed.filter((value): value is string => typeof value === 'string') : [];
  } catch {
    return [];
  }
}

export function hasActiveScan(db: Db, imageId: string): boolean {
  const row = db.get<{ count: number }>(
    `SELECT COUNT(*) AS count FROM scans WHERE image_id = ? AND status IN ('queued','running')`,
    [imageId],
  );
  return (row?.count ?? 0) > 0;
}

export interface QueueScanInput {
  environmentId: number | null;
  imageId: string;
  imageRef: string;
  kind?: ScanKind;
  profile: ScanProfile;
  trigger: ScanTrigger;
  priority?: number;
  runAfter?: string | null;
}

export function queueScan(db: Db, input: QueueScanInput, ifIdle = true): number | null {
  if (ifIdle && hasActiveScan(db, input.imageId)) return null;
  const result = db.run(
    `INSERT INTO scans (environment_id, image_id, image_ref, kind, profile, trigger, status, priority, queued_at, run_after, attempts)
     VALUES (?, ?, ?, ?, ?, ?, 'queued', ?, ?, ?, 1)`,
    [
      input.environmentId,
      input.imageId,
      input.imageRef.slice(0, 400),
      input.kind ?? 'vulnerability',
      input.profile,
      input.trigger,
      input.priority ?? 0,
      nowIso(),
      input.runAfter ?? null,
    ],
  );
  return result.lastInsertRowid;
}

export function getScan(db: Db, id: number): ScanRecord | null {
  const row = db.get<ScanRow>('SELECT * FROM scans WHERE id = ?', [id]);
  return row ? mapScan(row) : null;
}

/** Claims one ready queued scan, never starting two scans for the same environment at once. */
export function claimNextScan(db: Db): ScanRecord | null {
  const now = nowIso();
  return db.transaction(() => {
    const row = db.get<ScanRow>(
      `SELECT s.* FROM scans s
       WHERE s.status = 'queued' AND (s.run_after IS NULL OR s.run_after <= ?)
         AND NOT EXISTS (
           SELECT 1 FROM scans r WHERE r.status = 'running' AND r.environment_id IS s.environment_id
         )
       ORDER BY s.priority DESC, s.queued_at ASC
       LIMIT 1`,
      [now],
    );
    if (!row) return null;
    const claimed = db.run(
      `UPDATE scans SET status = 'running', started_at = ?, error_code = NULL, error_message = NULL
       WHERE id = ? AND status = 'queued'`,
      [now, row.id],
    );
    if (claimed.changes === 0) return null;
    return { ...mapScan(row), status: 'running', startedAt: now };
  });
}

export function markScanSuccess(
  db: Db,
  id: number,
  result: {
    environmentId: number | null;
    durationMs: number;
    scannerVersion: string | null;
    dbVersion: string | null;
    dbUpdatedAt: string | null;
    counts: { CRITICAL: number; HIGH: number; MEDIUM: number; LOW: number; UNKNOWN: number; TOTAL: number; FIXABLE: number };
    exitCode: number | null;
    warnings: string[];
  },
): void {
  db.run(
    `UPDATE scans SET status = 'success', finished_at = ?, duration_ms = ?, environment_id = ?,
       scanner_version = ?, db_version = ?, db_updated_at = ?,
       critical_count = ?, high_count = ?, medium_count = ?, low_count = ?, unknown_count = ?,
       total_count = ?, fixable_count = ?, exit_code = ?, warnings = ?
     WHERE id = ?`,
    [
      nowIso(),
      result.durationMs,
      result.environmentId,
      result.scannerVersion,
      result.dbVersion,
      result.dbUpdatedAt,
      result.counts.CRITICAL,
      result.counts.HIGH,
      result.counts.MEDIUM,
      result.counts.LOW,
      result.counts.UNKNOWN,
      result.counts.TOTAL,
      result.counts.FIXABLE,
      result.exitCode,
      JSON.stringify(result.warnings.slice(0, 20)),
      id,
    ],
  );
}

export function markScanFailed(
  db: Db,
  id: number,
  result: {
    errorCode: string;
    errorMessage: string;
    exitCode: number | null;
    retryAt?: string | null;
    warnings?: string[];
  },
): void {
  if (result.retryAt) {
    db.run(
      `UPDATE scans SET status = 'queued', run_after = ?, error_code = ?, error_message = ?, exit_code = ?,
         warnings = ?, attempts = attempts + 1
       WHERE id = ?`,
      [
        result.retryAt,
        result.errorCode,
        result.errorMessage.slice(0, 1000),
        result.exitCode,
        JSON.stringify((result.warnings ?? []).slice(0, 20)),
        id,
      ],
    );
    return;
  }
  db.run(
    `UPDATE scans SET status = 'failed', finished_at = ?,
       duration_ms = CAST((julianday(?) - julianday(COALESCE(started_at, queued_at))) * 86400000 AS INTEGER),
       error_code = ?, error_message = ?, exit_code = ?, warnings = ?
     WHERE id = ?`,
    [
      nowIso(),
      nowIso(),
      result.errorCode,
      result.errorMessage.slice(0, 1000),
      result.exitCode,
      JSON.stringify((result.warnings ?? []).slice(0, 20)),
      id,
    ],
  );
}

export function markScanCancelled(db: Db, id: number, message: string): void {
  const now = nowIso();
  db.run(
    `UPDATE scans SET status = 'cancelled', finished_at = ?, error_code = 'cancelled', error_message = ?,
       duration_ms = CAST((julianday(?) - julianday(started_at)) * 86400000 AS INTEGER)
     WHERE id = ? AND status IN ('queued','running')`,
    [now, message.slice(0, 500), now, id],
  );
}


export interface ScanFilters {
  status?: ScanStatus;
  kind?: ScanKind;
  imageId?: string;
  environmentId?: number;
  page: number;
  pageSize: number;
}

export function listScans(db: Db, filters: ScanFilters): { items: ScanRecord[]; total: number } {
  const conditions: string[] = [];
  const params: (string | number)[] = [];
  if (filters.status) {
    conditions.push('s.status = ?');
    params.push(filters.status);
  }
  if (filters.kind) {
    conditions.push('s.kind = ?');
    params.push(filters.kind);
  }
  if (filters.imageId) {
    conditions.push('s.image_id = ?');
    params.push(filters.imageId);
  }
  if (filters.environmentId) {
    conditions.push('s.environment_id = ?');
    params.push(filters.environmentId);
  }
  const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  const total = db.get<{ count: number }>(`SELECT COUNT(*) AS count FROM scans s ${where}`, params)?.count ?? 0;
  const rows = db.all<ScanRow>(
    `SELECT s.* FROM scans s ${where} ORDER BY s.queued_at DESC, s.id DESC LIMIT ? OFFSET ?`,
    [...params, filters.pageSize, (filters.page - 1) * filters.pageSize],
  );
  return { items: rows.map(mapScan), total };
}

export function recentScans(db: Db, limit = 10, kind: ScanKind = 'vulnerability'): ScanRecord[] {
  return db
    .all<ScanRow>('SELECT * FROM scans WHERE kind = ? ORDER BY queued_at DESC, id DESC LIMIT ?', [kind, limit])
    .map(mapScan);
}

export function scanStatusCounts(
  db: Db,
  since: string,
  kind: ScanKind = 'vulnerability',
): Record<ScanStatus, number> {
  const row = db.get<Record<string, number>>(
    `SELECT
       SUM(CASE WHEN status = 'queued' THEN 1 ELSE 0 END) AS queued,
       SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) AS running,
       SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) AS success,
       SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed,
       SUM(CASE WHEN status = 'cancelled' THEN 1 ELSE 0 END) AS cancelled
     FROM scans WHERE kind = ? AND queued_at >= ?`,
    [kind, since],
  );
  return {
    queued: Number(row?.queued ?? 0),
    running: Number(row?.running ?? 0),
    success: Number(row?.success ?? 0),
    failed: Number(row?.failed ?? 0),
    cancelled: Number(row?.cancelled ?? 0),
  };
}

/** Keeps the most recent scan per image forever; older successful history follows retention. */
export function pruneScans(db: Db, cutoff: string): number {
  const result = db.run(
    `DELETE FROM scans
     WHERE finished_at IS NOT NULL AND finished_at < ?
       AND id NOT IN (SELECT MAX(id) FROM scans GROUP BY image_id, kind)`,
    [cutoff],
  );
  return result.changes;
}

