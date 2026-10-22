import type { Db } from '../db/index.ts';
import { nowIso } from '../util/time.ts';

export type AlertKind =
  | 'new_findings'
  | 'resolved_findings'
  | 'fix_available'
  | 'known_exploited'
  | 'scan_failed'
  | 'stale_scan'
  | 'test';

export type AlertStatus = 'pending' | 'sending' | 'sent' | 'failed' | 'suppressed';

export interface AlertRecord {
  id: number;
  dedupeKey: string;
  kind: AlertKind;
  severity: string | null;
  environmentId: number | null;
  imageId: string | null;
  title: string;
  body: string;
  priority: number;
  tags: string | null;
  status: AlertStatus;
  attempts: number;
  nextAttemptAt: string | null;
  lastError: string | null;
  deliveryId: string | null;
  createdAt: string;
  updatedAt: string;
  sentAt: string | null;
}

interface AlertRow {
  id: number;
  dedupe_key: string;
  kind: AlertKind;
  severity: string | null;
  environment_id: number | null;
  image_id: string | null;
  title: string;
  body: string;
  priority: number;
  tags: string | null;
  status: AlertStatus;
  attempts: number;
  next_attempt_at: string | null;
  last_error: string | null;
  delivery_id: string | null;
  created_at: string;
  updated_at: string;
  sent_at: string | null;
}

function mapAlert(row: AlertRow): AlertRecord {
  return {
    id: row.id,
    dedupeKey: row.dedupe_key,
    kind: row.kind,
    severity: row.severity,
    environmentId: row.environment_id,
    imageId: row.image_id,
    title: row.title,
    body: row.body,
    priority: row.priority,
    tags: row.tags,
    status: row.status,
    attempts: row.attempts,
    nextAttemptAt: row.next_attempt_at,
    lastError: row.last_error,
    deliveryId: row.delivery_id,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    sentAt: row.sent_at,
  };
}

export interface CreateAlertInput {
  dedupeKey: string;
  kind: AlertKind;
  severity: string | null;
  environmentId: number | null;
  imageId: string | null;
  title: string;
  body: string;
  priority: number;
  tags: string | null;
}

/** Inserts an alert once per dedupe key. Returns null when the same alert already exists. */
export function createAlert(db: Db, input: CreateAlertInput): number | null {
  const now = nowIso();
  const result = db.run(
    `INSERT OR IGNORE INTO alerts
      (dedupe_key, kind, severity, environment_id, image_id, title, body, priority, tags, status, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)`,
    [
      input.dedupeKey,
      input.kind,
      input.severity,
      input.environmentId,
      input.imageId,
      input.title.slice(0, 300),
      input.body,
      Math.min(5, Math.max(1, input.priority)),
      input.tags,
      now,
      now,
    ],
  );
  return result.changes > 0 ? result.lastInsertRowid : null;
}


export interface AlertFilters {
  status?: AlertStatus;
  kind?: AlertKind;
  page: number;
  pageSize: number;
}

export function listAlerts(db: Db, filters: AlertFilters): { items: AlertRecord[]; total: number } {
  const conditions: string[] = [];
  const params: (string | number)[] = [];
  if (filters.status) {
    conditions.push('status = ?');
    params.push(filters.status);
  }
  if (filters.kind) {
    conditions.push('kind = ?');
    params.push(filters.kind);
  }
  const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  const total = db.get<{ count: number }>(`SELECT COUNT(*) AS count FROM alerts ${where}`, params)?.count ?? 0;
  const rows = db.all<AlertRow>(
    `SELECT * FROM alerts ${where} ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`,
    [...params, filters.pageSize, (filters.page - 1) * filters.pageSize],
  );
  return { items: rows.map(mapAlert), total };
}

export function pendingAlerts(db: Db, limit: number): AlertRecord[] {
  return db
    .all<AlertRow>(
      `SELECT * FROM alerts
       WHERE status = 'pending' AND (next_attempt_at IS NULL OR next_attempt_at <= ?)
       ORDER BY created_at ASC, id ASC LIMIT ?`,
      [nowIso(), limit],
    )
    .map(mapAlert);
}

export function claimAlert(db: Db, id: number): boolean {
  const result = db.run(
    `UPDATE alerts SET status = 'sending', attempts = attempts + 1, updated_at = ?
     WHERE id = ? AND status = 'pending'`,
    [nowIso(), id],
  );
  return result.changes > 0;
}

export function markAlertSent(db: Db, id: number): void {
  const now = nowIso();
  db.run(
    `UPDATE alerts SET status = 'sent', sent_at = ?, updated_at = ?, last_error = NULL, next_attempt_at = NULL
     WHERE id = ?`,
    [now, now, id],
  );
}

export function markAlertFailed(db: Db, id: number, error: string, retryAt: string | null): void {
  db.run(
    `UPDATE alerts SET status = ?, last_error = ?, next_attempt_at = ?, updated_at = ? WHERE id = ?`,
    [retryAt ? 'pending' : 'failed', error.slice(0, 500), retryAt, nowIso(), id],
  );
}

/** Alerts stuck in "sending" after a crash are retried on the next start. */
export function resetSendingAlerts(db: Db): number {
  const result = db.run(`UPDATE alerts SET status = 'pending', updated_at = ? WHERE status = 'sending'`, [nowIso()]);
  return result.changes;
}

export function alertStatusCounts(db: Db, since: string): Record<AlertStatus | 'total', number> {
  const row = db.get<Record<string, number>>(
    `SELECT
       SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) AS pending,
       SUM(CASE WHEN status = 'sent' THEN 1 ELSE 0 END) AS sent,
       SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed,
       SUM(CASE WHEN status = 'suppressed' THEN 1 ELSE 0 END) AS suppressed,
       COUNT(*) AS total
     FROM alerts WHERE created_at >= ?`,
    [since],
  );
  return {
    pending: Number(row?.pending ?? 0),
    sending: 0,
    sent: Number(row?.sent ?? 0),
    failed: Number(row?.failed ?? 0),
    suppressed: Number(row?.suppressed ?? 0),
    total: Number(row?.total ?? 0),
  };
}

export function pruneAlerts(db: Db, cutoff: string): number {
  const result = db.run(`DELETE FROM alerts WHERE created_at < ? AND status IN ('sent','failed','suppressed')`, [
    cutoff,
  ]);
  return result.changes;
}
