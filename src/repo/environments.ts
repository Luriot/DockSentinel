import type { Db } from '../db/index.ts';
import { encryptSecret, tryDecryptSecret } from '../secrets.ts';
import { nowIso } from '../util/time.ts';
import type { DockerConnection } from '../docker/client.ts';
import type { Severity } from '../domain/severity.ts';

export interface EnvironmentRecord {
  id: number;
  name: string;
  kind: 'unix' | 'tcp' | 'tls';
  address: string;
  tlsCa: string | null;
  tlsCert: string | null;
  tlsKey: string | null;
  tlsSkipVerify: boolean;
  enabled: boolean;
  scanEnabled: boolean;
  quickIntervalHours: number;
  standardIntervalHours: number;
  minAlertSeverity: Severity;
  status: 'unknown' | 'online' | 'offline';
  statusMessage: string | null;
  lastContactAt: string | null;
  lastDiscoveryAt: string | null;
  createdAt: string;
  updatedAt: string;
}

interface EnvironmentRow {
  id: number;
  name: string;
  kind: 'unix' | 'tcp' | 'tls';
  address: string;
  tls_ca: string | null;
  tls_cert: string | null;
  tls_key: string | null;
  tls_skip_verify: number;
  enabled: number;
  scan_enabled: number;
  quick_interval_hours: number;
  standard_interval_hours: number;
  min_alert_severity: string;
  status: 'unknown' | 'online' | 'offline';
  status_message: string | null;
  last_contact_at: string | null;
  last_discovery_at: string | null;
  created_at: string;
  updated_at: string;
}

function mapRow(row: EnvironmentRow): EnvironmentRecord {
  return {
    id: row.id,
    name: row.name,
    kind: row.kind,
    address: row.address,
    tlsCa: row.tls_ca,
    tlsCert: row.tls_cert,
    tlsKey: row.tls_key,
    tlsSkipVerify: row.tls_skip_verify === 1,
    enabled: row.enabled === 1,
    scanEnabled: row.scan_enabled === 1,
    quickIntervalHours: row.quick_interval_hours,
    standardIntervalHours: row.standard_interval_hours,
    minAlertSeverity: row.min_alert_severity as Severity,
    status: row.status,
    statusMessage: row.status_message,
    lastContactAt: row.last_contact_at,
    lastDiscoveryAt: row.last_discovery_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export function listEnvironments(db: Db): EnvironmentRecord[] {
  return db
    .all<EnvironmentRow>('SELECT * FROM environments ORDER BY name COLLATE NOCASE')
    .map(mapRow);
}

export function getEnvironment(db: Db, id: number): EnvironmentRecord | undefined {
  const row = db.get<EnvironmentRow>('SELECT * FROM environments WHERE id = ?', [id]);
  return row ? mapRow(row) : undefined;
}


export interface EnvironmentInput {
  name: string;
  kind: 'unix' | 'tcp' | 'tls';
  address: string;
  tlsCa?: string | null;
  tlsCert?: string | null;
  tlsKey?: string | null;
  tlsSkipVerify?: boolean;
  enabled?: boolean;
  scanEnabled?: boolean;
  quickIntervalHours?: number;
  standardIntervalHours?: number;
  minAlertSeverity?: Severity;
}

export function createEnvironment(db: Db, input: EnvironmentInput, key: Buffer): number {
  const now = nowIso();
  const useTls = input.kind === 'tls';
  const result = db.run(
    `INSERT INTO environments
      (name, kind, address, tls_ca, tls_cert, tls_key, tls_skip_verify, enabled, scan_enabled,
       quick_interval_hours, standard_interval_hours, min_alert_severity, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      input.name,
      input.kind,
      input.address,
      useTls && input.tlsCa ? encryptSecret(input.tlsCa, key) : null,
      useTls && input.tlsCert ? encryptSecret(input.tlsCert, key) : null,
      useTls && input.tlsKey ? encryptSecret(input.tlsKey, key) : null,
      input.tlsSkipVerify ? 1 : 0,
      input.enabled === false ? 0 : 1,
      input.scanEnabled === false ? 0 : 1,
      input.quickIntervalHours ?? 24,
      input.standardIntervalHours ?? 168,
      input.minAlertSeverity ?? 'HIGH',
      now,
      now,
    ],
  );
  return result.lastInsertRowid;
}

export interface EnvironmentPatch {
  name?: string;
  kind?: 'unix' | 'tcp' | 'tls';
  address?: string;
  /** undefined keeps the stored value, null clears it. */
  tlsCa?: string | null;
  tlsCert?: string | null;
  tlsKey?: string | null;
  tlsSkipVerify?: boolean;
  enabled?: boolean;
  scanEnabled?: boolean;
  quickIntervalHours?: number;
  standardIntervalHours?: number;
  minAlertSeverity?: Severity;
}

export function updateEnvironment(db: Db, id: number, patch: EnvironmentPatch, key: Buffer): void {
  const current = getEnvironment(db, id);
  if (!current) return;
  const now = nowIso();
  const kind = patch.kind ?? current.kind;
  const keepTls = kind === 'tls';
  const tlsCa = !keepTls ? null : patch.tlsCa === undefined ? current.tlsCa : patch.tlsCa ? encryptSecret(patch.tlsCa, key) : null;
  const tlsCert = !keepTls ? null : patch.tlsCert === undefined ? current.tlsCert : patch.tlsCert ? encryptSecret(patch.tlsCert, key) : null;
  const tlsKey = !keepTls ? null : patch.tlsKey === undefined ? current.tlsKey : patch.tlsKey ? encryptSecret(patch.tlsKey, key) : null;

  db.run(
    `UPDATE environments SET
      name = ?, kind = ?, address = ?, tls_ca = ?, tls_cert = ?, tls_key = ?, tls_skip_verify = ?,
      enabled = ?, scan_enabled = ?, quick_interval_hours = ?, standard_interval_hours = ?,
      min_alert_severity = ?, updated_at = ?
     WHERE id = ?`,
    [
      patch.name ?? current.name,
      kind,
      patch.address ?? current.address,
      tlsCa,
      tlsCert,
      tlsKey,
      (patch.tlsSkipVerify ?? current.tlsSkipVerify) ? 1 : 0,
      (patch.enabled ?? current.enabled) ? 1 : 0,
      (patch.scanEnabled ?? current.scanEnabled) ? 1 : 0,
      patch.quickIntervalHours ?? current.quickIntervalHours,
      patch.standardIntervalHours ?? current.standardIntervalHours,
      patch.minAlertSeverity ?? current.minAlertSeverity,
      now,
      id,
    ],
  );
}

export function deleteEnvironment(db: Db, id: number): void {
  db.run('DELETE FROM environments WHERE id = ?', [id]);
}

export function setEnvironmentStatus(
  db: Db,
  id: number,
  status: 'unknown' | 'online' | 'offline',
  message: string | null,
  options: { contact?: boolean; discovered?: boolean } = {},
): void {
  const now = nowIso();
  db.run(
    `UPDATE environments SET status = ?, status_message = ?,
       last_contact_at = CASE WHEN ? = 1 THEN ? ELSE last_contact_at END,
       last_discovery_at = CASE WHEN ? = 1 THEN ? ELSE last_discovery_at END,
       updated_at = ?
     WHERE id = ?`,
    [status, message, options.contact ? 1 : 0, now, options.discovered ? 1 : 0, now, now, id],
  );
}

/** Builds a Docker connection, decrypting TLS material. Throws when stored secrets are unreadable. */
export function toDockerConnection(record: EnvironmentRecord, key: Buffer): DockerConnection {
  const ca = record.tlsCa ? tryDecryptSecret(record.tlsCa, key) : null;
  const cert = record.tlsCert ? tryDecryptSecret(record.tlsCert, key) : null;
  const tlsKey = record.tlsKey ? tryDecryptSecret(record.tlsKey, key) : null;
  if (record.kind === 'tls') {
    if (!ca || !cert || !tlsKey) {
      throw new Error(
        'TLS material is missing or cannot be decrypted with the current secret key. Re-enter the certificate, key and CA.',
      );
    }
  }
  return {
    kind: record.kind,
    address: record.address,
    tlsCa: ca,
    tlsCert: cert,
    tlsKey,
    skipVerify: record.tlsSkipVerify,
  };
}

