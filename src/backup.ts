import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
} from 'node:fs';
import { isAbsolute, join, relative, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import type { Config } from './config.ts';
import { Db } from './db/index.ts';
import { nowIso } from './util/time.ts';

export interface BackupResult {
  databasePath: string;
  keyPath: string | null;
  createdAt: string;
  sizeBytes: number;
}

export interface BackupInfo {
  name: string;
  createdAt: string;
  sizeBytes: number;
  hasKey: boolean;
}

export function backupDirectory(dataDir: string): string {
  return join(dataDir, 'backups');
}

export function createBackup(config: Pick<Config, 'dataDir' | 'dbPath'>, targetDir = backupDirectory(config.dataDir)): BackupResult {
  mkdirSync(targetDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 23);
  const suffix = randomBytes(2).toString('hex');
  const databasePath = join(targetDir, `docksentinel-${stamp}-${suffix}.db`);
  if (existsSync(databasePath)) throw new Error(`Refusing to overwrite existing backup ${databasePath}`);

  const db = Db.open(config.dbPath);
  try {
    db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
    db.exec(`VACUUM INTO '${databasePath.replace(/'/g, "''")}'`);
  } finally {
    db.close();
  }

  const keySource = join(config.dataDir, 'secret.key');
  let keyPath: string | null = null;
  if (!process.env.DOCKSENTINEL_SECRET_KEY && existsSync(keySource)) {
    // Same suffix as the snapshot, so pruning can pair a backup with its key.
    keyPath = join(targetDir, `secret-${stamp}-${suffix}.key`);
    copyFileSync(keySource, keyPath);
  }
  return {
    databasePath,
    keyPath,
    createdAt: nowIso(),
    sizeBytes: statSync(databasePath).size,
  };
}

export function listBackups(dataDir: string): BackupInfo[] {
  const dir = backupDirectory(dataDir);
  let names: string[] = [];
  try {
    names = readdirSync(dir);
  } catch {
    return [];
  }
  return names
    .filter((name) => /^docksentinel-.*\.db$/.test(name))
    .map((name) => {
      const path = join(dir, name);
      const stat = statSync(path);
      return {
        name,
        createdAt: stat.mtime.toISOString(),
        sizeBytes: stat.size,
        hasKey: names.some((entry) => /^secret-.*\.key$/.test(entry)),
      };
    })
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

/**
 * Keeps the newest `keep` snapshots and removes the rest, with their key files (paired by the shared
 * suffix). Best effort: a file that cannot be removed is retried on the next run.
 */
export function pruneBackups(dataDir: string, keep: number): number {
  const dir = backupDirectory(dataDir);
  const backups = listBackups(dataDir);
  let names: string[] = [];
  try {
    names = readdirSync(dir);
  } catch {
    return 0;
  }
  let removed = 0;
  for (const backup of backups.slice(Math.max(0, keep))) {
    try {
      rmSync(join(dir, backup.name));
      removed += 1;
    } catch {
      // Retried next time.
    }
    const suffix = /-([0-9a-f]{4})\.db$/.exec(backup.name)?.[1];
    if (!suffix) continue;
    const keyName = names.find((name) => /^secret-/.test(name) && name.endsWith(`-${suffix}.key`));
    if (!keyName) continue;
    try {
      rmSync(join(dir, keyName));
      removed += 1;
    } catch {
      // Retried next time.
    }
  }
  return removed;
}

export interface AutoBackupOptions {
  /** Snapshot interval in hours; 0 disables automatic backups. */
  intervalHours: number;
  /** Number of snapshots kept, the newest first. */
  retention: number;
}

export interface AutoBackupResult {
  created: boolean;
  pruned: number;
  databasePath: string | null;
}

/** Takes a snapshot when the newest one is older than the interval, then applies retention. */
export function ensureAutoBackup(
  config: Pick<Config, 'dataDir' | 'dbPath'>,
  options: AutoBackupOptions,
  now: Date = new Date(),
): AutoBackupResult {
  if (options.intervalHours <= 0) return { created: false, pruned: 0, databasePath: null };
  const [newest] = listBackups(config.dataDir);
  const due = !newest || now.getTime() - Date.parse(newest.createdAt) >= options.intervalHours * 3_600_000;
  const databasePath = due ? createBackup(config).databasePath : null;
  const pruned = pruneBackups(config.dataDir, options.retention);
  return { created: databasePath !== null, pruned, databasePath };
}

/**
 * Rejects a copy whose header is valid but whose pages are corrupt. A staged file replaces the live
 * database at the next start, so it must be readable before anything is swapped.
 */
function assertHealthySqlite(file: string, label: string): void {
  let probe: DatabaseSync | null = null;
  try {
    probe = new DatabaseSync(file);
    const row = probe.prepare('PRAGMA quick_check').get() as Record<string, unknown> | undefined;
    const verdict = row ? Object.values(row)[0] : 'ok';
    if (verdict !== 'ok') throw new Error(String(verdict));
  } catch (error) {
    throw new Error(`${label} is not a healthy SQLite database: ${error instanceof Error ? error.message : String(error)}`);
  } finally {
    probe?.close();
  }
}

export function stageRestore(dataDir: string, dbPath: string, name: string): string {
  if (!/^[A-Za-z0-9._-]+\.db$/.test(name) || name.includes('..')) throw new Error('Invalid backup name');
  const source = resolve(backupDirectory(dataDir), name);
  const root = resolve(backupDirectory(dataDir));
  const relation = relative(root, source);
  if (relation.startsWith('..') || isAbsolute(relation)) throw new Error('Backup path escapes the backup directory');
  if (!existsSync(source)) throw new Error('Backup not found');
  const header = readFileSync(source).subarray(0, 16).toString('utf8');
  if (header !== 'SQLite format 3\u0000') throw new Error('The selected file is not a SQLite database');
  assertHealthySqlite(source, 'The selected backup');
  const staged = `${dbPath}.restore`;
  copyFileSync(source, staged);
  return staged;
}

/** Applies a staged restore before the database is opened. The original database is kept as a backup. */
export function applyPendingRestore(config: Pick<Config, 'dataDir' | 'dbPath'>): string | null {
  const staged = `${config.dbPath}.restore`;
  if (!existsSync(staged)) return null;
  const header = readFileSync(staged).subarray(0, 16).toString('utf8');
  if (header !== 'SQLite format 3\u0000') throw new Error(`Staged restore ${staged} is not a SQLite database`);
  assertHealthySqlite(staged, `Staged restore ${staged}`);
  const dir = backupDirectory(config.dataDir);
  mkdirSync(dir, { recursive: true });
  const safety = join(dir, `pre-restore-${new Date().toISOString().replace(/[:.]/g, '-')}.db`);
  if (existsSync(config.dbPath)) copyFileSync(config.dbPath, safety);
  for (const suffix of ['-wal', '-shm']) rmSync(`${config.dbPath}${suffix}`, { force: true });
  renameSync(staged, config.dbPath);
  return safety;
}
