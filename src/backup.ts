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
  const databasePath = join(targetDir, `docksentinel-${stamp}-${randomBytes(2).toString('hex')}.db`);
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
    keyPath = join(targetDir, `secret-${stamp}-${randomBytes(2).toString('hex')}.key`);
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
