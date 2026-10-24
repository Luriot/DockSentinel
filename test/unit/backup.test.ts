import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readdirSync, readFileSync, utimesSync, writeFileSync } from 'node:fs';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { Db } from '../../src/db/index.ts';
import {
  applyPendingRestore,
  backupDirectory,
  createBackup,
  ensureAutoBackup,
  listBackups,
  pruneBackups,
  stageRestore,
} from '../../src/backup.ts';

test('backup creation, listing, staging and startup restore', async () => {
  const root = await mkdtemp(join(tmpdir(), 'docksentinel-backup-'));
  const dataDir = join(root, 'data');
  const dbPath = join(dataDir, 'docksentinel.db');
  const config = { dataDir, dbPath };
  try {
    await mkdir(dataDir, { recursive: true });
    const db = Db.open(dbPath);
    db.run("INSERT INTO settings (key, value, updated_at) VALUES ('marker', 'original', '2026-01-01')");
    db.close();

    const backup = createBackup(config);
    assert.ok(backup.sizeBytes > 0);
    const listed = listBackups(dataDir);
    assert.equal(listed.length, 1);
    assert.equal(listed[0]?.name, backup.databasePath.split(/[\\/]/).pop());

    const restoreDb = Db.open(dbPath);
    restoreDb.run("UPDATE settings SET value = 'changed' WHERE key = 'marker'");
    restoreDb.close();

    stageRestore(dataDir, dbPath, listed[0]!.name);
    const safety = applyPendingRestore(config);
    assert.ok(safety);
    const restored = Db.open(dbPath);
    try {
      assert.equal(restored.get<{ value: string }>("SELECT value FROM settings WHERE key = 'marker'")?.value, 'original');
    } finally {
      restored.close();
    }

    await writeFile(join(dataDir, 'backups', 'bad.db'), 'not sqlite');
    assert.throws(() => stageRestore(dataDir, dbPath, 'bad.db'), /not a SQLite database/);
    assert.throws(() => stageRestore(dataDir, dbPath, '../escape.db'), /Invalid backup name/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('automatic backups respect the interval and retention', async () => {
  const root = await mkdtemp(join(tmpdir(), 'docksentinel-auto-backup-'));
  const dataDir = join(root, 'data');
  const dbPath = join(dataDir, 'docksentinel.db');
  const config = { dataDir, dbPath };
  try {
    await mkdir(dataDir, { recursive: true });
    const db = Db.open(dbPath);
    db.run("INSERT INTO settings (key, value, updated_at) VALUES ('marker', 'original', '2026-01-01')");
    db.close();

    const first = ensureAutoBackup(config, { intervalHours: 24, retention: 1 });
    assert.equal(first.created, true);
    assert.ok(first.databasePath);

    const tooSoon = ensureAutoBackup(config, { intervalHours: 24, retention: 1 }, new Date(Date.now() + 3_600_000));
    assert.equal(tooSoon.created, false);
    assert.equal(listBackups(dataDir).length, 1);

    const aged = new Date(Date.now() - 48 * 3_600_000);
    utimesSync(first.databasePath!, aged, aged);

    const second = ensureAutoBackup(config, { intervalHours: 24, retention: 1 });
    assert.equal(second.created, true);
    assert.notEqual(second.databasePath, first.databasePath);
    const remaining = listBackups(dataDir);
    assert.equal(remaining.length, 1, 'retention keeps a single snapshot');
    assert.equal(remaining[0]?.name, second.databasePath!.split(/[\\/]/).pop());
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('automatic backups can be disabled', async () => {
  const root = await mkdtemp(join(tmpdir(), 'docksentinel-no-backup-'));
  const dataDir = join(root, 'data');
  const dbPath = join(dataDir, 'docksentinel.db');
  try {
    await mkdir(dataDir, { recursive: true });
    Db.open(dbPath).close();
    const result = ensureAutoBackup({ dataDir, dbPath }, { intervalHours: 0, retention: 3 });
    assert.equal(result.created, false);
    assert.equal(listBackups(dataDir).length, 0);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('pruning removes old snapshots and their keys', async () => {
  const root = await mkdtemp(join(tmpdir(), 'docksentinel-prune-'));
  const dataDir = join(root, 'data');
  const dir = backupDirectory(dataDir);
  try {
    await mkdir(dir, { recursive: true });
    for (const [index, day] of ['01', '02', '03', '04'].entries()) {
      const when = new Date(2026, 0, Number(day));
      const suffix = `a00${index + 1}`;
      const dbFile = join(dir, `docksentinel-2026-01-${day}T00-00-00-000Z-${suffix}.db`);
      writeFileSync(dbFile, 'db');
      utimesSync(dbFile, when, when);
      const keyFile = join(dir, `secret-2026-01-${day}T00-00-00-000Z-${suffix}.key`);
      writeFileSync(keyFile, 'key');
      utimesSync(keyFile, when, when);
    }

    const removed = pruneBackups(dataDir, 2);
    assert.equal(removed, 4);
    const names = readdirSync(dir);
    assert.equal(names.filter((name) => name.endsWith('.db')).length, 2);
    assert.equal(names.filter((name) => name.endsWith('.key')).length, 2);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('a header-valid but corrupt backup never replaces the database', async () => {
  const root = await mkdtemp(join(tmpdir(), 'docksentinel-corrupt-'));
  const dataDir = join(root, 'data');
  const dbPath = join(dataDir, 'docksentinel.db');
  try {
    await mkdir(dataDir, { recursive: true });
    const db = Db.open(dbPath);
    db.run("INSERT INTO settings (key, value, updated_at) VALUES ('marker', ?, '2026-01-01')", ['x'.repeat(20_000)]);
    db.close();

    const backup = createBackup({ dataDir, dbPath });
    const name = backup.databasePath.split(/[\\/]/).pop()!;
    const corrupted = Buffer.from(readFileSync(backup.databasePath));
    corrupted.fill(0x41, 4096);
    writeFileSync(backup.databasePath, corrupted);

    assert.throws(() => stageRestore(dataDir, dbPath, name), /not a healthy SQLite database/);
    assert.equal(existsSync(`${dbPath}.restore`), false);

    writeFileSync(`${dbPath}.restore`, corrupted);
    assert.throws(() => applyPendingRestore({ dataDir, dbPath }), /not a healthy SQLite database/);

    const live = Db.open(dbPath);
    try {
      assert.equal(
        live.get<{ value: string }>("SELECT value FROM settings WHERE key = 'marker'")?.value.length,
        20_000,
        'the live database is untouched when a restore is refused',
      );
    } finally {
      live.close();
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
