import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { Db } from '../../src/db/index.ts';
import { applyPendingRestore, createBackup, listBackups, stageRestore } from '../../src/backup.ts';

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
