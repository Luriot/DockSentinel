import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Db } from '../../src/db/index.ts';
import { SCHEMA_VERSION } from '../../src/db/migrations.ts';

test('migrations apply cleanly and are idempotent', () => {
  const dir = mkdtempSync(join(tmpdir(), 'docksentinel-db-'));
  const path = join(dir, 'test.db');
  try {
    const first = Db.open(path);
    assert.equal(first.get<{ version: number }>('SELECT MAX(version) AS version FROM schema_migrations')?.version, SCHEMA_VERSION);
    first.close();

    const second = Db.open(path);
    const versions = second.all<{ version: number }>('SELECT version FROM schema_migrations');
    assert.equal(versions.length, SCHEMA_VERSION);
    second.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('foreign keys, strict tables and transactions behave', () => {
  const db = new Db(':memory:');
  db.migrate();

  assert.throws(() => db.run('INSERT INTO findings (image_id) VALUES (?)', ['missing-image']));

  assert.throws(() =>
    db.transaction(() => {
      db.run(
        `INSERT INTO images (image_id, first_seen_at, updated_at) VALUES ('sha256:one', '2026-01-01', '2026-01-01')`,
      );
      throw new Error('rollback');
    }),
  );
  assert.equal(db.get<{ count: number }>('SELECT COUNT(*) AS count FROM images')?.count, 0);

  db.transaction(() => {
    db.run(`INSERT INTO images (image_id, first_seen_at, updated_at) VALUES ('sha256:one', '2026-01-01', '2026-01-01')`);
    db.transaction(() => {
      db.run(`INSERT INTO images (image_id, first_seen_at, updated_at) VALUES ('sha256:two', '2026-01-02', '2026-01-02')`);
    });
  });
  assert.equal(db.get<{ count: number }>('SELECT COUNT(*) AS count FROM images')?.count, 2);
  db.close();
});
