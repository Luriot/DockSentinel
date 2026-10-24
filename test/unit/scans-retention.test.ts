import test from 'node:test';
import assert from 'node:assert/strict';
import { Db } from '../../src/db/index.ts';
import { pruneScans } from '../../src/repo/scans.ts';

test('retention keeps the latest scan and the latest successful scan per image', () => {
  const db = Db.open(':memory:');
  try {
    const insert = (status: string, finishedAt: string | null): void => {
      db.run(
        `INSERT INTO scans (image_id, image_ref, profile, trigger, status, queued_at, finished_at)
         VALUES ('img', 'img:1', 'standard', 'schedule', ?, ?, ?)`,
        [status, finishedAt ?? '2020-01-01T00:00:00.000Z', finishedAt],
      );
    };
    insert('queued', null);
    insert('success', '2019-01-01T00:00:00.000Z');
    insert('success', '2020-01-01T00:00:00.000Z');
    insert('failed', '2021-01-01T00:00:00.000Z');

    const removed = pruneScans(db, '2025-01-01T00:00:00.000Z');
    assert.equal(removed, 1, 'only the superseded success ages out');

    const rows = db.all<{ status: string; finished_at: string | null }>(
      'SELECT status, finished_at FROM scans ORDER BY id',
    );
    assert.deepEqual(rows.map((row) => ({ ...row })), [
      { status: 'queued', finished_at: null },
      { status: 'success', finished_at: '2020-01-01T00:00:00.000Z' },
      { status: 'failed', finished_at: '2021-01-01T00:00:00.000Z' },
    ]);
  } finally {
    db.close();
  }
});
