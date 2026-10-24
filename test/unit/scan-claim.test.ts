import test from 'node:test';
import assert from 'node:assert/strict';
import { Db } from '../../src/db/index.ts';
import { claimNextScan } from '../../src/repo/scans.ts';

test('several scans for the same environment can run in parallel', () => {
  const db = Db.open(':memory:');
  try {
    db.run(
      `INSERT INTO environments (name, kind, address, created_at, updated_at)
       VALUES ('unraid', 'unix', '/var/run/docker.sock', '2026-01-01', '2026-01-01')`,
    );
    for (const image of ['img-a', 'img-b']) {
      db.run(
        `INSERT INTO scans (environment_id, image_id, image_ref, profile, trigger, status, queued_at)
         VALUES (1, ?, ?, 'standard', 'schedule', 'queued', '2026-01-01T00:00:00.000Z')`,
        [image, `${image}:1`],
      );
    }

    const first = claimNextScan(db);
    const second = claimNextScan(db);
    assert.ok(first, 'first scan is claimed');
    assert.ok(second, 'a second scan on the same host is claimed while the first runs');
    assert.notEqual(first.id, second.id);
    assert.equal(claimNextScan(db), null, 'nothing else is queued');
  } finally {
    db.close();
  }
});
