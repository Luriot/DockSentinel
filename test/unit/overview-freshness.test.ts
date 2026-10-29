import test from 'node:test';
import assert from 'node:assert/strict';
import { Db } from '../../src/db/index.ts';
import { buildOverview } from '../../src/repo/overview.ts';
import { DEFAULT_SETTINGS } from '../../src/repo/settings.ts';

const IMAGE_ID = `sha256:${'9'.repeat(64)}`;

function insertScan(db: Db, kind: 'vulnerability' | 'content', finishedAt: string): void {
  db.run(
    `INSERT INTO scans (image_id, image_ref, kind, profile, trigger, status, queued_at, finished_at)
     VALUES (?, 'app:1', ?, 'standard', 'manual', 'success', ?, ?)`,
    [IMAGE_ID, kind, finishedAt, finishedAt],
  );
}

test('vulnerability freshness ignores successful content scans', () => {
  const db = Db.open(':memory:');
  try {
    insertScan(db, 'content', '2026-02-01T00:00:00.000Z');

    const contentOnly = buildOverview(db, DEFAULT_SETTINGS, new Date('2026-03-01T00:00:00.000Z'));
    assert.equal(contentOnly.scans.lastSuccessfulAt, null);

    insertScan(db, 'vulnerability', '2026-01-01T00:00:00.000Z');

    const withVulnerabilityScan = buildOverview(db, DEFAULT_SETTINGS, new Date('2026-03-01T00:00:00.000Z'));
    assert.equal(withVulnerabilityScan.scans.lastSuccessfulAt, '2026-01-01T00:00:00.000Z');
  } finally {
    db.close();
  }
});
