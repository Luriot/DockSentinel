import test from 'node:test';
import assert from 'node:assert/strict';
import { Db } from '../../src/db/index.ts';
import { applyScanFindings, listFindings, refreshImageFindingCounts, setFindingTriage } from '../../src/repo/findings.ts';
import type { NormalizedFinding } from '../../src/domain/findings.ts';

const IMAGE_ID = `sha256:${'4'.repeat(64)}`;

function finding(): NormalizedFinding {
  return {
    target: 'debian 11',
    class: 'os-pkgs',
    type: 'debian',
    vulnId: 'CVE-2026-0001',
    pkgName: 'openssl',
    installedVersion: '1.1.1k',
    fixedVersion: '1.1.1n',
    severity: 'HIGH',
    status: 'fixed',
    title: 'test finding',
    primaryUrl: 'https://example.com',
    cvssScore: 7.5,
    cvssSource: 'nvd',
    cvssVector: null,
    publishedAt: null,
    modifiedAt: null,
  };
}

test('ignored findings leave default views and image counts but remain restorable', () => {
  const db = Db.open(':memory:');
  db.run(
    `INSERT INTO environments (name, kind, address, created_at, updated_at)
     VALUES ('test', 'unix', '/var/run/docker.sock', '2026-01-01', '2026-01-01')`,
  );
  db.run(
    `INSERT INTO images (image_id, repo_digests, first_seen_at, updated_at)
     VALUES (?, '[]', '2026-01-01', '2026-01-01')`,
    [IMAGE_ID],
  );
  db.run(
    `INSERT INTO scans (environment_id, image_id, image_ref, profile, trigger, status, queued_at)
     VALUES (1, ?, 'test:1', 'standard', 'manual', 'success', '2026-01-01')`,
    [IMAGE_ID],
  );
  const applied = applyScanFindings(db, {
    imageId: IMAGE_ID,
    scanId: 1,
    findings: [finding()],
    now: '2026-01-02T00:00:00.000Z',
  });
  const id = applied.appeared[0]?.id;
  assert.ok(id);

  const updated = setFindingTriage(db, id, 'ignored', 'accepted risk', '2026-01-03T00:00:00.000Z');
  assert.equal(updated?.triageStatus, 'ignored');
  refreshImageFindingCounts(db, IMAGE_ID);
  assert.equal(db.get<{ high_count: number }>('SELECT high_count FROM images WHERE image_id = ?', [IMAGE_ID])?.high_count, 0);
  assert.equal(listFindings(db, { state: 'open', page: 1, pageSize: 10 }).total, 0);
  const all = listFindings(db, { state: 'open', includeSuppressed: true, page: 1, pageSize: 10 });
  assert.equal(all.total, 1);
  assert.equal(all.items[0]?.triageNote, 'accepted risk');

  setFindingTriage(db, id, 'none', null, '2026-01-04T00:00:00.000Z');
  refreshImageFindingCounts(db, IMAGE_ID);
  assert.equal(db.get<{ high_count: number }>('SELECT high_count FROM images WHERE image_id = ?', [IMAGE_ID])?.high_count, 1);
  assert.equal(listFindings(db, { state: 'open', page: 1, pageSize: 10 }).total, 1);
});
