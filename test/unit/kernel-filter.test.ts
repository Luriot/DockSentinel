import test from 'node:test';
import assert from 'node:assert/strict';
import { Db } from '../../src/db/index.ts';
import { applyScanFindings, listFindings, refreshImageFindingCounts } from '../../src/repo/findings.ts';
import { buildOverview } from '../../src/repo/overview.ts';
import { DEFAULT_SETTINGS } from '../../src/repo/settings.ts';
import type { NormalizedFinding } from '../../src/domain/findings.ts';

const IMAGE_ID = `sha256:${'8'.repeat(64)}`;

function finding(overrides: Partial<NormalizedFinding> = {}): NormalizedFinding {
  return {
    target: 'debian 12',
    class: 'os-pkgs',
    type: 'debian',
    vulnId: 'CVE-2026-0001',
    pkgName: 'openssl',
    installedVersion: '3.0.1',
    fixedVersion: '3.0.2',
    severity: 'HIGH',
    status: 'fixed',
    title: 'openssl issue',
    primaryUrl: 'https://example.com',
    cvssScore: 7.5,
    cvssSource: 'nvd',
    cvssVector: null,
    publishedAt: null,
    modifiedAt: null,
    ...overrides,
  };
}

function seed(db: Db): void {
  db.run(
    `INSERT INTO environments (name, kind, address, created_at, updated_at)
     VALUES ('test', 'unix', '/var/run/docker.sock', '2026-01-01', '2026-01-01')`,
  );
  db.run(
    `INSERT INTO images (image_id, repo_digests, first_seen_at, updated_at) VALUES (?, '[]', '2026-01-01', '2026-01-01')`,
    [IMAGE_ID],
  );
  db.run(
    `INSERT INTO scans (environment_id, image_id, image_ref, profile, trigger, status, queued_at)
     VALUES (1, ?, 'app:1', 'standard', 'manual', 'success', '2026-01-01')`,
    [IMAGE_ID],
  );
}

test('kernel package findings are stored but excluded from counts, lists and alerts', () => {
  const db = Db.open(':memory:');
  try {
    seed(db);
    const outcome = db.transaction(() =>
      applyScanFindings(db, {
        imageId: IMAGE_ID,
        scanId: 1,
        findings: [
          finding({ vulnId: 'CVE-2026-0001', pkgName: 'openssl', severity: 'HIGH' }),
          finding({
            vulnId: 'CVE-2026-0002',
            pkgName: 'linux-libc-dev',
            target: 'debian 12 (linux headers)',
            severity: 'CRITICAL',
          }),
        ],
        now: '2026-01-02T00:00:00.000Z',
      }),
    );
    // The scan counts (used for image cards and alerts) ignore kernel packages.
    assert.equal(outcome.counts.HIGH, 1);
    assert.equal(outcome.counts.CRITICAL, 0);
    assert.equal(
      db.get<{ count: number }>('SELECT COUNT(*) AS count FROM findings')?.count,
      2,
      'kernel findings stay stored for the explicit filter',
    );

    const byDefault = listFindings(db, { page: 1, pageSize: 10 });
    assert.equal(byDefault.total, 1);
    assert.equal(byDefault.items[0]?.pkgName, 'openssl');
    const withKernel = listFindings(db, { page: 1, pageSize: 10, includeKernel: true });
    assert.equal(withKernel.total, 2);

    refreshImageFindingCounts(db, IMAGE_ID);
    const image = db.get<{ critical_count: number; high_count: number }>(
      'SELECT critical_count, high_count FROM images WHERE image_id = ?',
      [IMAGE_ID],
    );
    assert.equal(image?.critical_count, 0);
    assert.equal(image?.high_count, 1);

    const overview = buildOverview(db, DEFAULT_SETTINGS);
    assert.equal(overview.counts.total, 1);
    assert.equal(overview.counts.high, 1);
    assert.equal(overview.counts.critical, 0);
  } finally {
    db.close();
  }
});
