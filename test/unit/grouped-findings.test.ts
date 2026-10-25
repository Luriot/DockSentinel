import test from 'node:test';
import assert from 'node:assert/strict';
import { Db } from '../../src/db/index.ts';
import { applyScanFindings, listGroupedFindings, purgeIgnoredFindings, refreshImageFindingCounts } from '../../src/repo/findings.ts';
import type { NormalizedFinding } from '../../src/domain/findings.ts';

function finding(overrides: Partial<NormalizedFinding> = {}): NormalizedFinding {
  return {
    target: 'debian 12',
    class: 'os-pkgs',
    type: 'debian',
    vulnId: 'CVE-2026-1111',
    pkgName: 'openssl',
    installedVersion: '3.0.1',
    fixedVersion: '3.0.2',
    severity: 'HIGH',
    status: 'fixed',
    title: 'Shared issue',
    primaryUrl: 'https://example.com',
    cvssScore: 7.5,
    cvssSource: 'nvd',
    cvssVector: null,
    publishedAt: null,
    modifiedAt: null,
    ...overrides,
  };
}

function seed(db: Db, imageId: string, scanId: number): void {
  db.run(
    `INSERT OR IGNORE INTO environments (name, kind, address, created_at, updated_at)
     VALUES ('test', 'unix', '/var/run/docker.sock', '2026-01-01', '2026-01-01')`,
  );
  db.run(
    `INSERT INTO images (image_id, repo_digests, first_seen_at, updated_at) VALUES (?, '[]', '2026-01-01', '2026-01-01')`,
    [imageId],
  );
  db.run(
    `INSERT INTO scans (environment_id, image_id, image_ref, profile, trigger, status, queued_at)
     VALUES (1, ?, 'app:1', 'standard', 'manual', 'success', '2026-01-01')`,
    [imageId],
  );
}

test('grouped findings merge the same CVE across images and expose duplicate targets', () => {
  const db = Db.open(':memory:');
  try {
    const first = `sha256:${'a'.repeat(64)}`;
    const second = `sha256:${'b'.repeat(64)}`;
    seed(db, first, 1);
    seed(db, second, 2);
    db.transaction(() => {
      applyScanFindings(db, {
        imageId: first,
        scanId: 1,
        findings: [
          finding({ target: 'debian 12' }),
          // Go module reporting duplicates the same package in several binaries.
          finding({ target: 'usr/local/bin/app', vulnId: 'CVE-2026-2222', pkgName: 'stdlib' }),
          finding({ target: 'usr/local/bin/tool', vulnId: 'CVE-2026-2222', pkgName: 'stdlib' }),
          finding({ vulnId: 'CVE-2026-3333', pkgName: 'linux-libc-dev', severity: 'CRITICAL' }),
        ],
        now: '2026-01-02T00:00:00.000Z',
      });
      applyScanFindings(db, {
        imageId: second,
        scanId: 2,
        findings: [finding({ target: 'alpine 3.20' })],
        now: '2026-01-02T00:00:00.000Z',
      });
    });

    const grouped = listGroupedFindings(db, { page: 1, pageSize: 10 });
    assert.equal(grouped.total, 2, 'openssl+stdlib are two groups; kernel is hidden');

    const openssl = grouped.items.find((item) => item.vulnId === 'CVE-2026-1111');
    assert.equal(openssl?.images, 2);
    assert.equal(openssl?.findings, 2);
    assert.equal(openssl?.fixable, 2);

    const stdlib = grouped.items.find((item) => item.vulnId === 'CVE-2026-2222');
    assert.equal(stdlib?.images, 1, 'duplicate targets stay in one image');
    assert.equal(stdlib?.targets, 2);
    assert.equal(stdlib?.findings, 2);

    const withKernel = listGroupedFindings(db, { page: 1, pageSize: 10, includeKernel: true });
    assert.equal(withKernel.total, 3);
  } finally {
    db.close();
  }
});

test('purging ignored packages removes their findings and refreshes image counters', () => {
  const db = Db.open(':memory:');
  try {
    const imageId = `sha256:${'c'.repeat(64)}`;
    seed(db, imageId, 1);
    db.transaction(() =>
      applyScanFindings(db, {
        imageId,
        scanId: 1,
        findings: [
          finding({ pkgName: 'openssl' }),
          finding({ vulnId: 'CVE-2026-4444', pkgName: 'chromium', severity: 'CRITICAL' }),
          finding({ vulnId: 'CVE-2026-5555', pkgName: 'chromium-common', severity: 'CRITICAL' }),
        ],
        now: '2026-01-02T00:00:00.000Z',
      }),
    );

    const result = purgeIgnoredFindings(db, ['CHROMIUM', 'chromium-common']);
    assert.equal(result.removed, 2);
    assert.deepEqual(result.images, [imageId]);
    for (const id of result.images) refreshImageFindingCounts(db, id);

    assert.equal(
      db.get<{ count: number }>('SELECT COUNT(*) AS count FROM findings')?.count,
      1,
      'only the non-ignored finding remains',
    );
    const image = db.get<{ critical_count: number; high_count: number }>(
      'SELECT critical_count, high_count FROM images WHERE image_id = ?',
      [imageId],
    );
    assert.equal(image?.critical_count, 0);
    assert.equal(image?.high_count, 1);
  } finally {
    db.close();
  }
});
