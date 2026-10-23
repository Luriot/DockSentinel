import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Db } from '../../src/db/index.ts';
import { applyScanFindings } from '../../src/repo/findings.ts';
import type { NormalizedFinding } from '../../src/domain/findings.ts';
import { syncKev } from '../../src/repo/kev.ts';
import { createLogger } from '../../src/logger.ts';

const IMAGE_ID = `sha256:${'1'.repeat(64)}`;
const SCAN_ID = 1;

function seed(db: Db): void {
  db.run(
    `INSERT INTO environments (name, kind, address, created_at, updated_at) VALUES ('test', 'unix', '/var/run/docker.sock', '2026-01-01', '2026-01-01')`,
  );
  db.run(
    `INSERT INTO images (image_id, repo_digests, first_seen_at, updated_at) VALUES (?, '[]', '2026-01-01', '2026-01-01')`,
    [IMAGE_ID],
  );
  db.run(
    `INSERT INTO scans (environment_id, image_id, image_ref, profile, trigger, status, queued_at)
     VALUES (1, ?, 'test:1', 'standard', 'manual', 'success', '2026-01-01')`,
    [IMAGE_ID],
  );
}

function finding(overrides: Partial<NormalizedFinding> = {}): NormalizedFinding {
  return {
    target: 'debian 11.7',
    class: 'os-pkgs',
    type: 'debian',
    vulnId: 'CVE-2024-0001',
    pkgName: 'openssl',
    installedVersion: '1.1.1k',
    fixedVersion: '1.1.1n',
    severity: 'HIGH',
    status: 'fixed',
    title: 'title',
    primaryUrl: 'https://example.com',
    cvssScore: 7.5,
    cvssSource: 'nvd',
    cvssVector: null,
    publishedAt: null,
    modifiedAt: null,
    ...overrides,
  };
}

test('findings appear, persist, resolve and reappear with an incremented episode', () => {
  const db = Db.open(':memory:');
  seed(db);

  const first = db.transaction(() =>
    applyScanFindings(db, {
      imageId: IMAGE_ID,
      scanId: SCAN_ID,
      findings: [finding(), finding({ vulnId: 'CVE-2024-0002', pkgName: 'curl' })],
      now: '2026-01-02T00:00:00.000Z',
    }),
  );
  assert.equal(first.appeared.length, 2);
  assert.equal(first.counts.HIGH, 2);
  assert.equal(first.counts.FIXABLE, 2);
  assert.equal(db.get<{ count: number }>(`SELECT COUNT(*) AS count FROM findings WHERE resolved_at IS NULL`)?.count, 2);

  const repeat = db.transaction(() =>
    applyScanFindings(db, {
      imageId: IMAGE_ID,
      scanId: 2,
      findings: [finding(), finding({ vulnId: 'CVE-2024-0002', pkgName: 'curl' })],
      now: '2026-01-03T00:00:00.000Z',
    }),
  );
  assert.equal(repeat.appeared.length, 0);
  assert.equal(repeat.resolved.length, 0);
  assert.equal(repeat.changed.length, 0);
  assert.equal(
    db.get<{ last_seen_at: string }>(`SELECT last_seen_at FROM findings WHERE vuln_id = 'CVE-2024-0001'`)?.last_seen_at,
    '2026-01-03T00:00:00.000Z',
  );

  const removed = db.transaction(() =>
    applyScanFindings(db, {
      imageId: IMAGE_ID,
      scanId: 3,
      findings: [finding()],
      now: '2026-01-04T00:00:00.000Z',
    }),
  );
  assert.equal(removed.resolved.length, 1);
  assert.equal(removed.resolved[0]?.vulnId, 'CVE-2024-0002');
  const resolvedRow = db.get<{ resolved_at: string | null; episode: number }>(
    `SELECT resolved_at, episode FROM findings WHERE vuln_id = 'CVE-2024-0002'`,
  );
  assert.ok(resolvedRow?.resolved_at);
  assert.equal(resolvedRow?.episode, 1);

  const reappeared = db.transaction(() =>
    applyScanFindings(db, {
      imageId: IMAGE_ID,
      scanId: 4,
      findings: [finding(), finding({ vulnId: 'CVE-2024-0002', pkgName: 'curl' })],
      now: '2026-01-05T00:00:00.000Z',
    }),
  );
  assert.equal(reappeared.appeared.length, 1);
  assert.equal(reappeared.appeared[0]?.episode, 2);
  const row = db.get<{ episode: number; resolved_at: string | null; first_seen_at: string }>(
    `SELECT episode, resolved_at, first_seen_at FROM findings WHERE vuln_id = 'CVE-2024-0002'`,
  );
  assert.equal(row?.episode, 2);
  assert.equal(row?.resolved_at, null);
  assert.equal(row?.first_seen_at, '2026-01-05T00:00:00.000Z');

  const kinds = db
    .all<{ kind: string; count: number }>(
      `SELECT kind, COUNT(*) AS count FROM finding_events GROUP BY kind ORDER BY kind`,
    )
    .map((entry) => ({ ...entry }));
  assert.deepEqual(kinds, [
    { kind: 'appeared', count: 2 },
    { kind: 'reappeared', count: 1 },
    { kind: 'resolved', count: 1 },
  ]);
  db.close();
});

test('severity and fix changes are recorded as events without reopening the finding', () => {
  const db = Db.open(':memory:');
  seed(db);
  db.transaction(() =>
    applyScanFindings(db, {
      imageId: IMAGE_ID,
      scanId: 1,
      findings: [finding({ severity: 'MEDIUM', fixedVersion: null })],
      now: '2026-01-02T00:00:00.000Z',
    }),
  );
  const outcome = db.transaction(() =>
    applyScanFindings(db, {
      imageId: IMAGE_ID,
      scanId: 2,
      findings: [finding({ severity: 'CRITICAL', fixedVersion: '1.1.1n' })],
      now: '2026-01-03T00:00:00.000Z',
    }),
  );
  assert.equal(outcome.changed.length, 1);
  assert.deepEqual(outcome.changed[0]?.changes.severity, { from: 'MEDIUM', to: 'CRITICAL' });
  assert.deepEqual(outcome.changed[0]?.changes.fixedVersion, { from: null, to: '1.1.1n' });
  assert.equal(db.get<{ count: number }>(`SELECT COUNT(*) AS count FROM finding_events WHERE kind = 'changed'`)?.count, 1);
  db.close();
});

test('KEV sync enriches findings and reports newly exploited entries once', async () => {
  const db = Db.open(':memory:');
  seed(db);
  db.transaction(() =>
    applyScanFindings(db, {
      imageId: IMAGE_ID,
      scanId: 1,
      findings: [finding({ vulnId: 'CVE-2023-1111', severity: 'HIGH' }), finding({ vulnId: 'CVE-2024-2222', pkgName: 'curl' })],
      now: '2026-01-02T00:00:00.000Z',
    }),
  );

  const catalog = {
    title: 'CISA KEV',
    catalogVersion: '2026.01.01',
    count: 2,
    vulnerabilities: [
      {
        cveID: 'CVE-2023-1111',
        vendorProject: 'Example',
        product: 'Widget',
        vulnerabilityName: 'Example RCE',
        dateAdded: '2025-12-01',
        dueDate: '2025-12-20',
        knownRansomwareCampaignUse: 'Known',
      },
      { cveID: 'not-a-cve', vendorProject: 'Bad' },
    ],
  };
  const fetchImpl = (async () => new Response(JSON.stringify(catalog), { status: 200 })) as typeof fetch;
  const logger = createLogger('silent');

  const first = await syncKev(db, { url: 'http://example.test/kev.json', log: logger, fetchImpl });
  assert.equal(first.ok, true);
  assert.equal(first.entryCount, 1);
  assert.equal(first.newlyFlagged.length, 1);
  assert.ok((first.newlyFlagged[0]?.findingId ?? 0) > 0);

  const enriched = db.get<{ kev: number; kev_added_at: string | null }>(
    `SELECT kev, kev_added_at FROM findings WHERE vuln_id = 'CVE-2023-1111'`,
  );
  assert.equal(enriched?.kev, 1);
  assert.equal(enriched?.kev_added_at, '2025-12-01');

  const second = await syncKev(db, { url: 'http://example.test/kev.json', log: logger, fetchImpl });
  assert.equal(second.ok, true);
  assert.deepEqual(second.newlyFlagged, [], 'already-known entries must not alert again');

  const failingFetch = (async () => {
    throw new Error('network down');
  }) as typeof fetch;
  const failed = await syncKev(db, { url: 'http://example.test/kev.json', log: logger, fetchImpl: failingFetch });
  assert.equal(failed.ok, false);
  const status = db.get<{ status: string; entry_count: number; error: string | null }>(
    'SELECT status, entry_count, error FROM kev_sync WHERE id = 1',
  );
  assert.equal(status?.status, 'error');
  assert.match(status?.error ?? '', /network down/);
  assert.equal(status?.entry_count, 1, 'a failed sync must preserve usable KEV data');
  assert.equal(
    db.get<{ kev: number }>(`SELECT kev FROM findings WHERE vuln_id = 'CVE-2023-1111'`)?.kev,
    1,
    'findings keep their last known KEV state on sync failure',
  );
  db.close();
});

test('scanning applies KEV metadata discovered before the scan', async () => {
  const db = Db.open(':memory:');
  seed(db);
  const catalog = {
    vulnerabilities: [
      {
        cveID: 'CVE-2024-0001',
        vendorProject: 'Example',
        product: 'OpenSSL',
        vulnerabilityName: 'Exploited bug',
        dateAdded: '2025-01-01',
        knownRansomwareCampaignUse: 'Unknown',
      },
    ],
  };
  const fetchImpl = (async () => new Response(JSON.stringify(catalog), { status: 200 })) as typeof fetch;
  await syncKev(db, { url: 'http://example.test/kev.json', log: createLogger('silent'), fetchImpl });

  db.transaction(() =>
    applyScanFindings(db, {
      imageId: IMAGE_ID,
      scanId: 1,
      findings: [finding({ vulnId: 'CVE-2024-0001' })],
      now: '2026-01-02T00:00:00.000Z',
    }),
  );
  const row = db.get<{ kev: number; kev_added_at: string | null }>(
    `SELECT kev, kev_added_at FROM findings WHERE vuln_id = 'CVE-2024-0001'`,
  );
  assert.equal(row?.kev, 1);
  assert.equal(row?.kev_added_at, '2025-01-01');
  db.close();
});
