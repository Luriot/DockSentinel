import test from 'node:test';
import assert from 'node:assert/strict';
import { Db } from '../../src/db/index.ts';
import { applyContentFindings, listContentFindings, pruneContentFindings } from '../../src/repo/content.ts';
import type { NormalizedContentFinding } from '../../src/domain/content.ts';

const IMAGE_ID = `sha256:${'2'.repeat(64)}`;

function seed(db: Db): void {
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
    `INSERT INTO scans (environment_id, image_id, image_ref, kind, profile, trigger, status, queued_at)
     VALUES (1, ?, 'test:1', 'content', 'quick', 'manual', 'success', '2026-01-01')`,
    [IMAGE_ID],
  );
}

function finding(overrides: Partial<NormalizedContentFinding> = {}): NormalizedContentFinding {
  return {
    kind: 'misconfiguration',
    scope: 'image-config',
    ruleId: 'DS-0002',
    category: 'Dockerfile Security Check',
    severity: 'HIGH',
    title: 'Image user should not be root',
    target: 'image config',
    message: 'Last USER command should not be root',
    resolution: 'Add a non-root USER',
    primaryUrl: 'https://avd.aquasec.com/misconfig/ds-0002',
    startLine: 3,
    endLine: 3,
    ...overrides,
  };
}

test('content findings appear, update, resolve and reappear', () => {
  const db = Db.open(':memory:');
  seed(db);

  const first = applyContentFindings(db, {
    imageId: IMAGE_ID,
    scanId: 1,
    findings: [finding(), finding({ kind: 'secret', scope: 'image', ruleId: 'aws-access-key-id', target: 'app/key', startLine: 1, endLine: 1, severity: 'CRITICAL', message: null, resolution: null, primaryUrl: null })],
    now: '2026-01-02T00:00:00.000Z',
  });
  assert.equal(first.appeared.length, 2);
  assert.equal(first.counts.HIGH, 1);
  assert.equal(first.counts.CRITICAL, 1);

  const open = listContentFindings(db, { state: 'open', page: 1, pageSize: 10 });
  assert.equal(open.total, 2);
  assert.equal(open.byKind.misconfiguration, 1);
  assert.equal(open.byKind.secret, 1);

  const second = applyContentFindings(db, {
    imageId: IMAGE_ID,
    scanId: 2,
    findings: [finding({ severity: 'CRITICAL' })],
    now: '2026-01-03T00:00:00.000Z',
  });
  assert.equal(second.appeared.length, 0);
  assert.equal(second.resolved.length, 1);
  assert.equal(second.counts.CRITICAL, 1);
  const active = listContentFindings(db, { state: 'open', page: 1, pageSize: 10 });
  assert.equal(active.total, 1);
  assert.equal(active.items[0]?.severity, 'CRITICAL');

  const third = applyContentFindings(db, {
    imageId: IMAGE_ID,
    scanId: 3,
    findings: [
      finding({ severity: 'CRITICAL' }),
      finding({ kind: 'secret', scope: 'image', ruleId: 'aws-access-key-id', target: 'app/key', startLine: 1, endLine: 1, severity: 'CRITICAL', message: null, resolution: null, primaryUrl: null }),
    ],
    now: '2026-01-04T00:00:00.000Z',
  });
  assert.equal(third.appeared.length, 1);
  const reactivated = listContentFindings(db, { state: 'open', page: 1, pageSize: 10 }).items.find(
    (item) => item.kind === 'secret',
  );
  assert.equal(reactivated?.episode, 2);
  const fourth = applyContentFindings(db, {
    imageId: IMAGE_ID,
    scanId: 4,
    findings: [finding({ severity: 'CRITICAL' })],
    now: '2026-01-05T00:00:00.000Z',
  });
  assert.equal(fourth.resolved.length, 1);
  assert.equal(pruneContentFindings(db, '2026-01-06T00:00:00.000Z'), 1);
});
