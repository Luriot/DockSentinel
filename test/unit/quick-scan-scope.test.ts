import test from 'node:test';
import assert from 'node:assert/strict';
import { Db } from '../../src/db/index.ts';
import { applyScanFindings } from '../../src/repo/findings.ts';
import type { NormalizedFinding } from '../../src/domain/findings.ts';

const IMAGE_ID = `sha256:${'d'.repeat(64)}`;

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
    title: 'issue',
    primaryUrl: null,
    cvssScore: null,
    cvssSource: null,
    cvssVector: null,
    publishedAt: null,
    modifiedAt: null,
    ...overrides,
  };
}

test('a quick scan does not resolve findings it never looked at', () => {
  const db = Db.open(':memory:');
  try {
    db.run(
      `INSERT INTO environments (name, kind, address, created_at, updated_at)
       VALUES ('test', 'unix', '/var/run/docker.sock', '2026-01-01', '2026-01-01')`,
    );
    db.run(
      `INSERT INTO images (image_id, repo_digests, first_seen_at, updated_at) VALUES (?, '[]', '2026-01-01', '2026-01-01')`,
      [IMAGE_ID],
    );
    for (const id of [1, 2]) {
      db.run(
        `INSERT INTO scans (id, environment_id, image_id, image_ref, profile, trigger, status, queued_at)
         VALUES (?, 1, ?, 'app:1', ?, 'manual', 'success', '2026-01-01')`,
        [id, IMAGE_ID, id === 1 ? 'standard' : 'quick'],
      );
    }
    const library = finding({
      target: 'app/node_modules/lodash',
      class: 'lang-pkgs',
      type: 'node-pkg',
      vulnId: 'CVE-2026-2222',
      pkgName: 'lodash',
    });
    db.transaction(() =>
      applyScanFindings(db, {
        imageId: IMAGE_ID,
        scanId: 1,
        findings: [finding(), library],
        now: '2026-01-02T00:00:00.000Z',
      }),
    );

    // Quick profile reports OS packages only: the Node finding must stay open.
    db.transaction(() =>
      applyScanFindings(db, {
        imageId: IMAGE_ID,
        scanId: 2,
        findings: [finding()],
        now: '2026-01-03T00:00:00.000Z',
        osOnly: true,
      }),
    );

    const lodash = db.get<{ resolved_at: string | null }>(
      `SELECT resolved_at FROM findings WHERE vuln_id = 'CVE-2026-2222'`,
    );
    assert.equal(lodash?.resolved_at, null, 'the language finding is not resolved by an OS-only scan');
  } finally {
    db.close();
  }
});
