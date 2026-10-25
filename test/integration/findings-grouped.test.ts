import test from 'node:test';
import assert from 'node:assert/strict';
import { createTestApp, authHeaders } from '../helpers/app.ts';
import { seedSuccessfulScan } from '../helpers/seed-scan.ts';
import type { NormalizedFinding } from '../../src/domain/findings.ts';

const IMAGE_ID = `sha256:${'e'.repeat(64)}`;

function finding(vulnId: string, pkgName: string): NormalizedFinding {
  return {
    target: 'debian 12',
    class: 'os-pkgs',
    type: 'debian',
    vulnId,
    pkgName,
    installedVersion: '1.0',
    fixedVersion: '1.1',
    severity: 'HIGH',
    status: 'fixed',
    title: 'issue',
    primaryUrl: null,
    cvssScore: null,
    cvssSource: null,
    cvssVector: null,
    publishedAt: null,
    modifiedAt: null,
  };
}

test('the grouped findings endpoint returns one row per CVE and package', async () => {
  const harness = await createTestApp();
  try {
    await harness.login();
    harness.db.run(
      `INSERT INTO environments (name, kind, address, created_at, updated_at)
       VALUES ('test', 'unix', '/var/run/docker.sock', '2026-01-01', '2026-01-01')`,
    );
    harness.db.run(
      `INSERT INTO images (image_id, repo_digests, first_seen_at, updated_at) VALUES (?, '[]', '2026-01-01', '2026-01-01')`,
      [IMAGE_ID],
    );
    seedSuccessfulScan(harness.db, {
      imageId: IMAGE_ID,
      environmentId: 1,
      findings: [finding('CVE-2026-1111', 'openssl'), finding('CVE-2026-2222', 'curl')],
    });

    const response = await harness.app.inject({
      method: 'GET',
      url: '/api/findings/grouped',
      headers: authHeaders(harness),
    });
    assert.equal(response.statusCode, 200, response.body);
    const body = response.json<{ total: number; items: { vulnId: string; images: number; findings: number }[] }>();
    assert.equal(body.total, 2);
    assert.equal(body.items.length, 2);
    assert.equal(body.items[0]?.images, 1);
    assert.equal(body.items[0]?.findings, 1);
  } finally {
    await harness.close();
  }
});
