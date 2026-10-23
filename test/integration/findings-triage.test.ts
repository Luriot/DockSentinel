import test from 'node:test';
import assert from 'node:assert/strict';
import { createTestApp, authHeaders } from '../helpers/app.ts';
import { seedSuccessfulScan } from '../helpers/seed-scan.ts';
import type { NormalizedFinding } from '../../src/domain/findings.ts';

const IMAGE_ID = `sha256:${'7'.repeat(64)}`;

function finding(): NormalizedFinding {
  return {
    target: 'debian 11',
    class: 'os-pkgs',
    type: 'debian',
    vulnId: 'CVE-2026-7777',
    pkgName: 'openssl',
    installedVersion: '1.1.1k',
    fixedVersion: '1.1.1n',
    severity: 'HIGH',
    status: 'fixed',
    title: '=formula-like title',
    primaryUrl: 'https://example.com',
    cvssScore: 7.5,
    cvssSource: 'nvd',
    cvssVector: null,
    publishedAt: null,
    modifiedAt: null,
  };
}

test('finding triage actions, suppression and CSV/JSON export', async () => {
  const harness = await createTestApp();
  try {
    const environment = harness.ctx.db.run(
      `INSERT INTO environments (name, kind, address, created_at, updated_at)
       VALUES ('test', 'unix', '/var/run/docker.sock', '2026-01-01', '2026-01-01')`,
    );
    harness.ctx.db.run(
      `INSERT INTO images (image_id, repo_digests, first_seen_at, updated_at)
       VALUES (?, '[]', '2026-01-01', '2026-01-01')`,
      [IMAGE_ID],
    );
    const environmentId = Number(environment.lastInsertRowid);
    harness.ctx.db.run(
      `INSERT INTO image_locations (image_id, environment_id, reference, tag, last_seen_at)
       VALUES (?, ?, 'test:1', 'test:1', '2026-01-01')`,
      [IMAGE_ID, environmentId],
    );
    const seeded = seedSuccessfulScan(harness.ctx.db, {
      imageId: IMAGE_ID,
      environmentId,
      findings: [finding()],
    });
    await harness.login();

    const open = await harness.app.inject({ method: 'GET', url: '/api/findings?state=open', headers: authHeaders(harness) });
    assert.equal(open.json<{ total: number }>().total, 1);

    const scanAll = await harness.app.inject({
      method: 'POST',
      url: '/api/scans/scan-all',
      headers: authHeaders(harness, true),
      payload: { profile: 'quick' },
    });
    assert.equal(scanAll.statusCode, 200, scanAll.body);
    assert.equal(scanAll.json<{ queued: number }>().queued, 1);

    const triage = await harness.app.inject({
      method: 'PATCH',
      url: `/api/findings/${seeded.outcome.appeared[0]?.id}/triage`,
      headers: authHeaders(harness, true),
      payload: { status: 'ignored', note: 'accepted risk' },
    });
    assert.equal(triage.statusCode, 200, triage.body);
    assert.equal(triage.json<{ finding: { triageStatus: string } }>().finding.triageStatus, 'ignored');

    const hidden = await harness.app.inject({ method: 'GET', url: '/api/findings?state=open', headers: authHeaders(harness) });
    assert.equal(hidden.json<{ total: number }>().total, 0);
    const visible = await harness.app.inject({
      method: 'GET',
      url: '/api/findings?state=open&includeSuppressed=true',
      headers: authHeaders(harness),
    });
    assert.equal(visible.json<{ total: number }>().total, 1);

    const csv = await harness.app.inject({
      method: 'GET',
      url: '/api/findings/export?state=open&includeSuppressed=true&format=csv',
      headers: authHeaders(harness),
    });
    assert.equal(csv.statusCode, 200, csv.body);
    assert.match(String(csv.headers['content-disposition']), /attachment/);
    assert.match(csv.body, /"'=formula-like title"/);

    const json = await harness.app.inject({
      method: 'GET',
      url: '/api/findings/export?state=open&includeSuppressed=true&format=json',
      headers: authHeaders(harness),
    });
    assert.equal(json.statusCode, 200, json.body);
    assert.equal(json.json<{ triageStatus: string }[]>()[0]?.triageStatus, 'ignored');
  } finally {
    await harness.close();
  }
});
