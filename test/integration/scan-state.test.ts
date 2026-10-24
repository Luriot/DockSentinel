import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createTestApp, authHeaders, type TestApp } from '../helpers/app.ts';
import { startFakeDocker, containerFixture } from '../helpers/fake-docker.ts';
import { scanStatusCounts } from '../../src/repo/scans.ts';

const IMAGE_ID = `sha256:${'5'.repeat(64)}`;

test('scan activity counts cancelled scans separately from failures', async () => {
  const harness = await createTestApp();
  try {
    const now = new Date().toISOString();
    for (const status of ['success', 'failed', 'cancelled']) {
      harness.db.run(
        `INSERT INTO scans (image_id, image_ref, profile, trigger, status, queued_at)
         VALUES (?, 'retry:1', 'standard', 'manual', ?, ?)`,
        [IMAGE_ID, status, now],
      );
    }

    const counts = scanStatusCounts(harness.db, new Date(Date.now() - 60_000).toISOString());
    assert.deepEqual(counts, { queued: 0, running: 0, success: 1, failed: 1, cancelled: 1 });
  } finally {
    await harness.close();
  }
});

test('a queued retry does not mark the image as failed', async () => {
  const docker = await startFakeDocker({
    images: [{ id: IMAGE_ID, repoTags: ['retry:1'], repoDigests: [] }],
    containers: [
      containerFixture({ id: 'a'.repeat(64), name: 'retry-app', image: 'retry:1', imageId: IMAGE_ID, state: 'running' }),
    ],
  });
  docker.setFailure('/get', { status: 500, body: 'export failed' });
  const harness = await createTestApp();
  try {
    await harness.login();
    const settings = await harness.app.inject({
      method: 'PATCH',
      url: '/api/settings',
      headers: authHeaders(harness, true),
      payload: { scanFailureRetries: 2 },
    });
    assert.equal(settings.statusCode, 200, settings.body);
    await harness.ctx.coordinator.start();

    const created = await harness.app.inject({
      method: 'POST',
      url: '/api/environments',
      headers: authHeaders(harness, true),
      payload: { name: 'retry-host', kind: 'tcp', address: `${docker.host}:${docker.port}` },
    });
    assert.equal(created.statusCode, 201, created.body);
    const environmentId = created.json<{ id: number }>().id;
    const discovered = await harness.app.inject({
      method: 'POST',
      url: `/api/environments/${environmentId}/discover`,
      headers: authHeaders(harness, true),
    });
    assert.equal(discovered.statusCode, 200, discovered.body);

    const queued = await harness.app.inject({
      method: 'POST',
      url: '/api/scans',
      headers: authHeaders(harness, true),
      payload: { imageId: IMAGE_ID, profile: 'quick' },
    });
    assert.equal(queued.statusCode, 202, queued.body);

    const scan = await waitForScan(harness, 'image_export_failed');
    assert.equal(scan.status, 'queued', 'the failed attempt must be requeued for a retry');
    assert.ok(scan.run_after, 'a retry must be scheduled in the future');

    const image = harness.db.get<{ last_scan_status: string | null }>(
      'SELECT last_scan_status FROM images WHERE image_id = ?',
      [IMAGE_ID],
    );
    assert.equal(image?.last_scan_status, null, 'a queued retry must not count as a terminal failure');
  } finally {
    await harness.close();
    await docker.close();
  }
});

async function waitForScan(
  harness: TestApp,
  errorCode: string,
): Promise<{ status: string; run_after: string | null }> {
  const deadline = Date.now() + 15_000;
  for (;;) {
    const row = harness.db.get<{ status: string; run_after: string | null; error_code: string | null }>(
      'SELECT status, run_after, error_code FROM scans ORDER BY id DESC LIMIT 1',
    );
    if (row?.error_code === errorCode) return row;
    if (Date.now() > deadline) throw new Error(`scan did not fail with ${errorCode}: ${JSON.stringify(row)}`);
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
}
