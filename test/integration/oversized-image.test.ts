import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createTestApp, authHeaders, type TestApp } from '../helpers/app.ts';
import { startFakeDocker, containerFixture, type FakeDocker } from '../helpers/fake-docker.ts';

const IMAGE_ID = `sha256:${'7'.repeat(64)}`;
// createTestApp caps the export at 64 MiB; this image is far above it.
const IMAGE_SIZE = 200 * 1024 * 1024;

let harness: TestApp;
let docker: FakeDocker;

before(async () => {
  docker = await startFakeDocker({
    images: [{ id: IMAGE_ID, repoTags: ['giant:1'], repoDigests: [], size: IMAGE_SIZE }],
    containers: [
      containerFixture({ id: 'c'.repeat(64), name: 'giant', image: 'giant:1', imageId: IMAGE_ID, state: 'running' }),
    ],
  });
  harness = await createTestApp();
  try {
    await harness.login();
    const created = await harness.app.inject({
      method: 'POST',
      url: '/api/environments',
      headers: authHeaders(harness, true),
      payload: { name: 'giant-host', kind: 'tcp', address: `${docker.host}:${docker.port}` },
    });
    assert.equal(created.statusCode, 201, created.body);
    const discovered = await harness.app.inject({
      method: 'POST',
      url: `/api/environments/${created.json<{ id: number }>().id}/discover`,
      headers: authHeaders(harness, true),
    });
    assert.equal(discovered.statusCode, 200, discovered.body);
  } catch (error) {
    await harness.close();
    await docker.close();
    throw error;
  }
});

after(async () => {
  await harness.close();
  await docker.close();
});

test('images above the export limit are refused manually and never queued automatically', async () => {
  const scan = await harness.app.inject({
    method: 'POST',
    url: '/api/scans',
    headers: authHeaders(harness, true),
    payload: { imageId: IMAGE_ID },
  });
  assert.equal(scan.statusCode, 409, scan.body);
  const body = scan.json<{ error: { code: string; message: string } }>();
  assert.equal(body.error.code, 'scan_not_queued');
  assert.match(body.error.message, /above MAX_IMAGE_EXPORT_BYTES/);

  assert.equal(harness.ctx.coordinator.enqueueScheduled(IMAGE_ID, 'standard', 'schedule'), null);
  assert.equal(
    harness.db.get<{ count: number }>('SELECT COUNT(*) AS count FROM scans')?.count,
    0,
    'no scan row is created for an oversized image',
  );
});
