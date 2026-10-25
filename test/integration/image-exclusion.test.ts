import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createTestApp, authHeaders, type TestApp } from '../helpers/app.ts';
import { startFakeDocker, containerFixture, type FakeDocker } from '../helpers/fake-docker.ts';

const IMAGE_ID = `sha256:${'f'.repeat(64)}`;

let harness: TestApp;
let docker: FakeDocker;

before(async () => {
  docker = await startFakeDocker({
    images: [{ id: IMAGE_ID, repoTags: ['quarantine:1'], repoDigests: [], size: 100 }],
    containers: [
      containerFixture({ id: 'q'.repeat(64), name: 'quarantine', image: 'quarantine:1', imageId: IMAGE_ID, state: 'exited' }),
    ],
  });
  harness = await createTestApp();
  try {
    await harness.login();
    const created = await harness.app.inject({
      method: 'POST',
      url: '/api/environments',
      headers: authHeaders(harness, true),
      payload: { name: 'quarantine-host', kind: 'tcp', address: `${docker.host}:${docker.port}` },
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

test('an excluded image is never scheduled, and manual scans are refused', async () => {
  const excluded = await harness.app.inject({
    method: 'PATCH',
    url: `/api/images/${encodeURIComponent(IMAGE_ID)}`,
    headers: authHeaders(harness, true),
    payload: { scanExcluded: true },
  });
  assert.equal(excluded.statusCode, 200, excluded.body);
  assert.equal(excluded.json<{ image: { scanExcluded: boolean } }>().image.scanExcluded, true);

  const manual = await harness.app.inject({
    method: 'POST',
    url: '/api/scans',
    headers: authHeaders(harness, true),
    payload: { imageId: IMAGE_ID },
  });
  assert.equal(manual.statusCode, 409, manual.body);
  assert.match(manual.json<{ error: { message: string } }>().error.message, /excluded from scanning/);

  await harness.ctx.scheduler.tick();
  assert.equal(
    harness.db.get<{ count: number }>('SELECT COUNT(*) AS count FROM scans')?.count,
    0,
    'the scheduler must not queue an excluded image',
  );

  const included = await harness.app.inject({
    method: 'PATCH',
    url: `/api/images/${encodeURIComponent(IMAGE_ID)}`,
    headers: authHeaders(harness, true),
    payload: { scanExcluded: false },
  });
  assert.equal(included.statusCode, 200, included.body);

  await harness.ctx.scheduler.tick();
  assert.equal(
    harness.db.get<{ count: number }>('SELECT COUNT(*) AS count FROM scans')?.count,
    1,
    'including the image restores scheduled scans',
  );
});
