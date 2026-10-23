import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createTestApp, authHeaders } from '../helpers/app.ts';
import { startFakeDocker, containerFixture } from '../helpers/fake-docker.ts';
import { buildSyntheticImage } from '../helpers/synthetic-image.ts';

test('one-click local Docker connection creates and discovers a host', async () => {
  const image = buildSyntheticImage();
  const docker = await startFakeDocker({
    images: [
      {
        id: image.imageId,
        repoTags: [image.repositoryTag],
        repoDigests: [`docksentinel-test@sha256:${'e'.repeat(64)}`],
        size: image.sizeBytes,
      },
    ],
    containers: [
      containerFixture({
        id: 'd'.repeat(64),
        name: 'local-app',
        imageId: image.imageId,
        state: 'running',
      }),
    ],
    archives: new Map([[image.imageId, image.archive]]),
  });
  const previousHost = process.env.DOCKER_HOST;
  process.env.DOCKER_HOST = `tcp://127.0.0.1:${docker.port}`;
  const harness = await createTestApp();
  try {
    await harness.login();
    const response = await harness.app.inject({
      method: 'POST',
      url: '/api/environments/local',
      headers: authHeaders(harness, true),
      payload: {},
    });
    assert.equal(response.statusCode, 201, response.body);
    const body = response.json<{
      created: boolean;
      environment: { id: number; name: string; kind: string; address: string; counts: { containers: number; images: number } };
      discovery: { containers: number; images: number } | null;
    }>();
    assert.equal(body.created, true);
    assert.equal(body.environment.name, 'This computer');
    assert.equal(body.environment.kind, 'tcp');
    assert.equal(body.discovery?.containers, 1);
    assert.equal(body.discovery?.images, 1);

    const again = await harness.app.inject({
      method: 'POST',
      url: '/api/environments/local',
      headers: authHeaders(harness, true),
      payload: {},
    });
    assert.equal(again.statusCode, 200, again.body);
    assert.equal(again.json<{ created: boolean }>().created, false);

    const listed = await harness.app.inject({
      method: 'GET',
      url: '/api/environments',
      headers: authHeaders(harness),
    });
    assert.equal(listed.json<{ items: unknown[] }>().items.length, 1);
  } finally {
    if (previousHost === undefined) delete process.env.DOCKER_HOST;
    else process.env.DOCKER_HOST = previousHost;
    await harness.close();
    await docker.close();
  }
});
