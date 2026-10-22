import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createTestApp, authHeaders, type TestApp } from '../helpers/app.ts';
import { startFakeDocker, containerFixture, type FakeDocker } from '../helpers/fake-docker.ts';

const IMAGE_ID = `sha256:${'a'.repeat(64)}`;
const SECOND_IMAGE_ID = `sha256:${'b'.repeat(64)}`;

let harness: TestApp;
let docker: FakeDocker;
let environmentId: number;

before(async () => {
  harness = await createTestApp();
  docker = await startFakeDocker({
    images: [
      {
        id: IMAGE_ID,
        repoTags: ['docksentinel-test:1'],
        repoDigests: [`docksentinel-test@sha256:${'c'.repeat(64)}`],
        size: 12345,
      },
      { id: SECOND_IMAGE_ID, repoTags: ['redis:7-alpine'], repoDigests: [], size: 54321 },
    ],
    containers: [
      containerFixture({
        id: 'a'.repeat(64),
        name: 'php-app',
        imageId: IMAGE_ID,
        state: 'running',
        ports: [{ IP: '0.0.0.0', PrivatePort: 80, PublicPort: 8080, Type: 'tcp' }],
        labels: {
          'docksentinel.exposure': 'internet',
          'docksentinel.criticality': 'critical',
          'traefik.enable': 'true',
          'traefik.http.middlewares.auth.basicauth.users': 'admin:$apr1$secret',
        },
      }),
      containerFixture({
        id: 'd'.repeat(64),
        name: 'worker',
        imageId: IMAGE_ID,
        state: 'running',
        ports: [],
        labels: {},
      }),
      containerFixture({
        id: 'e'.repeat(64),
        name: 'db',
        imageId: SECOND_IMAGE_ID,
        image: 'redis:7-alpine',
        state: 'exited',
        ports: [],
      }),
    ],
  });
  await harness.login();
});

after(async () => {
  await docker.close();
  await harness.close();
});

test('environment can be created and tested against a spec-shaped Docker API', async () => {
  const created = await harness.app.inject({
    method: 'POST',
    url: '/api/environments',
    headers: authHeaders(harness, true),
    payload: { name: 'Fake Docker', kind: 'tcp', address: `${docker.host}:${docker.port}` },
  });
  assert.equal(created.statusCode, 201, created.body);
  environmentId = created.json<{ id: number }>().id;

  const tested = await harness.app.inject({
    method: 'POST',
    url: `/api/environments/${environmentId}/test`,
    headers: authHeaders(harness, true),
  });
  assert.equal(tested.statusCode, 200);
  const result = tested.json<{ ok: boolean; version: { Version: string }; containers: number; images: number }>();
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.version.Version, '25.0.9');
  assert.equal(result.containers, 3);
  assert.equal(result.images, 2);
});

test('discovery records containers, images and docksentinel labels only', async () => {
  const discovered = await harness.app.inject({
    method: 'POST',
    url: `/api/environments/${environmentId}/discover`,
    headers: authHeaders(harness, true),
  });
  assert.equal(discovered.statusCode, 200, discovered.body);
  const summary = discovered.json<{ containers: number; images: number }>();
  assert.equal(summary.containers, 3);
  assert.equal(summary.images, 2);

  const containers = await harness.app.inject({
    method: 'GET',
    url: '/api/containers',
    headers: authHeaders(harness),
  });
  assert.equal(containers.statusCode, 200);
  const items = containers.json<{
    items: {
      name: string;
      state: string;
      exposure: string;
      labels: Record<string, string>;
      environmentName: string;
      imageId: string;
    }[];
  }>().items;
  assert.equal(items.length, 3);

  const php = items.find((item) => item.name === 'php-app');
  assert.ok(php);
  assert.equal(php.exposure, 'confirmed');
  assert.equal(php.environmentName, 'Fake Docker');
  assert.equal(php.labels['docksentinel.exposure'], 'internet');
  assert.equal('traefik.enable' in php.labels, false, 'non-docksentinel labels must not be stored');
  assert.equal('traefik.http.middlewares.auth.basicauth.users' in php.labels, false);

  const worker = items.find((item) => item.name === 'worker');
  assert.ok(worker);
  assert.equal(worker.exposure, 'internal');

  const db = items.find((item) => item.name === 'db');
  assert.ok(db);
  assert.equal(db.exposure, 'unknown');
});

test('images are deduplicated by immutable image ID', async () => {
  const response = await harness.app.inject({
    method: 'GET',
    url: '/api/images',
    headers: authHeaders(harness),
  });
  assert.equal(response.statusCode, 200);
  const body = response.json<{
    total: number;
    items: { imageId: string; references: { tag: string | null }[]; containerCount: number }[];
  }>();
  assert.equal(body.total, 2);
  const php = body.items.find((image) => image.imageId === IMAGE_ID);
  assert.ok(php);
  assert.equal(php.containerCount, 2);
  assert.ok(php.references.some((reference) => reference.tag === 'docksentinel-test:1'));
});

test('a failing endpoint does not affect another endpoint', async () => {
  const bad = await harness.app.inject({
    method: 'POST',
    url: '/api/environments',
    headers: authHeaders(harness, true),
    payload: { name: 'Unreachable', kind: 'tcp', address: '127.0.0.1:1' },
  });
  assert.equal(bad.statusCode, 201, bad.body);
  const badId = bad.json<{ id: number }>().id;

  const failed = await harness.app.inject({
    method: 'POST',
    url: `/api/environments/${badId}/discover`,
    headers: authHeaders(harness, true),
  });
  assert.equal(failed.statusCode, 502);

  const list = await harness.app.inject({ method: 'GET', url: '/api/environments', headers: authHeaders(harness) });
  const environments = list.json<{ items: { id: number; status: string; statusMessage: string | null }[] }>().items;
  const broken = environments.find((environment) => environment.id === badId);
  assert.ok(broken);
  assert.equal(broken.status, 'offline');
  assert.ok((broken.statusMessage?.length ?? 0) > 0);

  const healthy = environments.find((environment) => environment.id === environmentId);
  assert.ok(healthy);
  assert.equal(healthy.status, 'online');

  const containers = await harness.app.inject({
    method: 'GET',
    url: '/api/containers',
    headers: authHeaders(harness),
  });
  assert.equal(containers.json<{ total: number }>().total, 3);
});

test('Docker API mutations are never attempted', () => {
  assert.ok(docker.requests.length > 0);
  assert.ok(docker.requests.every((request) => request.method === 'GET'));
  assert.ok(docker.requests.every((request) => !/\/containers\/[^/]+\/(start|stop|restart|kill)/.test(request.path)));
});
