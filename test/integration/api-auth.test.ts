import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createTestApp, authHeaders, type TestApp } from '../helpers/app.ts';

let harness: TestApp;

before(async () => {
  harness = await createTestApp();
});

after(async () => {
  await harness.close();
});

test('health is public and setup state is discoverable', async () => {
  const health = await harness.app.inject({ method: 'GET', url: '/api/health' });
  assert.equal(health.statusCode, 200);
  assert.equal(health.json<{ status: string }>().status, 'ok');

  const session = await harness.app.inject({ method: 'GET', url: '/api/auth/session' });
  assert.equal(session.statusCode, 200);
  assert.deepEqual(session.json<{ needsSetup: boolean; authenticated: boolean }>().needsSetup, true);
  assert.equal(session.json<{ authenticated: boolean }>().authenticated, false);
});

test('protected endpoints reject unauthenticated requests', async () => {
  const response = await harness.app.inject({ method: 'GET', url: '/api/overview' });
  assert.equal(response.statusCode, 401);
  assert.equal(response.json<{ error: { code: string } }>().error.code, 'unauthorized');
});

test('setup rejects a wrong token and accepts the correct one once', async () => {
  const wrong = await harness.app.inject({
    method: 'POST',
    url: '/api/auth/setup',
    payload: { setupToken: 'nope', username: 'admin', password: 'correct-horse-battery' },
  });
  assert.equal(wrong.statusCode, 401);

  await harness.login();

  const again = await harness.app.inject({
    method: 'POST',
    url: '/api/auth/setup',
    payload: { setupToken: 'test-setup-token', username: 'admin2', password: 'correct-horse-battery' },
  });
  assert.equal(again.statusCode, 409);
});

test('authenticated session can read the overview and is protected by CSRF', async () => {
  const overview = await harness.app.inject({
    method: 'GET',
    url: '/api/overview',
    headers: authHeaders(harness),
  });
  assert.equal(overview.statusCode, 200);
  const body = overview.json<{ counts: { critical: number }; environments: unknown[] }>();
  assert.equal(body.counts.critical, 0);
  assert.deepEqual(body.environments, []);

  const withoutCsrf = await harness.app.inject({
    method: 'POST',
    url: '/api/environments',
    headers: authHeaders(harness),
    payload: { name: 'local', kind: 'unix', address: '/var/run/docker.sock' },
  });
  assert.equal(withoutCsrf.statusCode, 403);
});

test('environment validation rejects unsafe addresses and bad TLS material', async () => {
  const headers = authHeaders(harness, true);
  const relativeSocket = await harness.app.inject({
    method: 'POST',
    url: '/api/environments',
    headers,
    payload: { name: 'bad', kind: 'unix', address: 'docker.sock' },
  });
  assert.equal(relativeSocket.statusCode, 400);

  const badTls = await harness.app.inject({
    method: 'POST',
    url: '/api/environments',
    headers,
    payload: {
      name: 'tls-bad',
      kind: 'tls',
      address: '10.0.0.5:2376',
      tlsCa: 'not a pem',
      tlsCert: 'not a pem',
      tlsKey: 'not a pem',
    },
  });
  assert.equal(badTls.statusCode, 400);

  const valid = await harness.app.inject({
    method: 'POST',
    url: '/api/environments',
    headers,
    payload: { name: 'local', kind: 'unix', address: '/var/run/docker.sock' },
  });
  assert.equal(valid.statusCode, 201, valid.body);
  const created = valid.json<{ id: number; name: string; hasTls: boolean }>();
  assert.equal(created.name, 'local');
  assert.equal(created.hasTls, false);

  const duplicate = await harness.app.inject({
    method: 'POST',
    url: '/api/environments',
    headers,
    payload: { name: 'LOCAL', kind: 'unix', address: '/var/run/docker.sock' },
  });
  assert.equal(duplicate.statusCode, 409);

  const list = await harness.app.inject({ method: 'GET', url: '/api/environments', headers: authHeaders(harness) });
  assert.equal(list.statusCode, 200);
  assert.equal(list.json<{ items: unknown[] }>().items.length, 1);

  // Switching an endpoint away from TLS must not leave encrypted certificate material behind.
  const pemCa = '-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----';
  const pemCert = '-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----';
  const pemKey = '-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----';
  const tlsEnv = await harness.app.inject({
    method: 'POST',
    url: '/api/environments',
    headers,
    payload: { name: 'tls-endpoint', kind: 'tls', address: '10.0.0.5:2376', tlsCa: pemCa, tlsCert: pemCert, tlsKey: pemKey },
  });
  assert.equal(tlsEnv.statusCode, 201, tlsEnv.body);
  const tlsId = tlsEnv.json<{ id: number; hasTls: boolean }>().id;
  assert.equal(tlsEnv.json<{ hasTls: boolean }>().hasTls, true);
  const switched = await harness.app.inject({
    method: 'PATCH',
    url: `/api/environments/${tlsId}`,
    headers,
    payload: { kind: 'unix', address: '/var/run/docker.sock' },
  });
  assert.equal(switched.statusCode, 200, switched.body);
  assert.equal(switched.json<{ hasTls: boolean }>().hasTls, false);
});

test('unknown API routes return JSON 404 for authenticated users, and the SPA fallback reports an unbuilt UI', async () => {
  const missing = await harness.app.inject({
    method: 'GET',
    url: '/api/does-not-exist',
    headers: authHeaders(harness),
  });
  assert.equal(missing.statusCode, 404);
  assert.equal(missing.json<{ error: { code: string } }>().error.code, 'not_found');

  // Unauthenticated probes cannot distinguish existing from missing API routes.
  const anonymous = await harness.app.inject({ method: 'GET', url: '/api/does-not-exist' });
  assert.equal(anonymous.statusCode, 401);

  const spa = await harness.app.inject({ method: 'GET', url: '/containers' });
  assert.equal(spa.statusCode, 503);
});

test('login rate limiting and logout work', async () => {
  for (let index = 0; index < 12; index += 1) {
    await harness.app.inject({
      method: 'POST',
      url: '/api/auth/login',
      payload: { username: 'admin', password: 'wrong-password' },
    });
  }
  const limited = await harness.app.inject({
    method: 'POST',
    url: '/api/auth/login',
    payload: { username: 'admin', password: 'correct-horse-battery' },
  });
  assert.equal(limited.statusCode, 429);

  const logout = await harness.app.inject({
    method: 'POST',
    url: '/api/auth/logout',
    headers: authHeaders(harness, true),
  });
  assert.equal(logout.statusCode, 200);

  const afterLogout = await harness.app.inject({
    method: 'GET',
    url: '/api/overview',
    headers: authHeaders(harness),
  });
  assert.equal(afterLogout.statusCode, 401);
});
