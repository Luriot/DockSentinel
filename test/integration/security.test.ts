import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createTestApp, authHeaders, type TestApp } from '../helpers/app.ts';
import { startFakeNtfy, type FakeNtfy } from '../helpers/fake-ntfy.ts';
import { request as httpRequest } from 'node:http';
import type { AddressInfo } from 'node:net';

let harness: TestApp;
let ntfy: FakeNtfy;

before(async () => {
  ntfy = await startFakeNtfy();
  harness = await createTestApp();
  await harness.login();
});

after(async () => {
  await harness.close();
  await ntfy.close();
});

test('session cookies are HttpOnly, SameSite=Strict and not Secure over plain HTTP', async () => {
  const response = await harness.app.inject({
    method: 'POST',
    url: '/api/auth/login',
    payload: { username: 'admin', password: 'correct-horse-battery' },
  });
  assert.equal(response.statusCode, 200);
  const setCookie = response.headers['set-cookie'];
  const cookie = String(Array.isArray(setCookie) ? setCookie[0] : setCookie);
  assert.match(cookie, /HttpOnly/i);
  assert.match(cookie, /SameSite=Strict/i);
  assert.doesNotMatch(cookie, /Secure/i);
});

test('CSRF and Origin checks reject cross-site state changes', async () => {
  const wrongCsrf = await harness.app.inject({
    method: 'POST',
    url: '/api/environments',
    headers: { cookie: harness.cookie, 'x-csrf-token': 'wrong-token' },
    payload: { name: 'evil', kind: 'unix', address: '/var/run/docker.sock' },
  });
  assert.equal(wrongCsrf.statusCode, 403);

  const crossOrigin = await harness.app.inject({
    method: 'POST',
    url: '/api/environments',
    headers: {
      cookie: harness.cookie,
      'x-csrf-token': harness.csrf,
      origin: 'https://evil.example',
      host: 'docksentinel.local',
    },
    payload: { name: 'evil', kind: 'unix', address: '/var/run/docker.sock' },
  });
  assert.equal(crossOrigin.statusCode, 403);
});

test('absolute-form and percent-encoded API paths cannot bypass authentication', async () => {
  const absolute = await harness.app.inject({
    method: 'GET',
    url: 'http://evil.example/api/environments',
  });
  assert.ok([400, 401].includes(absolute.statusCode), absolute.body);

  const encoded = await harness.app.inject({
    method: 'GET',
    url: '/%61pi/environments',
  });
  assert.equal(encoded.statusCode, 401, encoded.body);

  const encodedWrite = await harness.app.inject({
    method: 'PATCH',
    url: '/%61pi/settings',
    payload: { alertOnNew: false },
  });
  assert.equal(encodedWrite.statusCode, 401, encodedWrite.body);
});

test('a raw absolute-form request target is rejected before routing', async () => {
  const app = await createTestApp();
  try {
    await app.app.listen({ port: 0, host: '127.0.0.1' });
    const address = app.app.server.address() as AddressInfo;
    const status = await new Promise<number>((resolve, reject) => {
      const request = httpRequest(
        {
          host: '127.0.0.1',
          port: address.port,
          method: 'GET',
          path: 'http://evil.example/api/environments',
          headers: { Host: 'docksentinel.local' },
        },
        (response) => {
          response.resume();
          response.on('end', () => resolve(response.statusCode ?? 0));
        },
      );
      request.on('error', reject);
      request.end();
    });
    assert.equal(status, 400);
  } finally {
    await app.close();
  }
});

test('SQL-like and XSS-like input is treated as data', async () => {
  const injected = await harness.app.inject({
    method: 'GET',
    url: `/api/findings?q=${encodeURIComponent("%' OR 1=1 --")}`,
    headers: authHeaders(harness),
  });
  assert.equal(injected.statusCode, 200);
  assert.equal(injected.json<{ total: number }>().total, 0);

  const xss = await harness.app.inject({
    method: 'GET',
    url: `/api/images/${encodeURIComponent('<script>alert(1)</script>')}`,
    headers: authHeaders(harness),
  });
  assert.equal(xss.statusCode, 404);
  assert.match(String(xss.headers['content-type']), /application\/json/);
  assert.equal(xss.body.includes('<script>'), false);
});

test('request bodies are size limited', async () => {
  const oversized = 'x'.repeat(700 * 1024);
  const response = await harness.app.inject({
    method: 'PATCH',
    url: '/api/settings',
    headers: { ...authHeaders(harness, true), 'content-type': 'application/json' },
    payload: JSON.stringify({ publicUrl: `https://example.com/${oversized}` }),
  });
  assert.equal(response.statusCode, 413);
});

test('settings validation rejects unsafe URLs and incomplete notification config', async () => {
  const badUrl = await harness.app.inject({
    method: 'PATCH',
    url: '/api/settings',
    headers: authHeaders(harness, true),
    payload: { publicUrl: 'javascript:alert(1)' },
  });
  assert.equal(badUrl.statusCode, 400);

  const enabledWithoutTopic = await harness.app.inject({
    method: 'PATCH',
    url: '/api/settings',
    headers: authHeaders(harness, true),
    payload: { ntfy: { enabled: true, baseUrl: ntfy.url, topic: '' } },
  });
  assert.equal(enabledWithoutTopic.statusCode, 400);

  const badTopic = await harness.app.inject({
    method: 'PATCH',
    url: '/api/settings',
    headers: authHeaders(harness, true),
    payload: { ntfy: { enabled: true, baseUrl: ntfy.url, topic: 'bad topic with spaces' } },
  });
  assert.equal(badTopic.statusCode, 400);

  const badAuth = await harness.app.inject({
    method: 'PATCH',
    url: '/api/settings',
    headers: authHeaders(harness, true),
    payload: {
      ntfy: { enabled: true, baseUrl: ntfy.url, topic: 'good-topic', authType: 'token', token: '' },
    },
  });
  assert.equal(badAuth.statusCode, 400);
});

test('notification secrets are encrypted at rest and cleared explicitly', async () => {
  const enabled = await harness.app.inject({
    method: 'PATCH',
    url: '/api/settings',
    headers: authHeaders(harness, true),
    payload: {
      ntfy: {
        enabled: true,
        baseUrl: ntfy.url,
        topic: 'secret-topic',
        authType: 'token',
        token: 'plaintext-token-value',
      },
    },
  });
  assert.equal(enabled.statusCode, 200, enabled.body);

  const stored = harness.db.get<{ value: string }>(`SELECT value FROM settings WHERE key = 'app'`);
  assert.ok(stored);
  assert.equal(stored.value.includes('plaintext-token-value'), false);
  assert.match(stored.value, /tokenEnc/);

  const publicSettings = await harness.app.inject({
    method: 'GET',
    url: '/api/settings',
    headers: authHeaders(harness),
  });
  assert.equal(publicSettings.body.includes('plaintext-token-value'), false);
  assert.equal(publicSettings.json<{ settings: { ntfy: { hasToken: boolean } } }>().settings.ntfy.hasToken, true);

  const cleared = await harness.app.inject({
    method: 'PATCH',
    url: '/api/settings',
    headers: authHeaders(harness, true),
    payload: { ntfy: { enabled: false, token: null } },
  });
  assert.equal(cleared.statusCode, 200, cleared.body);
  assert.equal(cleared.json<{ settings: { ntfy: { hasToken: boolean } } }>().settings.ntfy.hasToken, false);
});

test('password changes require the current password and rotate other sessions', async () => {
  const wrong = await harness.app.inject({
    method: 'POST',
    url: '/api/auth/password',
    headers: authHeaders(harness, true),
    payload: { currentPassword: 'not-the-password', newPassword: 'a-brand-new-password' },
  });
  assert.equal(wrong.statusCode, 401);

  const changed = await harness.app.inject({
    method: 'POST',
    url: '/api/auth/password',
    headers: authHeaders(harness, true),
    payload: { currentPassword: 'correct-horse-battery', newPassword: 'a-brand-new-password' },
  });
  assert.equal(changed.statusCode, 200, changed.body);

  const login = await harness.app.inject({
    method: 'POST',
    url: '/api/auth/login',
    payload: { username: 'admin', password: 'a-brand-new-password' },
  });
  assert.equal(login.statusCode, 200);

  const oldLogin = await harness.app.inject({
    method: 'POST',
    url: '/api/auth/login',
    payload: { username: 'admin', password: 'correct-horse-battery' },
  });
  assert.equal(oldLogin.statusCode, 401);
});

test('health and system endpoints do not expose secrets or credentials', async () => {
  const health = await harness.app.inject({ method: 'GET', url: '/api/health' });
  assert.equal(health.statusCode, 200);
  assert.equal(health.body.includes('secret'), false);
  assert.equal(health.body.includes('password'), false);

  const system = await harness.app.inject({ method: 'GET', url: '/api/system', headers: authHeaders(harness) });
  assert.equal(system.statusCode, 200);
  const body = system.body;
  assert.equal(body.includes('plaintext-token-value'), false);
  assert.equal(body.includes('password_hash'), false);
});
