import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createTestApp, authHeaders, type TestApp } from '../helpers/app.ts';
import { startFakeDocker, containerFixture, type FakeDocker } from '../helpers/fake-docker.ts';
import { startFakeNtfy, type FakeNtfy } from '../helpers/fake-ntfy.ts';
import { seedSuccessfulScan } from '../helpers/seed-scan.ts';
import type { NormalizedFinding } from '../../src/domain/findings.ts';

const IMAGE_ID = `sha256:${'9'.repeat(64)}`;

let harness: TestApp;
let docker: FakeDocker;
let ntfy: FakeNtfy;
let environmentId: number;

function finding(overrides: Partial<NormalizedFinding> = {}): NormalizedFinding {
  return {
    target: 'debian 11.7',
    class: 'os-pkgs',
    type: 'debian',
    vulnId: 'CVE-2024-1111',
    pkgName: 'openssl',
    installedVersion: '1.1.1k',
    fixedVersion: '1.1.1n',
    severity: 'HIGH',
    status: 'fixed',
    title: 'OpenSSL vulnerability',
    primaryUrl: 'https://example.com/CVE-2024-1111',
    cvssScore: 7.5,
    cvssSource: 'nvd',
    cvssVector: null,
    publishedAt: null,
    modifiedAt: null,
    ...overrides,
  };
}

async function enableNtfy(overrides: Record<string, unknown> = {}): Promise<void> {
  const response = await harness.app.inject({
    method: 'PATCH',
    url: '/api/settings',
    headers: authHeaders(harness, true),
    payload: {
      minAlertSeverity: 'HIGH',
      alertOnNew: true,
      alertOnResolved: true,
      alertOnScanFailure: true,
      publicUrl: 'http://docksentinel.local:8080',
      ntfy: {
        enabled: true,
        baseUrl: ntfy.url,
        topic: 'docksentinel-e2e',
        authType: 'token',
        token: 'super-secret-ntfy-token',
        priority: 'default',
        tags: 'shield',
        ...overrides,
      },
    },
  });
  assert.equal(response.statusCode, 200, response.body);
}

before(async () => {
  ntfy = await startFakeNtfy();
  docker = await startFakeDocker({
    images: [
      {
        id: IMAGE_ID,
        repoTags: ['php:8.1-apache'],
        repoDigests: [`php@sha256:${'7'.repeat(64)}`],
        size: 12345,
      },
    ],
    containers: [
      containerFixture({
        id: 'c'.repeat(64),
        name: 'php-app',
        image: 'php:8.1-apache',
        imageId: IMAGE_ID,
        state: 'running',
        ports: [{ IP: '0.0.0.0', PrivatePort: 80, PublicPort: 8080, Type: 'tcp' }],
      }),
    ],
  });
  harness = await createTestApp();
  await harness.login();
  const created = await harness.app.inject({
    method: 'POST',
    url: '/api/environments',
    headers: authHeaders(harness, true),
    payload: { name: 'Unraid', kind: 'tcp', address: `${docker.host}:${docker.port}` },
  });
  environmentId = created.json<{ id: number }>().id;
  const discovered = await harness.app.inject({
    method: 'POST',
    url: `/api/environments/${environmentId}/discover`,
    headers: authHeaders(harness, true),
  });
  assert.equal(discovered.statusCode, 200, discovered.body);
});

after(async () => {
  await harness.close();
  await docker.close();
  await ntfy.close();
});

test('settings never expose notification secrets', async () => {
  await enableNtfy();
  const response = await harness.app.inject({ method: 'GET', url: '/api/settings', headers: authHeaders(harness) });
  assert.equal(response.statusCode, 200);
  assert.equal(response.body.includes('super-secret-ntfy-token'), false);
  const body = response.json<{ settings: { ntfy: { hasToken: boolean; enabled: boolean; topic: string } } }>();
  assert.equal(body.settings.ntfy.enabled, true);
  assert.equal(body.settings.ntfy.hasToken, true);
  assert.equal(body.settings.ntfy.topic, 'docksentinel-e2e');
});

test('new findings produce one actionable alert and are not repeated on the same scan', async () => {
  const seeded = seedSuccessfulScan(harness.db, {
    imageId: IMAGE_ID,
    environmentId,
    imageRef: 'php:8.1-apache',
    findings: [finding(), finding({ vulnId: 'CVE-2024-2222', pkgName: 'curl', severity: 'CRITICAL' })],
  });
  harness.ctx.alerts.evaluateScan(seeded.scan, seeded.outcome);

  const alertCount = harness.db.get<{ count: number }>('SELECT COUNT(*) AS count FROM alerts WHERE kind = ?', [
    'new_findings',
  ])?.count;
  assert.equal(alertCount, 1, 'new findings should be grouped into a single notification per scan');

  // Re-evaluating the same scan result must not duplicate the alert.
  harness.ctx.alerts.evaluateScan(seeded.scan, seeded.outcome);
  assert.equal(
    harness.db.get<{ count: number }>('SELECT COUNT(*) AS count FROM alerts WHERE kind = ?', ['new_findings'])?.count,
    1,
  );

  assert.equal(ntfy.requests.length, 0, 'alerts stay queued until the dispatcher runs');
  await harness.ctx.dispatcher.tick();
  assert.equal(ntfy.requests.length, 1);
  const delivered = ntfy.requests[0]!;
  assert.equal(delivered.topic, 'docksentinel-e2e');
  assert.equal(delivered.headers.authorization, 'Bearer super-secret-ntfy-token');
  assert.equal(delivered.headers.markdown, 'yes');
  assert.match(String(delivered.headers.title), /critical|high/i);
  assert.match(delivered.body, /CVE-2024-2222/);
  assert.match(delivered.body, /php-app/);
  assert.match(delivered.body, /Unraid/);
  assert.match(delivered.body, /Fix available/);
  assert.match(delivered.body, /https:\/\/example\.com/);
  assert.equal(String(delivered.headers.click).startsWith('http://docksentinel.local:8080'), true);

  const stored = harness.db.get<{ status: string; attempts: number; sent_at: string | null }>(
    `SELECT status, attempts, sent_at FROM alerts WHERE kind = 'new_findings'`,
  );
  assert.equal(stored?.status, 'sent');
  assert.equal(stored?.attempts, 1);
  assert.ok(stored?.sent_at);
});

test('delivery failures are retried with backoff and recorded', async () => {
  const seeded = seedSuccessfulScan(harness.db, {
    imageId: IMAGE_ID,
    environmentId,
    imageRef: 'php:8.1-apache',
    findings: [
      finding(),
      finding({ vulnId: 'CVE-2024-2222', pkgName: 'curl', severity: 'CRITICAL' }),
      finding({ vulnId: 'CVE-2024-3333', pkgName: 'bash', severity: 'HIGH' }),
    ],
  });
  // Same findings plus one new one: a second scan's appeared set triggers a new alert.
  harness.ctx.alerts.evaluateScan(seeded.scan, seeded.outcome);
  const pending = harness.db.get<{ id: number }>(
    `SELECT id FROM alerts WHERE kind = 'new_findings' AND status = 'pending' ORDER BY id DESC LIMIT 1`,
  );
  assert.ok(pending, 'a new alert should be pending');
  const before = ntfy.requests.length;

  ntfy.failNext(1, 503, 'ntfy maintenance');
  await harness.ctx.dispatcher.tick();
  assert.equal(ntfy.requests.length, before + 1);

  const failed = harness.db.get<{ status: string; attempts: number; last_error: string; next_attempt_at: string | null }>(
    'SELECT status, attempts, last_error, next_attempt_at FROM alerts WHERE id = ?',
    [pending.id],
  );
  assert.equal(failed?.status, 'pending');
  assert.equal(failed?.attempts, 1);
  assert.match(failed?.last_error ?? '', /503/);
  assert.ok(failed?.next_attempt_at, 'retry must be scheduled with backoff');

  // Simulate the backoff elapsing, then deliver successfully.
  harness.db.run('UPDATE alerts SET next_attempt_at = ? WHERE id = ?', [
    '2020-01-01T00:00:00.000Z',
    pending.id,
  ]);
  await harness.ctx.dispatcher.tick();
  const sent = harness.db.get<{ status: string; attempts: number }>('SELECT status, attempts FROM alerts WHERE id = ?', [
    pending.id,
  ]);
  assert.equal(sent?.status, 'sent');
  assert.equal(sent?.attempts, 2);
});

test('resolved findings notify once and are only reported after a successful scan', async () => {
  const { scan } = seedSuccessfulScan(harness.db, {
    imageId: IMAGE_ID,
    environmentId,
    imageRef: 'php:8.1-apache',
    findings: [finding(), finding({ vulnId: 'CVE-2024-4444', pkgName: 'zlib' })],
  });
  const resolvedOnly = seedSuccessfulScan(harness.db, {
    imageId: IMAGE_ID,
    environmentId,
    imageRef: 'php:8.1-apache',
    findings: [finding()],
  });
  harness.ctx.alerts.evaluateScan(resolvedOnly.scan, resolvedOnly.outcome);
  assert.equal(resolvedOnly.outcome.resolved.length, 1);

  const alerts = harness.db.all<{ kind: string; body: string }>(
    `SELECT kind, body FROM alerts WHERE kind = 'resolved_findings'`,
  );
  assert.equal(alerts.length, 1);
  assert.match(alerts[0]?.body ?? '', /confirmed by a successful scan/i);
  const before = ntfy.requests.length;
  await harness.ctx.dispatcher.tick();
  assert.equal(ntfy.requests.length, before + 1);
  void scan;
});

test('test notifications report delivery failures and success', async () => {
  ntfy.failNext(1, 500, 'boom');
  const failed = await harness.app.inject({
    method: 'POST',
    url: '/api/notifications/test',
    headers: authHeaders(harness, true),
  });
  assert.equal(failed.statusCode, 200);
  assert.equal(failed.json<{ ok: boolean }>().ok, false);
  assert.match(failed.json<{ message: string }>().message, /500/);

  const succeeded = await harness.app.inject({
    method: 'POST',
    url: '/api/notifications/test',
    headers: authHeaders(harness, true),
  });
  assert.equal(succeeded.statusCode, 200);
  assert.equal(succeeded.json<{ ok: boolean }>().ok, true);

  const history = await harness.app.inject({
    method: 'GET',
    url: '/api/notifications?page=1&pageSize=50',
    headers: authHeaders(harness),
  });
  assert.equal(history.statusCode, 200);
  const body = history.json<{ counts: { sent: number; failed: number }; alerts: { items: { kind: string }[] } }>();
  assert.ok(body.alerts.items.some((alert) => alert.kind === 'test'));
  assert.ok(body.counts.sent >= 1);
  assert.ok(body.counts.failed >= 1);
});

test('disabled notifications never create alert rows', async () => {
  const disabled = await harness.app.inject({
    method: 'PATCH',
    url: '/api/settings',
    headers: authHeaders(harness, true),
    payload: { ntfy: { enabled: false } },
  });
  assert.equal(disabled.statusCode, 200, disabled.body);
  const before = harness.db.get<{ count: number }>('SELECT COUNT(*) AS count FROM alerts')?.count ?? 0;
  const seeded = seedSuccessfulScan(harness.db, {
    imageId: IMAGE_ID,
    environmentId,
    imageRef: 'php:8.1-apache',
    findings: [finding(), finding({ vulnId: 'CVE-2024-5555', pkgName: 'libc6', severity: 'CRITICAL' })],
  });
  harness.ctx.alerts.evaluateScan(seeded.scan, seeded.outcome);
  assert.equal(harness.db.get<{ count: number }>('SELECT COUNT(*) AS count FROM alerts')?.count, before);
  await enableNtfy();
});
