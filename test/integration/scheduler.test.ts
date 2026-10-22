import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createTestApp, authHeaders, type TestApp } from '../helpers/app.ts';
import { startFakeDocker, containerFixture, type FakeDocker } from '../helpers/fake-docker.ts';
import { startFakeNtfy, type FakeNtfy } from '../helpers/fake-ntfy.ts';

const IMAGE_ID = `sha256:${'3'.repeat(64)}`;

let harness: TestApp;
let docker: FakeDocker;
let ntfy: FakeNtfy;
let environmentId: number;

before(async () => {
  ntfy = await startFakeNtfy();
  docker = await startFakeDocker({
    images: [
      {
        id: IMAGE_ID,
        repoTags: ['nginx:1.25-alpine'],
        repoDigests: [`nginx@sha256:${'4'.repeat(64)}`],
        size: 999,
      },
    ],
    containers: [
      containerFixture({
        id: 'a'.repeat(64),
        name: 'reverse-proxy',
        image: 'nginx:1.25-alpine',
        imageId: IMAGE_ID,
        state: 'running',
        ports: [{ IP: '0.0.0.0', PrivatePort: 443, PublicPort: 443, Type: 'tcp' }],
      }),
    ],
  });
  harness = await createTestApp();
  await harness.login();
  const created = await harness.app.inject({
    method: 'POST',
    url: '/api/environments',
    headers: authHeaders(harness, true),
    payload: {
      name: 'Unraid',
      kind: 'tcp',
      address: `${docker.host}:${docker.port}`,
      quickIntervalHours: 1,
      standardIntervalHours: 168,
    },
  });
  environmentId = created.json<{ id: number }>().id;
  const settings = await harness.app.inject({
    method: 'PATCH',
    url: '/api/settings',
    headers: authHeaders(harness, true),
    payload: {
      discoveryIntervalMinutes: 1,
      scanOnDiscovery: true,
      scanFailureRetries: 0,
      alertOnStale: false,
      freshnessHours: 48,
    },
  });
  assert.equal(settings.statusCode, 200, settings.body);
});

after(async () => {
  await harness.close();
  await docker.close();
  await ntfy.close();
});

function scanCount(): number {
  return harness.db.get<{ count: number }>('SELECT COUNT(*) AS count FROM scans')?.count ?? 0;
}

test('scheduler discovers endpoints, queues scans for new images, and never duplicates work', async () => {
  await harness.ctx.scheduler.tick();

  const environment = harness.db.get<{ last_discovery_at: string | null; status: string }>(
    'SELECT last_discovery_at, status FROM environments WHERE id = ?',
    [environmentId],
  );
  assert.equal(environment?.status, 'online');
  assert.ok(environment?.last_discovery_at);

  assert.equal(harness.db.get<{ count: number }>('SELECT COUNT(*) AS count FROM containers')?.count, 1);
  assert.equal(scanCount(), 1);
  const queued = harness.db.get<{ trigger: string; profile: string; status: string }>(
    'SELECT trigger, profile, status FROM scans ORDER BY id DESC LIMIT 1',
  );
  assert.equal(queued?.trigger, 'new_image');
  assert.equal(queued?.profile, 'standard');
  assert.equal(queued?.status, 'queued');

  await harness.ctx.scheduler.tick();
  assert.equal(scanCount(), 1, 'a recently queued image must not be queued repeatedly');
});

test('quick scans are due before standard scans and deep scans happen when due', async () => {
  harness.db.run('DELETE FROM scans');
  const imageRow = harness.db.get<{ image_id: string }>('SELECT image_id FROM images LIMIT 1');
  assert.ok(imageRow);
  const twoHoursAgo = new Date(Date.now() - 2 * 3_600_000).toISOString();
  harness.db.run(`UPDATE images SET last_success_at = ?, last_scan_at = ?, last_scan_status = 'success' WHERE image_id = ?`, [
    twoHoursAgo,
    twoHoursAgo,
    imageRow.image_id,
  ]);

  await harness.ctx.scheduler.tick();
  const quick = harness.db.get<{ profile: string; trigger: string }>(
    'SELECT profile, trigger FROM scans ORDER BY id DESC LIMIT 1',
  );
  assert.equal(quick?.profile, 'quick');
  assert.equal(quick?.trigger, 'schedule');

  harness.db.run('DELETE FROM scans');
  const eightDaysAgo = new Date(Date.now() - 8 * 86_400_000).toISOString();
  harness.db.run(`UPDATE images SET last_success_at = ?, last_scan_at = ? WHERE image_id = ?`, [
    eightDaysAgo,
    eightDaysAgo,
    imageRow.image_id,
  ]);
  await harness.ctx.scheduler.tick();
  const standard = harness.db.get<{ profile: string }>('SELECT profile FROM scans ORDER BY id DESC LIMIT 1');
  assert.equal(standard?.profile, 'standard', 'the deeper scan wins when both intervals are due');
});

test('stale scans alert at most once per day when enabled', async () => {
  harness.db.run('DELETE FROM scans');
  const imageRow = harness.db.get<{ image_id: string }>('SELECT image_id FROM images LIMIT 1');
  assert.ok(imageRow);
  const eightDaysAgo = new Date(Date.now() - 8 * 86_400_000).toISOString();
  harness.db.run(`UPDATE images SET last_success_at = ?, last_scan_at = ? WHERE image_id = ?`, [
    eightDaysAgo,
    eightDaysAgo,
    imageRow.image_id,
  ]);

  const settings = await harness.app.inject({
    method: 'PATCH',
    url: '/api/settings',
    headers: authHeaders(harness, true),
    payload: {
      alertOnStale: true,
      ntfy: { enabled: true, baseUrl: ntfy.url, topic: 'stale-topic', authType: 'none' },
    },
  });
  assert.equal(settings.statusCode, 200, settings.body);

  await harness.ctx.scheduler.tick();
  await harness.ctx.scheduler.tick();
  const alerts = harness.db.all<{ kind: string }>(`SELECT kind FROM alerts WHERE kind = 'stale_scan'`);
  assert.equal(alerts.length, 1);
});
