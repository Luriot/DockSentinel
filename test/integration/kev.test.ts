import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createTestApp, authHeaders, type TestApp } from '../helpers/app.ts';
import { startFakeDocker, containerFixture, type FakeDocker } from '../helpers/fake-docker.ts';
import { startFakeNtfy, type FakeNtfy } from '../helpers/fake-ntfy.ts';
import { seedSuccessfulScan } from '../helpers/seed-scan.ts';

const IMAGE_ID = `sha256:${'5'.repeat(64)}`;
const CATALOG = {
  title: 'CISA Catalog of Known Exploited Vulnerabilities',
  catalogVersion: '2026.01.01',
  count: 1,
  vulnerabilities: [
    {
      cveID: 'CVE-2023-1111',
      vendorProject: 'Example',
      product: 'Widget',
      vulnerabilityName: 'Example widget RCE',
      dateAdded: '2025-12-01',
      dueDate: '2025-12-20',
      knownRansomwareCampaignUse: 'Known',
    },
  ],
};

let harness: TestApp;
let docker: FakeDocker;
let ntfy: FakeNtfy;
let kevServer: Server;
let kevPort: number;
let environmentId: number;

before(async () => {
  ntfy = await startFakeNtfy();
  kevServer = createServer((_request, response) => {
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.end(JSON.stringify(CATALOG));
  });
  await new Promise<void>((resolve) => kevServer.listen(0, '127.0.0.1', () => resolve()));
  kevPort = (kevServer.address() as AddressInfo).port;

  docker = await startFakeDocker({
    images: [{ id: IMAGE_ID, repoTags: ['example:1'], repoDigests: [], size: 100 }],
    containers: [
      containerFixture({
        id: 'b'.repeat(64),
        name: 'widget',
        image: 'example:1',
        imageId: IMAGE_ID,
        state: 'running',
      }),
    ],
  });

  harness = await createTestApp({ kevUrl: `http://127.0.0.1:${kevPort}/kev.json` });
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

  const settings = await harness.app.inject({
    method: 'PATCH',
    url: '/api/settings',
    headers: authHeaders(harness, true),
    payload: {
      alertOnNew: false,
      alertOnResolved: false,
      alertOnKev: true,
      ntfy: { enabled: true, baseUrl: ntfy.url, topic: 'kev-topic', authType: 'none' },
    },
  });
  assert.equal(settings.statusCode, 200, settings.body);
});

after(async () => {
  await harness.close();
  await docker.close();
  await ntfy.close();
  await new Promise<void>((resolve) => kevServer.close(() => resolve()));
});

test('KEV sync flags findings and raises a single known-exploited alert', async () => {
  seedSuccessfulScan(harness.db, {
    imageId: IMAGE_ID,
    environmentId,
    imageRef: 'example:1',
    findings: [
      {
        target: 'debian 11.7',
        class: 'os-pkgs',
        type: 'debian',
        vulnId: 'CVE-2023-1111',
        pkgName: 'widget',
        installedVersion: '1.0',
        fixedVersion: '1.1',
        severity: 'HIGH',
        status: 'fixed',
        title: 'Widget RCE',
        primaryUrl: 'https://example.com/advisory',
        cvssScore: 9.8,
        cvssSource: 'nvd',
        cvssVector: null,
        publishedAt: null,
        modifiedAt: null,
      },
    ],
  });

  const synced = await harness.app.inject({
    method: 'POST',
    url: '/api/kev/sync',
    headers: authHeaders(harness, true),
  });
  assert.equal(synced.statusCode, 200);
  assert.equal(synced.json<{ ok: boolean; entryCount: number }>().ok, true);
  assert.equal(synced.json<{ entryCount: number }>().entryCount, 1);

  const finding = harness.db.get<{ kev: number; kev_added_at: string | null }>(
    `SELECT kev, kev_added_at FROM findings WHERE vuln_id = 'CVE-2023-1111'`,
  );
  assert.equal(finding?.kev, 1);
  assert.equal(finding?.kev_added_at, '2025-12-01');

  const alert = harness.db.get<{ id: number; title: string; priority: number; status: string }>(
    `SELECT id, title, priority, status FROM alerts WHERE kind = 'known_exploited'`,
  );
  assert.ok(alert);
  assert.equal(alert.status, 'pending');
  assert.equal(alert.priority, 5);
  assert.match(alert.title, /known exploited/i);

  await harness.ctx.dispatcher.tick();
  assert.equal(ntfy.requests.length, 1);
  assert.match(ntfy.requests[0]?.body ?? '', /Known Exploited/i);
  assert.match(ntfy.requests[0]?.body ?? '', /CVE-2023-1111/);

  const again = await harness.app.inject({
    method: 'POST',
    url: '/api/kev/sync',
    headers: authHeaders(harness, true),
  });
  assert.equal(again.json<{ ok: boolean }>().ok, true);
  const alertCount = harness.db.get<{ count: number }>(
    `SELECT COUNT(*) AS count FROM alerts WHERE kind = 'known_exploited'`,
  )?.count;
  assert.equal(alertCount, 1, 'the same KEV-listed finding must not alert repeatedly');

  const settings = await harness.app.inject({ method: 'GET', url: '/api/settings', headers: authHeaders(harness) });
  const status = settings.json<{ kev: { available: boolean; entryCount: number; stale: boolean } }>().kev;
  assert.equal(status.available, true);
  assert.equal(status.entryCount, 1);
});

test('KEV sync failure keeps the previous catalog and reports the error', async () => {
  await new Promise<void>((resolve) => kevServer.close(() => resolve()));

  const failed = await harness.app.inject({
    method: 'POST',
    url: '/api/kev/sync',
    headers: authHeaders(harness, true),
  });
  assert.equal(failed.statusCode, 200);
  assert.equal(failed.json<{ ok: boolean; error: string }>().ok, false);
  assert.match(failed.json<{ error: string }>().error, /fetch|ECONNREFUSED|connect/i);

  const settings = await harness.app.inject({ method: 'GET', url: '/api/settings', headers: authHeaders(harness) });
  const status = settings.json<{
    kev: { available: boolean; entryCount: number; status: string; error: string | null };
  }>().kev;
  assert.equal(status.available, true);
  assert.equal(status.entryCount, 1);
  assert.equal(status.status, 'error');
  assert.ok(status.error);
  assert.equal(
    harness.db.get<{ kev: number }>(`SELECT kev FROM findings WHERE vuln_id = 'CVE-2023-1111'`)?.kev,
    1,
  );
});
