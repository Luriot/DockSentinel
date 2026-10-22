import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { createTestApp, authHeaders, type TestApp } from '../helpers/app.ts';
import { startFakeDocker, containerFixture, type FakeDocker } from '../helpers/fake-docker.ts';
import { buildSyntheticImage, type SyntheticImage } from '../helpers/synthetic-image.ts';
import { defaultTrivyCacheDir, trivyAvailable, trivyDatabasePresent } from '../helpers/trivy.ts';

const canRun = trivyAvailable() && trivyDatabasePresent();

let harness: TestApp;
let docker: FakeDocker;
let image: SyntheticImage;
let environmentId: number;
let imageId: string;

async function waitForScan(
  app: TestApp['app'],
  headers: Record<string, string>,
  scanId: number,
  timeoutMs = 180_000,
): Promise<Record<string, unknown>> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const response = await app.inject({ method: 'GET', url: `/api/scans/${scanId}`, headers });
    if (response.statusCode === 200) {
      const scan = response.json<{ scan: Record<string, unknown> }>().scan;
      if (scan.status === 'success' || scan.status === 'failed' || scan.status === 'cancelled') return scan;
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`scan ${scanId} did not finish within ${timeoutMs}ms`);
}

before(async () => {
  if (!canRun) return;
  image = buildSyntheticImage();
  docker = await startFakeDocker({
    images: [
      {
        id: image.imageId,
        repoTags: [image.repositoryTag],
        repoDigests: [`docksentinel-test@sha256:${'c'.repeat(64)}`],
        size: image.sizeBytes,
      },
    ],
    containers: [
      containerFixture({
        id: 'f'.repeat(64),
        name: 'php-app',
        imageId: image.imageId,
        state: 'running',
        ports: [{ IP: '0.0.0.0', PrivatePort: 80, PublicPort: 8080, Type: 'tcp' }],
        labels: { 'docksentinel.exposure': 'internet' },
      }),
    ],
    archives: new Map([[image.imageId, image.archive]]),
  });

  harness = await createTestApp({
    trivyBin: 'trivy',
    trivyCacheDir: defaultTrivyCacheDir(),
    scanTimeoutMs: 180_000,
  });
  await harness.login();
  await harness.ctx.coordinator.start();

  const created = await harness.app.inject({
    method: 'POST',
    url: '/api/environments',
    headers: authHeaders(harness, true),
    payload: { name: 'Fake Docker', kind: 'tcp', address: `${docker.host}:${docker.port}` },
  });
  assert.equal(created.statusCode, 201, created.body);
  environmentId = created.json<{ id: number }>().id;

  const discovered = await harness.app.inject({
    method: 'POST',
    url: `/api/environments/${environmentId}/discover`,
    headers: authHeaders(harness, true),
  });
  assert.equal(discovered.statusCode, 200, discovered.body);

  const images = await harness.app.inject({
    method: 'GET',
    url: '/api/images',
    headers: authHeaders(harness),
  });
  imageId = images.json<{ items: { imageId: string }[] }>().items[0]?.imageId ?? '';
  assert.equal(imageId, image.imageId);
});

after(async () => {
  if (!canRun) return;
  await harness.close();
  await docker.close();
});

test('real Trivy produces normalised findings for a docker-save image', { skip: !canRun }, async () => {
  const queued = await harness.app.inject({
    method: 'POST',
    url: `/api/images/${encodeURIComponent(imageId)}/scan`,
    headers: authHeaders(harness, true),
    payload: { profile: 'standard' },
  });
  assert.equal(queued.statusCode, 202, queued.body);
  const scanId = queued.json<{ scanId: number }>().scanId;

  const scan = await waitForScan(harness.app, authHeaders(harness), scanId);
  assert.equal(scan.status, 'success', JSON.stringify(scan));
  assert.equal(scan.attempts, 1);
  assert.ok(Number(scan.total) > 30, `expected real findings, got ${scan.total}`);
  assert.ok(Number(scan.critical) >= 1);
  assert.ok(Number(scan.high) >= 1);
  assert.ok(Number(scan.fixable) >= 1);
  assert.ok(typeof scan.scannerVersion === 'string' && scan.scannerVersion.length > 0);
  assert.ok(typeof scan.dbUpdatedAt === 'string' && !Number.isNaN(Date.parse(String(scan.dbUpdatedAt))));

  const findings = await harness.app.inject({
    method: 'GET',
    url: `/api/findings?imageId=${encodeURIComponent(imageId)}&severity=CRITICAL`,
    headers: authHeaders(harness),
  });
  assert.equal(findings.statusCode, 200);
  const body = findings.json<{
    items: {
      vulnId: string;
      severity: string;
      priority: { tier: string; factors: string[] };
      kev: number;
      containers: { name: string }[];
      fixedVersion: string | null;
    }[];
    counts: { CRITICAL: number };
  }>();
  assert.ok(body.items.length >= 1);
  assert.ok(body.items.every((finding) => finding.severity === 'CRITICAL'));
  assert.ok(body.items.some((finding) => finding.fixedVersion), 'at least one critical finding should list a fix');
  assert.ok(body.items.every((finding) => finding.kev === -1), 'KEV is unknown until the catalog is synced');
  assert.ok(body.items.some((finding) => finding.containers.some((container) => container.name === 'php-app')));
  assert.ok(body.items.some((finding) => finding.priority.tier === 'P1' || finding.priority.tier === 'P2'));

  const overview = await harness.app.inject({
    method: 'GET',
    url: '/api/overview',
    headers: authHeaders(harness),
  });
  assert.equal(overview.statusCode, 200);
  const summary = overview.json<{
    counts: { critical: number; high: number; total: number };
    workloads: { affectedRunningContainers: number };
  }>();
  assert.equal(summary.counts.critical, Number(scan.critical));
  assert.equal(summary.counts.high, Number(scan.high));
  assert.ok(summary.workloads.affectedRunningContainers >= 1);

  const exported = docker.requests.filter((request) => request.path.includes('/images/') && request.path.endsWith('/get'));
  assert.ok(exported.length >= 1);
  assert.ok(
    exported.some((request) => request.path.includes(encodeURIComponent(imageId))),
    'the image must be exported by immutable ID, never by a tag',
  );
  assert.ok(docker.requests.every((request) => request.method === 'GET'));
});

test('a failed scan keeps previous findings and never reports a clean image', { skip: !canRun }, async () => {
  const before = await harness.app.inject({
    method: 'GET',
    url: `/api/findings?imageId=${encodeURIComponent(imageId)}&state=open`,
    headers: authHeaders(harness),
  });
  const beforeCount = before.json<{ total: number }>().total;
  assert.ok(beforeCount > 0);

  const settings = await harness.app.inject({
    method: 'PATCH',
    url: '/api/settings',
    headers: authHeaders(harness, true),
    payload: { scanFailureRetries: 0 },
  });
  assert.equal(settings.statusCode, 200, settings.body);

  docker.setFailure('/get', { status: 500, body: 'simulated export failure' });

  const queued = await harness.app.inject({
    method: 'POST',
    url: `/api/images/${encodeURIComponent(imageId)}/scan`,
    headers: authHeaders(harness, true),
    payload: { profile: 'quick' },
  });
  assert.equal(queued.statusCode, 202, queued.body);
  const scan = await waitForScan(harness.app, authHeaders(harness), queued.json<{ scanId: number }>().scanId);
  assert.equal(scan.status, 'failed');
  assert.equal(scan.errorCode, 'image_export_failed');
  assert.equal(scan.attempts, 1, 'retry budget of zero must not schedule retries');
  assert.ok(String(scan.errorMessage).includes('500'));

  const after = await harness.app.inject({
    method: 'GET',
    url: `/api/findings?imageId=${encodeURIComponent(imageId)}&state=open`,
    headers: authHeaders(harness),
  });
  assert.equal(after.json<{ total: number }>().total, beforeCount, 'failed scans must not resolve findings');

  const imageResponse = await harness.app.inject({
    method: 'GET',
    url: `/api/images/${encodeURIComponent(imageId)}`,
    headers: authHeaders(harness),
  });
  assert.equal(imageResponse.statusCode, 200);
  const detail = imageResponse.json<{
    image: { lastScanStatus: string; lastSuccessAt: string | null; critical: number };
  }>();
  assert.equal(detail.image.lastScanStatus, 'failed');
  assert.ok(detail.image.lastSuccessAt);
  assert.ok(detail.image.critical > 0);

  const scans = await harness.app.inject({
    method: 'GET',
    url: `/api/scans?imageId=${encodeURIComponent(imageId)}`,
    headers: authHeaders(harness),
  });
  const activity = scans.json<{ items: { status: string }[] }>().items;
  assert.ok(activity.some((entry) => entry.status === 'success'));
  assert.ok(activity.some((entry) => entry.status === 'failed'));

  docker.setFailure('/get', null);
});

test('scan work directories are removed after completion', { skip: !canRun }, async () => {
  const entries = await readdir(join(harness.config.dataDir, 'tmp')).catch(() => [] as string[]);
  assert.deepEqual(entries.filter((entry) => entry.startsWith('scan-')), []);
});
