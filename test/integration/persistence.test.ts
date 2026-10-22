import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createTestApp, authHeaders, type TestApp } from '../helpers/app.ts';
import { SCHEMA_VERSION } from '../../src/db/migrations.ts';
import { recoverInterruptedScans } from '../../src/scan/recovery.ts';
import { queueScan } from '../../src/repo/scans.ts';

const IMAGE_ID = `sha256:${'2'.repeat(64)}`;

test('configuration, sessions and inventory survive a restart', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'docksentinel-persist-'));
  let first: TestApp | null = null;
  let second: TestApp | null = null;
  try {
    first = await createTestApp({ dataDir: dir });
    await first.login();
    const env = await first.app.inject({
      method: 'POST',
      url: '/api/environments',
      headers: authHeaders(first, true),
      payload: { name: 'Persistent', kind: 'unix', address: '/var/run/docker.sock' },
    });
    assert.equal(env.statusCode, 201, env.body);
    const settings = await first.app.inject({
      method: 'PATCH',
      url: '/api/settings',
      headers: authHeaders(first, true),
      payload: { freshnessHours: 12, discoveryIntervalMinutes: 15, publicUrl: 'https://docksentinel.example' },
    });
    assert.equal(settings.statusCode, 200, settings.body);

    // Insert inventory directly: this test is about persistence, not discovery.
    first.db.run(
      `INSERT INTO images (image_id, repo_digests, size_bytes, first_seen_at, updated_at)
       VALUES (?, '[]', 1000, ?, ?)`,
      [IMAGE_ID, new Date().toISOString(), new Date().toISOString()],
    );
    const queued = queueScan(first.db, {
      environmentId: 1,
      imageId: IMAGE_ID,
      imageRef: 'php:8.1-apache',
      profile: 'standard',
      trigger: 'manual',
    });
    assert.ok(queued);

    const cookie = first.cookie;
    await first.close();

    second = await createTestApp({ dataDir: dir });
    second.cookie = cookie;
    const session = await second.app.inject({
      method: 'GET',
      url: '/api/auth/session',
      headers: { cookie },
    });
    assert.equal(session.statusCode, 200);
    assert.equal(session.json<{ authenticated: boolean }>().authenticated, true, 'sessions survive restarts');

    const loaded = await second.app.inject({
      method: 'GET',
      url: '/api/settings',
      headers: { cookie },
    });
    assert.equal(loaded.statusCode, 200);
    const body = loaded.json<{ settings: { freshnessHours: number; discoveryIntervalMinutes: number; publicUrl: string } }>();
    assert.equal(body.settings.freshnessHours, 12);
    assert.equal(body.settings.discoveryIntervalMinutes, 15);
    assert.equal(body.settings.publicUrl, 'https://docksentinel.example');

    const envs = await second.app.inject({ method: 'GET', url: '/api/environments', headers: { cookie } });
    assert.equal(envs.json<{ items: unknown[] }>().items.length, 1);

    const scans = await second.app.inject({ method: 'GET', url: '/api/scans', headers: { cookie } });
    assert.equal(scans.json<{ total: number }>().total, 1);

    const versions = second.db.all<{ version: number }>('SELECT version FROM schema_migrations');
    assert.equal(versions.length, SCHEMA_VERSION, 'migrations are idempotent across restarts');
  } finally {
    if (second) await second.close();
    else if (first) {
      try {
        await first.close();
      } catch {
        /* already closed */
      }
    }
    await rm(dir, { recursive: true, force: true });
  }
});

test('recovery marks crashed scans correctly', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'docksentinel-recovery-'));
  const harness = await createTestApp({ dataDir: dir });
  try {
    harness.db.run(
      `INSERT INTO environments (name, kind, address, created_at, updated_at) VALUES ('e', 'unix', '/var/run/docker.sock', '2026-01-01', '2026-01-01')`,
    );
    harness.db.run(
      `INSERT INTO images (image_id, repo_digests, first_seen_at, updated_at) VALUES (?, '[]', '2026-01-01', '2026-01-01')`,
      [IMAGE_ID],
    );
    for (const attempts of [1, 4]) {
      const scanId = queueScan(
        harness.db,
        {
          environmentId: 1,
          imageId: IMAGE_ID,
          imageRef: 'php:8.1-apache',
          profile: 'standard',
          trigger: 'manual',
        },
        false,
      );
      harness.db.run(`UPDATE scans SET status = 'running', attempts = ? WHERE id = ?`, [attempts, scanId]);
    }

    const summary = recoverInterruptedScans(harness.db, 2);
    assert.deepEqual(summary, { requeued: 1, failed: 1 });
    const rows = harness.db.all<{ status: string; attempts: number; error_code: string | null }>(
      'SELECT status, attempts, error_code FROM scans ORDER BY id',
    );
    assert.equal(rows[0]?.status, 'queued');
    assert.equal(rows[0]?.attempts, 2);
    assert.equal(rows[0]?.error_code, 'interrupted');
    assert.equal(rows[1]?.status, 'failed');
    assert.equal(rows[1]?.error_code, 'interrupted');
  } finally {
    await harness.close();
    await rm(dir, { recursive: true, force: true });
  }
});
