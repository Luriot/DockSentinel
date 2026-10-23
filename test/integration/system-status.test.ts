import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createTestApp, authHeaders } from '../helpers/app.ts';

test('system status exposes health, disk, backups and update-check actions', async () => {
  const harness = await createTestApp();
  try {
    await harness.login();
    const status = await harness.app.inject({
      method: 'GET',
      url: '/api/system/status',
      headers: authHeaders(harness),
    });
    assert.equal(status.statusCode, 200, status.body);
    const body = status.json<{
      version: string;
      schemaVersion: number;
      scanner: { available: boolean };
      environments: unknown[];
      disk: unknown;
      backups: { items: unknown[]; last: unknown };
      update: unknown;
    }>();
    assert.ok(body.version.length > 0);
    assert.equal(body.schemaVersion, 3);
    assert.ok(Array.isArray(body.environments));
    assert.ok(Array.isArray(body.backups.items));
    assert.equal(body.update, null);

    const backup = await harness.app.inject({
      method: 'POST',
      url: '/api/system/backup',
      headers: authHeaders(harness, true),
      payload: {},
    });
    assert.equal(backup.statusCode, 200, backup.body);
    const backupBody = backup.json<{ databasePath: string; sizeBytes: number }>();
    assert.ok(backupBody.sizeBytes > 0);

    const after = await harness.app.inject({
      method: 'GET',
      url: '/api/system/status',
      headers: authHeaders(harness),
    });
    const afterBody = after.json<{ backups: { items: { name: string }[]; last: { name: string } | null } }>();
    assert.equal(afterBody.backups.items.length, 1);
    assert.ok(afterBody.backups.last?.name);

    const restore = await harness.app.inject({
      method: 'POST',
      url: '/api/system/restore',
      headers: authHeaders(harness, true),
      payload: { name: afterBody.backups.items[0]?.name },
    });
    assert.equal(restore.statusCode, 200, restore.body);
    assert.equal(restore.json<{ restartRequired: boolean }>().restartRequired, true);
  } finally {
    await harness.close();
  }
});
