import test from 'node:test';
import assert from 'node:assert/strict';
import { checkForUpdates } from '../../src/system/update.ts';

function response(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

test('update check reports newer, current, missing and failed releases', async () => {
  const newer = await checkForUpdates('0.1.0', async () =>
    response(200, { tag_name: 'v0.2.0', html_url: 'https://github.com/Luriot/DockSentinel/releases/tag/v0.2.0' }),
  );
  assert.equal(newer.state, 'available');
  assert.equal(newer.latestVersion, '0.2.0');

  const current = await checkForUpdates('0.2.0', async () => response(200, { tag_name: 'v0.2.0' }));
  assert.equal(current.state, 'current');

  const missing = await checkForUpdates('0.1.0', async () => response(404, { message: 'Not Found' }));
  assert.equal(missing.state, 'unknown');
  assert.match(missing.message, /No published/);

  const failed = await checkForUpdates('0.1.0', async () => {
    throw new Error('offline');
  });
  assert.equal(failed.state, 'error');
});
