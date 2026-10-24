import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createTestApp, authHeaders } from '../helpers/app.ts';

test('a failed KEV sync is not retried on every scheduler tick', async () => {
  let attempts = 0;
  const feed = createServer((_request, response) => {
    attempts += 1;
    response.writeHead(500, { 'Content-Type': 'application/json' });
    response.end('{"message":"unavailable"}');
  });
  await new Promise<void>((resolve) => feed.listen(0, '127.0.0.1', () => resolve()));
  const port = (feed.address() as AddressInfo).port;

  const harness = await createTestApp({ kevUrl: `http://127.0.0.1:${port}/kev.json` });
  try {
    await harness.login();

    await harness.ctx.kev.syncIfDue();
    assert.equal(attempts, 1);
    await harness.ctx.kev.syncIfDue();
    await harness.ctx.kev.syncIfDue();
    assert.equal(attempts, 1, 'a failed sync backs off instead of hitting the feed every minute');

    const manual = await harness.app.inject({
      method: 'POST',
      url: '/api/kev/sync',
      headers: authHeaders(harness, true),
    });
    assert.equal(manual.statusCode, 200);
    assert.equal(manual.json<{ ok: boolean }>().ok, false);
    assert.equal(attempts, 2, 'an explicit sync request still goes out');
  } finally {
    await harness.close();
    await new Promise<void>((resolve) => feed.close(() => resolve()));
  }
});
