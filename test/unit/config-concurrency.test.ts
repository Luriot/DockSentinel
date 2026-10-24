import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { availableParallelism, tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadConfig } from '../../src/config.ts';

test('the scan ceiling defaults to the CPUs available to the process', () => {
  const previous = process.env.SCAN_CONCURRENCY;
  delete process.env.SCAN_CONCURRENCY;
  try {
    const config = loadConfig({
      dataDir: mkdtempSync(join(tmpdir(), 'docksentinel-config-')),
      secretKey: Buffer.alloc(32, 1),
      webDist: join(tmpdir(), 'missing-web-dist'),
    });
    assert.equal(config.scanConcurrency, Math.min(8, Math.max(1, availableParallelism())));
  } finally {
    if (previous !== undefined) process.env.SCAN_CONCURRENCY = previous;
  }
});
