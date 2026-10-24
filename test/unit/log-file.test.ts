import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createDailyLogStream } from '../../src/logger.ts';

test('log files rotate daily and old files expire', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'docksentinel-logs-'));
  try {
    await writeFile(join(dir, 'docksentinel-2026-09-01.log'), 'expired\n');
    let current = new Date('2026-10-20T10:00:00');
    const stream = createDailyLogStream(dir, 14, () => current);
    stream.write('{"msg":"first"}\n');
    current = new Date('2026-10-21T10:00:00');
    stream.write('{"msg":"second"}\n');
    await new Promise<void>((resolve) => stream.end(() => resolve()));

    const names = (await readdir(dir)).sort();
    assert.deepEqual(names, ['docksentinel-2026-10-20.log', 'docksentinel-2026-10-21.log']);
    assert.match(await readFile(join(dir, 'docksentinel-2026-10-20.log'), 'utf8'), /first/);
    assert.match(await readFile(join(dir, 'docksentinel-2026-10-21.log'), 'utf8'), /second/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
