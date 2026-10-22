import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runProcess, ProcessError } from '../../src/scanner/process.ts';

const node = process.execPath;

function baseOptions(args: string[], timeoutMs = 5000) {
  return {
    command: node,
    args,
    env: { PATH: process.env.PATH ?? '' },
    timeoutMs,
    maxStderrBytes: 4096,
  };
}

test('runs a process and captures stdout, stderr and exit code', async () => {
  const result = await runProcess(baseOptions(['-e', "process.stdout.write('hello'); process.stderr.write('note');"]));
  assert.equal(result.exitCode, 0);
  assert.equal(result.stdout, 'hello');
  assert.equal(result.stderr, 'note');
});

test('non-zero exits surface stderr', async () => {
  await assert.rejects(
    () => runProcess(baseOptions(['-e', "process.stderr.write('boom'); process.exit(3);"])),
    (error: unknown) => {
      assert.ok(error instanceof ProcessError);
      assert.equal(error.code, 'nonzero_exit');
      assert.equal(error.exitCode, 3);
      assert.match(error.stderr, /boom/);
      return true;
    },
  );
});

test('timeouts kill the process', async () => {
  const started = Date.now();
  await assert.rejects(
    () => runProcess(baseOptions(['-e', 'setTimeout(() => {}, 30000);'], 400)),
    (error: unknown) => {
      assert.ok(error instanceof ProcessError);
      assert.equal(error.code, 'timeout');
      return true;
    },
  );
  assert.ok(Date.now() - started < 6000, 'the process must be killed, not waited out');
});

test('abort signals cancel a running process', async () => {
  const controller = new AbortController();
  setTimeout(() => controller.abort(), 200);
  await assert.rejects(
    () => runProcess({ ...baseOptions(['-e', 'setTimeout(() => {}, 30000);'], 10_000), signal: controller.signal }),
    (error: unknown) => {
      assert.ok(error instanceof ProcessError);
      assert.equal(error.code, 'aborted');
      return true;
    },
  );
});

test('missing binaries produce a spawn failure, not a crash', async () => {
  await assert.rejects(
    () =>
      runProcess({
        command: 'docksentinel-definitely-missing-binary',
        args: [],
        env: { PATH: '' },
        timeoutMs: 2000,
      }),
    (error: unknown) => {
      assert.ok(error instanceof ProcessError);
      assert.equal(error.code, 'spawn_failed');
      return true;
    },
  );
});

test('stdout is capped so a runaway scanner cannot exhaust memory', async () => {
  await assert.rejects(
    () => runProcess(baseOptions(['-e', "process.stdout.write('x'.repeat(2 * 1024 * 1024));"])),
    (error: unknown) => {
      assert.ok(error instanceof ProcessError);
      assert.equal(error.code, 'output_too_large');
      return true;
    },
  );
});

test('the child only receives the explicit environment', async () => {
  const previous = process.env.DOCKSENTINEL_SECRET_KEY;
  process.env.DOCKSENTINEL_SECRET_KEY = 'super-secret-value';
  try {
    const result = await runProcess(
      baseOptions(['-e', "process.stdout.write(String(process.env.DOCKSENTINEL_SECRET_KEY));"]),
    );
    assert.equal(result.stdout, 'undefined');
  } finally {
    if (previous === undefined) delete process.env.DOCKSENTINEL_SECRET_KEY;
    else process.env.DOCKSENTINEL_SECRET_KEY = previous;
  }
});
