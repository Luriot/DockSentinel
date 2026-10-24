import { spawn, type ChildProcess } from 'node:child_process';

export type ProcessErrorCode = 'spawn_failed' | 'timeout' | 'aborted' | 'output_too_large' | 'nonzero_exit';

export class ProcessError extends Error {
  readonly code: ProcessErrorCode;
  readonly exitCode: number | null;
  readonly stderr: string;

  constructor(code: ProcessErrorCode, message: string, exitCode: number | null, stderr = '') {
    super(message);
    this.name = 'ProcessError';
    this.code = code;
    this.exitCode = exitCode;
    this.stderr = stderr;
  }
}

export interface RunProcessOptions {
  command: string;
  args: readonly string[];
  env: NodeJS.ProcessEnv;
  cwd?: string;
  timeoutMs: number;
  maxStderrBytes?: number;
  signal?: AbortSignal;
}

export interface ProcessResult {
  exitCode: number | null;
  stdout: string;
  stderr: string;
  durationMs: number;
}

const DEFAULT_MAX_STDERR = 64 * 1024;
const MAX_STDOUT = 1024 * 1024;

function terminateTree(child: ChildProcess): void {
  if (!child.pid) return;
  if (process.platform === 'win32') {
    try {
      const killer = spawn('taskkill', ['/pid', String(child.pid), '/T', '/F'], {
        stdio: 'ignore',
        shell: false,
      });
      // A missing taskkill must not crash the app; fall back to killing the direct child.
      killer.on('error', () => child.kill('SIGKILL'));
      killer.unref();
    } catch {
      child.kill('SIGKILL');
    }
    return;
  }
  try {
    // Negative pid targets the whole process group, so wrapper scripts cannot leave scanner
    // children behind after a timeout or cancellation.
    process.kill(-child.pid, 'SIGKILL');
  } catch {
    child.kill('SIGKILL');
  }
}

/**
 * Runs a scanner without a shell. Arguments are passed as an array; the caller never supplies a
 * command string. stdout is capped, stderr is capped, and the process tree is killed on timeout,
 * cancellation or output overflow.
 */
export function runProcess(options: RunProcessOptions): Promise<ProcessResult> {
  const started = Date.now();
  const maxStderr = options.maxStderrBytes ?? DEFAULT_MAX_STDERR;

  return new Promise((resolve, reject) => {
    let settled = false;
    let timedOut = false;
    let aborted = false;
    let overflow = false;
    let stdoutBytes = 0;
    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    const stderrText = (): string => Buffer.concat(stderrChunks).toString('utf8').slice(0, maxStderr);

    let mainTimer: NodeJS.Timeout | undefined;
    let forceTimer: NodeJS.Timeout | undefined;

    const settle = (error: ProcessError | null, exitCode: number | null): void => {
      if (settled) return;
      settled = true;
      if (mainTimer) clearTimeout(mainTimer);
      if (forceTimer) clearTimeout(forceTimer);
      options.signal?.removeEventListener('abort', onAbort);
      if (error) {
        reject(error);
        return;
      }
      resolve({
        exitCode,
        stdout: Buffer.concat(stdoutChunks).toString('utf8'),
        stderr: stderrText(),
        durationMs: Date.now() - started,
      });
    };

    let child: ChildProcess;
    try {
      child = spawn(options.command, [...options.args], {
        cwd: options.cwd,
        env: options.env,
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
        detached: process.platform !== 'win32',
      });
    } catch (error) {
      reject(new ProcessError('spawn_failed', `Unable to start scanner: ${(error as Error).message}`, null));
      return;
    }

    const stop = (mark: () => void): void => {
      mark();
      terminateTree(child);
      forceTimer = setTimeout(() => {
        settle(new ProcessError(timedOut ? 'timeout' : aborted ? 'aborted' : 'output_too_large', stopMessage(), null, stderrText()), null);
      }, 3000);
      forceTimer.unref();
    };
    const stopMessage = (): string => {
      if (timedOut) return `Scanner timed out after ${options.timeoutMs}ms`;
      if (aborted) return 'Scan cancelled';
      return 'Scanner produced too much output';
    };

    const onAbort = (): void => {
      if (settled) return;
      aborted = true;
      stop(() => undefined);
    };
    options.signal?.addEventListener('abort', onAbort, { once: true });

    mainTimer = setTimeout(() => {
      if (settled) return;
      timedOut = true;
      stop(() => undefined);
    }, options.timeoutMs);
    mainTimer.unref();

    child.stdout?.on('data', (chunk: Buffer) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > MAX_STDOUT) {
        overflow = true;
        stop(() => undefined);
        return;
      }
      stdoutChunks.push(chunk);
    });

    child.stderr?.on('data', (chunk: Buffer) => {
      const total = stderrChunks.reduce((sum, item) => sum + item.length, 0);
      if (total < maxStderr) stderrChunks.push(chunk);
    });

    child.on('error', (error) => {
      if (settled) return;
      const code = (error as NodeJS.ErrnoException).code;
      settle(
        new ProcessError(
          'spawn_failed',
          code === 'ENOENT' ? `Scanner binary not found: ${options.command}` : `Scanner failed to start: ${error.message}`,
          null,
        ),
        null,
      );
    });

    child.on('close', (code) => {
      if (settled) return;
      if (timedOut) {
        settle(new ProcessError('timeout', stopMessage(), code, stderrText()), code);
      } else if (aborted) {
        settle(new ProcessError('aborted', stopMessage(), code, stderrText()), code);
      } else if (overflow) {
        settle(new ProcessError('output_too_large', stopMessage(), code, stderrText()), code);
      } else if (code !== 0) {
        settle(new ProcessError('nonzero_exit', `Scanner exited with code ${code ?? 'null'}`, code, stderrText()), code);
      } else {
        settle(null, code);
      }
    });
  });
}
