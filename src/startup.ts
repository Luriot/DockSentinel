import { constants } from 'node:fs';
import { access, mkdir, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';

const MIN_NODE = [24, 12, 0] as const;

export class StartupError extends Error {
  readonly hint: string | undefined;

  constructor(message: string, hint?: string) {
    super(message);
    this.name = 'StartupError';
    this.hint = hint;
  }
}

export function nodeVersionSupported(version: string = process.versions.node): boolean {
  const [major = 0, minor = 0, patch = 0] = version.split('.').map((part) => Number.parseInt(part, 10) || 0);
  const [minMajor, minMinor, minPatch] = MIN_NODE;
  if (major !== minMajor) return major > minMajor;
  if (minor !== minMinor) return minor > minMinor;
  return patch >= minPatch;
}

export function ensureSupportedNode(version: string = process.versions.node): void {
  if (nodeVersionSupported(version)) return;
  throw new StartupError(
    `DockSentinel requires Node.js ${MIN_NODE.join('.')} or newer; this runtime is ${version}.`,
    'Install a current Node.js LTS release from https://nodejs.org/ and run the launcher again.',
  );
}

export async function checkWebDist(webDist: string): Promise<void> {
  try {
    await access(join(webDist, 'index.html'), constants.R_OK);
  } catch {
    throw new StartupError(
      `The production web interface was not found at ${webDist}.`,
      'Run "npm run native:setup" (or "npm run build") to build it, then start DockSentinel again.',
    );
  }
}

export async function checkDataDir(dataDir: string): Promise<void> {
  try {
    await mkdir(dataDir, { recursive: true });
    const probe = join(dataDir, `.write-test-${randomBytes(6).toString('hex')}`);
    await writeFile(probe, 'ok', { mode: 0o600 });
    await rm(probe, { force: true });
    await access(dataDir, constants.R_OK | constants.W_OK);
  } catch {
    throw new StartupError(
      `DockSentinel cannot write to its data directory: ${dataDir}`,
      'Set DATA_DIR to a folder the current user can create and modify (for example a folder under the user profile).',
    );
  }
}

export function isLoopbackHost(host: string): boolean {
  const normalized = host.trim().toLowerCase();
  return normalized === '127.0.0.1' || normalized === '::1' || normalized === 'localhost';
}

export function listenErrorHint(error: unknown, host: string, port: number): StartupError | null {
  const code =
    error && typeof error === 'object' && 'code' in error ? String((error as { code?: unknown }).code) : '';
  if (code === 'EADDRINUSE') {
    return new StartupError(
      `Port ${port} is already in use on ${host}.`,
      `Stop the other process or start DockSentinel with a free port, for example: PORT=${port + 1} npm run native`,
    );
  }
  if (code === 'EACCES' || code === 'EPERM') {
    return new StartupError(
      `DockSentinel is not allowed to listen on ${host}:${port}.`,
      'Use a port above 1024, or set HOST=127.0.0.1 and PORT to a free high port.',
    );
  }
  return null;
}

export function browserUrl(host: string, port: number): string {
  const displayHost = host === '0.0.0.0' || host === '::' ? '127.0.0.1' : host;
  const bracketed = displayHost.includes(':') ? `[${displayHost}]` : displayHost;
  return `http://${bracketed}:${port}`;
}
