import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

export function trivyAvailable(): boolean {
  try {
    const result = spawnSync('trivy', ['--version'], { stdio: 'ignore', timeout: 15_000 });
    return result.status === 0;
  } catch {
    return false;
  }
}

/** Uses the machine's normal Trivy cache so integration tests do not re-download the vulnerability DB. */
export function defaultTrivyCacheDir(): string {
  if (process.env.TRIVY_TEST_CACHE_DIR) return process.env.TRIVY_TEST_CACHE_DIR;
  if (process.platform === 'win32') {
    return join(process.env.LOCALAPPDATA ?? join(homedir(), 'AppData', 'Local'), 'trivy');
  }
  return process.env.XDG_CACHE_HOME
    ? join(process.env.XDG_CACHE_HOME, 'trivy')
    : join(homedir(), '.cache', 'trivy');
}

export function trivyDatabasePresent(cacheDir: string = defaultTrivyCacheDir()): boolean {
  return existsSync(join(cacheDir, 'db', 'trivy.db')) || existsSync(join(cacheDir, 'db', 'metadata.json'));
}
