import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';

export const projectRoot = resolve(fileURLToPath(new URL('..', import.meta.url)));

export function nativeDataDir(): string {
  if (process.env.DATA_DIR && process.env.DATA_DIR.trim() !== '') return resolve(process.env.DATA_DIR);
  if (process.platform === 'win32') {
    return join(process.env.LOCALAPPDATA ?? join(homedir(), 'AppData', 'Local'), 'DockSentinel');
  }
  if (process.platform === 'darwin') return join(homedir(), 'Library', 'Application Support', 'DockSentinel');
  return join(process.env.XDG_DATA_HOME ?? join(homedir(), '.local', 'share'), 'docksentinel');
}

export function trivyToolsDir(dataDir = nativeDataDir()): string {
  return join(dataDir, 'tools');
}

export function localTrivyPath(dataDir = nativeDataDir()): string {
  return join(trivyToolsDir(dataDir), process.platform === 'win32' ? 'trivy.exe' : 'trivy');
}

export function resolveTrivyBin(dataDir = nativeDataDir()): string {
  if (process.env.TRIVY_BIN && process.env.TRIVY_BIN.trim() !== '') return process.env.TRIVY_BIN;
  const local = localTrivyPath(dataDir);
  return existsSync(local) ? local : 'trivy';
}

export function openBrowser(url: string): void {
  const command =
    process.platform === 'win32'
      ? { file: 'cmd.exe', args: ['/c', 'start', '', url] }
      : process.platform === 'darwin'
        ? { file: 'open', args: [url] }
        : { file: 'xdg-open', args: [url] };
  try {
    const child = spawn(command.file, command.args, { detached: true, stdio: 'ignore' });
    child.on('error', () => undefined);
    child.unref();
  } catch {
    // Opening a browser is a convenience; the URL is always printed.
  }
}
