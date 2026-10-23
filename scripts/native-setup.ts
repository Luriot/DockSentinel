#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { chmod, copyFile, mkdir, mkdtemp, readdir, rename, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { localTrivyPath, nativeDataDir, projectRoot, trivyToolsDir } from './native-paths.ts';

export const TRIVY_VERSION = process.env.TRIVY_VERSION?.trim() || '0.75.0';
const RELEASE_BASE = `https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}`;
const MAX_ARCHIVE_BYTES = 250 * 1024 * 1024;

export interface TrivyAsset {
  archive: string;
  checksumFile: string;
  extractedName: string;
}

export function trivyAssetFor(
  platform: NodeJS.Platform = process.platform,
  arch: string = process.arch,
): TrivyAsset {
  const checksumFile = `trivy_${TRIVY_VERSION}_checksums.txt`;
  const table: Record<string, { archive: string; extractedName: string }> = {
    'win32/x64': { archive: `trivy_${TRIVY_VERSION}_windows-64bit.zip`, extractedName: 'trivy.exe' },
    'darwin/x64': { archive: `trivy_${TRIVY_VERSION}_macOS-64bit.tar.gz`, extractedName: 'trivy' },
    'darwin/arm64': { archive: `trivy_${TRIVY_VERSION}_macOS-ARM64.tar.gz`, extractedName: 'trivy' },
    'linux/x64': { archive: `trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz`, extractedName: 'trivy' },
    'linux/arm64': { archive: `trivy_${TRIVY_VERSION}_Linux-ARM64.tar.gz`, extractedName: 'trivy' },
  };
  const found = table[`${platform}/${arch}`];
  if (!found) {
    throw new Error(
      `No verified Trivy release asset is configured for ${platform}/${arch}. ` +
        'Install Trivy manually and set TRIVY_BIN, or use Docker.',
    );
  }
  return { ...found, checksumFile };
}

/** Parses the official `sha256  filename` checksum file. */
export function parseChecksums(text: string): Map<string, string> {
  const checksums = new Map<string, string>();
  for (const line of text.split(/\r?\n/)) {
    const match = /^([a-f0-9]{64})\s+\*?(\S+)$/i.exec(line.trim());
    if (match?.[1] && match[2]) checksums.set(match[2], match[1].toLowerCase());
  }
  return checksums;
}

export function sha256(buffer: Buffer): string {
  return createHash('sha256').update(buffer).digest('hex');
}

export function verifyChecksum(buffer: Buffer, expected: string | undefined, asset: string): void {
  if (!expected) throw new Error(`No checksum was published for ${asset}; refusing to install it.`);
  const actual = sha256(buffer);
  if (actual !== expected.toLowerCase()) {
    throw new Error(`Checksum verification failed for ${asset}. Downloaded file was not installed.`);
  }
}

async function fetchBuffer(url: string, maxBytes: number): Promise<Buffer> {
  const response = await fetch(url, { redirect: 'follow' });
  if (!response.ok) throw new Error(`${url} returned HTTP ${response.status}`);
  const declared = Number(response.headers.get('content-length') ?? '0');
  if (declared > maxBytes) throw new Error(`${url} is larger than the ${maxBytes} byte limit`);
  const buffer = Buffer.from(await response.arrayBuffer());
  if (buffer.length > maxBytes) throw new Error(`${url} is larger than the ${maxBytes} byte limit`);
  return buffer;
}

async function extractBinary(archivePath: string, asset: TrivyAsset, destination: string): Promise<void> {
  const extractDir = await mkdtemp(join(tmpdir(), 'docksentinel-trivy-extract-'));
  try {
    if (process.platform === 'win32') {
      const quote = (value: string): string => `'${value.replace(/'/g, "''")}'`;
      const result = spawnSync(
        'powershell.exe',
        [
          '-NoLogo',
          '-NoProfile',
          '-NonInteractive',
          '-Command',
          `Expand-Archive -LiteralPath ${quote(archivePath)} -DestinationPath ${quote(extractDir)} -Force`,
        ],
        { encoding: 'utf8' },
      );
      if (result.status !== 0) {
        throw new Error(`Could not extract the Trivy archive with PowerShell: ${(result.stderr ?? '').trim()}`);
      }
    } else {
      const result = spawnSync('tar', ['-xzf', archivePath, '-C', extractDir], { encoding: 'utf8' });
      if (result.status !== 0) {
        throw new Error(`Could not extract the Trivy archive with tar: ${(result.stderr ?? '').trim()}`);
      }
    }

    const wanted = (await readdir(extractDir)).find((name) => name === asset.extractedName);
    if (!wanted) throw new Error(`The Trivy archive did not contain ${asset.extractedName}`);
    await mkdir(trivyToolsDir(), { recursive: true, mode: 0o700 });
    const temporary = `${destination}.download-${process.pid}`;
    await copyFile(join(extractDir, wanted), temporary);
    await chmod(temporary, 0o755);
    await rm(destination, { force: true });
    await rename(temporary, destination);
    await chmod(destination, 0o755);
  } finally {
    await rm(extractDir, { recursive: true, force: true }).catch(() => undefined);
  }
}

function verifyInstalledBinary(binary: string): string {
  const result = spawnSync(binary, ['--version'], { encoding: 'utf8', timeout: 30_000 });
  if (result.status !== 0) {
    throw new Error(`The installed Trivy binary did not start: ${(result.stderr ?? '').trim() || 'unknown error'}`);
  }
  return (result.stdout ?? '').split(/\r?\n/)[0]?.trim() || 'unknown version';
}

export async function installVerifiedTrivy(options: { force?: boolean } = {}): Promise<string> {
  const dataDir = nativeDataDir();
  const destination = localTrivyPath(dataDir);
  const asset = trivyAssetFor();

  if (!options.force) {
    try {
      const version = verifyInstalledBinary(destination);
      console.log(`Trivy already installed at ${destination} (${version})`);
      return destination;
    } catch {
      // Missing or broken; install a verified copy below.
    }
  }

  const archiveUrl = `${RELEASE_BASE}/${asset.archive}`;
  const checksumsUrl = `${RELEASE_BASE}/${asset.checksumFile}`;
  console.log(`Downloading ${asset.archive} from the official Trivy release...`);
  const [checksumsBuffer, archive] = await Promise.all([
    fetchBuffer(checksumsUrl, 2 * 1024 * 1024),
    fetchBuffer(archiveUrl, MAX_ARCHIVE_BYTES),
  ]);
  const expected = parseChecksums(checksumsBuffer.toString('utf8')).get(asset.archive);
  verifyChecksum(archive, expected, asset.archive);

  const tempDir = await mkdtemp(join(tmpdir(), 'docksentinel-trivy-archive-'));
  const tempArchive = join(tempDir, asset.archive);
  try {
    await writeFile(tempArchive, archive, { mode: 0o600 });
    await extractBinary(tempArchive, asset, destination);
  } finally {
    await rm(tempDir, { recursive: true, force: true }).catch(() => undefined);
  }

  const version = verifyInstalledBinary(destination);
  console.log(`Verified and installed Trivy: ${version}`);
  console.log(`Location: ${destination}`);
  return destination;
}

function runBuild(): void {
  const npmCli = process.env.npm_execpath;
  const result = npmCli
    ? spawnSync(process.execPath, [npmCli, 'run', 'build'], {
        cwd: projectRoot,
        stdio: 'inherit',
      })
    : spawnSync(process.platform === 'win32' ? 'npm.cmd' : 'npm', ['run', 'build'], {
        cwd: projectRoot,
        stdio: 'inherit',
        shell: process.platform === 'win32',
      });
  if (result.error) throw new Error(`Could not run the UI build: ${result.error.message}`);
  if (result.status !== 0) throw new Error('The production web build failed; fix the reported error and rerun.');
}

function usage(): void {
  console.log(`DockSentinel native setup

  npm run native:setup                 build the UI and install verified Trivy into the native data folder
  npm run native:setup -- --skip-build skip the UI build (only if web/dist already exists)
  npm run native:setup -- --force      reinstall Trivy even if a working copy exists

Environment:
  DATA_DIR       override the data folder (default: ${nativeDataDir()})
  TRIVY_VERSION  override the pinned Trivy release (checksums still verified)
  TRIVY_BIN      use an existing scanner at launch (setup still installs the managed copy)`);
}

async function main(): Promise<void> {
  const args = new Set(process.argv.slice(2));
  if (args.has('--help') || args.has('-h')) {
    usage();
    return;
  }
  if (!args.has('--skip-build')) runBuild();
  await installVerifiedTrivy({ force: args.has('--force') });
  const dataDir = nativeDataDir();
  console.log('');
  console.log(`Native data folder: ${dataDir}`);
  console.log('Start DockSentinel with: npm run native');
  console.log('Optional: npm run native -- --open');
}

const directEntry = process.argv[1] ? resolve(process.argv[1]) === fileURLToPath(import.meta.url) : false;
if (directEntry) {
  main().catch((error: unknown) => {
    console.error(`Native setup failed: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  });
}
