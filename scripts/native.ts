#!/usr/bin/env node
import { existsSync } from 'node:fs';
import { start, formatStartupError } from '../src/index.ts';
import {
  localTrivyPath,
  nativeDataDir,
  openBrowser,
  resolveTrivyBin,
} from './native-paths.ts';
import { isLoopbackHost, StartupError } from '../src/startup.ts';

function usage(): void {
  console.log(`DockSentinel native launcher

  npm run native             start on http://127.0.0.1:8080
  npm run native -- --open   also open the browser after startup
  npm run native:setup       build the UI and install verified Trivy

Environment:
  DATA_DIR   data, database, encryption key and Trivy cache folder
  HOST       bind address (default 127.0.0.1; Docker keeps its own default)
  PORT       HTTP port (default 8080)
  TRIVY_BIN  existing Trivy binary; otherwise the managed copy or PATH is used`);
}

async function main(): Promise<void> {
  const args = new Set(process.argv.slice(2));
  if (args.has('--help') || args.has('-h')) {
    usage();
    return;
  }

  const dataDir = nativeDataDir();
  process.env.DATA_DIR ??= dataDir;
  process.env.HOST ??= '127.0.0.1';

  const localTrivy = localTrivyPath(dataDir);
  if (!process.env.TRIVY_BIN && existsSync(localTrivy)) {
    process.env.TRIVY_BIN = localTrivy;
  }
  const trivy = resolveTrivyBin(dataDir);
  if (!isLoopbackHost(process.env.HOST)) {
    console.warn(
      `Warning: DockSentinel is binding to ${process.env.HOST}, not only the local computer. ` +
        'Make sure the network and firewall are intentional.',
    );
  }
  if (trivy === 'trivy' && !existsSync(localTrivy)) {
    console.warn(`Trivy was not found at ${localTrivy}. Run "npm run native:setup" to install it.`);
    console.warn('DockSentinel will start, but scans will fail until a scanner is available.');
  }

  const started = await start();
  console.log(`Data folder: ${started.dataDir}`);
  if (args.has('--open')) openBrowser(started.url);
}

main().catch((error: unknown) => {
  console.error(formatStartupError(error));
  if (!(error instanceof StartupError) && error instanceof Error && error.stack) console.error(error.stack);
  process.exitCode = 1;
});
