import { mkdir } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadConfig } from './config.ts';
import { createLogger } from './logger.ts';
import { Db } from './db/index.ts';
import { getUser } from './auth.ts';
import { loadSettings, type AppSettings } from './repo/settings.ts';
import { DiscoveryService } from './discovery.ts';
import { ScanCoordinator } from './scan/coordinator.ts';
import { AlertService } from './notify/service.ts';
import { NotificationDispatcher } from './notify/dispatcher.ts';
import { KevService } from './intel/kev-service.ts';
import { Scheduler } from './jobs/scheduler.ts';
import { buildServer } from './api/server.ts';
import type { AppContext } from './api/context.ts';
import { getScannerInfo } from './scanner/info.ts';
import { applyPendingRestore } from './backup.ts';
import {
  browserUrl,
  checkDataDir,
  checkWebDist,
  ensureSupportedNode,
  listenErrorHint,
  StartupError,
} from './startup.ts';

export interface StartedServer {
  host: string;
  port: number;
  url: string;
  dataDir: string;
}

export async function start(): Promise<StartedServer> {
  ensureSupportedNode();
  const config = loadConfig();
  await checkWebDist(config.webDist);
  await checkDataDir(config.dataDir);

  const log = createLogger(config.logLevel, {
    logDir: config.logDir,
    retentionDays: config.logRetentionDays,
  });
  const startedAt = Date.now();

  const restoreSafety = applyPendingRestore(config);
  if (restoreSafety) log.warn({ safetyBackup: restoreSafety }, 'applied staged database restore');
  await mkdir(config.trivyCacheDir, { recursive: true });
  const db = Db.open(config.dbPath);
  const getSettings = (): AppSettings => loadSettings(db, config.secretKey);

  const alerts = new AlertService(db, log, getSettings);
  const kev = new KevService(db, config, log, alerts);
  const discovery = new DiscoveryService(db, config.secretKey, log);
  const coordinator = new ScanCoordinator({ db, config, log, alerts, getSettings });
  const dispatcher = new NotificationDispatcher(db, log, getSettings);
  const scheduler = new Scheduler({ db, log, discovery, coordinator, alerts, kev, getSettings, config });

  const setupToken = createSetupToken(db, config, log);
  const ctx: AppContext = {
    db,
    config,
    log,
    discovery,
    coordinator,
    alerts,
    dispatcher,
    kev,
    scheduler,
    getSettings,
    setupToken,
    startedAt,
  };

  const app = await buildServer(ctx);
  try {
    await app.listen({ port: config.port, host: config.host });
  } catch (error) {
    await app.close().catch(() => undefined);
    db.close();
    throw listenErrorHint(error, config.host, config.port) ?? error;
  }

  await coordinator.start();
  dispatcher.start();
  scheduler.start();

  const url = browserUrl(config.host, config.port);
  log.info(
    {
      version: config.version,
      url,
      port: config.port,
      host: config.host,
      dataDir: config.dataDir,
      trivy: config.trivyBin,
      trivyCache: config.trivyCacheDir,
      scanConcurrency: getSettings().scanConcurrency,
    },
    'DockSentinel started',
  );
  console.log(`DockSentinel is available at ${url}`);

  void getScannerInfo(config, true).then((info) => {
    if (!info.available) {
      log.warn(
        { error: info.error },
        'Trivy scanner is not available; scans will fail until it is installed. Run "npm run native:setup" for the native installer.',
      );
    } else {
      log.info({ version: info.version, dbUpdatedAt: info.dbUpdatedAt }, 'Trivy scanner detected');
    }
  });

  let shuttingDown = false;
  const shutdown = async (signal: string): Promise<void> => {
    if (shuttingDown) return;
    shuttingDown = true;
    log.info({ signal }, 'shutting down');
    scheduler.stop();
    dispatcher.stop();
    try {
      await app.close();
    } catch (error) {
      log.warn({ err: error instanceof Error ? error.message : String(error) }, 'HTTP close failed');
    }
    await coordinator.stop();
    try {
      db.close();
    } catch {
      // A closed database during shutdown is harmless.
    }
    process.exit(0);
  };

  process.on('SIGINT', () => void shutdown('SIGINT'));
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('unhandledRejection', (reason) => {
    log.error({ reason: reason instanceof Error ? reason.message : String(reason) }, 'unhandled promise rejection');
  });

  return { host: config.host, port: config.port, url, dataDir: config.dataDir };
}

function createSetupToken(
  db: Db,
  config: { setupToken: string | null },
  log: ReturnType<typeof createLogger>,
): () => string | null {
  if (getUser(db)) return () => null;
  const token = config.setupToken ?? randomBytes(9).toString('base64url');
  // The token is deliberately written to the log exactly once; it is not redacted because the
  // operator needs it to complete first-run setup.
  log.warn(`DockSentinel initial setup token: ${token}`);
  log.warn('Open the web interface and enter this token to create the administrator account.');
  return () => (getUser(db) ? null : token);
}

export function formatStartupError(error: unknown): string {
  if (error instanceof StartupError) {
    return `${error.message}${error.hint ? `\n${error.hint}` : ''}`;
  }
  return error instanceof Error ? error.message : String(error);
}

const directEntry = process.argv[1] ? resolve(process.argv[1]) === fileURLToPath(import.meta.url) : false;
if (directEntry) {
  start().catch((error: unknown) => {
    // Startup failures must be loud and must exit non-zero so service managers surface the problem.
    console.error(formatStartupError(error));
    if (!(error instanceof StartupError) && error instanceof Error && error.stack) console.error(error.stack);
    process.exitCode = 1;
  });
}
