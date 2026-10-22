import { mkdir } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
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

async function main(): Promise<void> {
  const config = loadConfig();
  const log = createLogger(config.logLevel);
  const startedAt = Date.now();

  await mkdir(config.trivyCacheDir, { recursive: true });
  const db = Db.open(config.dbPath);
  const getSettings = (): AppSettings => loadSettings(db, config.secretKey);

  const alerts = new AlertService(db, log, getSettings);
  const kev = new KevService(db, config, log, alerts);
  const discovery = new DiscoveryService(db, config.secretKey, log);
  const coordinator = new ScanCoordinator({ db, config, log, alerts, getSettings });
  const dispatcher = new NotificationDispatcher(db, log, getSettings);
  const scheduler = new Scheduler({ db, log, discovery, coordinator, alerts, kev, getSettings });

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
  await coordinator.start();
  dispatcher.start();
  scheduler.start();

  await app.listen({ port: config.port, host: config.host });
  log.info(
    {
      version: config.version,
      port: config.port,
      host: config.host,
      dataDir: config.dataDir,
      trivy: config.trivyBin,
      trivyCache: config.trivyCacheDir,
      scanConcurrency: getSettings().scanConcurrency,
    },
    'DockSentinel started',
  );

  void getScannerInfo(config, true).then((info) => {
    if (!info.available) log.warn({ error: info.error }, 'Trivy scanner is not available; scans will fail until it is installed');
    else log.info({ version: info.version, dbUpdatedAt: info.dbUpdatedAt }, 'Trivy scanner detected');
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

main().catch((error) => {
  // Startup failures must be loud and must exit non-zero so container restarts surface the problem.
  console.error(error);
  process.exit(1);
});
