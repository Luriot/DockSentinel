import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadConfig, type Config } from '../../src/config.ts';
import { createLogger } from '../../src/logger.ts';
import { Db } from '../../src/db/index.ts';
import { loadSettings, type AppSettings } from '../../src/repo/settings.ts';
import { DiscoveryService } from '../../src/discovery.ts';
import { ScanCoordinator } from '../../src/scan/coordinator.ts';
import { AlertService } from '../../src/notify/service.ts';
import { NotificationDispatcher } from '../../src/notify/dispatcher.ts';
import { KevService } from '../../src/intel/kev-service.ts';
import { Scheduler } from '../../src/jobs/scheduler.ts';
import { buildServer } from '../../src/api/server.ts';
import type { AppContext } from '../../src/api/context.ts';
import { getUser } from '../../src/auth.ts';

export type TestServer = Awaited<ReturnType<typeof buildServer>>;

export interface TestApp {
  app: TestServer;
  ctx: AppContext;
  db: Db;
  config: Config;
  dir: string;
  close: () => Promise<void>;
  cookie: string;
  csrf: string;
  login: () => Promise<void>;
}

export interface TestAppOptions {
  setupToken?: string;
  trivyBin?: string;
  trivyCacheDir?: string;
  dataDir?: string;
  scanTimeoutMs?: number;
  logLevel?: string;
  kevUrl?: string;
  /** Start the scan worker loop and scheduler inside the harness. */
  runWorkers?: boolean;
}

export function createTestContext(config: Config, db: Db, log: ReturnType<typeof createLogger>): AppContext {
  const getSettings = (): AppSettings => loadSettings(db, config.secretKey);
  const alerts = new AlertService(db, log, getSettings);
  const kev = new KevService(db, config, log, alerts);
  const discovery = new DiscoveryService(db, config.secretKey, log);
  const coordinator = new ScanCoordinator({ db, config, log, alerts, getSettings });
  const dispatcher = new NotificationDispatcher(db, log, getSettings);
  const scheduler = new Scheduler({ db, log, discovery, coordinator, alerts, kev, getSettings });
  return {
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
    setupToken: () => (getUser(db) ? null : 'test-setup-token'),
    startedAt: Date.now(),
  };
}

export async function createTestApp(options: TestAppOptions = {}): Promise<TestApp> {
  const dir = options.dataDir ?? (await mkdtemp(join(tmpdir(), 'docksentinel-test-')));
  const config = loadConfig({
    dataDir: dir,
    dbPath: join(dir, 'test.db'),
    webDist: join(dir, 'web-dist-missing'),
    secretKey: Buffer.alloc(32, 7),
    logLevel: options.logLevel ?? 'silent',
    trustProxy: false,
    cookieSecure: 'never',
    trivyBin: options.trivyBin ?? join(dir, 'missing-trivy'),
    trivyCacheDir: options.trivyCacheDir ?? join(dir, 'trivy-cache'),
    setupToken: options.setupToken ?? 'test-setup-token',
    scanTimeoutMs: options.scanTimeoutMs ?? 30_000,
    scanConcurrency: 2,
    maxOutputBytes: 8 * 1024 * 1024,
    maxImageExportBytes: 64 * 1024 * 1024,
    imageExportTimeoutMs: 30_000,
    kevUrl: options.kevUrl ?? 'http://127.0.0.1:1/kev.json',
    isTest: true,
  });
  const log = createLogger('silent');
  const db = Db.open(config.dbPath);
  const ctx = createTestContext(config, db, log);
  const app = await buildServer(ctx);
  if (options.runWorkers) {
    await ctx.coordinator.start();
    ctx.dispatcher.start(10_000);
    ctx.scheduler.start(60_000);
  }

  const harness: TestApp = {
    app,
    ctx,
    db,
    config,
    dir,
    cookie: '',
    csrf: '',
    async login(): Promise<void> {
      const response = await app.inject({
        method: 'POST',
        url: '/api/auth/setup',
        payload: { setupToken: 'test-setup-token', username: 'admin', password: 'correct-horse-battery' },
      });
      if (response.statusCode !== 200) throw new Error(`setup failed: ${response.statusCode} ${response.body}`);
      const auth = response.json() as { csrfToken: string };
      harness.csrf = auth.csrfToken;
      const setCookie = response.headers['set-cookie'];
      const cookieHeader = Array.isArray(setCookie) ? setCookie[0] : setCookie;
      harness.cookie = String(cookieHeader ?? '').split(';')[0] ?? '';
      if (!harness.cookie) throw new Error('session cookie missing');
    },
    async close(): Promise<void> {
      await ctx.coordinator.stop();
      ctx.scheduler.stop();
      ctx.dispatcher.stop();
      await app.close();
      try {
        db.close();
      } catch {
        // already closed
      }
      if (!options.dataDir) await rm(dir, { recursive: true, force: true });
    },
  };
  return harness;
}

export function authHeaders(harness: TestApp, mutating = false): Record<string, string> {
  return {
    cookie: harness.cookie,
    ...(mutating ? { 'x-csrf-token': harness.csrf } : {}),
  };
}
