import type { Db } from '../db/index.ts';
import type { Config } from '../config.ts';
import type { Logger } from '../logger.ts';
import type { DiscoveryService } from '../discovery.ts';
import type { ScanCoordinator } from '../scan/coordinator.ts';
import type { AlertService } from '../notify/service.ts';
import type { NotificationDispatcher } from '../notify/dispatcher.ts';
import type { KevService } from '../intel/kev-service.ts';
import type { Scheduler } from '../jobs/scheduler.ts';
import type { AppSettings } from '../repo/settings.ts';

export interface AppContext {
  db: Db;
  config: Config;
  log: Logger;
  discovery: DiscoveryService;
  coordinator: ScanCoordinator;
  alerts: AlertService;
  dispatcher: NotificationDispatcher;
  kev: KevService;
  scheduler: Scheduler;
  getSettings: () => AppSettings;
  setupToken: () => string | null;
  startedAt: number;
}
