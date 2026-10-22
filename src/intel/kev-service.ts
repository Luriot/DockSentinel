import type { Db } from '../db/index.ts';
import type { Config } from '../config.ts';
import type { Logger } from '../logger.ts';
import type { AlertService } from '../notify/service.ts';
import { getKevStatus, syncKev, type KevStatus } from '../repo/kev.ts';
import { ageHours } from '../util/time.ts';

const SYNC_INTERVAL_HOURS = 24;

export class KevService {
  private readonly db: Db;
  private readonly config: Config;
  private readonly log: Logger;
  private readonly alerts: AlertService;
  private inFlight = false;

  constructor(db: Db, config: Config, log: Logger, alerts: AlertService) {
    this.db = db;
    this.config = config;
    this.log = log;
    this.alerts = alerts;
  }

  status(): KevStatus {
    return getKevStatus(this.db);
  }

  async syncIfDue(): Promise<void> {
    const status = this.status();
    const age = ageHours(status.syncedAt);
    if (age !== null && age < SYNC_INTERVAL_HOURS) return;
    await this.syncNow();
  }

  async syncNow(): Promise<{ ok: boolean; entryCount: number; error: string | null }> {
    if (this.inFlight) return { ok: false, entryCount: 0, error: 'A synchronization is already running' };
    this.inFlight = true;
    try {
      const result = await syncKev(this.db, { url: this.config.kevUrl, log: this.log });
      if (result.ok && result.newlyFlagged.length > 0) {
        try {
          this.alerts.evaluateKnownExploited(result.newlyFlagged);
        } catch (error) {
          this.log.warn(
            { err: error instanceof Error ? error.message : String(error) },
            'known-exploited alerts failed',
          );
        }
      }
      return { ok: result.ok, entryCount: result.entryCount, error: result.error };
    } finally {
      this.inFlight = false;
    }
  }
}
