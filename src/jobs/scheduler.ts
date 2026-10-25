import type { Db } from '../db/index.ts';
import type { Logger } from '../logger.ts';
import type { Config } from '../config.ts';
import type { AppSettings } from '../repo/settings.ts';
import type { DiscoveryService } from '../discovery.ts';
import type { ScanCoordinator } from '../scan/coordinator.ts';
import type { AlertService } from '../notify/service.ts';
import type { KevService } from '../intel/kev-service.ts';
import { listEnvironments } from '../repo/environments.ts';
import { ageHours, isoAfter, nowIso } from '../util/time.ts';
import { runMaintenance } from './maintenance.ts';
import { ensureAutoBackup } from '../backup.ts';
import type { ScanProfile } from '../scanner/trivy.ts';

interface DueImageRow {
  image_id: string;
  last_success_at: string | null;
  last_scan_status: string | null;
  last_scan_at: string | null;
  quick_hours: number | null;
  standard_hours: number | null;
}

const MAINTENANCE_INTERVAL_MS = 24 * 60 * 60 * 1000;
const FAILED_RESCAN_GRACE_HOURS = 6;
const MAX_NEW_IMAGE_SCANS = 25;
const MAX_SCHEDULED_SCANS = 20;
const MAX_STALE_ALERTS = 20;

export class Scheduler {
  private readonly db: Db;
  private readonly log: Logger;
  private readonly discovery: DiscoveryService;
  private readonly coordinator: ScanCoordinator;
  private readonly alerts: AlertService;
  private readonly kev: KevService;
  private readonly getSettings: () => AppSettings;
  private readonly config: Config;
  private timer: NodeJS.Timeout | null = null;
  private busy = false;
  private stopped = false;
  private lastMaintenance = 0;

  constructor(deps: {
    db: Db;
    log: Logger;
    discovery: DiscoveryService;
    coordinator: ScanCoordinator;
    alerts: AlertService;
    kev: KevService;
    getSettings: () => AppSettings;
    config: Config;
  }) {
    this.db = deps.db;
    this.log = deps.log;
    this.discovery = deps.discovery;
    this.coordinator = deps.coordinator;
    this.alerts = deps.alerts;
    this.kev = deps.kev;
    this.getSettings = deps.getSettings;
    this.config = deps.config;
  }

  start(intervalMs = 60_000): void {
    this.timer = setInterval(() => void this.tick(), intervalMs);
    this.timer.unref();
    setTimeout(() => void this.tick(), 2_000).unref();
  }

  stop(): void {
    this.stopped = true;
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  async tick(): Promise<void> {
    if (this.busy || this.stopped) return;
    this.busy = true;
    try {
      if (this.getSettings().kevEnabled) await this.kev.syncIfDue();
      await this.discoverDueEnvironments();
      this.scheduleDueScans();
      this.alertStaleImages();
      await this.maybeRunMaintenance();
    } catch (error) {
      this.log.error({ err: error instanceof Error ? error.message : String(error) }, 'scheduler tick failed');
    } finally {
      this.busy = false;
    }
  }

  private async discoverDueEnvironments(): Promise<void> {
    const settings = this.getSettings();
    const cutoff = isoAfter(-settings.discoveryIntervalMinutes * 60_000);
    for (const environment of listEnvironments(this.db)) {
      if (!environment.enabled) continue;
      if (environment.lastDiscoveryAt && environment.lastDiscoveryAt > cutoff) continue;
      try {
        await this.discovery.discover(environment);
        if (settings.scanOnDiscovery) this.queueNewImages(environment.id);
      } catch (error) {
        // Independent endpoints must never block one another.
        this.log.warn(
          { environmentId: environment.id, err: error instanceof Error ? error.message : String(error) },
          'scheduled discovery failed',
        );
      }
    }
  }

  private queueNewImages(environmentId: number): void {
    const cutoff = isoAfter(-6 * 3_600_000);
    const images = this.db.all<{ image_id: string }>(
      `SELECT i.image_id FROM images i
       WHERE i.last_success_at IS NULL
         AND i.scan_excluded = 0
         AND EXISTS (SELECT 1 FROM containers c WHERE c.image_id = i.image_id AND c.present = 1 AND c.environment_id = ?)
         AND NOT EXISTS (
           SELECT 1 FROM scans s
           WHERE s.image_id = i.image_id AND (s.status IN ('queued','running') OR s.queued_at > ?)
         )
       ORDER BY (SELECT COUNT(*) FROM containers c WHERE c.image_id = i.image_id AND c.present = 1) DESC
       LIMIT ?`,
      [environmentId, cutoff, MAX_NEW_IMAGE_SCANS],
    );
    for (const image of images) {
      this.coordinator.enqueueScheduled(image.image_id, 'standard', 'new_image', 5);
    }
    if (images.length > 0) this.log.info({ environmentId, count: images.length }, 'queued scans for new images');
  }

  private scheduleDueScans(): void {
    const settings = this.getSettings();
    const now = nowIso();
    const rows = this.db.all<DueImageRow>(
      `SELECT i.image_id, i.last_success_at, i.last_scan_status, i.last_scan_at,
         (SELECT MIN(CASE WHEN e.quick_interval_hours > 0 THEN e.quick_interval_hours END)
            FROM image_locations l JOIN environments e ON e.id = l.environment_id
            WHERE l.image_id = i.image_id AND e.enabled = 1 AND e.scan_enabled = 1) AS quick_hours,
         (SELECT MIN(CASE WHEN e.standard_interval_hours > 0 THEN e.standard_interval_hours END)
            FROM image_locations l JOIN environments e ON e.id = l.environment_id
            WHERE l.image_id = i.image_id AND e.enabled = 1 AND e.scan_enabled = 1) AS standard_hours
       FROM images i
       WHERE i.scan_excluded = 0
         AND EXISTS (SELECT 1 FROM containers c WHERE c.image_id = i.image_id AND c.present = 1)
         AND EXISTS (
           SELECT 1 FROM image_locations l JOIN environments e ON e.id = l.environment_id
           WHERE l.image_id = i.image_id AND e.enabled = 1 AND e.scan_enabled = 1
         )
         AND NOT EXISTS (SELECT 1 FROM scans s WHERE s.image_id = i.image_id AND s.status IN ('queued','running'))
       ORDER BY (i.last_success_at IS NULL) DESC, i.critical_count DESC, i.last_success_at ASC
       LIMIT 200`,
    );

    let queued = 0;
    for (const row of rows) {
      if (queued >= MAX_SCHEDULED_SCANS) break;
      if (
        row.last_scan_status === 'failed' &&
        row.last_scan_at &&
        (ageHours(row.last_scan_at, new Date(now)) ?? 0) < FAILED_RESCAN_GRACE_HOURS
      ) {
        continue;
      }

      let profile: ScanProfile | null = null;
      if (!row.last_success_at) {
        profile = 'standard';
      } else {
        const age = ageHours(row.last_success_at, new Date(now)) ?? 0;
        if (row.standard_hours && age >= row.standard_hours) profile = 'standard';
        else if (row.quick_hours && age >= row.quick_hours) profile = 'quick';
      }
      if (!profile) continue;
      const scanId = this.coordinator.enqueueScheduled(row.image_id, profile, 'schedule', profile === 'standard' ? 2 : 0);
      if (scanId) queued += 1;
    }
    if (queued > 0) this.log.info({ count: queued, concurrency: settings.scanConcurrency }, 'scheduled scans queued');
  }

  private alertStaleImages(): void {
    const settings = this.getSettings();
    if (!settings.alertOnStale) return;
    const staleBefore = isoAfter(-settings.freshnessHours * 2 * 3_600_000);
    const rows = this.db.all<{ image_id: string; last_success_at: string }>(
      `SELECT i.image_id, i.last_success_at FROM images i
       WHERE i.last_success_at IS NOT NULL AND i.last_success_at < ? AND i.scan_excluded = 0
         AND EXISTS (SELECT 1 FROM containers c WHERE c.image_id = i.image_id AND c.present = 1 AND c.state = 'running')
       ORDER BY i.last_success_at ASC LIMIT ?`,
      [staleBefore, MAX_STALE_ALERTS],
    );
    for (const row of rows) {
      try {
        this.alerts.evaluateStale(row.image_id, row.last_success_at);
      } catch (error) {
        this.log.warn(
          { imageId: row.image_id, err: error instanceof Error ? error.message : String(error) },
          'stale alert evaluation failed',
        );
      }
    }
  }

  private async maybeRunMaintenance(): Promise<void> {
    const due = this.lastMaintenance === 0 || Date.now() - this.lastMaintenance >= MAINTENANCE_INTERVAL_MS;
    if (!due) return;
    this.lastMaintenance = Date.now();
    try {
      runMaintenance(this.db, this.getSettings(), this.log);
    } catch (error) {
      this.log.error(
        { err: error instanceof Error ? error.message : String(error) },
        'retention maintenance failed',
      );
    }
    this.runAutomaticBackup();
  }

  private runAutomaticBackup(): void {
    try {
      const result = ensureAutoBackup(this.config, {
        intervalHours: this.config.backupIntervalHours,
        retention: this.config.backupRetention,
      });
      if (result.created) {
        this.log.info({ databasePath: result.databasePath, pruned: result.pruned }, 'automatic database backup created');
      } else if (result.pruned > 0) {
        this.log.info({ pruned: result.pruned }, 'old database backups removed');
      }
    } catch (error) {
      this.log.warn(
        { err: error instanceof Error ? error.message : String(error) },
        'automatic database backup failed',
      );
    }
  }
}
