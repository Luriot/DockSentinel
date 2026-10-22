import type { Db } from '../db/index.ts';
import type { Logger } from '../logger.ts';
import type { AppSettings } from '../repo/settings.ts';
import {
  claimAlert,
  markAlertFailed,
  markAlertSent,
  pendingAlerts,
  resetSendingAlerts,
  type AlertKind,
  type AlertRecord,
} from '../repo/alerts.ts';
import { NtfyError, resolveNtfyPriority, sendNtfy, validateNtfySettings } from './ntfy.ts';
import { isoAfter } from '../util/time.ts';

const BACKOFF_MINUTES = [1, 5, 15, 60];
const MAX_ATTEMPTS = 5;

function retryAt(attempts: number): string | null {
  if (attempts >= MAX_ATTEMPTS) return null;
  const minutes = BACKOFF_MINUTES[Math.min(attempts - 1, BACKOFF_MINUTES.length - 1)] ?? 60;
  return isoAfter(minutes * 60_000);
}

function clickPath(kind: AlertKind, imageId: string | null): string {
  if (imageId) return `/vulnerabilities?image=${encodeURIComponent(imageId)}`;
  if (kind === 'scan_failed' || kind === 'stale_scan') return '/scans';
  return '/';
}

function combinedTags(settings: AppSettings, alert: AlertRecord): string[] {
  const base = settings.ntfy.tags
    .split(',')
    .map((tag) => tag.trim())
    .filter(Boolean);
  const extra = (alert.tags ?? '')
    .split(',')
    .map((tag) => tag.trim())
    .filter(Boolean);
  return [...new Set([...extra, ...base])].slice(0, 5);
}

export class NotificationDispatcher {
  private readonly db: Db;
  private readonly log: Logger;
  private readonly getSettings: () => AppSettings;
  private timer: NodeJS.Timeout | null = null;
  private inFlight = false;
  private lastConfigError: string | null = null;

  constructor(db: Db, log: Logger, getSettings: () => AppSettings) {
    this.db = db;
    this.log = log;
    this.getSettings = getSettings;
  }

  start(intervalMs = 15_000): void {
    const reset = resetSendingAlerts(this.db);
    if (reset > 0) this.log.warn({ count: reset }, 'reset alerts interrupted mid-delivery');
    this.timer = setInterval(() => void this.tick(), intervalMs);
    this.timer.unref();
    void this.tick();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  async tick(): Promise<void> {
    if (this.inFlight) return;
    this.inFlight = true;
    try {
      const settings = this.getSettings();
      if (!settings.ntfy.enabled) return;
      const configError = validateNtfySettings(settings.ntfy);
      if (configError) {
        if (this.lastConfigError !== configError) {
          this.lastConfigError = configError;
          this.log.warn({ error: configError }, 'notifications enabled but misconfigured; alerts stay queued');
        }
        return;
      }
      this.lastConfigError = null;

      for (const alert of pendingAlerts(this.db, 20)) {
        if (!claimAlert(this.db, alert.id)) continue;
        await this.sendAlert({ ...alert, attempts: alert.attempts + 1 }, settings);
      }
    } finally {
      this.inFlight = false;
    }
  }

  private async sendAlert(alert: AlertRecord, settings: AppSettings): Promise<boolean> {
    const publicUrl = settings.publicUrl.trim();
    try {
      await sendNtfy(settings.ntfy, {
        title: alert.title,
        body: alert.body,
        priority: resolveNtfyPriority(settings.ntfy, alert.priority),
        tags: combinedTags(settings, alert),
        clickUrl: publicUrl ? `${publicUrl.replace(/\/+$/, '')}${clickPath(alert.kind, alert.imageId)}` : null,
      });
      markAlertSent(this.db, alert.id);
      this.log.info({ alertId: alert.id, kind: alert.kind }, 'alert delivered');
      return true;
    } catch (error) {
      const message =
        error instanceof NtfyError
          ? `${error.message}${error.detail ? `: ${error.detail}` : ''}`
          : error instanceof Error
            ? error.message
            : 'Delivery failed';
      const nextAttempt = retryAt(alert.attempts);
      markAlertFailed(this.db, alert.id, message, nextAttempt);
      this.log.warn(
        { alertId: alert.id, attempt: alert.attempts, willRetry: Boolean(nextAttempt), error: message.slice(0, 300) },
        'alert delivery failed',
      );
      return false;
    }
  }
}
