import { mkdir, mkdtemp, readdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import type { Db } from '../db/index.ts';
import type { Config } from '../config.ts';
import type { Logger } from '../logger.ts';
import { DockerClient, DockerError } from '../docker/client.ts';
import { getEnvironment, toDockerConnection, type EnvironmentRecord } from '../repo/environments.ts';
import { applyScanFindings, refreshImageFindingCounts, type ApplyScanOutcome } from '../repo/findings.ts';
import { applyContentFindings } from '../repo/content.ts';
import { describeImage, listScanEnvironments, updateImageAfterScan } from '../repo/images.ts';
import {
  claimNextScan,
  getScan,
  markScanCancelled,
  markScanFailed,
  markScanSuccess,
  queueScan,
  type ScanKind,
  type ScanRecord,
  type ScanTrigger,
} from '../repo/scans.ts';
import {
  ScannerError,
  TrivyAdapter,
  type ContentScanners,
  type ScanProfile,
  type ScannerRunResult,
} from '../scanner/trivy.ts';
import { invalidateScannerInfo } from '../scanner/info.ts';
import { filterIgnoredPackages } from '../domain/packages.ts';
import { dedupeFindings } from '../domain/findings.ts';
import { recoverInterruptedScans } from './recovery.ts';
import type { AlertService } from '../notify/service.ts';
import type { AppSettings } from '../repo/settings.ts';
import { isoAfter, nowIso } from '../util/time.ts';

class ScanExecutionError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = 'ScanExecutionError';
    this.code = code;
  }
}

const RETRIABLE = new Set([
  'timeout',
  'docker_unreachable',
  'image_export_failed',
  'scanner_failed',
  'db_unavailable',
  'scan_failed',
  'interrupted',
]);

const FALLBACK_ENVIRONMENTS = 3;

function retryDelayMs(attempt: number): number {
  const seconds = Math.min(15 * 60, 30 * 2 ** Math.max(0, attempt - 1));
  return seconds * 1000;
}

function formatGiB(bytes: number): string {
  return `${(bytes / 1024 ** 3).toFixed(1)} GiB`;
}

function tooLargeMessage(size: number, maxBytes: number): string {
  return `Image is ${formatGiB(size)}, above MAX_IMAGE_EXPORT_BYTES (${formatGiB(maxBytes)}); raise the limit to scan it`;
}

/** Size above the configured export cap, or null when the image can be scanned. */
function oversizedImageSize(db: Db, imageId: string, maxBytes: number): number | null {
  const size = db.get<{ size_bytes: number | null }>('SELECT size_bytes FROM images WHERE image_id = ?', [imageId])
    ?.size_bytes;
  return size && size > maxBytes ? size : null;
}

export interface QueueResult {
  queued: boolean;
  scanId: number | null;
  message: string;
}

export class ScanCoordinator {
  private readonly db: Db;
  private readonly config: Config;
  private readonly log: Logger;
  private readonly alerts: AlertService;
  private readonly getSettings: () => AppSettings;
  private readonly running = new Map<number, AbortController>();
  private readonly tasks = new Set<Promise<void>>();
  private readonly tmpRoot: string;
  private timer: NodeJS.Timeout | null = null;
  private stopped = false;
  private ticking = false;

  constructor(deps: {
    db: Db;
    config: Config;
    log: Logger;
    alerts: AlertService;
    getSettings: () => AppSettings;
  }) {
    this.db = deps.db;
    this.config = deps.config;
    this.log = deps.log;
    this.alerts = deps.alerts;
    this.getSettings = deps.getSettings;
    this.tmpRoot = join(this.config.dataDir, 'tmp');
  }

  async start(): Promise<void> {
    await mkdir(this.tmpRoot, { recursive: true, mode: 0o700 });
    await this.cleanLeftoverWorkDirs();
    const recovery = recoverInterruptedScans(this.db, this.getSettings().scanFailureRetries);
    if (recovery.requeued + recovery.failed > 0) {
      this.log.warn(recovery, 'recovered interrupted scans');
    }
    this.timer = setInterval(() => void this.tick(), 1500);
    this.timer.unref();
    void this.tick();
  }

  async stop(): Promise<void> {
    this.stopped = true;
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    for (const controller of this.running.values()) controller.abort();
    await Promise.race([Promise.allSettled([...this.tasks]), new Promise((resolve) => setTimeout(resolve, 5000))]);
  }

  get activeCount(): number {
    return this.running.size;
  }

  enqueueManual(imageId: string, profile: ScanProfile, kind: ScanKind = 'vulnerability'): QueueResult {
    const image = this.db.get<{ image_id: string }>('SELECT image_id FROM images WHERE image_id = ?', [imageId]);
    if (!image) return { queued: false, scanId: null, message: 'Image is not in the inventory' };
    const oversized = oversizedImageSize(this.db, imageId, this.config.maxImageExportBytes);
    if (oversized !== null) {
      return {
        queued: false,
        scanId: null,
        message: tooLargeMessage(oversized, this.config.maxImageExportBytes),
      };
    }
    const environments = listScanEnvironments(this.db, imageId);
    if (environments.length === 0) {
      return { queued: false, scanId: null, message: 'No enabled Docker environment currently holds this image' };
    }
    if (kind === 'content' && !this.contentScanners()) {
      return {
        queued: false,
        scanId: null,
        message: 'Enable misconfiguration and/or secret scanning in Settings before requesting a content scan',
      };
    }
    const display = describeImage(this.db, imageId);
    const scanId = queueScan(
      this.db,
      {
        environmentId: environments[0] ?? null,
        imageId,
        imageRef: display.displayRef,
        kind,
        profile: kind === 'content' ? 'quick' : profile,
        trigger: 'manual',
        priority: 100,
      },
      true,
    );
    if (!scanId) return { queued: false, scanId: null, message: 'A scan for this image is already queued or running' };
    this.log.info({ scanId, imageId, profile, kind }, 'manual scan queued');
    void this.tick();
    return { queued: true, scanId, message: 'Scan queued' };
  }

  enqueueAllManual(profile: ScanProfile, cursor = '', limit = 100): {
    queued: number;
    skipped: number;
    total: number;
    nextCursor: string | null;
  } {
    const pageSize = Math.max(1, Math.min(limit, 200));
    const total = this.db.get<{ count: number }>('SELECT COUNT(*) AS count FROM images')?.count ?? 0;
    const images = this.db.all<{ image_id: string }>(
      `SELECT image_id FROM images WHERE image_id > ?
       AND EXISTS (SELECT 1 FROM image_locations l WHERE l.image_id = images.image_id)
       ORDER BY image_id LIMIT ?`,
      [cursor, pageSize],
    );
    let queued = 0;
    let skipped = 0;
    for (const image of images) {
      const result = this.enqueueManual(image.image_id, profile, 'vulnerability');
      if (result.queued) queued += 1;
      else skipped += 1;
    }
    const nextCursor = images.length === pageSize ? images[images.length - 1]?.image_id ?? null : null;
    this.log.info({ queued, skipped, total, batch: images.length, profile }, 'manual scan-all batch requested');
    return { queued, skipped, total, nextCursor };
  }

  enqueueScheduled(imageId: string, profile: ScanProfile, trigger: ScanTrigger, priority = 0): number | null {
    // Oversized images are never queued automatically: they would fail on every retry cycle.
    if (oversizedImageSize(this.db, imageId, this.config.maxImageExportBytes) !== null) return null;
    const environments = listScanEnvironments(this.db, imageId);
    if (environments.length === 0) return null;
    const display = describeImage(this.db, imageId);
    return queueScan(
      this.db,
      {
        environmentId: environments[0] ?? null,
        imageId,
        imageRef: display.displayRef,
        kind: 'vulnerability',
        profile,
        trigger,
        priority,
      },
      true,
    );
  }

  cancel(scanId: number): boolean {
    const scan = getScan(this.db, scanId);
    if (!scan) return false;
    if (scan.status === 'queued') {
      markScanCancelled(this.db, scanId, 'Cancelled before the scan started');
      return true;
    }
    if (scan.status === 'running') {
      const controller = this.running.get(scanId);
      if (controller) {
        controller.abort();
        return true;
      }
    }
    return false;
  }

  async tick(): Promise<void> {
    if (this.ticking || this.stopped) return;
    this.ticking = true;
    try {
      const settings = this.getSettings();
      const limit = Math.max(1, Math.min(settings.scanConcurrency, this.config.scanConcurrency));
      while (this.running.size < limit) {
        const scan = claimNextScan(this.db);
        if (!scan) break;
        const controller = new AbortController();
        this.running.set(scan.id, controller);
        const task = this.execute(scan, controller)
          .catch((error) => {
            this.log.error({ scanId: scan.id, err: error instanceof Error ? error.message : String(error) }, 'scan task crashed');
          })
          .finally(() => {
            this.running.delete(scan.id);
            this.tasks.delete(task);
            void this.tick();
          });
        this.tasks.add(task);
      }
    } finally {
      this.ticking = false;
    }
  }

  private async execute(scan: ScanRecord, controller: AbortController): Promise<void> {
    const workDir = await mkdtemp(join(this.tmpRoot, 'scan-'));
    const archivePath = join(workDir, 'image.tar');
    let lastError: unknown = null;

    try {
      const environments = listScanEnvironments(this.db, scan.imageId).slice(0, FALLBACK_ENVIRONMENTS);
      if (environments.length === 0) {
        throw new ScanExecutionError('no_target', 'No enabled Docker environment currently holds this image');
      }

      for (const environmentId of environments) {
        if (controller.signal.aborted) throw new ScannerError('cancelled', 'Scan cancelled');
        const environment = getEnvironment(this.db, environmentId);
        if (!environment || !environment.enabled || !environment.scanEnabled) continue;

        try {
          const result = await this.scanOnEnvironment(scan, environment, workDir, archivePath, controller.signal);
          if (controller.signal.aborted) throw new ScannerError('cancelled', 'Scan cancelled');
          this.complete(scan, environment, result);
          return;
        } catch (error) {
          lastError = error;
          if (controller.signal.aborted || this.stopped) break;
          if (!this.tryNextEnvironment(error)) break;
          await rm(archivePath, { force: true }).catch(() => undefined);
        }
      }
      throw lastError ?? new ScanExecutionError('scan_failed', 'Scan failed without a specific error');
    } catch (error) {
      this.fail(scan, error);
    } finally {
      this.running.delete(scan.id);
      await rm(workDir, { recursive: true, force: true }).catch(() => undefined);
    }
  }

  private contentScanners(): ContentScanners | null {
    const settings = this.getSettings();
    if (!settings.misconfigScanEnabled && !settings.secretScanEnabled) return null;
    return { misconfig: settings.misconfigScanEnabled, secret: settings.secretScanEnabled };
  }

  private async scanOnEnvironment(
    scan: ScanRecord,
    environment: EnvironmentRecord,
    workDir: string,
    archivePath: string,
    signal: AbortSignal,
  ): Promise<ScannerRunResult> {
    const advertisedSize = this.db.get<{ size_bytes: number | null }>(
      'SELECT size_bytes FROM images WHERE image_id = ?',
      [scan.imageId],
    )?.size_bytes;
    if (advertisedSize && advertisedSize > this.config.maxImageExportBytes) {
      throw new ScanExecutionError('image_too_large', tooLargeMessage(advertisedSize, this.config.maxImageExportBytes));
    }

    let client: DockerClient;
    try {
      client = new DockerClient(toDockerConnection(environment, this.config.secretKey));
    } catch (error) {
      throw new ScanExecutionError(
        'docker_unreachable',
        error instanceof Error ? error.message : 'Endpoint configuration could not be read',
      );
    }

    await client.exportImage(scan.imageId, archivePath, {
      maxBytes: this.config.maxImageExportBytes,
      timeoutMs: this.config.imageExportTimeoutMs,
      signal,
    });

    const adapter = new TrivyAdapter({
      bin: this.config.trivyBin,
      cacheDir: this.config.trivyCacheDir,
      maxOutputBytes: this.config.maxOutputBytes,
      maxTimeoutMs: this.config.scanTimeoutMs,
    });
    const contentScanners = scan.kind === 'content' ? this.contentScanners() : null;
    if (scan.kind === 'content' && !contentScanners) {
      throw new ScanExecutionError('content_disabled', 'Content scanning was disabled in Settings before the scan started');
    }
    return adapter.run({
      archivePath,
      workDir,
      profile: scan.profile,
      mode: scan.kind === 'content' ? 'content' : 'vulnerability',
      contentScanners: contentScanners ?? undefined,
      signal,
    });
  }

  private complete(scan: ScanRecord, environment: EnvironmentRecord, result: ScannerRunResult): void {
    if (scan.kind === 'content') {
      this.completeContent(scan, environment, result);
      return;
    }
    const ignored = this.getSettings().ignoredPackages;
    const findings = dedupeFindings(filterIgnoredPackages(result.findings, ignored));
    const now = nowIso();
    const outcome: ApplyScanOutcome = this.db.transaction(() => {
      const applied = applyScanFindings(this.db, {
        imageId: scan.imageId,
        scanId: scan.id,
        findings,
        now,
        osOnly: scan.profile === 'quick',
      });
      markScanSuccess(this.db, scan.id, {
        environmentId: environment.id,
        durationMs: result.durationMs,
        scannerVersion: result.scannerVersion,
        dbVersion: result.dbVersion,
        dbUpdatedAt: result.dbUpdatedAt,
        counts: applied.counts,
        exitCode: result.exitCode,
        warnings: result.warnings,
      });
      updateImageAfterScan(this.db, scan.imageId, scan.id, 'success', applied.counts, result.os);
      refreshImageFindingCounts(this.db, scan.imageId);
      return applied;
    });

    invalidateScannerInfo();
    const updated = getScan(this.db, scan.id) ?? scan;
    this.log.info(
      {
        scanId: scan.id,
        imageId: scan.imageId,
        environment: environment.name,
        findings: result.findings.length,
        appeared: outcome.appeared.length,
        resolved: outcome.resolved.length,
        durationMs: result.durationMs,
      },
      'scan completed',
    );

    try {
      this.alerts.evaluateScan(updated, outcome);
    } catch (error) {
      this.log.error({ scanId: scan.id, err: error instanceof Error ? error.message : String(error) }, 'alert evaluation failed');
    }
  }

  private completeContent(scan: ScanRecord, environment: EnvironmentRecord, result: ScannerRunResult): void {
    const now = nowIso();
    const outcome = this.db.transaction(() => {
      const applied = applyContentFindings(this.db, {
        imageId: scan.imageId,
        scanId: scan.id,
        findings: result.contentFindings,
        now,
      });
      markScanSuccess(this.db, scan.id, {
        environmentId: environment.id,
        durationMs: result.durationMs,
        scannerVersion: result.scannerVersion,
        dbVersion: null,
        dbUpdatedAt: null,
        counts: applied.counts,
        exitCode: result.exitCode,
        warnings: result.warnings,
      });
      return applied;
    });
    this.log.info(
      {
        scanId: scan.id,
        imageId: scan.imageId,
        environment: environment.name,
        kind: scan.kind,
        findings: result.contentFindings.length,
        appeared: outcome.appeared.length,
        resolved: outcome.resolved.length,
        durationMs: result.durationMs,
      },
      'content scan completed',
    );
  }

  private fail(scan: ScanRecord, error: unknown): void {
    const info = describeFailure(error);
    const settings = this.getSettings();

    if (info.code === 'cancelled' && !this.stopped) {
      markScanCancelled(this.db, scan.id, 'Scan cancelled by user');
      if (scan.kind === 'vulnerability') this.updateImageScanStatus(scan, 'cancelled');
      return;
    }

    const code = this.stopped ? 'interrupted' : info.code;
    const canRetry = RETRIABLE.has(code) && scan.attempts <= settings.scanFailureRetries;
    const retryAt = canRetry ? (this.stopped ? nowIso() : isoAfter(retryDelayMs(scan.attempts))) : null;
    markScanFailed(this.db, scan.id, {
      errorCode: code,
      errorMessage: info.message,
      exitCode: info.exitCode,
      retryAt,
    });
    if (retryAt) {
      this.log.warn(
        { scanId: scan.id, imageId: scan.imageId, code, attempt: scan.attempts, retryAt },
        'scan failed; retry scheduled',
      );
      return;
    }
    // Only a terminal failure changes the status shown for the image: while a retry is still queued
    // the last successful result remains the truth, and the scan row already shows the pending retry.
    if (scan.kind === 'vulnerability') this.updateImageScanStatus(scan, 'failed');

    this.log.error({ scanId: scan.id, imageId: scan.imageId, code, error: info.message }, 'scan failed permanently');
    if (scan.kind === 'content') return;
    try {
      this.alerts.evaluateScanFailure(scan, code, info.message);
    } catch (alertError) {
      this.log.error(
        { scanId: scan.id, err: alertError instanceof Error ? alertError.message : String(alertError) },
        'failure alert evaluation failed',
      );
    }
  }

  private updateImageScanStatus(scan: ScanRecord, status: 'failed' | 'cancelled'): void {
    try {
      updateImageAfterScan(this.db, scan.imageId, null, status, null, null);
    } catch (error) {
      this.log.warn(
        { imageId: scan.imageId, err: error instanceof Error ? error.message : String(error) },
        'unable to update image status',
      );
    }
  }

  private tryNextEnvironment(error: unknown): boolean {
    // Docker-level failures can be endpoint specific, so another host may still hold the image.
    // Scanner failures are environment independent: retrying elsewhere would only waste time.
    return error instanceof DockerError;
  }

  private async cleanLeftoverWorkDirs(): Promise<void> {
    try {
      const entries = await readdir(this.tmpRoot, { withFileTypes: true });
      for (const entry of entries) {
        if (!entry.isDirectory() || !entry.name.startsWith('scan-')) continue;
        await rm(join(this.tmpRoot, entry.name), { recursive: true, force: true }).catch(() => undefined);
      }
    } catch {
      // A missing or unreadable temp directory is recreated on demand by mkdtemp.
    }
  }
}

function describeFailure(error: unknown): { code: string; message: string; exitCode: number | null } {
  if (error instanceof ScannerError) {
    return { code: error.code, message: error.message, exitCode: error.exitCode };
  }
  if (error instanceof DockerError) {
    const code =
      error.code === 'unreachable' || error.code === 'timeout'
        ? 'docker_unreachable'
        : error.code === 'insufficient_space'
          ? 'insufficient_space'
          : 'image_export_failed';
    return { code, message: `Docker operation failed: ${error.message}`, exitCode: null };
  }
  if (error instanceof ScanExecutionError) {
    return { code: error.code, message: error.message, exitCode: null };
  }
  return {
    code: 'scan_failed',
    message: error instanceof Error ? error.message.slice(0, 1000) : 'Scan failed unexpectedly',
    exitCode: null,
  };
}
