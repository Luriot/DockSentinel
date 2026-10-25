import { createHash } from 'node:crypto';
import type { Db } from '../db/index.ts';
import type { Logger } from '../logger.ts';
import type { AppSettings } from '../repo/settings.ts';
import type { Severity } from '../domain/severity.ts';
import { normalizeSeverity } from '../domain/severity.ts';
import { parseWorkloadLabels, resolveAlertThreshold, shouldAlertForFinding } from '../domain/policy.ts';
import type { ContainerSummary } from '../repo/containers.ts';
import { listContainersForImage } from '../repo/containers.ts';
import { describeImage } from '../repo/images.ts';
import { findingsByIds, type ApplyScanOutcome, type FindingRecord } from '../repo/findings.ts';
import { kevIsAvailable } from '../repo/kev.ts';
import type { ScanRecord } from '../repo/scans.ts';
import { createAlert, markAlertFailed, markAlertSent } from '../repo/alerts.ts';
import type { NormalizedFinding } from '../domain/findings.ts';
import { isKernelPackage } from '../domain/packages.ts';
import {
  fixesAvailableMessage,
  knownExploitedMessage,
  newFindingsMessage,
  resolvedFindingsMessage,
  scanFailedMessage,
  staleScanMessage,
  testMessage,
  type BuiltMessage,
  type ImageAlertContext,
} from './messages.ts';
import { sendNtfy, validateNtfySettings, NtfyError } from './ntfy.ts';
import { isoDay } from '../util/time.ts';

interface ScanContext {
  image: ImageAlertContext;
  monitored: ContainerSummary[];
  environmentSeverity: Map<number, Severity>;
}

function toNormalized(finding: FindingRecord): NormalizedFinding {
  return {
    target: finding.target,
    class: finding.class,
    type: finding.type,
    vulnId: finding.vulnId,
    pkgName: finding.pkgName,
    installedVersion: finding.installedVersion,
    fixedVersion: finding.fixedVersion,
    severity: finding.severity,
    status: finding.status,
    title: finding.title,
    primaryUrl: finding.primaryUrl,
    cvssScore: finding.cvssScore,
    cvssSource: finding.cvssSource,
    cvssVector: finding.cvssVector,
    publishedAt: finding.publishedAt,
    modifiedAt: finding.modifiedAt,
  };
}

export class AlertService {
  private readonly db: Db;
  private readonly log: Logger;
  private readonly getSettings: () => AppSettings;

  constructor(db: Db, log: Logger, getSettings: () => AppSettings) {
    this.db = db;
    this.log = log;
    this.getSettings = getSettings;
  }

  /** Records deduplicated alerts for meaningful changes after a successful scan. */
  evaluateScan(scan: ScanRecord, outcome: ApplyScanOutcome): void {
    const settings = this.getSettings();
    if (!settings.ntfy.enabled) return;
    const context = this.contextFor(scan.imageId);
    if (!context || context.monitored.length === 0) return;

    if (settings.alertOnNew && outcome.appeared.length > 0) {
      const alertable = outcome.appeared
        .filter((entry) => !isKernelPackage(entry.finding.pkgName))
        .filter((entry) => !this.isSuppressed(entry.id))
        .map((entry) => entry.finding)
        .filter((finding) => this.isAlertable(context, finding));
      if (alertable.length > 0) {
        const kevIds = new Set<string>();
        if (kevIsAvailable(this.db)) {
          for (const finding of alertable) {
            if (this.db.get('SELECT cve_id FROM kev WHERE cve_id = ?', [finding.vulnId])) kevIds.add(finding.vulnId);
          }
        }
        const message = newFindingsMessage(context.image, scan, alertable, kevIds, settings.publicUrl);
        this.record('new_findings', `new:${scan.imageId}:${scan.id}`, scan.environmentId, scan.imageId, message);
      }
    }

    if (settings.alertOnResolved && outcome.resolved.length > 0) {
      const alertable = outcome.resolved
        .filter((finding) => !isKernelPackage(finding.pkgName))
        .filter((finding) => !this.isSuppressed(finding.id))
        .filter((finding) => this.isAlertable(context, finding));
      if (alertable.length > 0) {
        const message = resolvedFindingsMessage(context.image, scan, alertable, settings.publicUrl);
        this.record('resolved_findings', `resolved:${scan.imageId}:${scan.id}`, scan.environmentId, scan.imageId, message);
      }
    }

    const fixedIds = outcome.changed
      .filter((change) => !change.changes.fixedVersion?.from && Boolean(change.changes.fixedVersion?.to))
      .map((change) => change.finding.id);
    if (fixedIds.length > 0) {
      const fixed = findingsByIds(this.db, fixedIds)
        .filter((finding) => !isKernelPackage(finding.pkgName))
        .filter((finding) => finding.triageStatus !== 'ignored' && finding.triageStatus !== 'false_positive')
        .map(toNormalized)
        .filter((finding) => finding.fixedVersion && this.isAlertable(context, finding));
      if (fixed.length > 0) {
        const message = fixesAvailableMessage(context.image, fixed, settings.publicUrl);
        this.record('fix_available', `fix:${scan.imageId}:${scan.id}`, scan.environmentId, scan.imageId, message);
      }
    }
  }

  /** Final failures only (retries exhausted), at most one notification per image, environment and day. */
  evaluateScanFailure(scan: ScanRecord, errorCode: string, errorMessage: string): void {
    const settings = this.getSettings();
    if (!settings.ntfy.enabled || !settings.alertOnScanFailure) return;
    const environment = scan.environmentId
      ? this.db.get<{ name: string }>('SELECT name FROM environments WHERE id = ?', [scan.environmentId])
      : undefined;
    const context = this.contextFor(scan.imageId);
    const message = scanFailedMessage(
      context?.image ?? null,
      environment?.name ?? 'Unknown environment',
      scan.imageRef,
      errorCode,
      errorMessage,
      settings.publicUrl,
    );
    const key = `scan_failed:${scan.environmentId ?? 0}:${scan.imageId}:${isoDay()}`;
    this.record('scan_failed', key, scan.environmentId, scan.imageId, message);
  }

  evaluateKnownExploited(entries: { findingId: number; imageId: string; episode: number }[]): void {
    const settings = this.getSettings();
    if (!settings.ntfy.enabled || !settings.alertOnKev || entries.length === 0) return;

    const byImage = new Map<string, number[]>();
    for (const entry of entries) {
      const bucket = byImage.get(entry.imageId) ?? [];
      bucket.push(entry.findingId);
      byImage.set(entry.imageId, bucket);
    }

    for (const [imageId, findingIds] of byImage) {
      const context = this.contextFor(imageId);
      if (!context || context.monitored.length === 0) continue;
      const findings = findingsByIds(this.db, findingIds)
        .filter((finding) => finding.triageStatus !== 'ignored' && finding.triageStatus !== 'false_positive')
        .filter((finding) => this.isAlertable(context, { vulnId: finding.vulnId, severity: finding.severity }));
      if (findings.length === 0) continue;
      const message = knownExploitedMessage(
        context.image,
        findings.map((finding) => ({
          vulnId: finding.vulnId,
          pkgName: finding.pkgName,
          severity: finding.severity,
          title: finding.title,
          primaryUrl: finding.primaryUrl,
        })),
        settings.publicUrl,
      );
      const hash = createHash('sha256')
        .update(findings.map((finding) => finding.id).sort((a, b) => a - b).join(','))
        .digest('hex')
        .slice(0, 16);
      this.record('known_exploited', `kev:${imageId}:${hash}`, null, imageId, message);
    }
  }

  evaluateStale(imageId: string, lastSuccessAt: string | null): void {
    const settings = this.getSettings();
    if (!settings.ntfy.enabled || !settings.alertOnStale) return;
    const context = this.contextFor(imageId);
    if (!context || context.monitored.length === 0) return;
    const message = staleScanMessage(context.image, lastSuccessAt, settings.publicUrl);
    this.record('stale_scan', `stale:${imageId}:${isoDay()}`, null, imageId, message);
  }

  async sendTest(): Promise<{ ok: boolean; message: string; alertId: number | null }> {
    const settings = this.getSettings();
    if (!settings.ntfy.enabled) return { ok: false, message: 'Notifications are disabled', alertId: null };
    const configError = validateNtfySettings(settings.ntfy);
    if (configError) return { ok: false, message: configError, alertId: null };

    const message = testMessage(settings.publicUrl);
    const alertId = createAlert(this.db, {
      dedupeKey: `test:${Date.now()}`,
      kind: 'test',
      severity: null,
      environmentId: null,
      imageId: null,
      title: message.title,
      body: message.body,
      priority: message.priority,
      tags: message.tags.join(','),
    });
    try {
      await sendNtfy(settings.ntfy, message);
      if (alertId) markAlertSent(this.db, alertId);
      return { ok: true, message: 'Test notification delivered', alertId };
    } catch (error) {
      const text =
        error instanceof NtfyError ? `${error.message}${error.detail ? `: ${error.detail}` : ''}` : 'Delivery failed';
      if (alertId) markAlertFailed(this.db, alertId, text, null);
      return { ok: false, message: text, alertId };
    }
  }

  private contextFor(imageId: string): ScanContext | null {
    const display = describeImage(this.db, imageId);
    const containers = listContainersForImage(this.db, imageId);
    if (containers.length === 0) return null;
    const monitored = containers.filter(
      (container) => container.present && parseWorkloadLabels(container.labels).monitored,
    );
    const environmentSeverity = new Map<number, Severity>();
    for (const row of this.db.all<{ id: number; min_alert_severity: string }>(
      'SELECT id, min_alert_severity FROM environments',
    )) {
      environmentSeverity.set(row.id, normalizeSeverity(row.min_alert_severity));
    }
    return {
      image: {
        imageId,
        displayRef: display.displayRef,
        references: display.references,
        containers,
        environmentNames: [...new Set(containers.map((container) => container.environmentName))],
      },
      monitored,
      environmentSeverity,
    };
  }

  private isSuppressed(findingId: number): boolean {
    return Boolean(
      this.db.get("SELECT 1 AS suppressed FROM findings WHERE id = ? AND triage_status IN ('ignored','false_positive')", [
        findingId,
      ]),
    );
  }

  private isAlertable(context: ScanContext, finding: { vulnId: string; severity: Severity }): boolean {
    const settings = this.getSettings();
    return context.monitored.some((container) => {
      const policy = parseWorkloadLabels(container.labels);
      const threshold = resolveAlertThreshold(
        settings.minAlertSeverity,
        context.environmentSeverity.get(container.environmentId) ?? settings.minAlertSeverity,
        policy,
      );
      return shouldAlertForFinding(finding.severity, threshold, finding.vulnId, policy);
    });
  }

  private record(
    kind: 'new_findings' | 'resolved_findings' | 'fix_available' | 'known_exploited' | 'scan_failed' | 'stale_scan',
    dedupeKey: string,
    environmentId: number | null,
    imageId: string | null,
    message: BuiltMessage,
  ): void {
    const id = createAlert(this.db, {
      dedupeKey,
      kind,
      severity: message.severity,
      environmentId,
      imageId,
      title: message.title,
      body: message.body,
      priority: message.priority,
      tags: message.tags.join(','),
    });
    if (id) this.log.info({ alertId: id, kind, imageId }, 'alert queued');
  }
}
