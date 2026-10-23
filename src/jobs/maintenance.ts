import type { Db } from '../db/index.ts';
import type { AppSettings } from '../repo/settings.ts';
import type { Logger } from '../logger.ts';
import { nowIso } from '../util/time.ts';
import { pruneScans } from '../repo/scans.ts';
import { pruneAlerts } from '../repo/alerts.ts';
import { pruneResolvedFindings } from '../repo/findings.ts';
import { pruneContentFindings } from '../repo/content.ts';

export interface MaintenanceResult {
  scans: number;
  alerts: number;
  events: number;
  findings: number;
  contentFindings: number;
  containers: number;
  images: number;
}

/**
 * Retention cleanup. The most recent scan per image is always kept so the UI can explain the
 * current state even after history ages out.
 */
export function runMaintenance(db: Db, settings: AppSettings, log: Logger): MaintenanceResult {
  const now = Date.now();
  const cutoff = (days: number): string => new Date(now - days * 86_400_000).toISOString();

  const result = db.transaction(() => {
    const scans = pruneScans(db, cutoff(settings.retentionScansDays));
    const alerts = pruneAlerts(db, cutoff(settings.retentionAlertsDays));
    const findings = pruneResolvedFindings(db, cutoff(settings.retentionResolvedFindingsDays));
    const contentFindings = pruneContentFindings(db, cutoff(settings.retentionResolvedFindingsDays));
    const events = db.run('DELETE FROM finding_events WHERE created_at < ?', [cutoff(settings.retentionEventsDays)]).changes;
    const containers = db.run(
      `DELETE FROM containers WHERE present = 0 AND last_seen_at < ?`,
      [cutoff(30)],
    ).changes;
    const images = db.run(
      `DELETE FROM images
       WHERE updated_at < ?
         AND NOT EXISTS (SELECT 1 FROM image_locations l WHERE l.image_id = images.image_id)
         AND NOT EXISTS (SELECT 1 FROM containers c WHERE c.image_id = images.image_id)`,
      [cutoff(30)],
    ).changes;
    db.run(`DELETE FROM sessions WHERE expires_at < ?`, [nowIso()]);
    db.run(`DELETE FROM scans WHERE status = 'queued' AND queued_at < ?`, [cutoff(7)]);
    return { scans, alerts, events, findings, contentFindings, containers, images };
  });

  try {
    db.exec('PRAGMA optimize');
    db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
  } catch {
    // Checkpoint is best effort; it never affects correctness.
  }

  if (
    result.scans +
      result.alerts +
      result.events +
      result.findings +
      result.contentFindings +
      result.containers +
      result.images >
    0
  ) {
    log.info(result, 'retention cleanup completed');
  }
  return result;
}
