import type { Db } from '../db/index.ts';
import { nowIso } from '../util/time.ts';

export interface RecoverySummary {
  requeued: number;
  failed: number;
}

/**
 * Scans left "running" by a crash are requeued while they still have retry budget, otherwise they
 * are marked failed. Findings are untouched either way.
 */
export function recoverInterruptedScans(db: Db, maxRetries: number): RecoverySummary {
  const rows = db.all<{ id: number; attempts: number }>(
    `SELECT id, attempts FROM scans WHERE status = 'running'`,
  );
  const summary: RecoverySummary = { requeued: 0, failed: 0 };
  for (const row of rows) {
    if (row.attempts <= maxRetries) {
      db.run(
        `UPDATE scans SET status = 'queued', started_at = NULL, run_after = NULL, attempts = attempts + 1,
           error_code = 'interrupted', error_message = 'Application restarted during the scan; requeued'
         WHERE id = ?`,
        [row.id],
      );
      summary.requeued += 1;
    } else {
      db.run(
        `UPDATE scans SET status = 'failed', finished_at = ?, error_code = 'interrupted',
           error_message = 'Application restarted during the scan and the retry budget was exhausted'
         WHERE id = ?`,
        [nowIso(), row.id],
      );
      summary.failed += 1;
    }
  }
  return summary;
}
