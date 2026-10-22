import type { Db } from '../../src/db/index.ts';
import {
  applyScanFindings,
  type ApplyScanOutcome,
} from '../../src/repo/findings.ts';
import {
  getScan,
  markScanSuccess,
  queueScan,
  type ScanRecord,
} from '../../src/repo/scans.ts';
import { updateImageAfterScan } from '../../src/repo/images.ts';
import { nowIso } from '../../src/util/time.ts';

export interface SeedScanOptions {
  imageId: string;
  environmentId: number;
  imageRef?: string;
  findings: import('../../src/domain/findings.ts').NormalizedFinding[];
  profile?: 'quick' | 'standard';
  finishedAt?: string;
}

/** Creates a completed successful scan directly, without spawning a scanner. */
export function seedSuccessfulScan(
  db: Db,
  options: SeedScanOptions,
): { scan: ScanRecord; outcome: ApplyScanOutcome } {
  const scanId = queueScan(
    db,
    {
      environmentId: options.environmentId,
      imageId: options.imageId,
      imageRef: options.imageRef ?? 'docksentinel-test:1',
      profile: options.profile ?? 'standard',
      trigger: 'manual',
    },
    false,
  );
  if (scanId === null) throw new Error('unable to create test scan');
  db.run(`UPDATE scans SET status = 'running', started_at = ? WHERE id = ?`, [nowIso(), scanId]);

  const outcome = db.transaction(() => {
    const applied = applyScanFindings(db, {
      imageId: options.imageId,
      scanId,
      findings: options.findings,
      now: options.finishedAt ?? nowIso(),
    });
    markScanSuccess(db, scanId, {
      environmentId: options.environmentId,
      durationMs: 1234,
      scannerVersion: '0.75.0-test',
      dbVersion: '2',
      dbUpdatedAt: '2026-01-01T00:00:00.000Z',
      counts: applied.counts,
      exitCode: 0,
      warnings: [],
    });
    updateImageAfterScan(db, options.imageId, scanId, 'success', applied.counts, options.environmentId, {
      family: 'debian',
      version: '11.7',
    });
    return applied;
  });

  const scan = getScan(db, scanId);
  if (!scan) throw new Error('test scan vanished');
  return { scan, outcome };
}
