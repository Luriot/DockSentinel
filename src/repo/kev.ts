import type { Db } from '../db/index.ts';
import { nowIso } from '../util/time.ts';
import type { Logger } from '../logger.ts';


export interface KevLookup {
  dateAdded: string | null;
}

export interface KevStatus {
  status: 'idle' | 'ok' | 'error';
  syncedAt: string | null;
  catalogVersion: string | null;
  entryCount: number;
  error: string | null;
  available: boolean;
  stale: boolean;
}

export interface KevSyncResult {
  ok: boolean;
  entryCount: number;
  newlyFlagged: { findingId: number; imageId: string; episode: number }[];
  error: string | null;
}

export function kevIsAvailable(db: Db): boolean {
  const row = db.get<{ entry_count: number | null }>('SELECT entry_count FROM kev_sync WHERE id = 1');
  return (row?.entry_count ?? 0) > 0;
}

export function lookupKev(db: Db, cveId: string): KevLookup | null {
  const row = db.get<{ date_added: string | null }>('SELECT date_added FROM kev WHERE cve_id = ?', [cveId]);
  return row ? { dateAdded: row.date_added } : null;
}

export function getKevStatus(db: Db): KevStatus {
  const row = db.get<{
    status: 'idle' | 'ok' | 'error';
    synced_at: string | null;
    catalog_version: string | null;
    entry_count: number | null;
    error: string | null;
  }>('SELECT status, synced_at, catalog_version, entry_count, error FROM kev_sync WHERE id = 1');
  const syncedAt = row?.synced_at ?? null;
  const stale = syncedAt ? Date.now() - Date.parse(syncedAt) > 7 * 86_400_000 : false;
  return {
    status: row?.status ?? 'idle',
    syncedAt,
    catalogVersion: row?.catalog_version ?? null,
    entryCount: row?.entry_count ?? 0,
    error: row?.error ?? null,
    available: (row?.entry_count ?? 0) > 0,
    stale,
  };
}

const MAX_KEV_BYTES = 8 * 1024 * 1024;

/**
 * Fetches CISA's Known Exploited Vulnerabilities catalog. This is enrichment only: a failure
 * leaves existing KEV data untouched and marks it stale rather than corrupting findings.
 */
export async function syncKev(
  db: Db,
  options: { url: string; log: Logger; fetchImpl?: typeof fetch; now?: string },
): Promise<KevSyncResult> {
  const now = options.now ?? nowIso();
  const fetchImpl = options.fetchImpl ?? fetch;

  try {
    const response = await fetchImpl(options.url, {
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(60_000),
    });
    if (!response.ok) {
      throw new Error(`KEV feed returned HTTP ${response.status}`);
    }
    const raw = await response.text();
    if (raw.length > MAX_KEV_BYTES) throw new Error('KEV feed is larger than the safety limit');
    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('KEV feed is not a JSON object');
    const catalog = parsed as Record<string, unknown>;
    const entries = catalog.vulnerabilities;
    if (!Array.isArray(entries) || entries.length === 0) throw new Error('KEV feed contains no vulnerabilities');

    const valid: { cveId: string; dateAdded: string | null }[] = [];
    for (const entry of entries) {
      if (!entry || typeof entry !== 'object' || Array.isArray(entry)) continue;
      const item = entry as Record<string, unknown>;
      if (typeof item.cveID !== 'string' || !/^CVE-\d{4}-\d{4,}$/i.test(item.cveID)) continue;
      valid.push({
        cveId: item.cveID.toUpperCase(),
        dateAdded: typeof item.dateAdded === 'string' ? item.dateAdded.slice(0, 30) : null,
      });
    }
    if (valid.length === 0) throw new Error('KEV feed contained no usable entries');

    const catalogVersion =
      typeof catalog.catalogVersion === 'string' ? catalog.catalogVersion.slice(0, 40) : null;

    const result = db.transaction(() => {
      // Rows that will become known-exploited need to be compared against the *new* catalog,
      // so compute the set from the incoming data before replacing the table.
      const knownIncoming = new Set(valid.map((entry) => entry.cveId));
      const newlyExploitedIds = db
        .all<{ id: number; image_id: string; episode: number; vuln_id: string }>(
          `SELECT id, image_id, episode, vuln_id FROM findings WHERE resolved_at IS NULL AND kev != 1`,
        )
        .filter((finding) => knownIncoming.has(finding.vuln_id.toUpperCase()))
        .map((finding) => ({ findingId: finding.id, imageId: finding.image_id, episode: finding.episode }));

      db.run('DELETE FROM kev');
      for (const entry of valid) {
        db.run(
          `INSERT INTO kev (cve_id, date_added, synced_at) VALUES (?, ?, ?)
           ON CONFLICT(cve_id) DO UPDATE SET date_added = excluded.date_added, synced_at = excluded.synced_at`,
          [entry.cveId, entry.dateAdded, now],
        );
      }

      db.run(
        `UPDATE findings SET
           kev = 1,
           kev_added_at = (SELECT date_added FROM kev WHERE kev.cve_id = findings.vuln_id)
         WHERE vuln_id IN (SELECT cve_id FROM kev)`,
      );
      db.run(
        `UPDATE findings SET kev = 0, kev_added_at = NULL
         WHERE kev = 1 AND vuln_id NOT IN (SELECT cve_id FROM kev)`,
      );

      db.run(
        `UPDATE kev_sync SET status = 'ok', synced_at = ?, catalog_version = ?, entry_count = ?, error = NULL WHERE id = 1`,
        [now, catalogVersion, valid.length],
      );
      return newlyExploitedIds;
    });

    options.log.info({ entries: valid.length, catalogVersion }, 'CISA KEV catalog synced');
    return { ok: true, entryCount: valid.length, newlyFlagged: result, error: null };
  } catch (error) {
    const message = error instanceof Error ? error.message.slice(0, 300) : 'KEV sync failed';
    db.run(`UPDATE kev_sync SET status = 'error', error = ? WHERE id = 1`, [message]);
    options.log.warn({ error: message }, 'CISA KEV sync failed');
    return { ok: false, entryCount: 0, newlyFlagged: [], error: message };
  }
}
