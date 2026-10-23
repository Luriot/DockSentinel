import type { Db } from '../db/index.ts';
import type { Severity } from '../domain/severity.ts';
import {
  contentIdentity,
  countContentSeverities,
  type ContentFindingRecord,
  type ContentKind,
  type ContentScope,
  type NormalizedContentFinding,
} from '../domain/content.ts';

interface ContentFindingRow {
  id: number;
  image_id: string;
  kind: ContentKind;
  scope: ContentScope;
  identity: string;
  rule_id: string;
  category: string | null;
  severity: Severity;
  title: string;
  target: string;
  message: string | null;
  resolution: string | null;
  primary_url: string | null;
  start_line: number | null;
  end_line: number | null;
  episode: number;
  first_seen_at: string;
  last_seen_at: string;
  last_scan_id: number | null;
  resolved_at: string | null;
}

function mapContentFinding(row: ContentFindingRow): ContentFindingRecord {
  return {
    id: row.id,
    imageId: row.image_id,
    kind: row.kind,
    scope: row.scope,
    ruleId: row.rule_id,
    category: row.category,
    severity: row.severity,
    title: row.title,
    target: row.target,
    message: row.message,
    resolution: row.resolution,
    primaryUrl: row.primary_url,
    startLine: row.start_line,
    endLine: row.end_line,
    episode: row.episode,
    firstSeenAt: row.first_seen_at,
    lastSeenAt: row.last_seen_at,
    lastScanId: row.last_scan_id,
    resolvedAt: row.resolved_at,
  };
}

export interface ApplyContentOutcome {
  appeared: NormalizedContentFinding[];
  resolved: ContentFindingRecord[];
  counts: ReturnType<typeof countContentSeverities>;
}

/**
 * Applies a successful content scan. Only a successfully parsed report may resolve findings;
 * failed or incomplete scans never call this function. Secret values are never stored.
 */
export function applyContentFindings(
  db: Db,
  input: { imageId: string; scanId: number; findings: NormalizedContentFinding[]; now: string },
): ApplyContentOutcome {
  const unique = new Map<string, NormalizedContentFinding>();
  for (const finding of input.findings) unique.set(contentIdentity(finding), finding);

  const existing = db.all<ContentFindingRow>('SELECT * FROM content_findings WHERE image_id = ?', [input.imageId]);
  const byIdentity = new Map(existing.map((row) => [row.identity, row]));
  const seen = new Set<string>();
  const appeared: NormalizedContentFinding[] = [];

  for (const [identity, finding] of unique) {
    seen.add(identity);
    const row = byIdentity.get(identity);
    if (!row) {
      db.run(
        `INSERT INTO content_findings
          (image_id, kind, scope, identity, rule_id, category, severity, title, target, message, resolution,
           primary_url, start_line, end_line, episode, first_seen_at, last_seen_at, last_scan_id, resolved_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, NULL)`,
        [
          input.imageId,
          finding.kind,
          finding.scope,
          identity,
          finding.ruleId,
          finding.category,
          finding.severity,
          finding.title,
          finding.target,
          finding.message,
          finding.resolution,
          finding.primaryUrl,
          finding.startLine,
          finding.endLine,
          input.now,
          input.now,
          input.scanId,
        ],
      );
      appeared.push(finding);
      continue;
    }

    const reactivated = row.resolved_at !== null;
    if (reactivated) appeared.push(finding);
    db.run(
      `UPDATE content_findings SET
         kind = ?, scope = ?, rule_id = ?, category = ?, severity = ?, title = ?, target = ?, message = ?,
         resolution = ?, primary_url = ?, start_line = ?, end_line = ?, episode = ?,
         first_seen_at = ?, last_seen_at = ?, last_scan_id = ?, resolved_at = NULL
       WHERE id = ?`,
      [
        finding.kind,
        finding.scope,
        finding.ruleId,
        finding.category,
        finding.severity,
        finding.title,
        finding.target,
        finding.message,
        finding.resolution,
        finding.primaryUrl,
        finding.startLine,
        finding.endLine,
        reactivated ? row.episode + 1 : row.episode,
        reactivated ? input.now : row.first_seen_at,
        input.now,
        input.scanId,
        row.id,
      ],
    );
  }

  const resolved: ContentFindingRecord[] = [];
  for (const row of existing) {
    if (row.resolved_at !== null || seen.has(row.identity)) continue;
    db.run('UPDATE content_findings SET resolved_at = ? WHERE id = ?', [input.now, row.id]);
    resolved.push(mapContentFinding({ ...row, resolved_at: input.now }));
  }

  return { appeared, resolved, counts: countContentSeverities([...unique.values()]) };
}

export interface ContentFilters {
  imageId?: string;
  kind?: ContentKind;
  severity?: Severity;
  state?: 'open' | 'resolved' | 'all';
  search?: string;
  page: number;
  pageSize: number;
}

export function listContentFindings(
  db: Db,
  filters: ContentFilters,
): { items: ContentFindingRecord[]; total: number; counts: Record<Severity, number>; byKind: Record<ContentKind, number> } {
  const conditions: string[] = [];
  const params: (string | number)[] = [];
  if (filters.imageId) {
    conditions.push('c.image_id = ?');
    params.push(filters.imageId);
  }
  if (filters.kind) {
    conditions.push('c.kind = ?');
    params.push(filters.kind);
  }
  if (filters.severity) {
    conditions.push('c.severity = ?');
    params.push(filters.severity);
  }
  if (filters.search) {
    conditions.push('(c.target LIKE ? OR c.title LIKE ? OR c.rule_id LIKE ?)');
    const term = `%${filters.search}%`;
    params.push(term, term, term);
  }
  if (filters.state === 'resolved') conditions.push('c.resolved_at IS NOT NULL');
  else if (filters.state !== 'all') conditions.push('c.resolved_at IS NULL');

  const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  const total = db.get<{ count: number }>(`SELECT COUNT(*) AS count FROM content_findings c ${where}`, params)?.count ?? 0;
  const countRow =
    db.get<Record<string, number>>(
      `SELECT
         SUM(CASE WHEN c.severity = 'CRITICAL' THEN 1 ELSE 0 END) AS CRITICAL,
         SUM(CASE WHEN c.severity = 'HIGH' THEN 1 ELSE 0 END) AS HIGH,
         SUM(CASE WHEN c.severity = 'MEDIUM' THEN 1 ELSE 0 END) AS MEDIUM,
         SUM(CASE WHEN c.severity = 'LOW' THEN 1 ELSE 0 END) AS LOW,
         SUM(CASE WHEN c.severity = 'UNKNOWN' THEN 1 ELSE 0 END) AS UNKNOWN
       FROM content_findings c ${where}`,
      params,
    ) ?? {};
  const kindRow =
    db.get<Record<string, number>>(
      `SELECT
         SUM(CASE WHEN c.kind = 'misconfiguration' THEN 1 ELSE 0 END) AS misconfiguration,
         SUM(CASE WHEN c.kind = 'secret' THEN 1 ELSE 0 END) AS secret
       FROM content_findings c ${where}`,
      params,
    ) ?? {};

  const rows = db.all<ContentFindingRow>(
    `SELECT c.* FROM content_findings c
     ${where}
     ORDER BY CASE c.severity
       WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END DESC,
       c.last_seen_at DESC, c.id DESC
     LIMIT ? OFFSET ?`,
    [...params, filters.pageSize, (filters.page - 1) * filters.pageSize],
  );

  return {
    items: rows.map(mapContentFinding),
    total,
    counts: {
      CRITICAL: Number(countRow.CRITICAL ?? 0),
      HIGH: Number(countRow.HIGH ?? 0),
      MEDIUM: Number(countRow.MEDIUM ?? 0),
      LOW: Number(countRow.LOW ?? 0),
      UNKNOWN: Number(countRow.UNKNOWN ?? 0),
    },
    byKind: {
      misconfiguration: Number(kindRow.misconfiguration ?? 0),
      secret: Number(kindRow.secret ?? 0),
    },
  };
}

export function pruneContentFindings(db: Db, cutoff: string): number {
  return db.run('DELETE FROM content_findings WHERE resolved_at IS NOT NULL AND resolved_at < ?', [cutoff]).changes;
}
