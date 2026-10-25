import type { Db } from '../db/index.ts';
import type { NormalizedFinding, StoredFinding, TriageStatus } from '../domain/findings.ts';
import { countSeverities, diffFindings, type FindingChange } from '../domain/findings.ts';
import { normalizeSeverity, type Severity } from '../domain/severity.ts';
import { isKernelPackage, nonKernelPackageSql } from '../domain/packages.ts';
import { parseWorkloadLabels } from '../domain/policy.ts';
import type { ExposureState } from '../domain/exposure.ts';
import { prioritiseFinding, type PriorityResult } from '../domain/priority.ts';
import type { ContainerSummary } from './containers.ts';
import { listContainersForImage } from './containers.ts';
import { kevIsAvailable, lookupKev } from './kev.ts';

export interface FindingRecord {
  id: number;
  imageId: string;
  target: string;
  class: string | null;
  type: string | null;
  vulnId: string;
  pkgName: string;
  installedVersion: string;
  fixedVersion: string | null;
  severity: Severity;
  status: string | null;
  title: string | null;
  primaryUrl: string | null;
  cvssScore: number | null;
  cvssSource: string | null;
  cvssVector: string | null;
  publishedAt: string | null;
  modifiedAt: string | null;
  kev: -1 | 0 | 1;
  kevAddedAt: string | null;
  episode: number;
  firstSeenAt: string;
  lastSeenAt: string;
  lastScanId: number | null;
  resolvedAt: string | null;
  triageStatus: TriageStatus;
  triageNote: string | null;
  triagedAt: string | null;
}

interface FindingRow {
  id: number;
  image_id: string;
  target: string;
  class: string | null;
  type: string | null;
  vuln_id: string;
  pkg_name: string;
  installed_version: string;
  fixed_version: string | null;
  severity: string;
  status: string | null;
  title: string | null;
  primary_url: string | null;
  cvss_score: number | null;
  cvss_source: string | null;
  cvss_vector: string | null;
  published_at: string | null;
  modified_at: string | null;
  kev: number;
  kev_added_at: string | null;
  episode: number;
  first_seen_at: string;
  last_seen_at: string;
  last_scan_id: number | null;
  resolved_at: string | null;
  triage_status: TriageStatus;
  triage_note: string | null;
  triaged_at: string | null;
}

function mapFinding(row: FindingRow): FindingRecord {
  return {
    id: row.id,
    imageId: row.image_id,
    target: row.target,
    class: row.class,
    type: row.type,
    vulnId: row.vuln_id,
    pkgName: row.pkg_name,
    installedVersion: row.installed_version,
    fixedVersion: row.fixed_version,
    severity: normalizeSeverity(row.severity),
    status: row.status,
    title: row.title,
    primaryUrl: row.primary_url,
    cvssScore: row.cvss_score,
    cvssSource: row.cvss_source,
    cvssVector: row.cvss_vector,
    publishedAt: row.published_at,
    modifiedAt: row.modified_at,
    kev: row.kev === 1 ? 1 : row.kev === 0 ? 0 : -1,
    kevAddedAt: row.kev_added_at,
    episode: row.episode,
    firstSeenAt: row.first_seen_at,
    lastSeenAt: row.last_seen_at,
    lastScanId: row.last_scan_id,
    resolvedAt: row.resolved_at,
    triageStatus: row.triage_status,
    triageNote: row.triage_note,
    triagedAt: row.triaged_at,
  };
}

export interface FindingView extends FindingRecord {
  priority: PriorityResult;
  containers: ContainerSummary[];
  containerCount: number;
  runningContainerCount: number;
  environmentNames: string[];
  exposure: ExposureState | null;
}

function exposureFromState(states: ExposureState[]): ExposureState | null {
  if (states.length === 0) return null;
  if (states.includes('confirmed')) return 'confirmed';
  if (states.includes('potential')) return 'potential';
  if (states.includes('internal')) return 'internal';
  return 'unknown';
}

export function enhanceFinding(finding: FindingRecord, containers: ContainerSummary[]): FindingView {
  const running = containers.some((container) => container.running);
  const exposure = exposureFromState(containers.map((container) => container.exposure));
  let criticality: 'critical' | 'high' | 'normal' | 'low' | null = null;
  for (const container of containers) {
    const policy = parseWorkloadLabels(container.labels);
    if (!policy.criticality) continue;
    if (policy.criticality === 'critical') criticality = 'critical';
    else if (policy.criticality === 'high' && criticality !== 'critical') criticality = 'high';
    else if (policy.criticality === 'normal' && !criticality) criticality = 'normal';
    else if (policy.criticality === 'low' && !criticality) criticality = 'low';
  }
  const priority = prioritiseFinding({
    severity: finding.severity,
    kev: finding.kev,
    hasFix: Boolean(finding.fixedVersion),
    running,
    exposure: exposure ?? 'unknown',
    criticality,
  });
  return {
    ...finding,
    priority,
    containers,
    containerCount: containers.filter((container) => container.present).length,
    runningContainerCount: containers.filter((container) => container.present && container.running).length,
    environmentNames: [...new Set(containers.map((container) => container.environmentName))],
    exposure,
  };
}

export interface ApplyScanOutcome {
  appeared: { finding: NormalizedFinding; id: number; episode: number }[];
  resolved: StoredFinding[];
  changed: FindingChange[];
  counts: ReturnType<typeof countSeverities>;
}

/**
 * Applies a successful scan inside the caller's transaction. Findings are keyed by image ID and
 * identity; a finding missing from a successful report is resolved, never inferred from a failure.
 * A quick profile only reports OS packages, so `osOnly` keeps its older language findings attached
 * instead of resolving packages the scan never looked at.
 */
export function applyScanFindings(
  db: Db,
  input: { imageId: string; scanId: number; findings: NormalizedFinding[]; now: string; osOnly?: boolean },
): ApplyScanOutcome {
  const previous = db
    .all<{
      id: number;
      target: string;
      vuln_id: string;
      pkg_name: string;
      installed_version: string;
      fixed_version: string | null;
      severity: string;
      title: string | null;
      primary_url: string | null;
      episode: number;
    }>(
      `SELECT id, target, vuln_id, pkg_name, installed_version, fixed_version, severity, title, primary_url, episode
       FROM findings WHERE image_id = ? AND resolved_at IS NULL${input.osOnly ? " AND class = 'os-pkgs'" : ''}`,
      [input.imageId],
    )
    .map((row) => ({
      id: row.id,
      target: row.target,
      vulnId: row.vuln_id,
      pkgName: row.pkg_name,
      installedVersion: row.installed_version,
      fixedVersion: row.fixed_version,
      severity: normalizeSeverity(row.severity),
      title: row.title,
      primaryUrl: row.primary_url,
      episode: row.episode,
    }));

  const diff = diffFindings(previous, input.findings);
  const kevAvailable = kevIsAvailable(db);
  const appeared: ApplyScanOutcome['appeared'] = [];

  for (const finding of diff.appeared) {
    const kev = kevAvailable ? lookupKev(db, finding.vulnId) : null;
    const existing = db.get<{ id: number; episode: number; resolved_at: string | null }>(
      `SELECT id, episode, resolved_at FROM findings
       WHERE image_id = ? AND target = ? AND vuln_id = ? AND pkg_name = ? AND installed_version = ?`,
      [input.imageId, finding.target, finding.vulnId, finding.pkgName, finding.installedVersion],
    );
    if (existing && existing.resolved_at) {
      const nextEpisode = existing.episode + 1;
      db.run(
        `UPDATE findings SET severity = ?, status = ?, title = ?, primary_url = ?, fixed_version = ?, class = ?, type = ?,
           cvss_score = ?, cvss_source = ?, cvss_vector = ?, published_at = ?, modified_at = ?,
           kev = ?, kev_added_at = ?, episode = ?, first_seen_at = ?, last_seen_at = ?,
           last_scan_id = ?, resolved_at = NULL
         WHERE id = ?`,
        [
          normalizeSeverity(finding.severity),
          finding.status,
          finding.title,
          finding.primaryUrl,
          finding.fixedVersion,
          finding.class,
          finding.type,
          finding.cvssScore,
          finding.cvssSource,
          finding.cvssVector,
          finding.publishedAt,
          finding.modifiedAt,
          kevAvailable ? (kev ? 1 : 0) : -1,
          kev?.dateAdded ?? null,
          nextEpisode,
          input.now,
          input.now,
          input.scanId,
          existing.id,
        ],
      );
      db.run(
        `INSERT INTO finding_events (finding_id, scan_id, image_id, kind, detail, created_at)
         VALUES (?, ?, ?, 'reappeared', ?, ?)`,
        [existing.id, input.scanId, input.imageId, JSON.stringify({ severity: finding.severity }), input.now],
      );
      appeared.push({ finding, id: existing.id, episode: nextEpisode });
      continue;
    }

    const inserted = db.run(
      `INSERT INTO findings
        (image_id, target, class, type, vuln_id, pkg_name, installed_version, fixed_version, severity, status,
         title, primary_url, cvss_score, cvss_source, cvss_vector, published_at, modified_at,
         kev, kev_added_at, episode, first_seen_at, last_seen_at, last_scan_id, resolved_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, NULL)`,
      [
        input.imageId,
        finding.target,
        finding.class,
        finding.type,
        finding.vulnId,
        finding.pkgName,
        finding.installedVersion,
        finding.fixedVersion,
        normalizeSeverity(finding.severity),
        finding.status,
        finding.title,
        finding.primaryUrl,
        finding.cvssScore,
        finding.cvssSource,
        finding.cvssVector,
        finding.publishedAt,
        finding.modifiedAt,
        kevAvailable ? (kev ? 1 : 0) : -1,
        kev?.dateAdded ?? null,
        input.now,
        input.now,
        input.scanId,
      ],
    );
    db.run(
      `INSERT INTO finding_events (finding_id, scan_id, image_id, kind, detail, created_at)
       VALUES (?, ?, ?, 'appeared', ?, ?)`,
      [
        inserted.lastInsertRowid,
        input.scanId,
        input.imageId,
        JSON.stringify({ severity: normalizeSeverity(finding.severity), fixedVersion: finding.fixedVersion }),
        input.now,
      ],
    );
    appeared.push({ finding, id: inserted.lastInsertRowid, episode: 1 });
  }

  for (const change of diff.changed) {
    const finding = input.findings.find(
      (candidate) =>
        candidate.target === change.finding.target &&
        candidate.vulnId === change.finding.vulnId &&
        candidate.pkgName === change.finding.pkgName &&
        candidate.installedVersion === change.finding.installedVersion,
    );
    if (!finding) continue;
    const kev = kevAvailable ? lookupKev(db, finding.vulnId) : null;
    db.run(
      `UPDATE findings SET severity = ?, fixed_version = ?, status = ?, title = ?, primary_url = ?,
         cvss_score = ?, cvss_source = ?, cvss_vector = ?, published_at = ?, modified_at = ?,
         kev = ?, kev_added_at = ?, last_seen_at = ?, last_scan_id = ?
       WHERE id = ?`,
      [
        normalizeSeverity(finding.severity),
        finding.fixedVersion,
        finding.status,
        finding.title,
        finding.primaryUrl,
        finding.cvssScore,
        finding.cvssSource,
        finding.cvssVector,
        finding.publishedAt,
        finding.modifiedAt,
        kevAvailable ? (kev ? 1 : 0) : -1,
        kev?.dateAdded ?? null,
        input.now,
        input.scanId,
        change.finding.id,
      ],
    );
    db.run(
      `INSERT INTO finding_events (finding_id, scan_id, image_id, kind, detail, created_at)
       VALUES (?, ?, ?, 'changed', ?, ?)`,
      [change.finding.id, input.scanId, input.imageId, JSON.stringify(change.changes), input.now],
    );
  }

  for (const finding of diff.unchanged) {
    const kev = kevAvailable ? lookupKev(db, finding.vulnId) : null;
    db.run(
      `UPDATE findings SET last_seen_at = ?, last_scan_id = ?,
         kev = ?, kev_added_at = ?,
         cvss_score = COALESCE(?, cvss_score), title = COALESCE(?, title), primary_url = COALESCE(?, primary_url)
       WHERE id = (
         SELECT id FROM findings
         WHERE image_id = ? AND target = ? AND vuln_id = ? AND pkg_name = ? AND installed_version = ? AND resolved_at IS NULL
       )`,
      [
        input.now,
        input.scanId,
        kevAvailable ? (kev ? 1 : 0) : -1,
        kev?.dateAdded ?? null,
        finding.cvssScore,
        finding.title,
        finding.primaryUrl,
        input.imageId,
        finding.target,
        finding.vulnId,
        finding.pkgName,
        finding.installedVersion,
      ],
    );
  }

  for (const resolved of diff.resolved) {
    db.run('UPDATE findings SET resolved_at = ?, last_scan_id = ? WHERE id = ?', [
      input.now,
      input.scanId,
      resolved.id,
    ]);
    db.run(
      `INSERT INTO finding_events (finding_id, scan_id, image_id, kind, detail, created_at)
       VALUES (?, ?, ?, 'resolved', ?, ?)`,
      [
        resolved.id,
        input.scanId,
        input.imageId,
        JSON.stringify({ severity: resolved.severity, title: resolved.title }),
        input.now,
      ],
    );
  }

  return {
    appeared,
    resolved: diff.resolved,
    changed: diff.changed,
    counts: countSeverities(input.findings.filter((finding) => !isKernelPackage(finding.pkgName))),
  };
}

export interface FindingFilters {
  search?: string;
  severities?: Severity[];
  imageId?: string;
  environmentId?: number;
  kevOnly?: boolean;
  fixableOnly?: boolean;
  runningOnly?: boolean;
  state?: 'open' | 'resolved' | 'all';
  includeSuppressed?: boolean;
  /** Kernel/header packages are hidden unless explicitly requested. */
  includeKernel?: boolean;
  page: number;
  pageSize: number;
}

const SEVERITY_ORDER_SQL = `CASE f.severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END`;

function severityFromRank(rank: number): Severity {
  return rank >= 4 ? 'CRITICAL' : rank === 3 ? 'HIGH' : rank === 2 ? 'MEDIUM' : rank === 1 ? 'LOW' : 'UNKNOWN';
}

function buildFindingConditions(filters: FindingFilters): {
  conditions: string[];
  params: (string | number)[];
} {
  const conditions: string[] = [];
  const params: (string | number)[] = [];
  const state = filters.state ?? 'open';
  if (state === 'open') conditions.push('f.resolved_at IS NULL');
  if (state === 'resolved') conditions.push('f.resolved_at IS NOT NULL');
  if (!filters.includeSuppressed) conditions.push("f.triage_status NOT IN ('ignored','false_positive')");
  if (!filters.includeKernel) conditions.push(nonKernelPackageSql('f.pkg_name'));
  if (filters.imageId) {
    conditions.push('f.image_id = ?');
    params.push(filters.imageId);
  }
  if (filters.severities && filters.severities.length > 0) {
    conditions.push(`f.severity IN (${filters.severities.map(() => '?').join(',')})`);
    params.push(...filters.severities);
  }
  if (filters.kevOnly) conditions.push('f.kev = 1');
  if (filters.fixableOnly) conditions.push("f.fixed_version IS NOT NULL AND f.fixed_version <> ''");
  if (filters.runningOnly) {
    conditions.push(
      'EXISTS (SELECT 1 FROM containers c WHERE c.image_id = f.image_id AND c.present = 1 AND c.state = \'running\')',
    );
  }
  if (filters.environmentId) {
    conditions.push(
      'EXISTS (SELECT 1 FROM containers c WHERE c.image_id = f.image_id AND c.present = 1 AND c.environment_id = ?)',
    );
    params.push(filters.environmentId);
  }
  if (filters.search) {
    conditions.push(
      `(f.vuln_id LIKE ? OR f.pkg_name LIKE ? OR f.title LIKE ? OR f.image_id LIKE ? OR
        EXISTS (SELECT 1 FROM image_locations l WHERE l.image_id = f.image_id AND l.reference LIKE ?))`,
    );
    const like = `%${filters.search}%`;
    params.push(like, like, like, like, like);
  }
  return { conditions, params };
}

function countFindings(
  db: Db,
  where: string,
  params: (string | number)[],
): Record<Severity, number> {
  const counts = db.get<Record<Severity, number>>(
    `SELECT
       SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) AS CRITICAL,
       SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) AS HIGH,
       SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END) AS MEDIUM,
       SUM(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END) AS LOW,
       SUM(CASE WHEN severity = 'UNKNOWN' THEN 1 ELSE 0 END) AS UNKNOWN
     FROM findings f ${where}`,
    params,
  ) ?? { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
  return {
    CRITICAL: Number(counts.CRITICAL ?? 0),
    HIGH: Number(counts.HIGH ?? 0),
    MEDIUM: Number(counts.MEDIUM ?? 0),
    LOW: Number(counts.LOW ?? 0),
    UNKNOWN: Number(counts.UNKNOWN ?? 0),
  };
}

export function listFindings(
  db: Db,
  filters: FindingFilters,
): { items: FindingView[]; total: number; counts: Record<Severity, number> } {
  const { conditions, params } = buildFindingConditions(filters);
  const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

  const total = db.get<{ count: number }>(`SELECT COUNT(*) AS count FROM findings f ${where}`, params)?.count ?? 0;
  const counts = countFindings(db, where, params);

  const rows = db.all<FindingRow>(
    `SELECT f.* FROM findings f
     ${where}
     ORDER BY ${SEVERITY_ORDER_SQL} DESC, f.kev DESC,
       (f.fixed_version IS NOT NULL AND f.fixed_version <> '') DESC,
       EXISTS (SELECT 1 FROM containers c WHERE c.image_id = f.image_id AND c.present = 1 AND c.state = 'running') DESC,
       f.last_seen_at DESC
     LIMIT ? OFFSET ?`,
    [...params, filters.pageSize, (filters.page - 1) * filters.pageSize],
  );

  const containerCache = new Map<string, ContainerSummary[]>();
  const items = rows.map((row) => {
    const finding = mapFinding(row);
    let containers = containerCache.get(row.image_id);
    if (!containers) {
      containers = listContainersForImage(db, row.image_id);
      containerCache.set(row.image_id, containers);
    }
    return enhanceFinding(finding, containers);
  });

  return { items, total, counts };
}

export interface GroupedFinding {
  vulnId: string;
  pkgName: string;
  severity: Severity;
  title: string | null;
  primaryUrl: string | null;
  kev: number;
  fixable: number;
  images: number;
  targets: number;
  findings: number;
  lastSeenAt: string;
}

/**
 * One row per vulnerability + package across images, so a CVE touching 48 images is one line.
 * `targets` exposes how many Trivy targets reported it (Go binaries often duplicate a package).
 */
export function listGroupedFindings(
  db: Db,
  filters: FindingFilters,
): { items: GroupedFinding[]; total: number; counts: Record<Severity, number> } {
  const { conditions, params } = buildFindingConditions(filters);
  const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  const total =
    db.get<{ count: number }>(
      `SELECT COUNT(*) AS count FROM (
         SELECT 1 FROM findings f ${where} GROUP BY f.vuln_id, f.pkg_name
       )`,
      params,
    )?.count ?? 0;
  const counts = countFindings(db, where, params);
  const rows = db.all<{
    vuln_id: string;
    pkg_name: string;
    rank: number;
    title: string | null;
    primary_url: string | null;
    kev: number;
    fixable: number;
    images: number;
    targets: number;
    findings: number;
    last_seen_at: string;
  }>(
    `SELECT f.vuln_id, f.pkg_name,
       MAX(${SEVERITY_ORDER_SQL}) AS rank,
       MAX(f.title) AS title,
       MAX(f.primary_url) AS primary_url,
       MAX(f.kev) AS kev,
       SUM(CASE WHEN f.fixed_version IS NOT NULL AND f.fixed_version <> '' THEN 1 ELSE 0 END) AS fixable,
       COUNT(DISTINCT f.image_id) AS images,
       COUNT(DISTINCT f.target) AS targets,
       COUNT(*) AS findings,
       MAX(f.last_seen_at) AS last_seen_at
     FROM findings f ${where}
     GROUP BY f.vuln_id, f.pkg_name
     ORDER BY rank DESC, kev DESC, images DESC, findings DESC
     LIMIT ? OFFSET ?`,
    [...params, filters.pageSize, (filters.page - 1) * filters.pageSize],
  );

  return {
    total,
    counts,
    items: rows.map((row) => ({
      vulnId: row.vuln_id,
      pkgName: row.pkg_name,
      severity: severityFromRank(row.rank),
      title: row.title,
      primaryUrl: row.primary_url,
      kev: row.kev,
      fixable: row.fixable,
      images: row.images,
      targets: row.targets,
      findings: row.findings,
      lastSeenAt: row.last_seen_at,
    })),
  };
}

export function refreshImageFindingCounts(db: Db, imageId: string): void {
  const kernel = nonKernelPackageSql('findings.pkg_name');
  db.run(
    `UPDATE images SET
       critical_count = (SELECT COUNT(*) FROM findings WHERE image_id = images.image_id AND resolved_at IS NULL AND triage_status NOT IN ('ignored','false_positive') AND severity = 'CRITICAL' AND ${kernel}),
       high_count = (SELECT COUNT(*) FROM findings WHERE image_id = images.image_id AND resolved_at IS NULL AND triage_status NOT IN ('ignored','false_positive') AND severity = 'HIGH' AND ${kernel}),
       medium_count = (SELECT COUNT(*) FROM findings WHERE image_id = images.image_id AND resolved_at IS NULL AND triage_status NOT IN ('ignored','false_positive') AND severity = 'MEDIUM' AND ${kernel}),
       low_count = (SELECT COUNT(*) FROM findings WHERE image_id = images.image_id AND resolved_at IS NULL AND triage_status NOT IN ('ignored','false_positive') AND severity = 'LOW' AND ${kernel}),
       unknown_count = (SELECT COUNT(*) FROM findings WHERE image_id = images.image_id AND resolved_at IS NULL AND triage_status NOT IN ('ignored','false_positive') AND severity = 'UNKNOWN' AND ${kernel}),
       fixable_count = (SELECT COUNT(*) FROM findings WHERE image_id = images.image_id AND resolved_at IS NULL AND triage_status NOT IN ('ignored','false_positive') AND fixed_version IS NOT NULL AND fixed_version <> '' AND ${kernel})
     WHERE image_id = ?`,
    [imageId],
  );
}

/** Recomputes materialized counters after the kernel-package policy arrives with an upgrade. */
export function refreshAllImageFindingCounts(db: Db): number {
  const images = db.all<{ image_id: string }>('SELECT image_id FROM images');
  for (const image of images) refreshImageFindingCounts(db, image.image_id);
  return images.length;
}

/** Deletes every finding of the given packages (ignored packages) and reports affected images. */
export function purgeIgnoredFindings(db: Db, packageNames: readonly string[]): { removed: number; images: string[] } {
  if (packageNames.length === 0) return { removed: 0, images: [] };
  const placeholders = packageNames.map(() => '?').join(',');
  const images = db
    .all<{ image_id: string }>(
      `SELECT DISTINCT image_id FROM findings WHERE pkg_name COLLATE NOCASE IN (${placeholders})`,
      packageNames,
    )
    .map((row) => row.image_id);
  const removed = db.run(`DELETE FROM findings WHERE pkg_name COLLATE NOCASE IN (${placeholders})`, packageNames).changes;
  return { removed, images };
}

export function setFindingTriage(
  db: Db,
  id: number,
  status: TriageStatus,
  note: string | null,
  now: string,
): FindingRecord | null {
  const row = db.get<FindingRow>('SELECT * FROM findings WHERE id = ?', [id]);
  if (!row) return null;
  db.run(
    `UPDATE findings SET triage_status = ?, triage_note = ?, triaged_at = ? WHERE id = ?`,
    [status, status === 'none' ? null : note, status === 'none' ? null : now, id],
  );
  return mapFinding({ ...row, triage_status: status, triage_note: status === 'none' ? null : note, triaged_at: status === 'none' ? null : now });
}

export function getFinding(db: Db, id: number): FindingView | null {
  const row = db.get<FindingRow>('SELECT * FROM findings WHERE id = ?', [id]);
  if (!row) return null;
  return enhanceFinding(mapFinding(row), listContainersForImage(db, row.image_id));
}

export function findingsByIds(db: Db, ids: number[]): FindingRecord[] {
  if (ids.length === 0) return [];
  const placeholders = ids.map(() => '?').join(',');
  return db.all<FindingRow>(`SELECT * FROM findings WHERE id IN (${placeholders})`, ids).map(mapFinding);
}

export function eventsForFinding(db: Db, findingId: number, limit = 50): FindingEventView[] {
  return db
    .all<{
      id: number;
      kind: string;
      detail: string | null;
      created_at: string;
      scan_id: number | null;
      vuln_id: string;
      pkg_name: string;
      severity: string;
    }>(
      `SELECT e.id, e.kind, e.detail, e.created_at, e.scan_id, f.vuln_id, f.pkg_name, f.severity
       FROM finding_events e JOIN findings f ON f.id = e.finding_id
       WHERE e.finding_id = ? ORDER BY e.created_at DESC LIMIT ?`,
      [findingId, limit],
    )
    .map((row) => ({
      id: row.id,
      kind: row.kind,
      detail: row.detail,
      createdAt: row.created_at,
      scanId: row.scan_id,
      vulnId: row.vuln_id,
      pkgName: row.pkg_name,
      severity: row.severity,
    }));
}

export interface FindingEventView {
  id: number;
  kind: string;
  detail: string | null;
  createdAt: string;
  scanId: number | null;
  vulnId: string;
  pkgName: string;
  severity: string;
}

export function listFindingEvents(db: Db, imageId: string, limit = 100): FindingEventView[] {
  return db.all<{
    id: number;
    kind: string;
    detail: string | null;
    created_at: string;
    scan_id: number | null;
    vuln_id: string;
    pkg_name: string;
    severity: string;
  }>(
     `SELECT e.id, e.kind, e.detail, e.created_at, e.scan_id, f.vuln_id, f.pkg_name, f.severity
      FROM finding_events e JOIN findings f ON f.id = e.finding_id
      WHERE e.image_id = ? AND ${nonKernelPackageSql('f.pkg_name')}
      ORDER BY e.created_at DESC LIMIT ?`,
    [imageId, limit],
  ).map((row) => ({
    id: row.id,
    kind: row.kind,
    detail: row.detail,
    createdAt: row.created_at,
    scanId: row.scan_id,
    vulnId: row.vuln_id,
    pkgName: row.pkg_name,
    severity: row.severity,
  }));
}

export function recentFindingEvents(db: Db, limit = 20): (FindingEventView & { imageId: string; imageRef: string | null })[] {
  return db
    .all<{
      id: number;
      kind: string;
      detail: string | null;
      created_at: string;
      scan_id: number | null;
      vuln_id: string;
      pkg_name: string;
      severity: string;
      image_id: string;
      image_ref: string | null;
    }>(
      `SELECT e.id, e.kind, e.detail, e.created_at, e.scan_id, f.vuln_id, f.pkg_name, f.severity, e.image_id,
              (SELECT l.reference FROM image_locations l WHERE l.image_id = e.image_id AND l.tag IS NOT NULL
               ORDER BY l.last_seen_at DESC LIMIT 1) AS image_ref
       FROM finding_events e JOIN findings f ON f.id = e.finding_id
       WHERE ${nonKernelPackageSql('f.pkg_name')}
       ORDER BY e.created_at DESC LIMIT ?`,
      [limit],
    )
    .map((row) => ({
      id: row.id,
      kind: row.kind,
      detail: row.detail,
      createdAt: row.created_at,
      scanId: row.scan_id,
      vulnId: row.vuln_id,
      pkgName: row.pkg_name,
      severity: row.severity,
      imageId: row.image_id,
      imageRef: row.image_ref,
    }));
}

/** Findings older than the retention window whose image is no longer running anywhere. */
export function pruneResolvedFindings(db: Db, cutoff: string): number {
  const result = db.run(
    `DELETE FROM findings WHERE resolved_at IS NOT NULL AND resolved_at < ?
       AND NOT EXISTS (SELECT 1 FROM containers c WHERE c.image_id = findings.image_id AND c.present = 1)`,
    [cutoff],
  );
  return result.changes;
}
