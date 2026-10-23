import type { Db } from '../db/index.ts';
import { nowIso } from '../util/time.ts';
import type { NormalizedContainer, NormalizedImage } from '../docker/normalize.ts';
import type { SeverityCounts } from '../domain/findings.ts';

export interface ImageReference {
  environmentId: number;
  environmentName: string;
  reference: string;
  tag: string | null;
}

export interface ImageSummary {
  imageId: string;
  repoDigests: string[];
  osFamily: string | null;
  osVersion: string | null;
  sizeBytes: number | null;
  createdTs: string | null;
  firstSeenAt: string;
  lastScanAt: string | null;
  lastScanStatus: string | null;
  lastSuccessAt: string | null;
  lastSuccessScanId: number | null;
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
  fixable: number;
  containerCount: number;
  runningContainerCount: number;
  environmentCount: number;
  references: ImageReference[];
}

interface ImageRow {
  image_id: string;
  repo_digests: string;
  size_bytes: number | null;
  os_family: string | null;
  os_version: string | null;
  created_ts: string | null;
  first_seen_at: string;
  last_scan_at: string | null;
  last_scan_status: string | null;
  last_success_at: string | null;
  last_success_scan_id: number | null;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  unknown_count: number;
  fixable_count: number;
  container_count: number;
  running_count: number;
  env_count: number;
}


export function upsertImage(db: Db, image: NormalizedImage, now: string, trustDigests: boolean): void {
  db.run(
    `INSERT INTO images (image_id, repo_digests, size_bytes, created_ts, first_seen_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(image_id) DO UPDATE SET
       repo_digests = CASE WHEN ? = 1 THEN excluded.repo_digests ELSE images.repo_digests END,
       size_bytes = COALESCE(excluded.size_bytes, images.size_bytes),
       created_ts = COALESCE(images.created_ts, excluded.created_ts),
       updated_at = excluded.updated_at`,
    [
      image.imageId,
      JSON.stringify(image.repoDigests),
      image.sizeBytes,
      image.createdTs,
      now,
      now,
      trustDigests ? 1 : 0,
    ],
  );
}

export function ensureImageFromContainer(db: Db, imageId: string, now: string): void {
  db.run(
    `INSERT INTO images (image_id, repo_digests, first_seen_at, updated_at)
     VALUES (?, '[]', ?, ?)
     ON CONFLICT(image_id) DO UPDATE SET updated_at = excluded.updated_at`,
    [imageId, now, now],
  );
}

export function replaceImageLocations(db: Db, environmentId: number, now: string, images: NormalizedImage[]): void {
  db.run('DELETE FROM image_locations WHERE environment_id = ?', [environmentId]);
  for (const image of images) {
    const seen = new Set<string>();
    const entries: { reference: string; tag: string | null }[] = [];
    for (const tag of image.repoTags) entries.push({ reference: tag, tag });
    for (const digest of image.repoDigests) entries.push({ reference: digest, tag: null });
    if (entries.length === 0) entries.push({ reference: image.imageId, tag: null });
    for (const entry of entries) {
      if (seen.has(entry.reference)) continue;
      seen.add(entry.reference);
      db.run(
        `INSERT OR IGNORE INTO image_locations (image_id, environment_id, reference, tag, last_seen_at)
         VALUES (?, ?, ?, ?, ?)`,
        [image.imageId, environmentId, entry.reference.slice(0, 400), entry.tag?.slice(0, 300) ?? null, now],
      );
    }
  }
}


export function updateImageAfterScan(
  db: Db,
  imageId: string,
  scanId: number | null,
  status: 'success' | 'failed' | 'cancelled',
  counts: SeverityCounts | null,
  os: { family: string | null; version: string | null } | null,
): void {
  const now = nowIso();
  if (status === 'success' && counts) {
    db.run(
      `UPDATE images SET
         last_scan_at = ?, last_scan_status = 'success', last_success_at = ?, last_success_scan_id = ?,
         critical_count = ?, high_count = ?, medium_count = ?, low_count = ?, unknown_count = ?, fixable_count = ?,
         os_family = COALESCE(?, os_family), os_version = COALESCE(?, os_version), updated_at = ?
       WHERE image_id = ?`,
      [
        now,
        now,
        scanId,
        counts.CRITICAL,
        counts.HIGH,
        counts.MEDIUM,
        counts.LOW,
        counts.UNKNOWN,
        counts.FIXABLE,
        os?.family ?? null,
        os?.version ?? null,
        now,
        imageId,
      ],
    );
    return;
  }
  db.run('UPDATE images SET last_scan_at = ?, last_scan_status = ?, updated_at = ? WHERE image_id = ?', [
    now,
    status,
    now,
    imageId,
  ]);
}

export interface ImageFilters {
  search?: string;
  imageId?: string;
  environmentId?: number;
  minCritical?: boolean;
  minHigh?: boolean;
  neverScanned?: boolean;
  staleBefore?: string | null;
  page: number;
  pageSize: number;
}

export function listImages(db: Db, filters: ImageFilters): { items: ImageSummary[]; total: number } {
  const conditions: string[] = [];
  const params: (string | number)[] = [];
  if (filters.imageId) {
    conditions.push('i.image_id = ?');
    params.push(filters.imageId);
  }
  if (filters.search) {
    conditions.push(
      `(i.image_id LIKE ? OR i.repo_digests LIKE ? OR EXISTS (SELECT 1 FROM image_locations l WHERE l.image_id = i.image_id AND l.reference LIKE ?))`,
    );
    const like = `%${filters.search}%`;
    params.push(like, like, like);
  }
  if (filters.environmentId) {
    conditions.push('EXISTS (SELECT 1 FROM image_locations l WHERE l.image_id = i.image_id AND l.environment_id = ?)');
    params.push(filters.environmentId);
  }
  if (filters.minCritical) conditions.push('i.critical_count > 0');
  if (filters.minHigh) conditions.push('i.high_count > 0');
  if (filters.neverScanned) conditions.push('i.last_success_at IS NULL');
  if (filters.staleBefore) {
    conditions.push('(i.last_success_at IS NULL OR i.last_success_at < ?)');
    params.push(filters.staleBefore);
  }
  const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  const total =
    db.get<{ count: number }>(`SELECT COUNT(*) AS count FROM images i ${where}`, params)?.count ?? 0;

  const rows = db.all<ImageRow>(
    `SELECT i.image_id, i.repo_digests, i.size_bytes, i.os_family, i.os_version, i.created_ts, i.first_seen_at,
            i.last_scan_at, i.last_scan_status, i.last_success_at, i.last_success_scan_id,
            i.critical_count, i.high_count, i.medium_count, i.low_count, i.unknown_count, i.fixable_count,
            (SELECT COUNT(*) FROM containers c WHERE c.image_id = i.image_id AND c.present = 1) AS container_count,
            (SELECT COUNT(*) FROM containers c WHERE c.image_id = i.image_id AND c.present = 1 AND c.state = 'running') AS running_count,
            (SELECT COUNT(DISTINCT environment_id) FROM image_locations l WHERE l.image_id = i.image_id) AS env_count
     FROM images i
     ${where}
     ORDER BY i.critical_count DESC, i.high_count DESC, (i.last_success_at IS NULL) DESC, i.updated_at DESC
     LIMIT ? OFFSET ?`,
    [...params, filters.pageSize, (filters.page - 1) * filters.pageSize],
  );

  const ids = rows.map((row) => row.image_id);
  const referencesByImage = new Map<string, ImageReference[]>();
  if (ids.length > 0) {
    const placeholders = ids.map(() => '?').join(',');
    const refs = db.all<{
      image_id: string;
      environment_id: number;
      environment_name: string;
      reference: string;
      tag: string | null;
    }>(
      `SELECT l.image_id, l.environment_id, e.name AS environment_name, l.reference, l.tag
       FROM image_locations l JOIN environments e ON e.id = l.environment_id
       WHERE l.image_id IN (${placeholders})
       ORDER BY l.tag IS NULL, l.reference`,
      ids,
    );
    for (const ref of refs) {
      const list = referencesByImage.get(ref.image_id) ?? [];
      list.push({
        environmentId: ref.environment_id,
        environmentName: ref.environment_name,
        reference: ref.reference,
        tag: ref.tag,
      });
      referencesByImage.set(ref.image_id, list);
    }
  }

  const items = rows.map((row) => ({
    imageId: row.image_id,
    repoDigests: safeParseStringArray(row.repo_digests),
    osFamily: row.os_family,
    osVersion: row.os_version,
    sizeBytes: row.size_bytes,
    createdTs: row.created_ts,
    firstSeenAt: row.first_seen_at,
    lastScanAt: row.last_scan_at,
    lastScanStatus: row.last_scan_status,
    lastSuccessAt: row.last_success_at,
    lastSuccessScanId: row.last_success_scan_id,
    critical: row.critical_count,
    high: row.high_count,
    medium: row.medium_count,
    low: row.low_count,
    unknown: row.unknown_count,
    fixable: row.fixable_count,
    containerCount: row.container_count,
    runningContainerCount: row.running_count,
    environmentCount: row.env_count,
    references: referencesByImage.get(row.image_id) ?? [],
  }));
  return { items, total };
}

export function getImage(db: Db, imageId: string): ImageSummary | null {
  return listImages(db, { imageId, page: 1, pageSize: 1 }).items[0] ?? null;
}

export function safeParseStringArray(raw: string | null | undefined): string[] {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw) as unknown;
    return Array.isArray(parsed) ? parsed.filter((value): value is string => typeof value === 'string') : [];
  } catch {
    return [];
  }
}

export interface ImageDisplay {
  imageId: string;
  displayRef: string;
  references: { reference: string; tag: string | null; environmentName: string }[];
}

/** Human-friendly image naming used in alerts and detail views. */
export function describeImage(db: Db, imageId: string): ImageDisplay {
  const rows = db.all<{ reference: string; tag: string | null; environment_name: string }>(
    `SELECT l.reference, l.tag, e.name AS environment_name
     FROM image_locations l JOIN environments e ON e.id = l.environment_id
     WHERE l.image_id = ? ORDER BY l.tag IS NULL, l.last_seen_at DESC`,
    [imageId],
  );
  const firstTag = rows.find((row) => row.tag);
  const displayRef = firstTag?.tag ?? rows[0]?.reference ?? `${imageId.slice(0, 19)}…`;
  return {
    imageId,
    displayRef,
    references: rows.map((row) => ({
      reference: row.reference,
      tag: row.tag,
      environmentName: row.environment_name,
    })),
  };
}


export function listScanEnvironments(db: Db, imageId: string): number[] {
  return db
    .all<{ environment_id: number }>(
      `SELECT DISTINCT l.environment_id
       FROM image_locations l JOIN environments e ON e.id = l.environment_id
       WHERE l.image_id = ? AND e.enabled = 1 AND e.scan_enabled = 1
       ORDER BY (e.status = 'online') DESC, e.id`,
      [imageId],
    )
    .map((row) => row.environment_id);
}


export function syncContainers(
  db: Db,
  environmentId: number,
  containers: NormalizedContainer[],
  startedAt: string,
): { inserted: number; updated: number } {
  let inserted = 0;
  let updated = 0;
  for (const container of containers) {
    const existing = db.get<{ id: string }>(
      'SELECT id FROM containers WHERE environment_id = ? AND id = ?',
      [environmentId, container.id],
    );
    db.run(
      `INSERT INTO containers
        (id, environment_id, name, image_ref, image_id, state, labels, ports, network_mode,
         exposure_state, exposure_reason, created_ts, present, first_seen_at, last_seen_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
       ON CONFLICT(environment_id, id) DO UPDATE SET
         name = excluded.name, image_ref = excluded.image_ref, image_id = excluded.image_id,
         state = excluded.state, labels = excluded.labels, ports = excluded.ports,
         network_mode = excluded.network_mode, exposure_state = excluded.exposure_state,
         exposure_reason = excluded.exposure_reason, created_ts = COALESCE(containers.created_ts, excluded.created_ts),
         present = 1, last_seen_at = excluded.last_seen_at`,
      [
        container.id,
        environmentId,
        container.name,
        container.imageRef,
        container.imageId,
        container.state,
        JSON.stringify(container.labels),
        JSON.stringify(container.ports),
        container.networkMode,
        container.exposureState,
        container.exposureReason,
        container.createdTs,
        startedAt,
        startedAt,
      ],
    );
    if (existing) updated += 1;
    else inserted += 1;
  }

  db.run('UPDATE containers SET present = 0 WHERE environment_id = ? AND last_seen_at < ?', [
    environmentId,
    startedAt,
  ]);
  return { inserted, updated };
}
