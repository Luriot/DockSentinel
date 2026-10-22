import type { Db } from '../db/index.ts';
import type { ExposureState } from '../domain/exposure.ts';
import type { NormalizedPort } from '../docker/normalize.ts';

export interface ContainerSummary {
  id: string;
  environmentId: number;
  environmentName: string;
  name: string;
  imageRef: string;
  imageId: string | null;
  state: string;
  running: boolean;
  present: boolean;
  exposure: ExposureState;
  exposureReason: string | null;
  labels: Record<string, string>;
  ports: NormalizedPort[];
  networkMode: string | null;
  createdTs: string | null;
  firstSeenAt: string;
  lastSeenAt: string;
  critical: number;
  high: number;
  fixable: number;
  lastSuccessAt: string | null;
  lastScanStatus: string | null;
}

interface ContainerRow {
  id: string;
  environment_id: number;
  environment_name: string;
  name: string;
  image_ref: string;
  image_id: string | null;
  state: string;
  labels: string;
  ports: string;
  network_mode: string | null;
  exposure_state: ExposureState;
  exposure_reason: string | null;
  created_ts: string | null;
  present: number;
  first_seen_at: string;
  last_seen_at: string;
  critical_count: number | null;
  high_count: number | null;
  fixable_count: number | null;
  last_success_at: string | null;
  last_scan_status: string | null;
}

function mapContainer(row: ContainerRow): ContainerSummary {
  return {
    id: row.id,
    environmentId: row.environment_id,
    environmentName: row.environment_name,
    name: row.name,
    imageRef: row.image_ref,
    imageId: row.image_id,
    state: row.state,
    running: row.state.toLowerCase() === 'running',
    present: row.present === 1,
    exposure: row.exposure_state,
    exposureReason: row.exposure_reason,
    labels: safeParseObject(row.labels),
    ports: safeParsePorts(row.ports),
    networkMode: row.network_mode,
    createdTs: row.created_ts,
    firstSeenAt: row.first_seen_at,
    lastSeenAt: row.last_seen_at,
    critical: row.critical_count ?? 0,
    high: row.high_count ?? 0,
    fixable: row.fixable_count ?? 0,
    lastSuccessAt: row.last_success_at,
    lastScanStatus: row.last_scan_status,
  };
}

function safeParseObject(raw: string): Record<string, string> {
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
    const result: Record<string, string> = {};
    for (const [key, value] of Object.entries(parsed as Record<string, unknown>)) {
      if (typeof value === 'string') result[key] = value;
    }
    return result;
  } catch {
    return {};
  }
}

function safeParsePorts(raw: string): NormalizedPort[] {
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((value): value is NormalizedPort => Boolean(value) && typeof value === 'object');
  } catch {
    return [];
  }
}

const BASE_SELECT = `
  SELECT c.id, c.environment_id, e.name AS environment_name, c.name, c.image_ref, c.image_id, c.state,
         c.labels, c.ports, c.network_mode, c.exposure_state, c.exposure_reason, c.created_ts, c.present,
         c.first_seen_at, c.last_seen_at,
         i.critical_count, i.high_count, i.fixable_count, i.last_success_at, i.last_scan_status
  FROM containers c
  JOIN environments e ON e.id = c.environment_id
  LEFT JOIN images i ON i.image_id = c.image_id`;

export interface ContainerFilters {
  search?: string;
  environmentId?: number;
  exposure?: ExposureState;
  status?: 'running' | 'stopped' | 'all';
  includeRemoved?: boolean;
  page: number;
  pageSize: number;
}

export function listContainers(db: Db, filters: ContainerFilters): { items: ContainerSummary[]; total: number } {
  const conditions: string[] = [];
  const params: (string | number)[] = [];
  if (!filters.includeRemoved) conditions.push('c.present = 1');
  if (filters.environmentId) {
    conditions.push('c.environment_id = ?');
    params.push(filters.environmentId);
  }
  if (filters.status === 'running') conditions.push("c.state = 'running'");
  if (filters.status === 'stopped') conditions.push("c.state <> 'running'");
  if (filters.exposure) {
    conditions.push('c.exposure_state = ?');
    params.push(filters.exposure);
  }
  if (filters.search) {
    conditions.push('(c.name LIKE ? OR c.image_ref LIKE ? OR c.id LIKE ?)');
    const like = `%${filters.search}%`;
    params.push(like, like, like);
  }
  const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  const total = db.get<{ count: number }>(
    `SELECT COUNT(*) AS count FROM containers c ${where}`,
    params,
  )?.count ?? 0;

  const rows = db.all<ContainerRow>(
    `${BASE_SELECT}
     ${where}
     ORDER BY (c.state = 'running') DESC, i.critical_count DESC, i.high_count DESC, c.name COLLATE NOCASE
     LIMIT ? OFFSET ?`,
    [...params, filters.pageSize, (filters.page - 1) * filters.pageSize],
  );
  return { items: rows.map(mapContainer), total };
}

export function listContainersForImage(db: Db, imageId: string): ContainerSummary[] {
  return db
    .all<ContainerRow>(
      `${BASE_SELECT} WHERE c.image_id = ? ORDER BY c.present DESC, (c.state = 'running') DESC, c.name COLLATE NOCASE`,
      [imageId],
    )
    .map(mapContainer);
}

export function getContainer(db: Db, environmentId: number, id: string): ContainerSummary | null {
  const row = db.get<ContainerRow>(`${BASE_SELECT} WHERE c.environment_id = ? AND c.id = ?`, [environmentId, id]);
  return row ? mapContainer(row) : null;
}


