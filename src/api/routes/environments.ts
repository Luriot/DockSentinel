import type { FastifyInstance } from 'fastify';
import type { AppContext } from '../context.ts';
import { ApiError, badRequest, conflict, notFound } from '../errors.ts';
import { parseId } from '../http.ts';
import { parseAddress } from '../../docker/client.ts';
import {
  createEnvironment,
  deleteEnvironment,
  getEnvironment,
  setEnvironmentStatus,
  updateEnvironment,
} from '../../repo/environments.ts';
import { SEVERITIES, type Severity } from '../../domain/severity.ts';

const ENV_SELECT = `
  SELECT e.id, e.name, e.kind, e.status, e.status_message, e.enabled, e.scan_enabled, e.address,
         e.quick_interval_hours, e.standard_interval_hours, e.min_alert_severity, e.tls_skip_verify,
         e.created_at, e.updated_at, e.last_contact_at, e.last_discovery_at,
         (e.tls_cert IS NOT NULL) AS tls,
         (SELECT COUNT(*) FROM containers c WHERE c.environment_id = e.id AND c.present = 1) AS containers,
         (SELECT COUNT(*) FROM containers c WHERE c.environment_id = e.id AND c.present = 1 AND c.state = 'running') AS running_containers,
         (SELECT COUNT(*) FROM image_locations l WHERE l.environment_id = e.id) AS images,
         (SELECT COUNT(DISTINCT f.id) FROM findings f
            WHERE f.resolved_at IS NULL AND f.severity = 'CRITICAL'
              AND EXISTS (SELECT 1 FROM containers c WHERE c.image_id = f.image_id AND c.environment_id = e.id AND c.present = 1)) AS critical,
         (SELECT COUNT(DISTINCT f.id) FROM findings f
            WHERE f.resolved_at IS NULL AND f.severity = 'HIGH'
              AND EXISTS (SELECT 1 FROM containers c WHERE c.image_id = f.image_id AND c.environment_id = e.id AND c.present = 1)) AS high
  FROM environments e`;

interface EnvironmentRow {
  id: number;
  name: string;
  kind: string;
  status: 'unknown' | 'online' | 'offline';
  status_message: string | null;
  enabled: number;
  scan_enabled: number;
  address: string;
  quick_interval_hours: number;
  standard_interval_hours: number;
  min_alert_severity: string;
  tls_skip_verify: number;
  tls: number;
  created_at: string;
  updated_at: string;
  last_contact_at: string | null;
  last_discovery_at: string | null;
  containers: number;
  running_containers: number;
  images: number;
  critical: number;
  high: number;
}

function serialize(row: EnvironmentRow): Record<string, unknown> {
  return {
    id: row.id,
    name: row.name,
    kind: row.kind,
    address: row.address,
    status: row.status,
    statusMessage: row.status_message,
    enabled: row.enabled === 1,
    scanEnabled: row.scan_enabled === 1,
    quickIntervalHours: row.quick_interval_hours,
    standardIntervalHours: row.standard_interval_hours,
    minAlertSeverity: row.min_alert_severity,
    tlsSkipVerify: row.tls_skip_verify === 1,
    hasTls: row.tls === 1,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    lastContactAt: row.last_contact_at,
    lastDiscoveryAt: row.last_discovery_at,
    counts: {
      containers: row.containers,
      runningContainers: row.running_containers,
      images: row.images,
      critical: row.critical,
      high: row.high,
    },
  };
}

function loadRow(ctx: AppContext, id: number): EnvironmentRow | null {
  return ctx.db.get<EnvironmentRow>(`${ENV_SELECT} WHERE e.id = ?`, [id]) ?? null;
}

function checkPem(value: string | null | undefined, label: string): void {
  if (!value) return;
  if (value.length > 120_000) badRequest(`${label} is too large`);
  if (!value.includes('-----BEGIN')) badRequest(`${label} must be PEM encoded`);
}

function validateAddress(kind: string, address: string): void {
  try {
    parseAddress({ kind: kind as 'unix' | 'tcp' | 'tls', address });
  } catch (error) {
    badRequest(error instanceof Error ? error.message : 'Invalid endpoint address');
  }
}

const environmentBodySchema = {
  type: 'object',
  additionalProperties: false,
  properties: {
    name: { type: 'string', minLength: 1, maxLength: 100 },
    kind: { type: 'string', enum: ['unix', 'tcp', 'tls'] },
    address: { type: 'string', minLength: 1, maxLength: 500 },
    tlsCa: { type: ['string', 'null'], maxLength: 120000 },
    tlsCert: { type: ['string', 'null'], maxLength: 120000 },
    tlsKey: { type: ['string', 'null'], maxLength: 120000 },
    tlsSkipVerify: { type: 'boolean' },
    enabled: { type: 'boolean' },
    scanEnabled: { type: 'boolean' },
    quickIntervalHours: { type: 'integer', minimum: 0, maximum: 2160 },
    standardIntervalHours: { type: 'integer', minimum: 0, maximum: 8760 },
    minAlertSeverity: { type: 'string', enum: [...SEVERITIES] },
  },
} as const;

interface EnvironmentBody {
  name?: string;
  kind?: 'unix' | 'tcp' | 'tls';
  address?: string;
  tlsCa?: string | null;
  tlsCert?: string | null;
  tlsKey?: string | null;
  tlsSkipVerify?: boolean;
  enabled?: boolean;
  scanEnabled?: boolean;
  quickIntervalHours?: number;
  standardIntervalHours?: number;
  minAlertSeverity?: Severity;
}

function assertTlsComplete(kind: string, hasCa: boolean, hasCert: boolean, hasKey: boolean, skipVerify: boolean): void {
  if (kind !== 'tls') return;
  if (!hasCert || !hasKey) badRequest('TLS endpoints require a client certificate and key (PEM)');
  if (!hasCa && !skipVerify) {
    badRequest('Provide a CA certificate, or explicitly enable skip-verify for a self-signed endpoint');
  }
}

function sqliteConflict(error: unknown): never {
  const message = error instanceof Error ? error.message : '';
  if (/UNIQUE constraint failed/i.test(message)) conflict('An environment with that name already exists');
  throw error;
}

export function registerEnvironmentRoutes(app: FastifyInstance, ctx: AppContext): void {
  app.get('/environments', async () => ({
    items: ctx.db.all<EnvironmentRow>(`${ENV_SELECT} ORDER BY e.name COLLATE NOCASE`).map(serialize),
  }));

  app.post(
    '/environments',
    { schema: { body: { ...environmentBodySchema, required: ['name', 'kind', 'address'] } } },
    async (req, reply) => {
      const body = req.body as EnvironmentBody;
      const settings = ctx.getSettings();
      const name = body.name?.trim();
      if (!name) badRequest('Environment name is required');
      if (!body.kind || !body.address) badRequest('Endpoint kind and address are required');
      validateAddress(body.kind, body.address);
      checkPem(body.tlsCa, 'CA certificate');
      checkPem(body.tlsCert, 'Client certificate');
      checkPem(body.tlsKey, 'Client key');
      assertTlsComplete(body.kind, Boolean(body.tlsCa), Boolean(body.tlsCert), Boolean(body.tlsKey), Boolean(body.tlsSkipVerify));

      let id: number;
      try {
        id = createEnvironment(
          ctx.db,
          {
            name,
            kind: body.kind,
            address: body.address.trim(),
            tlsCa: body.tlsCa ?? null,
            tlsCert: body.tlsCert ?? null,
            tlsKey: body.tlsKey ?? null,
            tlsSkipVerify: body.tlsSkipVerify ?? false,
            enabled: body.enabled ?? true,
            scanEnabled: body.scanEnabled ?? true,
            quickIntervalHours: body.quickIntervalHours ?? settings.defaultQuickIntervalHours,
            standardIntervalHours: body.standardIntervalHours ?? settings.defaultStandardIntervalHours,
            minAlertSeverity: body.minAlertSeverity ?? settings.minAlertSeverity,
          },
          ctx.config.secretKey,
        );
      } catch (error) {
        sqliteConflict(error);
      }
      ctx.log.info({ environmentId: id, name }, 'environment created');
      reply.code(201);
      return serialize(loadRow(ctx, id)!);
    },
  );

  app.patch('/environments/:id', { schema: { body: environmentBodySchema } }, async (req) => {
    const id = parseId((req.params as { id: string }).id, 'id');
    const current = getEnvironment(ctx.db, id);
    if (!current) notFound('Environment not found');
    const body = req.body as EnvironmentBody;

    const kind = body.kind ?? current.kind;
    const address = (body.address ?? current.address).trim();
    validateAddress(kind, address);
    if (body.name !== undefined && body.name.trim().length === 0) badRequest('Environment name is required');
    checkPem(body.tlsCa, 'CA certificate');
    checkPem(body.tlsCert, 'Client certificate');
    checkPem(body.tlsKey, 'Client key');
    assertTlsComplete(
      kind,
      body.tlsCa === undefined ? Boolean(current.tlsCa) : Boolean(body.tlsCa),
      body.tlsCert === undefined ? Boolean(current.tlsCert) : Boolean(body.tlsCert),
      body.tlsKey === undefined ? Boolean(current.tlsKey) : Boolean(body.tlsKey),
      body.tlsSkipVerify ?? current.tlsSkipVerify,
    );

    try {
      updateEnvironment(
        ctx.db,
        id,
        {
          name: body.name?.trim(),
          kind: body.kind,
          address,
          tlsCa: body.tlsCa,
          tlsCert: body.tlsCert,
          tlsKey: body.tlsKey,
          tlsSkipVerify: body.tlsSkipVerify,
          enabled: body.enabled,
          scanEnabled: body.scanEnabled,
          quickIntervalHours: body.quickIntervalHours,
          standardIntervalHours: body.standardIntervalHours,
          minAlertSeverity: body.minAlertSeverity,
        },
        ctx.config.secretKey,
      );
    } catch (error) {
      sqliteConflict(error);
    }
    if (kind !== current.kind || address !== current.address) setEnvironmentStatus(ctx.db, id, 'unknown', null);
    ctx.log.info({ environmentId: id }, 'environment updated');
    return serialize(loadRow(ctx, id)!);
  });

  app.delete('/environments/:id', async (req) => {
    const id = parseId((req.params as { id: string }).id, 'id');
    const environment = getEnvironment(ctx.db, id);
    if (!environment) notFound('Environment not found');
    const active = ctx.db.get<{ count: number }>(
      `SELECT COUNT(*) AS count FROM scans WHERE environment_id = ? AND status IN ('queued','running')`,
      [id],
    );
    if ((active?.count ?? 0) > 0) {
      conflict('A scan is queued or running for this environment. Cancel or wait for it before deleting.');
    }
    deleteEnvironment(ctx.db, id);
    ctx.log.info({ environmentId: id, name: environment.name }, 'environment deleted');
    return { ok: true };
  });

  app.post('/environments/:id/test', async (req) => {
    const id = parseId((req.params as { id: string }).id, 'id');
    const environment = getEnvironment(ctx.db, id);
    if (!environment) notFound('Environment not found');
    return ctx.discovery.test(environment);
  });

  app.post('/environments/:id/discover', async (req) => {
    const id = parseId((req.params as { id: string }).id, 'id');
    const environment = getEnvironment(ctx.db, id);
    if (!environment) notFound('Environment not found');
    if (!environment.enabled) conflict('Environment is disabled');
    try {
      return await ctx.discovery.discover(environment);
    } catch (error) {
      throw new ApiError(502, 'endpoint_unavailable', error instanceof Error ? error.message : 'Discovery failed');
    }
  });
}
