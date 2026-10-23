import type { FastifyInstance } from 'fastify';
import type { AppContext } from '../context.ts';
import { notFound } from '../errors.ts';
import { parseBoolean, parseId, parsePagination } from '../http.ts';
import { buildOverview } from '../../repo/overview.ts';
import { listImages, getImage } from '../../repo/images.ts';
import { listContainers, getContainer, listContainersForImage } from '../../repo/containers.ts';
import { listFindings, listFindingEvents } from '../../repo/findings.ts';
import { listScans } from '../../repo/scans.ts';
import { isoAfter } from '../../util/time.ts';
import type { ExposureState } from '../../domain/exposure.ts';
import type { ScanProfile } from '../../scanner/trivy.ts';

function parseExposure(value: unknown): ExposureState | undefined {
  if (typeof value !== 'string') return undefined;
  return ['confirmed', 'potential', 'internal', 'unknown'].includes(value) ? (value as ExposureState) : undefined;
}

function parseProfile(value: unknown): ScanProfile {
  return value === 'quick' ? 'quick' : 'standard';
}

export function registerInventoryRoutes(app: FastifyInstance, ctx: AppContext): void {
  app.get('/overview', async () => {
    const settings = ctx.getSettings();
    return {
      ...buildOverview(ctx.db, settings),
    };
  });

  app.get(
    '/images',
    {
      schema: {
        querystring: {
          type: 'object',
          additionalProperties: true,
          properties: {
            q: { type: 'string', maxLength: 200 },
            envId: { type: 'integer', minimum: 1 },
            minSeverity: { type: 'string', enum: ['critical', 'high'] },
            neverScanned: { type: 'boolean' },
            stale: { type: 'boolean' },
            page: { type: 'integer', minimum: 1 },
            pageSize: { type: 'integer', minimum: 1, maximum: 100 },
          },
        },
      },
    },
    async (req) => {
      const query = req.query as {
        q?: string;
        envId?: number;
        minSeverity?: 'critical' | 'high';
        neverScanned?: boolean;
        stale?: boolean;
        page?: number;
        pageSize?: number;
      };
      const { page, pageSize } = parsePagination(query.page, query.pageSize);
      const settings = ctx.getSettings();
      const result = listImages(ctx.db, {
        search: query.q?.trim() || undefined,
        environmentId: query.envId,
        minCritical: query.minSeverity === 'critical',
        minHigh: query.minSeverity === 'high',
        neverScanned: query.neverScanned === true,
        staleBefore: query.stale === true ? isoAfter(-settings.freshnessHours * 3_600_000) : null,
        page,
        pageSize,
      });
      return { ...result, page, pageSize };
    },
  );

  app.get('/images/:imageId', async (req) => {
    const imageId = (req.params as { imageId: string }).imageId;
    const image = getImage(ctx.db, imageId);
    if (!image) notFound('Image not found');
    const findings = listFindings(ctx.db, { imageId, page: 1, pageSize: 10, state: 'open' });
    return {
      image,
      containers: listContainersForImage(ctx.db, imageId),
      findings: findings.items,
      findingCounts: findings.counts,
      totalFindings: findings.total,
      scans: listScans(ctx.db, { imageId, page: 1, pageSize: 8 }).items,
      events: listFindingEvents(ctx.db, imageId, 15),
    };
  });

  app.post(
    '/images/:imageId/scan',
    {
      schema: {
        body: {
          type: 'object',
          additionalProperties: false,
          properties: { profile: { type: 'string', enum: ['quick', 'standard'] } },
        },
      },
    },
    async (req, reply) => {
      const imageId = (req.params as { imageId: string }).imageId;
      const body = (req.body ?? {}) as { profile?: ScanProfile };
      const result = ctx.coordinator.enqueueManual(imageId, parseProfile(body.profile));
      if (!result.queued) {
        reply.code(409);
        return { error: { code: 'scan_not_queued', message: result.message } };
      }
      reply.code(202);
      return { scanId: result.scanId, message: result.message };
    },
  );

  app.get(
    '/containers',
    {
      schema: {
        querystring: {
          type: 'object',
          additionalProperties: true,
          properties: {
            q: { type: 'string', maxLength: 200 },
            envId: { type: 'integer', minimum: 1 },
            status: { type: 'string', enum: ['running', 'stopped', 'all'] },
            exposure: { type: 'string', enum: ['confirmed', 'potential', 'internal', 'unknown'] },
            includeRemoved: { type: 'boolean' },
            page: { type: 'integer', minimum: 1 },
            pageSize: { type: 'integer', minimum: 1, maximum: 100 },
          },
        },
      },
    },
    async (req) => {
      const query = req.query as {
        q?: string;
        envId?: number;
        status?: 'running' | 'stopped' | 'all';
        exposure?: string;
        includeRemoved?: boolean;
        page?: number;
        pageSize?: number;
      };
      const { page, pageSize } = parsePagination(query.page, query.pageSize);
      const result = listContainers(ctx.db, {
        search: query.q?.trim() || undefined,
        environmentId: query.envId,
        status: query.status ?? 'all',
        exposure: parseExposure(query.exposure),
        includeRemoved: parseBoolean(query.includeRemoved),
        page,
        pageSize,
      });
      return { ...result, page, pageSize };
    },
  );

  app.get('/containers/:environmentId/:id', async (req) => {
    const params = req.params as { environmentId: string; id: string };
    const environmentId = parseId(params.environmentId, 'environmentId');
    const container = getContainer(ctx.db, environmentId, params.id);
    if (!container) notFound('Container not found');

    const image = container.imageId ? getImage(ctx.db, container.imageId) : null;
    const findings = container.imageId
      ? listFindings(ctx.db, { imageId: container.imageId, page: 1, pageSize: 10, state: 'open' })
      : { items: [], total: 0, counts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 } };

    return {
      container,
      image,
      findings: findings.items,
      findingCounts: findings.counts,
      totalFindings: findings.total,
      scans: container.imageId ? listScans(ctx.db, { imageId: container.imageId, page: 1, pageSize: 5 }).items : [],
    };
  });
}
