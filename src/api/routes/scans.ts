import type { FastifyInstance } from 'fastify';
import type { AppContext } from '../context.ts';
import { conflict, notFound } from '../errors.ts';
import { parseId, parsePagination } from '../http.ts';
import { getScan, listScans, type ScanKind, type ScanStatus } from '../../repo/scans.ts';
import { describeImage } from '../../repo/images.ts';
import { getEnvironment } from '../../repo/environments.ts';
import type { ScanProfile } from '../../scanner/trivy.ts';

const STATUSES = new Set(['queued', 'running', 'success', 'failed', 'cancelled']);

export function registerScanRoutes(app: FastifyInstance, ctx: AppContext): void {
  app.get(
    '/scans',
    {
      schema: {
        querystring: {
          type: 'object',
          additionalProperties: true,
          properties: {
            status: { type: 'string', enum: ['queued', 'running', 'success', 'failed', 'cancelled'] },
            imageId: { type: 'string', maxLength: 100 },
            envId: { type: 'integer', minimum: 1 },
            kind: { type: 'string', enum: ['vulnerability', 'content'] },
            page: { type: 'integer', minimum: 1 },
            pageSize: { type: 'integer', minimum: 1, maximum: 100 },
          },
        },
      },
    },
    async (req) => {
      const query = req.query as {
        status?: string;
        imageId?: string;
        envId?: number;
        kind?: string;
        page?: number;
        pageSize?: number;
      };
      const { page, pageSize } = parsePagination(query.page, query.pageSize);
      const status = query.status && STATUSES.has(query.status) ? (query.status as ScanStatus) : undefined;
      const result = listScans(ctx.db, {
        status,
        imageId: query.imageId,
        environmentId: query.envId,
        kind: query.kind === 'content' ? 'content' : query.kind === 'vulnerability' ? 'vulnerability' : undefined,
        page,
        pageSize,
      });
      return { ...result, page, pageSize };
    },
  );

  app.get('/scans/:id', async (req) => {
    const id = parseId((req.params as { id: string }).id, 'id');
    const scan = getScan(ctx.db, id);
    if (!scan) notFound('Scan not found');
    const environment = scan.environmentId ? getEnvironment(ctx.db, scan.environmentId) : null;
    return {
      scan,
      environment: environment ? { id: environment.id, name: environment.name, status: environment.status } : null,
      image: describeImage(ctx.db, scan.imageId),
    };
  });

  app.post(
    '/scans',
    {
      schema: {
        body: {
          type: 'object',
          additionalProperties: false,
          required: ['imageId'],
          properties: {
            imageId: { type: 'string', minLength: 1, maxLength: 100 },
            profile: { type: 'string', enum: ['quick', 'standard'] },
            kind: { type: 'string', enum: ['vulnerability', 'content'] },
          },
        },
      },
    },
    async (req, reply) => {
      const body = req.body as { imageId: string; profile?: ScanProfile; kind?: ScanKind };
      const result = ctx.coordinator.enqueueManual(
        body.imageId,
        body.profile === 'quick' ? 'quick' : 'standard',
        body.kind === 'content' ? 'content' : 'vulnerability',
      );
      if (!result.queued) conflict(result.message, 'scan_not_queued');
      reply.code(202);
      return { scanId: result.scanId, message: result.message };
    },
  );

  app.post('/scans/:id/cancel', async (req) => {
    const id = parseId((req.params as { id: string }).id, 'id');
    const scan = getScan(ctx.db, id);
    if (!scan) notFound('Scan not found');
    const cancelled = ctx.coordinator.cancel(id);
    if (!cancelled) conflict('Only queued or running scans can be cancelled', 'not_cancellable');
    return { ok: true };
  });
}
