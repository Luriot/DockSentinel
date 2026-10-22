import type { FastifyInstance } from 'fastify';
import type { AppContext } from '../context.ts';
import { notFound } from '../errors.ts';
import { parseBoolean, parseId, parsePagination } from '../http.ts';
import { eventsForFinding, getFinding, listFindings } from '../../repo/findings.ts';
import { getImage } from '../../repo/images.ts';
import { listScans } from '../../repo/scans.ts';
import type { Severity } from '../../domain/severity.ts';

const SEVERITY_VALUES = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']);

function parseSeverities(raw: unknown): Severity[] | undefined {
  if (typeof raw !== 'string' || raw.trim() === '') return undefined;
  const values = raw
    .split(',')
    .map((value) => value.trim().toUpperCase())
    .filter((value) => SEVERITY_VALUES.has(value));
  return values.length > 0 ? (values as Severity[]) : undefined;
}

export function registerFindingRoutes(app: FastifyInstance, ctx: AppContext): void {
  app.get(
    '/findings',
    {
      schema: {
        querystring: {
          type: 'object',
          additionalProperties: true,
          properties: {
            q: { type: 'string', maxLength: 200 },
            severity: { type: 'string', maxLength: 100 },
            envId: { type: 'integer', minimum: 1 },
            imageId: { type: 'string', maxLength: 100 },
            kev: { type: 'boolean' },
            fixable: { type: 'boolean' },
            running: { type: 'boolean' },
            state: { type: 'string', enum: ['open', 'resolved', 'all'] },
            page: { type: 'integer', minimum: 1 },
            pageSize: { type: 'integer', minimum: 1, maximum: 100 },
          },
        },
      },
    },
    async (req) => {
      const query = req.query as {
        q?: string;
        severity?: string;
        envId?: number;
        imageId?: string;
        kev?: boolean;
        fixable?: boolean;
        running?: boolean;
        state?: 'open' | 'resolved' | 'all';
        page?: number;
        pageSize?: number;
      };
      const { page, pageSize } = parsePagination(query.page, query.pageSize);
      const result = listFindings(ctx.db, {
        search: query.q?.trim() || undefined,
        severities: parseSeverities(query.severity),
        environmentId: query.envId,
        imageId: query.imageId,
        kevOnly: parseBoolean(query.kev),
        fixableOnly: parseBoolean(query.fixable),
        runningOnly: parseBoolean(query.running),
        state: query.state ?? 'open',
        page,
        pageSize,
      });
      return { ...result, page, pageSize };
    },
  );

  app.get('/findings/:id', async (req) => {
    const id = parseId((req.params as { id: string }).id, 'id');
    const finding = getFinding(ctx.db, id);
    if (!finding) notFound('Finding not found');
    return {
      finding,
      image: getImage(ctx.db, finding.imageId),
      events: eventsForFinding(ctx.db, id, 50),
      scans: listScans(ctx.db, { imageId: finding.imageId, page: 1, pageSize: 5 }).items,
    };
  });
}
