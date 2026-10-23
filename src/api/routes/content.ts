import type { FastifyInstance } from 'fastify';
import type { AppContext } from '../context.ts';
import { parsePagination } from '../http.ts';
import { listContentFindings, type ContentFilters } from '../../repo/content.ts';
import { describeImage } from '../../repo/images.ts';
import type { Severity } from '../../domain/severity.ts';
import type { ContentKind } from '../../domain/content.ts';

const SEVERITIES = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']);

export function registerContentRoutes(app: FastifyInstance, ctx: AppContext): void {
  app.get(
    '/content-findings',
    {
      schema: {
        querystring: {
          type: 'object',
          additionalProperties: true,
          properties: {
            imageId: { type: 'string', maxLength: 100 },
            kind: { type: 'string', enum: ['misconfiguration', 'secret'] },
            severity: { type: 'string', enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'] },
            state: { type: 'string', enum: ['open', 'resolved', 'all'] },
            q: { type: 'string', maxLength: 200 },
            page: { type: 'integer', minimum: 1 },
            pageSize: { type: 'integer', minimum: 1, maximum: 100 },
          },
        },
      },
    },
    async (req) => {
      const query = req.query as {
        imageId?: string;
        kind?: string;
        severity?: string;
        state?: string;
        q?: string;
        page?: number;
        pageSize?: number;
      };
      const { page, pageSize } = parsePagination(query.page, query.pageSize);
      const filters: ContentFilters = {
        imageId: query.imageId,
        kind: query.kind as ContentKind | undefined,
        severity: query.severity && SEVERITIES.has(query.severity) ? (query.severity as Severity) : undefined,
        state: query.state === 'resolved' || query.state === 'all' ? query.state : 'open',
        search: query.q?.trim() || undefined,
        page,
        pageSize,
      };
      const result = listContentFindings(ctx.db, filters);
      const imageRefs = new Map<string, string>();
      for (const item of result.items) {
        if (!imageRefs.has(item.imageId)) imageRefs.set(item.imageId, describeImage(ctx.db, item.imageId).displayRef);
      }
      return {
        ...result,
        items: result.items.map((item) => ({ ...item, imageRef: imageRefs.get(item.imageId) ?? 'unknown image' })),
        page,
        pageSize,
      };
    },
  );
}
