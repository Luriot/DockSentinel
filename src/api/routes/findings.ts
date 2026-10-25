import type { FastifyInstance } from 'fastify';
import type { AppContext } from '../context.ts';
import { notFound } from '../errors.ts';
import { parseBoolean, parseId, parsePagination } from '../http.ts';
import { eventsForFinding, getFinding, listFindings, listGroupedFindings, refreshImageFindingCounts, setFindingTriage } from '../../repo/findings.ts';
import { getImage } from '../../repo/images.ts';
import { listScans } from '../../repo/scans.ts';
import type { Severity } from '../../domain/severity.ts';
import type { TriageStatus } from '../../domain/findings.ts';

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
            includeSuppressed: { type: 'boolean' },
            includeKernel: { type: 'boolean' },
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
        includeSuppressed?: boolean;
        includeKernel?: boolean;
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
        includeSuppressed: parseBoolean(query.includeSuppressed),
        includeKernel: parseBoolean(query.includeKernel),
        page,
        pageSize,
      });
      return { ...result, page, pageSize };
    },
  );

  app.get(
    '/findings/grouped',
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
            includeSuppressed: { type: 'boolean' },
            includeKernel: { type: 'boolean' },
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
        includeSuppressed?: boolean;
        includeKernel?: boolean;
        page?: number;
        pageSize?: number;
      };
      const { page, pageSize } = parsePagination(query.page, query.pageSize);
      const result = listGroupedFindings(ctx.db, {
        search: query.q?.trim() || undefined,
        severities: parseSeverities(query.severity),
        environmentId: query.envId,
        imageId: query.imageId,
        kevOnly: parseBoolean(query.kev),
        fixableOnly: parseBoolean(query.fixable),
        runningOnly: parseBoolean(query.running),
        state: query.state ?? 'open',
        includeSuppressed: parseBoolean(query.includeSuppressed),
        includeKernel: parseBoolean(query.includeKernel),
        page,
        pageSize,
      });
      return { ...result, page, pageSize };
    },
  );

  app.get(
    '/findings/export',
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
            includeSuppressed: { type: 'boolean' },
            includeKernel: { type: 'boolean' },
            format: { type: 'string', enum: ['csv', 'json'] },
          },
        },
      },
    },
    async (req, reply) => {
      const query = req.query as {
        q?: string;
        severity?: string;
        envId?: number;
        imageId?: string;
        kev?: boolean;
        fixable?: boolean;
        running?: boolean;
        state?: 'open' | 'resolved' | 'all';
        includeSuppressed?: boolean;
        includeKernel?: boolean;
        format?: 'csv' | 'json';
      };
      const result = listFindings(ctx.db, {
        search: query.q?.trim() || undefined,
        severities: parseSeverities(query.severity),
        environmentId: query.envId,
        imageId: query.imageId,
        kevOnly: parseBoolean(query.kev),
        fixableOnly: parseBoolean(query.fixable),
        runningOnly: parseBoolean(query.running),
        state: query.state ?? 'open',
        includeSuppressed: parseBoolean(query.includeSuppressed),
        includeKernel: parseBoolean(query.includeKernel),
        page: 1,
        pageSize: 10_000,
      });
      const rows = result.items.map((finding) => ({
        imageId: finding.imageId,
        image: finding.containers[0]?.imageRef ?? finding.imageId,
        vulnerability: finding.vulnId,
        title: finding.title,
        package: finding.pkgName,
        installedVersion: finding.installedVersion,
        fixedVersion: finding.fixedVersion,
        severity: finding.severity,
        knownExploited: finding.kev,
        priorityTier: finding.priority.tier,
        priorityScore: finding.priority.score,
        containers: finding.containers.map((container) => container.name).join('; '),
        firstSeenAt: finding.firstSeenAt,
        lastSeenAt: finding.lastSeenAt,
        triageStatus: finding.triageStatus,
        triageNote: finding.triageNote,
        target: finding.target,
      }));
      if ((query.format ?? 'csv') === 'json') {
        reply.header('Content-Disposition', 'attachment; filename="docksentinel-findings.json"');
        return reply.type('application/json; charset=utf-8').send(JSON.stringify(rows, null, 2));
      }
      const header = Object.keys(rows[0] ?? {
        imageId: '', image: '', vulnerability: '', title: '', package: '', installedVersion: '', fixedVersion: '', severity: '',
        knownExploited: '', priorityTier: '', priorityScore: '', containers: '', firstSeenAt: '', lastSeenAt: '',
        triageStatus: '', triageNote: '', target: '',
      });
      const cell = (value: unknown): string => {
        let text = value === null || value === undefined ? '' : String(value);
        if (/^[=+\-@]/.test(text)) text = `'${text}`;
        return `"${text.replace(/"/g, '""')}"`;
      };
      const csv = [header.join(','), ...rows.map((row) => header.map((key) => cell((row as Record<string, unknown>)[key])).join(','))].join('\r\n');
      reply.header('Content-Disposition', 'attachment; filename="docksentinel-findings.csv"');
      return reply.type('text/csv; charset=utf-8').send(csv);
    },
  );

  app.patch(
    '/findings/:id/triage',
    {
      schema: {
        body: {
          type: 'object',
          additionalProperties: false,
          required: ['status'],
          properties: {
            status: { type: 'string', enum: ['none', 'acknowledged', 'ignored', 'false_positive'] },
            note: { type: ['string', 'null'], maxLength: 500 },
          },
        },
      },
    },
    async (req) => {
      const id = parseId((req.params as { id: string }).id, 'id');
      const body = req.body as { status: TriageStatus; note?: string | null };
      const updated = setFindingTriage(ctx.db, id, body.status, body.note?.trim() || null, new Date().toISOString());
      if (!updated) notFound('Finding not found');
      refreshImageFindingCounts(ctx.db, updated.imageId);
      return { finding: getFinding(ctx.db, id) };
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
