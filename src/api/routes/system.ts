import type { FastifyInstance } from 'fastify';
import type { AppContext } from '../context.ts';
import { badRequest } from '../errors.ts';
import { parsePagination } from '../http.ts';
import {
  isValidTopic,
  loadSettings,
  saveSettings,
  toPublicSettings,
  type AppSettings,
  type NtfyAuthType,
  type NtfyPriority,
} from '../../repo/settings.ts';
import { validateNtfySettings } from '../../notify/ntfy.ts';
import { alertStatusCounts, listAlerts, type AlertKind, type AlertStatus } from '../../repo/alerts.ts';
import { getScannerInfo } from '../../scanner/info.ts';
import { SCHEMA_VERSION } from '../../db/migrations.ts';
import { scanStatusCounts } from '../../repo/scans.ts';
import { isoAfter } from '../../util/time.ts';

interface NtfyPatch {
  enabled?: boolean;
  baseUrl?: string;
  topic?: string;
  priority?: NtfyPriority;
  tags?: string;
  authType?: NtfyAuthType;
  username?: string;
  token?: string | null;
  password?: string | null;
}

interface SettingsPatch {
  scanConcurrency?: number;
  discoveryIntervalMinutes?: number;
  defaultQuickIntervalHours?: number;
  defaultStandardIntervalHours?: number;
  freshnessHours?: number;
  minAlertSeverity?: AppSettings['minAlertSeverity'];
  alertOnNew?: boolean;
  alertOnResolved?: boolean;
  alertOnKev?: boolean;
  alertOnScanFailure?: boolean;
  alertOnStale?: boolean;
  scanFailureRetries?: number;
  scanOnDiscovery?: boolean;
  retentionScansDays?: number;
  retentionAlertsDays?: number;
  retentionResolvedFindingsDays?: number;
  retentionEventsDays?: number;
  publicUrl?: string;
  kevEnabled?: boolean;
  misconfigScanEnabled?: boolean;
  secretScanEnabled?: boolean;
  ntfy?: NtfyPatch;
}

const settingsSchema = {
  type: 'object',
  additionalProperties: false,
  properties: {
    scanConcurrency: { type: 'integer', minimum: 1, maximum: 8 },
    discoveryIntervalMinutes: { type: 'integer', minimum: 1, maximum: 1440 },
    defaultQuickIntervalHours: { type: 'integer', minimum: 0, maximum: 2160 },
    defaultStandardIntervalHours: { type: 'integer', minimum: 0, maximum: 8760 },
    freshnessHours: { type: 'integer', minimum: 1, maximum: 720 },
    minAlertSeverity: { type: 'string', enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'] },
    alertOnNew: { type: 'boolean' },
    alertOnResolved: { type: 'boolean' },
    alertOnKev: { type: 'boolean' },
    alertOnScanFailure: { type: 'boolean' },
    alertOnStale: { type: 'boolean' },
    scanFailureRetries: { type: 'integer', minimum: 0, maximum: 5 },
    scanOnDiscovery: { type: 'boolean' },
    retentionScansDays: { type: 'integer', minimum: 7, maximum: 3650 },
    retentionAlertsDays: { type: 'integer', minimum: 7, maximum: 3650 },
    retentionResolvedFindingsDays: { type: 'integer', minimum: 30, maximum: 3650 },
    retentionEventsDays: { type: 'integer', minimum: 30, maximum: 3650 },
    publicUrl: { type: 'string', maxLength: 500 },
    kevEnabled: { type: 'boolean' },
    misconfigScanEnabled: { type: 'boolean' },
    secretScanEnabled: { type: 'boolean' },
    ntfy: {
      type: 'object',
      additionalProperties: false,
      properties: {
        enabled: { type: 'boolean' },
        baseUrl: { type: 'string', maxLength: 500 },
        topic: { type: 'string', maxLength: 64 },
        priority: { type: 'string', enum: ['min', 'low', 'default', 'high', 'urgent', 'max'] },
        tags: { type: 'string', maxLength: 200 },
        authType: { type: 'string', enum: ['none', 'basic', 'token'] },
        username: { type: 'string', maxLength: 200 },
        token: { type: ['string', 'null'], maxLength: 500 },
        password: { type: ['string', 'null'], maxLength: 500 },
      },
    },
  },
} as const;

function stripUndefined<T extends Record<string, unknown>>(value: T): Partial<T> {
  const result: Partial<T> = {};
  for (const [key, entry] of Object.entries(value)) {
    if (entry !== undefined) (result as Record<string, unknown>)[key] = entry;
  }
  return result;
}

function validatePublicUrl(value: string): void {
  if (!value) return;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return badRequest('Public base URL is not a valid URL');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') badRequest('Public base URL must use http or https');
}

export function registerSystemRoutes(app: FastifyInstance, ctx: AppContext): void {
  const api = async (): Promise<Record<string, unknown>> => {
    const settings = ctx.getSettings();
    return {
      settings: toPublicSettings(settings),
      kev: ctx.kev.status(),
      scanner: await getScannerInfo(ctx.config),
    };
  };

  app.get('/settings', async () => api());

  app.patch('/settings', { schema: { body: settingsSchema } }, async (req) => {
    const patch = req.body as SettingsPatch;
    const current = loadSettings(ctx.db, ctx.config.secretKey);
    const { ntfy: ntfyPatch, ...topLevel } = patch;
    const next: AppSettings = {
      ...current,
      ...stripUndefined(topLevel as Record<string, unknown>),
      ntfy: { ...current.ntfy, ...stripUndefined((ntfyPatch ?? {}) as Record<string, unknown>) },
    };

    if (next.publicUrl) validatePublicUrl(next.publicUrl);
    if (next.ntfy.topic && !isValidTopic(next.ntfy.topic)) {
      badRequest('ntfy topic must be 1-64 characters: letters, numbers, dash or underscore');
    }
    const ntfyError = validateNtfySettings(next.ntfy);
    if (next.ntfy.enabled && ntfyError) badRequest(ntfyError);

    saveSettings(ctx.db, ctx.config.secretKey, next);
    ctx.log.info({ keys: Object.keys(patch) }, 'settings updated');
    return api();
  });

  app.get(
    '/notifications',
    {
      schema: {
        querystring: {
          type: 'object',
          additionalProperties: true,
          properties: {
            status: { type: 'string', enum: ['pending', 'sending', 'sent', 'failed'] },
            kind: { type: 'string', maxLength: 40 },
            page: { type: 'integer', minimum: 1 },
            pageSize: { type: 'integer', minimum: 1, maximum: 100 },
          },
        },
      },
    },
    async (req) => {
      const query = req.query as { status?: string; kind?: string; page?: number; pageSize?: number };
      const { page, pageSize } = parsePagination(query.page, query.pageSize, 50);
      const settings = ctx.getSettings();
      const alerts = listAlerts(ctx.db, {
        status: query.status as AlertStatus | undefined,
        kind: query.kind as AlertKind | undefined,
        page,
        pageSize,
      });
      return {
        ntfy: toPublicSettings(settings).ntfy,
        publicUrl: settings.publicUrl,
        alerts: { ...alerts, page, pageSize },
        counts: alertStatusCounts(ctx.db, isoAfter(-90 * 86_400_000)),
      };
    },
  );

  app.post('/notifications/test', async () => ctx.alerts.sendTest());

  app.post('/kev/sync', async () => ctx.kev.syncNow());

  app.get('/system', async () => ({
    version: ctx.config.version,
    nodeVersion: process.version,
    uptimeSeconds: Math.round((Date.now() - ctx.startedAt) / 1000),
    schemaVersion: SCHEMA_VERSION,
    scanner: await getScannerInfo(ctx.config),
    kev: ctx.kev.status(),
    scans: { active: ctx.coordinator.activeCount },
    activity: scanStatusCounts(ctx.db, isoAfter(-24 * 3_600_000)),
    limits: {
      scanConcurrency: Math.min(ctx.getSettings().scanConcurrency, ctx.config.scanConcurrency),
      scanTimeoutMs: ctx.config.scanTimeoutMs,
      maxOutputBytes: ctx.config.maxOutputBytes,
      maxImageExportBytes: ctx.config.maxImageExportBytes,
    },
  }));
}
