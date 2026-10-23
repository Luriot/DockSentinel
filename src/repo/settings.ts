import type { Db } from '../db/index.ts';
import { encryptSecret, tryDecryptSecret } from '../secrets.ts';
import type { Severity } from '../domain/severity.ts';
import { isSeverity } from '../domain/severity.ts';
import { nowIso } from '../util/time.ts';

export type NtfyAuthType = 'none' | 'basic' | 'token';
export type NtfyPriority = 'min' | 'low' | 'default' | 'high' | 'urgent' | 'max';

export interface NtfySettings {
  enabled: boolean;
  baseUrl: string;
  topic: string;
  priority: NtfyPriority;
  tags: string;
  authType: NtfyAuthType;
  username: string;
  /** Decrypted in memory only; never serialised to API responses or logs. */
  token: string | null;
  password: string | null;
}

export interface AppSettings {
  scanConcurrency: number;
  discoveryIntervalMinutes: number;
  defaultQuickIntervalHours: number;
  defaultStandardIntervalHours: number;
  freshnessHours: number;
  minAlertSeverity: Severity;
  alertOnNew: boolean;
  alertOnResolved: boolean;
  alertOnKev: boolean;
  alertOnScanFailure: boolean;
  alertOnStale: boolean;
  scanFailureRetries: number;
  scanOnDiscovery: boolean;
  retentionScansDays: number;
  retentionAlertsDays: number;
  retentionResolvedFindingsDays: number;
  retentionEventsDays: number;
  publicUrl: string;
  kevEnabled: boolean;
  /** Opt-in manual content scans; both default off. */
  misconfigScanEnabled: boolean;
  secretScanEnabled: boolean;
  ntfy: NtfySettings;
}

export const DEFAULT_SETTINGS: AppSettings = {
  scanConcurrency: 2,
  discoveryIntervalMinutes: 10,
  defaultQuickIntervalHours: 24,
  defaultStandardIntervalHours: 168,
  freshnessHours: 48,
  minAlertSeverity: 'HIGH',
  alertOnNew: true,
  alertOnResolved: true,
  alertOnKev: true,
  alertOnScanFailure: true,
  alertOnStale: false,
  scanFailureRetries: 2,
  scanOnDiscovery: true,
  retentionScansDays: 90,
  retentionAlertsDays: 90,
  retentionResolvedFindingsDays: 180,
  retentionEventsDays: 180,
  publicUrl: '',
  kevEnabled: true,
  misconfigScanEnabled: false,
  secretScanEnabled: false,
  ntfy: {
    enabled: false,
    baseUrl: 'https://ntfy.sh',
    topic: '',
    priority: 'default',
    tags: 'shield',
    authType: 'none',
    username: '',
    token: null,
    password: null,
  },
};

const SETTINGS_KEY = 'app';

interface StoredNtfy {
  enabled?: boolean;
  baseUrl?: string;
  topic?: string;
  priority?: string;
  tags?: string;
  authType?: string;
  username?: string;
  tokenEnc?: string;
  passwordEnc?: string;
}

type StoredSettings = Partial<Omit<AppSettings, 'ntfy'>> & { ntfy?: StoredNtfy };

function clampInt(value: unknown, fallback: number, min: number, max: number): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) return fallback;
  return Math.min(max, Math.max(min, Math.round(value)));
}

function bool(value: unknown, fallback: boolean): boolean {
  return typeof value === 'boolean' ? value : fallback;
}

function text(value: unknown, fallback: string, maxLength: number): string {
  if (typeof value !== 'string') return fallback;
  return value.slice(0, maxLength);
}

export function loadSettings(db: Db, key: Buffer): AppSettings {
  const row = db.get<{ value: string }>('SELECT value FROM settings WHERE key = ?', [SETTINGS_KEY]);
  let stored: StoredSettings = {};
  if (row) {
    try {
      const parsed = JSON.parse(row.value) as unknown;
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) stored = parsed as StoredSettings;
    } catch {
      stored = {};
    }
  }

  const ntfyStored = stored.ntfy ?? {};
  const authType: NtfyAuthType =
    ntfyStored.authType === 'basic' || ntfyStored.authType === 'token' ? ntfyStored.authType : 'none';
  const priority: NtfyPriority =
    ntfyStored.priority === 'min' ||
    ntfyStored.priority === 'low' ||
    ntfyStored.priority === 'high' ||
    ntfyStored.priority === 'urgent' ||
    ntfyStored.priority === 'max'
      ? ntfyStored.priority
      : 'default';

  return {
    scanConcurrency: clampInt(stored.scanConcurrency, DEFAULT_SETTINGS.scanConcurrency, 1, 8),
    discoveryIntervalMinutes: clampInt(
      stored.discoveryIntervalMinutes,
      DEFAULT_SETTINGS.discoveryIntervalMinutes,
      1,
      1440,
    ),
    defaultQuickIntervalHours: clampInt(
      stored.defaultQuickIntervalHours,
      DEFAULT_SETTINGS.defaultQuickIntervalHours,
      0,
      24 * 90,
    ),
    defaultStandardIntervalHours: clampInt(
      stored.defaultStandardIntervalHours,
      DEFAULT_SETTINGS.defaultStandardIntervalHours,
      0,
      24 * 365,
    ),
    freshnessHours: clampInt(stored.freshnessHours, DEFAULT_SETTINGS.freshnessHours, 1, 24 * 30),
    minAlertSeverity: isSeverity(stored.minAlertSeverity) ? stored.minAlertSeverity : DEFAULT_SETTINGS.minAlertSeverity,
    alertOnNew: bool(stored.alertOnNew, DEFAULT_SETTINGS.alertOnNew),
    alertOnResolved: bool(stored.alertOnResolved, DEFAULT_SETTINGS.alertOnResolved),
    alertOnKev: bool(stored.alertOnKev, DEFAULT_SETTINGS.alertOnKev),
    alertOnScanFailure: bool(stored.alertOnScanFailure, DEFAULT_SETTINGS.alertOnScanFailure),
    alertOnStale: bool(stored.alertOnStale, DEFAULT_SETTINGS.alertOnStale),
    scanFailureRetries: clampInt(stored.scanFailureRetries, DEFAULT_SETTINGS.scanFailureRetries, 0, 5),
    scanOnDiscovery: bool(stored.scanOnDiscovery, DEFAULT_SETTINGS.scanOnDiscovery),
    retentionScansDays: clampInt(stored.retentionScansDays, DEFAULT_SETTINGS.retentionScansDays, 7, 3650),
    retentionAlertsDays: clampInt(stored.retentionAlertsDays, DEFAULT_SETTINGS.retentionAlertsDays, 7, 3650),
    retentionResolvedFindingsDays: clampInt(
      stored.retentionResolvedFindingsDays,
      DEFAULT_SETTINGS.retentionResolvedFindingsDays,
      30,
      3650,
    ),
    retentionEventsDays: clampInt(stored.retentionEventsDays, DEFAULT_SETTINGS.retentionEventsDays, 30, 3650),
    publicUrl: text(stored.publicUrl, DEFAULT_SETTINGS.publicUrl, 500),
    kevEnabled: bool(stored.kevEnabled, DEFAULT_SETTINGS.kevEnabled),
    misconfigScanEnabled: bool(stored.misconfigScanEnabled, DEFAULT_SETTINGS.misconfigScanEnabled),
    secretScanEnabled: bool(stored.secretScanEnabled, DEFAULT_SETTINGS.secretScanEnabled),
    ntfy: {
      enabled: bool(ntfyStored.enabled, DEFAULT_SETTINGS.ntfy.enabled),
      baseUrl: text(ntfyStored.baseUrl, DEFAULT_SETTINGS.ntfy.baseUrl, 500),
      topic: text(ntfyStored.topic, DEFAULT_SETTINGS.ntfy.topic, 64),
      priority,
      tags: text(ntfyStored.tags, DEFAULT_SETTINGS.ntfy.tags, 200),
      authType,
      username: text(ntfyStored.username, '', 200),
      token: tryDecryptSecret(ntfyStored.tokenEnc, key),
      password: tryDecryptSecret(ntfyStored.passwordEnc, key),
    },
  };
}

export function saveSettings(db: Db, key: Buffer, settings: AppSettings): void {
  const tokenEnc = settings.ntfy.token ? encryptSecret(settings.ntfy.token, key) : null;
  const passwordEnc = settings.ntfy.password ? encryptSecret(settings.ntfy.password, key) : null;

  const stored: StoredSettings = {
    ...settings,
    ntfy: {
      enabled: settings.ntfy.enabled,
      baseUrl: settings.ntfy.baseUrl,
      topic: settings.ntfy.topic,
      priority: settings.ntfy.priority,
      tags: settings.ntfy.tags,
      authType: settings.ntfy.authType,
      username: settings.ntfy.username,
      tokenEnc: tokenEnc ?? undefined,
      passwordEnc: passwordEnc ?? undefined,
    },
  };
  db.run(
    `INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
     ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
    [SETTINGS_KEY, JSON.stringify(stored), nowIso()],
  );
}

export interface PublicNtfySettings {
  enabled: boolean;
  baseUrl: string;
  topic: string;
  priority: NtfyPriority;
  tags: string;
  authType: NtfyAuthType;
  username: string;
  hasToken: boolean;
  hasPassword: boolean;
}

export interface PublicSettings extends Omit<AppSettings, 'ntfy'> {
  ntfy: PublicNtfySettings;
}

export function toPublicSettings(settings: AppSettings): PublicSettings {
  return {
    ...settings,
    ntfy: {
      enabled: settings.ntfy.enabled,
      baseUrl: settings.ntfy.baseUrl,
      topic: settings.ntfy.topic,
      priority: settings.ntfy.priority,
      tags: settings.ntfy.tags,
      authType: settings.ntfy.authType,
      username: settings.ntfy.username,
      hasToken: Boolean(settings.ntfy.token),
      hasPassword: Boolean(settings.ntfy.password),
    },
  };
}

export function isValidTopic(topic: string): boolean {
  return /^[-_A-Za-z0-9]{1,64}$/.test(topic);
}
