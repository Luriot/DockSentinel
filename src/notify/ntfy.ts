import type { NtfyPriority, NtfySettings } from '../repo/settings.ts';
import { isValidTopic } from '../repo/settings.ts';

export class NtfyError extends Error {
  readonly status: number | null;
  readonly detail: string;

  constructor(message: string, status: number | null = null, detail = '') {
    super(message);
    this.name = 'NtfyError';
    this.status = status;
    this.detail = detail;
  }
}

export interface NtfyMessage {
  title: string;
  body: string;
  priority: number;
  tags: string[];
  clickUrl?: string | null;
}

const MAX_BODY_BYTES = 3800;

export function resolveNtfyPriority(settings: NtfySettings, fallback: number): number {
  const map: Record<NtfyPriority, number> = {
    min: 1,
    low: 2,
    default: 0,
    high: 4,
    urgent: 5,
    max: 5,
  };
  const configured = map[settings.priority];
  return configured && configured > 0 ? configured : fallback;
}

export function validateNtfySettings(settings: NtfySettings): string | null {
  let url: URL;
  try {
    url = new URL(settings.baseUrl);
  } catch {
    return 'ntfy base URL is not a valid URL';
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return 'ntfy base URL must use http or https';
  if (url.username || url.password) return 'Do not embed credentials in the ntfy URL; use the auth fields instead';
  if (!isValidTopic(settings.topic)) return 'ntfy topic must be 1-64 characters: letters, numbers, dash or underscore';
  if (settings.authType === 'basic' && (!settings.username || !settings.password)) {
    return 'Basic authentication requires a username and password';
  }
  if (settings.authType === 'token' && !settings.token) return 'Token authentication requires an access token';
  return null;
}

function truncateUtf8(text: string, maxBytes: number): string {
  const buffer = Buffer.from(text, 'utf8');
  if (buffer.length <= maxBytes) return text;
  return `${buffer.subarray(0, maxBytes - 3).toString('utf8')}…`;
}

function authHeader(settings: NtfySettings): string | null {
  if (settings.authType === 'token' && settings.token) return `Bearer ${settings.token}`;
  if (settings.authType === 'basic' && settings.username && settings.password) {
    return `Basic ${Buffer.from(`${settings.username}:${settings.password}`, 'utf8').toString('base64')}`;
  }
  return null;
}

/** Publishes one message to an ntfy topic using the documented HTTP publish API. */
export async function sendNtfy(
  settings: NtfySettings,
  message: NtfyMessage,
  fetchImpl: typeof fetch = fetch,
): Promise<void> {
  const configError = validateNtfySettings(settings);
  if (configError) throw new NtfyError(configError);
  if (!settings.enabled) throw new NtfyError('Notifications are disabled');

  const url = `${settings.baseUrl.replace(/\/+$/, '')}/${encodeURIComponent(settings.topic)}`;
  const headers: Record<string, string> = {
    'Content-Type': 'text/markdown; charset=utf-8',
    Markdown: 'yes',
    Title: message.title.replace(/[\r\n]+/g, ' ').slice(0, 200),
    Priority: String(Math.min(5, Math.max(1, message.priority))),
    Tags: message.tags
      .map((tag) => tag.replace(/[^A-Za-z0-9_+-]/g, ''))
      .filter(Boolean)
      .slice(0, 5)
      .join(','),
  };
  if (message.clickUrl) headers.Click = message.clickUrl.slice(0, 500);
  const auth = authHeader(settings);
  if (auth) headers.Authorization = auth;

  let response: Response;
  try {
    response = await fetchImpl(url, {
      method: 'POST',
      headers,
      body: truncateUtf8(message.body, MAX_BODY_BYTES),
      signal: AbortSignal.timeout(15_000),
    });
  } catch (error) {
    throw new NtfyError(
      `Notification request failed: ${error instanceof Error ? error.message.slice(0, 200) : 'unknown error'}`,
    );
  }

  if (!response.ok) {
    let detail = '';
    try {
      detail = (await response.text()).replace(/\s+/g, ' ').trim().slice(0, 300);
    } catch {
      detail = '';
    }
    throw new NtfyError(`ntfy returned HTTP ${response.status}`, response.status, detail);
  }
}
