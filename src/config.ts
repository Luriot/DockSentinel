import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

function readVersion(): string {
  try {
    const pkg = JSON.parse(readFileSync(resolve(projectRoot, 'package.json'), 'utf8')) as { version?: string };
    return pkg.version ?? '0.0.0';
  } catch {
    return '0.0.0';
  }
}

function intEnv(name: string, fallback: number, min: number, max: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const value = Number.parseInt(raw, 10);
  if (!Number.isFinite(value) || value < min || value > max) {
    throw new Error(`${name} must be an integer between ${min} and ${max}`);
  }
  return value;
}

function boolEnv(name: string, fallback: boolean): boolean {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(raw.toLowerCase());
}

function loadSecretKey(dataDir: string): Buffer {
  const fromEnv = process.env.DOCKSENTINEL_SECRET_KEY;
  if (fromEnv && fromEnv.trim() !== '') {
    const buf = /^[0-9a-fA-F]{64}$/.test(fromEnv) ? Buffer.from(fromEnv, 'hex') : Buffer.from(fromEnv, 'base64');
    if (buf.length !== 32) throw new Error('DOCKSENTINEL_SECRET_KEY must be 32 bytes (base64 or 64-char hex)');
    return buf;
  }

  const keyPath = resolve(dataDir, 'secret.key');
  if (existsSync(keyPath)) {
    const buf = Buffer.from(readFileSync(keyPath, 'utf8').trim(), 'base64');
    if (buf.length !== 32) throw new Error(`Secret key file ${keyPath} is invalid`);
    return buf;
  }

  const generated = randomBytes(32);
  mkdirSync(dataDir, { recursive: true });
  writeFileSync(keyPath, `${generated.toString('base64')}\n`, { mode: 0o600 });
  try {
    chmodSync(keyPath, 0o600);
  } catch {
    // Windows does not always support POSIX modes; protect the data directory instead.
  }
  return generated;
}

export type CookieSecureMode = 'auto' | 'always' | 'never';

export interface Config {
  readonly version: string;
  readonly projectRoot: string;
  readonly port: number;
  readonly host: string;
  readonly dataDir: string;
  readonly dbPath: string;
  readonly webDist: string;
  readonly secretKey: Buffer;
  readonly logLevel: string;
  readonly trustProxy: boolean;
  readonly cookieSecure: CookieSecureMode;
  readonly trivyBin: string;
  readonly trivyCacheDir: string;
  readonly scanConcurrency: number;
  readonly scanTimeoutMs: number;
  readonly maxOutputBytes: number;
  readonly maxImageExportBytes: number;
  readonly imageExportTimeoutMs: number;
  readonly setupToken: string | null;
  readonly kevUrl: string;
  readonly isTest: boolean;
}

export function loadConfig(overrides: Partial<Config> = {}): Config {
  const dataDir = overrides.dataDir ?? process.env.DATA_DIR ?? resolve(projectRoot, 'data');
  mkdirSync(dataDir, { recursive: true });

  const secureRaw = (process.env.COOKIE_SECURE ?? 'auto').toLowerCase();
  const cookieSecure: CookieSecureMode =
    secureRaw === 'always' || secureRaw === 'never' || secureRaw === 'auto' ? secureRaw : 'auto';
  const isTest = process.env.NODE_ENV === 'test' || process.env.DOCKSENTINEL_TEST === '1';

  return {
    version: readVersion(),
    projectRoot,
    port: overrides.port ?? intEnv('PORT', 8080, 1, 65535),
    host: overrides.host ?? process.env.HOST ?? '0.0.0.0',
    dataDir,
    dbPath: overrides.dbPath ?? resolve(dataDir, 'docksentinel.db'),
    webDist: overrides.webDist ?? resolve(projectRoot, 'web', 'dist'),
    secretKey: overrides.secretKey ?? loadSecretKey(dataDir),
    logLevel: overrides.logLevel ?? process.env.LOG_LEVEL ?? (isTest ? 'silent' : 'info'),
    trustProxy: overrides.trustProxy ?? boolEnv('TRUST_PROXY', false),
    cookieSecure: overrides.cookieSecure ?? cookieSecure,
    trivyBin: overrides.trivyBin ?? process.env.TRIVY_BIN ?? 'trivy',
    trivyCacheDir: overrides.trivyCacheDir ?? process.env.TRIVY_CACHE_DIR ?? resolve(dataDir, 'trivy-cache'),
    scanConcurrency: overrides.scanConcurrency ?? intEnv('SCAN_CONCURRENCY', 2, 1, 8),
    scanTimeoutMs:
      overrides.scanTimeoutMs ?? intEnv('SCAN_TIMEOUT_MS', 15 * 60 * 1000, 10_000, 60 * 60 * 1000),
    maxOutputBytes:
      overrides.maxOutputBytes ??
      intEnv('SCAN_MAX_OUTPUT_BYTES', 96 * 1024 * 1024, 1024 * 1024, 512 * 1024 * 1024),
    maxImageExportBytes:
      overrides.maxImageExportBytes ??
      intEnv('MAX_IMAGE_EXPORT_BYTES', 8 * 1024 * 1024 * 1024, 16 * 1024 * 1024, 64 * 1024 * 1024 * 1024),
    imageExportTimeoutMs:
      overrides.imageExportTimeoutMs ?? intEnv('IMAGE_EXPORT_TIMEOUT_MS', 10 * 60 * 1000, 10_000, 60 * 60 * 1000),
    setupToken: overrides.setupToken ?? (process.env.SETUP_TOKEN?.trim() || null),
    kevUrl:
      overrides.kevUrl ??
      process.env.KEV_URL ??
      'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    isTest,
  };
}
