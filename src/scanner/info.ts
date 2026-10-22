import type { Config } from '../config.ts';
import { runProcess } from '../scanner/process.ts';
import { scannerEnv } from '../scanner/trivy.ts';

export interface ScannerInfo {
  available: boolean;
  version: string | null;
  dbUpdatedAt: string | null;
  dbSchema: string | null;
  checkedAt: string;
  error: string | null;
}

let cached: { at: number; info: ScannerInfo } | null = null;
const CACHE_TTL_MS = 5 * 60_000;

export async function getScannerInfo(config: Config, force = false): Promise<ScannerInfo> {
  if (!force && cached && Date.now() - cached.at < CACHE_TTL_MS) return cached.info;

  const info: ScannerInfo = {
    available: false,
    version: null,
    dbUpdatedAt: null,
    dbSchema: null,
    checkedAt: new Date().toISOString(),
    error: null,
  };
  try {
    const result = await runProcess({
      command: config.trivyBin,
      args: ['version', '--format', 'json'],
      env: scannerEnv(config.trivyCacheDir),
      timeoutMs: 10_000,
      maxStderrBytes: 8 * 1024,
    });
    const parsed = JSON.parse(result.stdout) as {
      Version?: unknown;
      VulnerabilityDB?: { Version?: unknown; UpdatedAt?: unknown };
    };
    info.available = true;
    info.version = typeof parsed.Version === 'string' ? parsed.Version : null;
    info.dbUpdatedAt = typeof parsed.VulnerabilityDB?.UpdatedAt === 'string' ? parsed.VulnerabilityDB.UpdatedAt : null;
    info.dbSchema =
      typeof parsed.VulnerabilityDB?.Version === 'number' || typeof parsed.VulnerabilityDB?.Version === 'string'
        ? String(parsed.VulnerabilityDB.Version)
        : null;
  } catch (error) {
    info.error = error instanceof Error ? error.message.slice(0, 300) : 'Scanner is not available';
  }
  cached = { at: Date.now(), info };
  return info;
}

