import { readFile, stat, unlink } from 'node:fs/promises';
import { basename, join } from 'node:path';
import { ProcessError, runProcess } from './process.ts';
import { InvalidReportError, parseTrivyContentReport, parseTrivyReport } from './normalize.ts';
import type { NormalizedFinding } from '../domain/findings.ts';
import type { NormalizedContentFinding } from '../domain/content.ts';

export type ScanProfile = 'quick' | 'standard';
export type ScanMode = 'vulnerability' | 'content';
export interface ContentScanners {
  misconfig: boolean;
  secret: boolean;
}

export type ScannerErrorCode =
  | 'scanner_unavailable'
  | 'timeout'
  | 'cancelled'
  | 'output_too_large'
  | 'invalid_output'
  | 'scanner_failed'
  | 'db_unavailable';

export class ScannerError extends Error {
  readonly code: ScannerErrorCode;
  readonly exitCode: number | null;
  readonly stderrTail: string;

  constructor(code: ScannerErrorCode, message: string, exitCode: number | null = null, stderrTail = '') {
    super(message);
    this.name = 'ScannerError';
    this.code = code;
    this.exitCode = exitCode;
    this.stderrTail = stderrTail;
  }
}

export interface ScannerRunInput {
  /** docker-save archive of the exact image ID being scanned. */
  archivePath: string;
  /** Per-scan scratch directory; the report is written and removed here. */
  workDir: string;
  profile: ScanProfile;
  /** Defaults to vulnerability scanning for backward compatibility. */
  mode?: ScanMode;
  /** Required when mode is content; at least one entry must be true. */
  contentScanners?: ContentScanners;
  signal?: AbortSignal;
}

export interface ScannerRunResult {
  findings: NormalizedFinding[];
  contentFindings: NormalizedContentFinding[];
  scannerVersion: string | null;
  dbVersion: string | null;
  dbUpdatedAt: string | null;
  os: { family: string | null; version: string | null } | null;
  warnings: string[];
  exitCode: number | null;
  durationMs: number;
  stderrTail: string;
}

export interface ScannerAdapter {
  readonly name: string;
  run(input: ScannerRunInput): Promise<ScannerRunResult>;
}

export interface TrivyOptions {
  bin: string;
  cacheDir: string;
  maxOutputBytes: number;
  /** Hard ceiling from configuration: quick is clamped to it, standard uses it. */
  maxTimeoutMs: number;
}

interface ProfileDefinition {
  vulnType: string;
  skipJavaDb: boolean;
  /** Target timeout, or null to use the configured hard ceiling. */
  timeoutMs: number | null;
}

const PROFILES: Record<ScanProfile, ProfileDefinition> = {
  // OS packages only, Java index skipped: fast and cheap, but does not cover language dependencies.
  quick: { vulnType: 'os', skipJavaDb: true, timeoutMs: 5 * 60_000 },
  // OS + language packages: covers application dependencies (npm, Python, PHP, Java, ...).
  standard: { vulnType: 'os,library', skipJavaDb: false, timeoutMs: null },
};

/** Quick keeps its short target; standard uses the configured ceiling, so large images can get more time. */
export function scannerTimeoutMs(profile: ScanProfile, maxTimeoutMs: number): number {
  const target = PROFILES[profile].timeoutMs;
  return target === null ? maxTimeoutMs : Math.min(target, maxTimeoutMs);
}

const DB_ERROR_PATTERN =
  /(database error|db error|failed to download (the )?vulnerability db|failed to download vulnerability database|--skip-db-update cannot be specified|failed to update the vulnerability database)/i;
const CACHE_LOCK_PATTERN = /cache may be in use by another process/i;

/** Trivy exits non-zero on a busy shared cache; retrying against the cached DB avoids the lock. */
export function shouldRetryWithCachedDatabase(stderr: string): boolean {
  return DB_ERROR_PATTERN.test(stderr) || CACHE_LOCK_PATTERN.test(stderr);
}

export function scannerEnv(cacheDir: string): NodeJS.ProcessEnv {
  const allowed = [
    'PATH',
    'HOME',
    'USERPROFILE',
    'TMPDIR',
    'TEMP',
    'TMP',
    'LANG',
    'LC_ALL',
    'HTTP_PROXY',
    'HTTPS_PROXY',
    'NO_PROXY',
    'http_proxy',
    'https_proxy',
    'no_proxy',
    'SSL_CERT_FILE',
    'SSL_CERT_DIR',
  ];
  const env: NodeJS.ProcessEnv = {};
  for (const name of allowed) {
    const value = process.env[name];
    if (value !== undefined) env[name] = value;
  }
  env.TRIVY_CACHE_DIR = cacheDir;
  return env;
}

interface TrivyVersionInfo {
  version: string | null;
  dbUpdatedAt: string | null;
  dbSchema: string | null;
}

export class TrivyAdapter implements ScannerAdapter {
  readonly name = 'trivy';
  private readonly options: TrivyOptions;

  constructor(options: TrivyOptions) {
    this.options = options;
  }

  async run(input: ScannerRunInput): Promise<ScannerRunResult> {
    if (input.mode === 'content') return this.runContent(input);
    const started = Date.now();
    const profile = PROFILES[input.profile];
    const timeoutMs = scannerTimeoutMs(input.profile, this.options.maxTimeoutMs);
    const reportName = `report-${input.profile}.json`;
    const reportPath = join(input.workDir, reportName);
    const warnings: string[] = [];

    let result;
    try {
      result = await this.invokeScanner(input, profile, timeoutMs, reportName, false);
    } catch (error) {
      if (error instanceof ProcessError && error.code === 'nonzero_exit' && shouldRetryWithCachedDatabase(error.stderr)) {
        if (CACHE_LOCK_PATTERN.test(error.stderr)) {
          // Another scan is updating the shared cache; let it finish before reading the cached DB.
          await new Promise((resolve) => setTimeout(resolve, 5000));
          warnings.push('Scanner cache was busy; retried with the cached database');
        } else {
          warnings.push('Vulnerability database update failed; retried with the cached database');
        }
        try {
          result = await this.invokeScanner(input, profile, timeoutMs, reportName, true);
        } catch (retryError) {
          throw this.mapError(retryError);
        }
      } else {
        throw this.mapError(error);
      }
    }

    const raw = await this.readReport(reportPath);

    let parsed;
    try {
      parsed = parseTrivyReport(raw);
    } catch (error) {
      if (error instanceof InvalidReportError) {
        throw new ScannerError('invalid_output', `Scanner report could not be trusted: ${error.message}`);
      }
      throw error;
    }

    const version = await this.readVersion();
    if (!version.dbUpdatedAt) warnings.push('Vulnerability database timestamp could not be determined');
    if (version.dbUpdatedAt) {
      const ageDays = (Date.now() - Date.parse(version.dbUpdatedAt)) / 86_400_000;
      if (Number.isFinite(ageDays) && ageDays > 7) {
        warnings.push(`Vulnerability database is ${Math.floor(ageDays)} days old`);
      }
    }

    const archiveBase = basename(input.archivePath);
    const stripArchivePrefix = (target: string): string => {
      if (target === input.archivePath) return archiveBase;
      if (target.startsWith(`${input.archivePath} `)) return `${archiveBase}${target.slice(input.archivePath.length)}`;
      if (target.startsWith(`${input.archivePath}/`)) return target.slice(input.archivePath.length + 1);
      return target;
    };

    const findings: NormalizedFinding[] = parsed.findings.map((finding) => ({
      target: stripArchivePrefix(finding.target),
      class: finding.class,
      type: finding.type,
      vulnId: finding.vulnId,
      pkgName: finding.pkgName,
      installedVersion: finding.installedVersion,
      fixedVersion: finding.fixedVersion,
      severity: finding.severity,
      status: finding.status,
      title: finding.title,
      primaryUrl: finding.primaryUrl,
      cvssScore: finding.cvssScore,
      cvssSource: finding.cvssSource,
      cvssVector: finding.cvssVector,
      publishedAt: finding.publishedAt,
      modifiedAt: finding.modifiedAt,
    }));

    return {
      findings,
      contentFindings: [],
      scannerVersion: version.version,
      dbVersion: version.dbSchema,
      dbUpdatedAt: version.dbUpdatedAt,
      os: parsed.os,
      warnings: [...warnings, ...parsed.warnings],
      exitCode: result.exitCode,
      durationMs: Date.now() - started,
      stderrTail: result.stderr.slice(-1500),
    };
  }

  private async runContent(input: ScannerRunInput): Promise<ScannerRunResult> {
    const started = Date.now();
    const scanners = input.contentScanners;
    if (!scanners || (!scanners.misconfig && !scanners.secret)) {
      throw new ScannerError('scanner_failed', 'No content scanners were selected');
    }
    const selected: string[] = [];
    if (scanners.misconfig) selected.push('misconfig');
    if (scanners.secret) selected.push('secret');
    const timeoutMs = Math.min(10 * 60_000, this.options.maxTimeoutMs);
    const reportName = 'report-content.json';
    const reportPath = join(input.workDir, reportName);

    let result;
    try {
      result = await this.invokeContentScanner(input, selected, timeoutMs, reportName);
    } catch (error) {
      throw this.mapContentError(error);
    }

    const raw = await this.readReport(reportPath);
    let parsed;
    try {
      parsed = parseTrivyContentReport(raw, { path: input.archivePath, base: basename(input.archivePath) });
    } catch (error) {
      if (error instanceof InvalidReportError) {
        throw new ScannerError('invalid_output', `Scanner report could not be trusted: ${error.message}`);
      }
      throw error;
    }
    const version = await this.readVersion();
    return {
      findings: [],
      contentFindings: parsed.findings,
      scannerVersion: version.version,
      dbVersion: null,
      dbUpdatedAt: null,
      os: null,
      warnings: parsed.warnings,
      exitCode: result.exitCode,
      durationMs: Date.now() - started,
      // Secret scanning output must never be copied into logs or API errors.
      stderrTail: '',
    };
  }

  private async readReport(reportPath: string): Promise<string> {
    try {
      const info = await stat(reportPath);
      if (info.size === 0) throw new ScannerError('invalid_output', 'Scanner produced an empty report');
      if (info.size > this.options.maxOutputBytes) {
        throw new ScannerError(
          'output_too_large',
          `Scanner report is ${Math.round(info.size / (1024 * 1024))} MiB, above the configured limit`,
        );
      }
      return await readFile(reportPath, 'utf8');
    } catch (error) {
      if (error instanceof ScannerError) throw error;
      throw new ScannerError('invalid_output', 'Scanner did not produce a readable report');
    } finally {
      await unlink(reportPath).catch(() => undefined);
    }
  }

  private async invokeContentScanner(
    input: ScannerRunInput,
    scanners: string[],
    timeoutMs: number,
    reportName: string,
  ) {
    const args = [
      'image',
      '--input',
      basename(input.archivePath),
      '--format',
      'json',
      '--output',
      reportName,
      '--quiet',
      '--scanners',
      scanners.join(','),
      '--image-config-scanners',
      scanners.join(','),
      '--cache-dir',
      this.options.cacheDir,
      '--timeout',
      `${Math.ceil(timeoutMs / 1000) + 30}s`,
    ];
    return runProcess({
      command: this.options.bin,
      args,
      cwd: input.workDir,
      env: scannerEnv(this.options.cacheDir),
      timeoutMs,
      signal: input.signal,
      maxStderrBytes: 64 * 1024,
    });
  }

  private async invokeScanner(
    input: ScannerRunInput,
    profile: ProfileDefinition,
    timeoutMs: number,
    reportName: string,
    skipDbUpdate: boolean,
  ) {
    // Run from the work directory with relative paths. Trivy copies the input argument into the
    // Result.Target field, so an absolute path would make every finding identity random and cause
    // spurious resolve/reappear cycles on every scan.
    const args = [
      'image',
      '--input',
      basename(input.archivePath),
      '--format',
      'json',
      '--output',
      reportName,
      '--quiet',
      '--scanners',
      'vuln',
      '--vuln-type',
      profile.vulnType,
      '--cache-dir',
      this.options.cacheDir,
      '--timeout',
      `${Math.ceil(timeoutMs / 1000) + 30}s`,
    ];
    if (profile.skipJavaDb) args.push('--skip-java-db-update');
    if (skipDbUpdate) args.push('--skip-db-update');

    return runProcess({
      command: this.options.bin,
      args,
      cwd: input.workDir,
      env: scannerEnv(this.options.cacheDir),
      timeoutMs,
      signal: input.signal,
      maxStderrBytes: 64 * 1024,
    });
  }

  private async readVersion(): Promise<TrivyVersionInfo> {
    try {
      const result = await runProcess({
        command: this.options.bin,
        args: ['version', '--format', 'json'],
        env: scannerEnv(this.options.cacheDir),
        timeoutMs: 20_000,
        maxStderrBytes: 8 * 1024,
      });
      const parsed = JSON.parse(result.stdout) as {
        Version?: unknown;
        VulnerabilityDB?: { Version?: unknown; UpdatedAt?: unknown };
      };
      return {
        version: typeof parsed.Version === 'string' ? parsed.Version : null,
        dbUpdatedAt: typeof parsed.VulnerabilityDB?.UpdatedAt === 'string' ? parsed.VulnerabilityDB.UpdatedAt : null,
        dbSchema:
          typeof parsed.VulnerabilityDB?.Version === 'number' || typeof parsed.VulnerabilityDB?.Version === 'string'
            ? String(parsed.VulnerabilityDB.Version)
            : null,
      };
    } catch {
      return { version: null, dbUpdatedAt: null, dbSchema: null };
    }
  }

  private mapContentError(error: unknown): ScannerError {
    if (error instanceof ScannerError) {
      return new ScannerError(error.code, contentErrorMessage(error.code, error.exitCode), error.exitCode);
    }
    if (error instanceof InvalidReportError) {
      return new ScannerError('invalid_output', 'Scanner report could not be trusted');
    }
    if (error instanceof ProcessError) {
      const code =
        error.code === 'spawn_failed'
          ? 'scanner_unavailable'
          : error.code === 'timeout'
            ? 'timeout'
            : error.code === 'aborted'
              ? 'cancelled'
              : error.code === 'output_too_large'
                ? 'output_too_large'
                : 'scanner_failed';
      return new ScannerError(code, contentErrorMessage(code, error.exitCode), error.exitCode);
    }
    return new ScannerError('scanner_failed', 'Trivy content scan failed');
  }

  private mapError(error: unknown): ScannerError {
    if (error instanceof ScannerError) return error;
    if (error instanceof InvalidReportError) return new ScannerError('invalid_output', error.message);
    if (error instanceof ProcessError) {
      const exitCode = error.exitCode;
      switch (error.code) {
        case 'spawn_failed':
          return new ScannerError('scanner_unavailable', error.message, exitCode, error.stderr);
        case 'timeout':
          return new ScannerError('timeout', error.message, exitCode, error.stderr);
        case 'aborted':
          return new ScannerError('cancelled', 'Scan cancelled', exitCode, error.stderr);
        case 'output_too_large':
          return new ScannerError('output_too_large', error.message, exitCode, error.stderr);
        case 'nonzero_exit':
        default:
          if (DB_ERROR_PATTERN.test(error.stderr) && /skip-db-update cannot be specified/i.test(error.stderr)) {
            return new ScannerError(
              'db_unavailable',
              'Vulnerability database is unavailable and no cached copy exists. Check the container network and Trivy cache volume.',
              exitCode,
              error.stderr,
            );
          }
          return new ScannerError(
            'scanner_failed',
            `Trivy failed: ${lastMeaningfulLine(error.stderr) || error.message}`,
            exitCode,
            error.stderr,
          );
      }
    }
    return new ScannerError('scanner_failed', error instanceof Error ? error.message : 'Scanner failed');
  }
}

function contentErrorMessage(code: ScannerErrorCode, exitCode: number | null): string {
  switch (code) {
    case 'scanner_unavailable':
      return 'Trivy is not available or could not be started.';
    case 'timeout':
      return 'Trivy content scan timed out.';
    case 'cancelled':
      return 'Scan cancelled';
    case 'output_too_large':
      return 'Scanner report exceeded the configured size limit.';
    case 'invalid_output':
      return 'Scanner report could not be trusted.';
    default:
      return `Trivy content scan failed (exit code ${exitCode ?? 'unknown'}). Check network access for the checks bundle and the scanner log.`;
  }
}

function lastMeaningfulLine(stderr: string): string {
  const lines = stderr
    .split(/\r?\n/)
    .map((line) => line.replace(/\s+/g, ' ').trim())
    .filter(Boolean);
  for (let index = lines.length - 1; index >= 0; index -= 1) {
    const line = lines[index];
    if (line && /fatal|error|failed/i.test(line)) return line.slice(0, 300);
  }
  return (lines[lines.length - 1] ?? '').slice(0, 300);
}
