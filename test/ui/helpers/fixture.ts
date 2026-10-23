import { spawn, type ChildProcess } from 'node:child_process';
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Db } from '../../../src/db/index.ts';
import { hashPassword } from '../../../src/passwords.ts';
import { setCredentials } from '../../../src/auth.ts';
import { DEFAULT_SETTINGS, saveSettings } from '../../../src/repo/settings.ts';
import {
  createAlert,
  markAlertFailed,
  markAlertSent,
} from '../../../src/repo/alerts.ts';
import { markScanFailed, queueScan } from '../../../src/repo/scans.ts';
import { updateImageAfterScan } from '../../../src/repo/images.ts';
import { seedSuccessfulScan } from '../../helpers/seed-scan.ts';
import type { NormalizedFinding } from '../../../src/domain/findings.ts';

export const TEST_PASSWORD = 'correct-horse-battery';
const SECRET_KEY = Buffer.alloc(32, 11);
const PROJECT_ROOT = new URL('../../../', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');

const PHP_IMAGE = `sha256:${'a'.repeat(64)}`;
const NGINX_IMAGE = `sha256:${'b'.repeat(64)}`;
const PHP_DIGEST = `sha256:${'c'.repeat(64)}`;

function nowMinus(hours: number): string {
  return new Date(Date.now() - hours * 3_600_000).toISOString();
}

async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      const port = typeof address === 'object' && address ? address.port : 0;
      server.close(() => resolve(port));
    });
  });
}

export async function createDataDir(): Promise<string> {
  return mkdtemp(join(tmpdir(), 'docksentinel-ui-'));
}

function finding(overrides: Partial<NormalizedFinding>): NormalizedFinding {
  return {
    target: 'debian 11.7',
    class: 'os-pkgs',
    type: 'debian',
    vulnId: 'CVE-2024-0000',
    pkgName: 'openssl',
    installedVersion: '1.1.1k',
    fixedVersion: '1.1.1n',
    severity: 'HIGH',
    status: 'fixed',
    title: 'Example vulnerability',
    primaryUrl: 'https://example.com/advisory',
    cvssScore: 8.1,
    cvssSource: 'nvd',
    cvssVector: null,
    publishedAt: '2025-01-01T00:00:00Z',
    modifiedAt: '2025-02-01T00:00:00Z',
    ...overrides,
  };
}

/** Seeds a realistic instance so the UI can be exercised without Docker or a scanner. */
export async function seedInstance(dataDir: string): Promise<void> {
  const db = Db.open(join(dataDir, 'docksentinel.db'));
  try {
    const now = new Date().toISOString();
    db.run(
      `INSERT INTO environments (name, kind, address, enabled, scan_enabled, status, status_message, last_contact_at,
         last_discovery_at, created_at, updated_at)
       VALUES ('Unraid', 'unix', '/var/run/docker.sock', 1, 1, 'online', NULL, ?, ?, ?, ?)`,
      [now, now, nowMinus(240), now],
    );
    db.run(
      `INSERT INTO environments (name, kind, address, enabled, scan_enabled, status, status_message, last_contact_at,
         last_discovery_at, created_at, updated_at)
       VALUES ('Remote Office', 'tcp', '10.10.0.5:2375', 1, 1, 'offline', 'connect ECONNREFUSED 10.10.0.5:2375', ?, ?, ?, ?)`,
      [nowMinus(3), nowMinus(60), nowMinus(72), now],
    );

    saveSettings(db, SECRET_KEY, {
      ...DEFAULT_SETTINGS,
      discoveryIntervalMinutes: 600,
      scanOnDiscovery: false,
      kevEnabled: false,
      alertOnStale: false,
      freshnessHours: 48,
    });

    setCredentials(db, 'admin', await hashPassword(TEST_PASSWORD));

    db.run(
      `INSERT INTO images (image_id, repo_digests, size_bytes, os_family, os_version, first_seen_at, updated_at)
       VALUES (?, ?, 104857600, 'debian', '11.7', ?, ?)`,
      [PHP_IMAGE, JSON.stringify([`php@${PHP_DIGEST}`]), nowMinus(240), now],
    );
    db.run(
      `INSERT INTO images (image_id, repo_digests, size_bytes, os_family, os_version, first_seen_at, updated_at)
       VALUES (?, '[]', 20971520, 'alpine', '3.19', ?, ?)`,
      [NGINX_IMAGE, nowMinus(240), now],
    );
    db.run(
      `INSERT INTO image_locations (image_id, environment_id, reference, tag, last_seen_at)
       VALUES (?, 1, 'php:8.1-apache', 'php:8.1-apache', ?)`,
      [PHP_IMAGE, now],
    );
    db.run(
      `INSERT INTO image_locations (image_id, environment_id, reference, tag, last_seen_at)
       VALUES (?, 1, 'nginx:1.25-alpine', 'nginx:1.25-alpine', ?)`,
      [NGINX_IMAGE, now],
    );

    const insertContainer = (
      id: string,
      name: string,
      imageRef: string,
      imageId: string,
      state: string,
      exposure: string,
      reason: string | null,
      labels: Record<string, string>,
      ports: unknown[],
      present: number,
    ): void => {
      db.run(
        `INSERT INTO containers (id, environment_id, name, image_ref, image_id, state, labels, ports, network_mode,
           exposure_state, exposure_reason, created_ts, present, first_seen_at, last_seen_at)
         VALUES (?, 1, ?, ?, ?, ?, ?, ?, 'bridge', ?, ?, ?, ?, ?, ?)`,
        [
          id,
          name,
          imageRef,
          imageId,
          state,
          JSON.stringify(labels),
          JSON.stringify(ports),
          exposure,
          reason,
          nowMinus(300),
          present,
          nowMinus(240),
          present === 1 ? now : nowMinus(6),
        ],
      );
    };

    insertContainer('1'.repeat(64), 'php-app', 'php:8.1-apache', PHP_IMAGE, 'running', 'confirmed', 'Declared Internet-facing by the docksentinel.exposure container label', { 'docksentinel.exposure': 'internet', 'docksentinel.criticality': 'critical' }, [{ ip: '0.0.0.0', privatePort: 80, publicPort: 8080, type: 'tcp' }], 1);
    insertContainer('2'.repeat(64), 'php-worker', 'php:8.1-apache', PHP_IMAGE, 'running', 'internal', 'No published host ports', {}, [], 1);
    insertContainer('3'.repeat(64), 'reverse-proxy', 'nginx:1.25-alpine', NGINX_IMAGE, 'running', 'potential', 'Published host port 443/tcp on all interfaces', {}, [{ ip: '0.0.0.0', privatePort: 443, publicPort: 443, type: 'tcp' }], 1);
    insertContainer('4'.repeat(64), 'old-debug-shell', 'php:8.1-apache', PHP_IMAGE, 'exited', 'unknown', 'Container is not running; exposure cannot be assessed', {}, [], 0);

    const phpFindings: NormalizedFinding[] = [
      finding({ vulnId: 'CVE-2024-1111', pkgName: 'openssl', installedVersion: '1.1.1k', fixedVersion: '1.1.1n', severity: 'CRITICAL', title: 'OpenSSL buffer overrun' }),
      finding({ vulnId: 'CVE-2024-2222', pkgName: 'curl', installedVersion: '7.74.0', fixedVersion: null, severity: 'CRITICAL', title: 'curl heap corruption' }),
      finding({ vulnId: 'CVE-2023-3333', pkgName: 'libxml2', installedVersion: '2.9.10', fixedVersion: '2.9.14', severity: 'HIGH', title: 'libxml2 use after free' }),
      finding({ vulnId: 'CVE-2023-4444', pkgName: 'bash', installedVersion: '5.1', fixedVersion: '5.1-2+deb11u2', severity: 'HIGH', title: 'bash stack overflow' }),
      finding({ vulnId: 'CVE-2022-5555', pkgName: 'zlib1g', installedVersion: '1.2.11', fixedVersion: null, severity: 'MEDIUM', title: 'zlib out of bounds write' }),
      finding({ vulnId: 'CVE-2022-6666', pkgName: 'sudo', installedVersion: '1.9.5', fixedVersion: null, severity: 'LOW', title: 'sudo information disclosure' }),
    ];
    seedSuccessfulScan(db, {
      imageId: PHP_IMAGE,
      environmentId: 1,
      imageRef: 'php:8.1-apache',
      findings: phpFindings,
      finishedAt: nowMinus(2),
    });
    seedSuccessfulScan(db, {
      imageId: NGINX_IMAGE,
      environmentId: 1,
      imageRef: 'nginx:1.25-alpine',
      findings: [],
      finishedAt: nowMinus(1),
    });

    db.run(
      `INSERT INTO kev (cve_id, date_added, synced_at) VALUES ('CVE-2024-1111', '2026-09-01', ?)`,
      [nowMinus(12)],
    );
    db.run(`UPDATE findings SET kev = 0, kev_added_at = NULL`);
    db.run(`UPDATE findings SET kev = 1, kev_added_at = '2026-09-01' WHERE vuln_id = 'CVE-2024-1111'`);
    db.run(
      `UPDATE kev_sync SET status = 'ok', synced_at = ?, catalog_version = '2026.10.01', entry_count = 1, error = NULL WHERE id = 1`,
      [nowMinus(12)],
    );

    const failedScanId = queueScan(
      db,
      {
        environmentId: 1,
        imageId: PHP_IMAGE,
        imageRef: 'php:8.1-apache',
        profile: 'standard',
        trigger: 'schedule',
      },
      false,
    );
    if (failedScanId) {
      db.run(`UPDATE scans SET status = 'running', started_at = ? WHERE id = ?`, [nowMinus(4), failedScanId]);
      markScanFailed(db, failedScanId, {
        errorCode: 'image_export_failed',
        errorMessage: 'Docker image export returned HTTP 500: simulated daemon failure',
        exitCode: null,
      });
      updateImageAfterScan(db, PHP_IMAGE, null, 'failed', null, null);
    }

    const sentAlert = createAlert(db, {
      dedupeKey: 'new:seed:1',
      kind: 'new_findings',
      severity: 'CRITICAL',
      environmentId: 1,
      imageId: PHP_IMAGE,
      title: '2 critical, 2 high in php:8.1-apache',
      body: '**2 CRITICAL, 2 HIGH risk findings** were found by a successful scan.\n\n**Affected:** `php-app`, `php-worker`',
      priority: 5,
      tags: 'rotating_light',
    });
    if (sentAlert) {
      markAlertSent(db, sentAlert);
      db.run('UPDATE alerts SET attempts = 1 WHERE id = ?', [sentAlert]);
    }

    const failedAlert = createAlert(db, {
      dedupeKey: 'kev:seed:1',
      kind: 'known_exploited',
      severity: 'CRITICAL',
      environmentId: null,
      imageId: PHP_IMAGE,
      title: 'Known exploited vulnerability affects php:8.1-apache',
      body: '**CVE-2024-1111** is listed in CISA KEV.',
      priority: 5,
      tags: 'skull',
    });
    if (failedAlert) {
      markAlertFailed(db, failedAlert, 'ntfy returned HTTP 503: service unavailable', null);
      db.run('UPDATE alerts SET attempts = 3 WHERE id = ?', [failedAlert]);
    }
  } finally {
    db.close();
  }
}

export interface UiServer {
  url: string;
  stop: () => Promise<void>;
}

export async function startAppServer(dataDir: string): Promise<UiServer> {
  const webDist = join(PROJECT_ROOT, 'web', 'dist', 'index.html');
  if (!existsSync(webDist)) {
    execFileSync('npx', ['vite', 'build', '--config', 'web/vite.config.ts'], {
      cwd: PROJECT_ROOT,
      stdio: 'inherit',
      shell: true,
    });
  }

  const port = await freePort();
  const output: string[] = [];
  const child: ChildProcess = spawn(process.execPath, ['src/index.ts'], {
    cwd: PROJECT_ROOT,
    env: {
      ...process.env,
      DATA_DIR: dataDir,
      HOST: '127.0.0.1',
      PORT: String(port),
      SETUP_TOKEN: 'ui-setup-token',
      LOG_LEVEL: 'silent',
      DOCKSENTINEL_SECRET_KEY: SECRET_KEY.toString('hex'),
      KEV_URL: 'http://127.0.0.1:1/kev.json',
      NODE_ENV: 'test',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout?.on('data', (chunk: Buffer) => output.push(chunk.toString()));
  child.stderr?.on('data', (chunk: Buffer) => output.push(chunk.toString()));

  const url = `http://127.0.0.1:${port}`;
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`DockSentinel exited during startup:\n${output.join('')}`);
    }
    try {
      const response = await fetch(`${url}/api/health`);
      if (response.ok) {
        return {
          url,
          stop: async () => {
            if (child.exitCode === null) {
              child.kill();
              await new Promise<void>((resolve) => {
                const timer = setTimeout(() => {
                  if (child.exitCode === null) child.kill('SIGKILL');
                  resolve();
                }, 3000);
                child.once('exit', () => {
                  clearTimeout(timer);
                  resolve();
                });
              });
            }
          },
        };
      }
    } catch {
      // Server is not listening yet.
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  child.kill();
  throw new Error(`DockSentinel did not become ready:\n${output.join('')}`);
}

export async function cleanupDataDir(dataDir: string): Promise<void> {
  await rm(dataDir, { recursive: true, force: true }).catch(() => undefined);
}

export async function prepareSeededInstance(shotDir: string): Promise<{ server: UiServer; dataDir: string }> {
  await mkdir(shotDir, { recursive: true });
  const dataDir = await createDataDir();
  await seedInstance(dataDir);
  const server = await startAppServer(dataDir);
  return { server, dataDir };
}
