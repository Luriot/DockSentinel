import { test, expect, type Page } from '@playwright/test';
import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import {
  cleanupDataDir,
  createDataDir,
  prepareSeededInstance,
  startAppServer,
  TEST_PASSWORD,
  type UiServer,
} from './helpers/fixture.ts';

const SCREENS = join(process.cwd(), 'test-results', 'screens');

let server: UiServer;
let dataDir: string;

test.beforeAll(async () => {
  await mkdir(SCREENS, { recursive: true });
  const prepared = await prepareSeededInstance(SCREENS);
  server = prepared.server;
  dataDir = prepared.dataDir;
});

test.afterAll(async () => {
  await server?.stop();
  if (dataDir) await cleanupDataDir(dataDir);
});

async function login(page: Page): Promise<void> {
  const response = await page.request.post(`${server.url}/api/auth/login`, {
    data: { username: 'admin', password: TEST_PASSWORD },
  });
  expect(response.ok()).toBeTruthy();
}

test('sign-in validates credentials and loads the security overview', async ({ page }) => {
  await page.goto(server.url);
  await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();

  await page.getByLabel('Username').fill('admin');
  await page.getByLabel('Password').fill('wrong-password');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('alert')).toContainText('Invalid username or password');

  await page.getByLabel('Password').fill(TEST_PASSWORD);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('heading', { name: 'Overview', level: 1 })).toBeVisible();
  await expect(page.getByText('Critical open').first()).toBeVisible();
  await expect(page.locator('.kpi-value').first()).toHaveText('2');
  await page.screenshot({ path: join(SCREENS, '01-overview.png'), fullPage: true });
});

test('priority queue leads into the vulnerability workflow', async ({ page }) => {
  await login(page);
  await page.goto(server.url);

  const queue = page.locator('table').first();
  await expect(queue.locator('tbody tr')).toHaveCount(4);
  await expect(queue).toContainText('CVE-2024-1111');
  await expect(queue.locator('tbody tr').first().locator('.tier')).toHaveText('P1');

  await queue.locator('tbody tr').first().click();
  await expect(page).toHaveURL(/\/vulnerabilities\?q=CVE-2024-1111/);
  await expect(page.getByRole('heading', { name: 'Vulnerabilities', level: 1 })).toBeVisible();

  await page.locator('table tbody tr').first().click();
  const dialog = page.getByRole('dialog');
  await expect(dialog).toBeVisible();
  await expect(dialog.getByText('CVE-2024-1111').first()).toBeVisible();
  await expect(dialog.getByText('Why this priority')).toBeVisible();
  await expect(dialog.getByText('Known exploited', { exact: false }).first()).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(dialog).toBeHidden();
  await page.screenshot({ path: join(SCREENS, '02-vulnerabilities.png'), fullPage: true });
});

test('severity and known-exploited filters narrow findings', async ({ page }) => {
  await login(page);
  await page.goto(`${server.url}/vulnerabilities`);
  await expect(page.locator('table tbody tr')).toHaveCount(6);

  await page.getByRole('button', { name: 'Critical' }).click();
  await expect(page).toHaveURL(/severity=CRITICAL/);
  const rows = page.locator('table tbody tr');
  await expect(rows).toHaveCount(2);
  const criticalBadges = page.locator('table tbody tr .badge.sev-CRITICAL');
  await expect(criticalBadges).toHaveCount(2);

  await page.getByRole('button', { name: 'Known exploited' }).click();
  await expect(page.locator('table tbody tr')).toHaveCount(1);
  await expect(page.locator('table tbody tr').first()).toContainText('CVE-2024-1111');

  await page.getByRole('button', { name: 'Clear filters' }).click();
  await expect(page.locator('table tbody tr')).toHaveCount(6);
});

test('images are deduplicated and can queue a scan', async ({ page }) => {
  await login(page);
  await page.goto(`${server.url}/images`);
  await expect(page.locator('table tbody tr')).toHaveCount(2);
  await expect(page.locator('table')).toContainText('php:8.1-apache');
  await expect(page.locator('table')).toContainText('nginx:1.25-alpine');

  await page.locator('table tbody tr').first().getByRole('button', { name: 'Quick' }).click();
  await expect(page.getByRole('status').filter({ hasText: 'scan queued' })).toBeVisible();

  await page.locator('table tbody tr').first().click();
  const drawer = page.getByRole('dialog');
  await expect(drawer).toBeVisible();
  await expect(drawer.getByText('Image ID', { exact: true })).toBeVisible();
  await expect(drawer.getByText('Containers using this image')).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(drawer).toBeHidden();
  await page.screenshot({ path: join(SCREENS, '03-images.png'), fullPage: true });
});

test('environments show independent status and validate unsafe addresses', async ({ page }) => {
  await login(page);
  await page.goto(`${server.url}/environments`);
  await expect(page.getByRole('article', { name: 'Unraid' })).toBeVisible();
  await expect(page.getByRole('article', { name: 'Remote Office' })).toBeVisible();
  await expect(page.getByRole('article', { name: 'Remote Office' })).toContainText('Offline');
  await expect(page.getByText('Docker access is privileged.').first()).toBeVisible();

  await page.getByRole('button', { name: 'Connect remote host' }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel('Name').fill('Broken endpoint');
  await dialog.getByLabel('Socket path').fill('relative.sock');
  await dialog.getByRole('button', { name: 'Connect host' }).click();
  await expect(dialog.getByRole('alert')).toContainText('absolute path');
  await dialog.getByRole('button', { name: 'Cancel' }).click();
  await page.screenshot({ path: join(SCREENS, '04-environments.png'), fullPage: true });
});

test('scan activity distinguishes failures from clean scans', async ({ page }) => {
  await login(page);
  await page.goto(`${server.url}/scans`);
  await expect(page.getByRole('heading', { name: 'Scans', level: 1 })).toBeVisible();
  const failedRow = page.locator('table tbody tr').filter({ hasText: 'Failed' }).first();
  await expect(failedRow).toBeVisible();
  await failedRow.click();
  const drawer = page.getByRole('dialog');
  await expect(drawer.getByText('image_export_failed')).toBeVisible();
  await expect(drawer.getByText('not a clean result')).toBeVisible();
  await page.keyboard.press('Escape');
  await page.screenshot({ path: join(SCREENS, '05-scans.png'), fullPage: true });
});

test('notifications expose policy, delivery history and configuration errors', async ({ page }) => {
  await login(page);
  await page.goto(`${server.url}/notifications`);
  await expect(page.getByRole('heading', { name: 'ntfy delivery' })).toBeVisible();
  await expect(page.locator('table tbody tr')).toHaveCount(2);

  await page.locator('table tbody tr').first().click();
  const drawer = page.getByRole('dialog');
  await expect(drawer.getByText('Message')).toBeVisible();
  await page.keyboard.press('Escape');

  await page.getByLabel('Send notifications through ntfy').check();
  await page.getByRole('button', { name: 'Save notification settings' }).click();
  await expect(page.getByRole('alert')).toContainText(/topic/i);
  await page.screenshot({ path: join(SCREENS, '06-notifications.png'), fullPage: true });
});

test('configuration and secret findings show metadata without secret values', async ({ page }) => {
  await login(page);
  await page.goto(`${server.url}/content`);
  await expect(page.getByRole('heading', { name: 'Configuration & secrets', level: 1 })).toBeVisible();
  await expect(page.getByText('1 misconfigurations')).toBeVisible();
  await expect(page.getByText('1 secrets')).toBeVisible();
  await expect(page.locator('table tbody tr')).toHaveCount(2);
  await page.locator('table tbody tr').filter({ hasText: 'Secret' }).first().click();
  const drawer = page.getByRole('dialog');
  await expect(drawer.getByText('AWS Access Key ID')).toBeVisible();
  await expect(drawer.getByText(/matched secret value is not stored/)).toBeVisible();
  await page.keyboard.press('Escape');
  await page.screenshot({ path: join(SCREENS, '06b-content.png'), fullPage: true });
});

test('finding triage acknowledges and clears a finding, and exports CSV', async ({ page }) => {
  await login(page);
  await page.goto(`${server.url}/vulnerabilities`);
  await page.locator('table tbody tr').first().click();
  const drawer = page.getByRole('dialog');
  await expect(drawer.getByRole('heading', { name: 'Triage' })).toBeVisible();
  await drawer.getByRole('button', { name: 'Acknowledge' }).click();
  await expect(drawer.getByText('Acknowledged')).toBeVisible();
  await drawer.getByRole('button', { name: 'Clear' }).click();
  await expect(drawer.getByText('Not triaged')).toBeVisible();
  await page.keyboard.press('Escape');

  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Export CSV' }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toMatch(/\.csv$/);
});

test('system status shows storage, hosts and creates a backup', async ({ page }) => {
  await login(page);
  await page.goto(`${server.url}/status`);
  await expect(page.getByRole('heading', { name: 'System status', level: 1 })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Storage' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Docker hosts' })).toBeVisible();
  await page.getByRole('button', { name: 'Create backup' }).click();
  await expect(page.getByRole('status').filter({ hasText: 'Backup created' })).toBeVisible();
  await expect(page.locator('table').filter({ hasText: 'docksentinel-' }).first()).toBeVisible();
  await page.screenshot({ path: join(SCREENS, '07b-status.png'), fullPage: true });
});

test('settings changes are validated and persisted', async ({ page }) => {
  await login(page);
  await page.goto(`${server.url}/settings`);
  const freshness = page.locator('#freshnessHours');
  await expect(freshness).toHaveValue('48');
  await freshness.fill('36');
  const alertingCard = freshness.locator('xpath=ancestor::section');
  await alertingCard.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByRole('status').filter({ hasText: 'Settings saved' })).toBeVisible();

  await page.reload();
  await expect(page.locator('#freshnessHours')).toHaveValue('36');

  const misconfigToggle = page.getByLabel(/Enable misconfiguration scans/);
  await expect(misconfigToggle).toBeChecked();
  await misconfigToggle.uncheck();
  const scanningCard = misconfigToggle.locator('xpath=ancestor::section');
  await scanningCard.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByRole('status').filter({ hasText: 'Settings saved' })).toBeVisible();
  await page.reload();
  await expect(page.getByLabel(/Enable misconfiguration scans/)).not.toBeChecked();
  await page.screenshot({ path: join(SCREENS, '07-settings.png'), fullPage: true });
});

test('mobile layout has no horizontal overflow and keeps navigation reachable', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await login(page);
  await page.goto(server.url);
  await expect(page.getByRole('link', { name: 'Overview' }).first()).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Overview', level: 1 })).toBeVisible();
  const overflow = await page.evaluate('document.documentElement.scrollWidth - window.innerWidth');
  expect(overflow).toBeLessThanOrEqual(1);
  await page.screenshot({ path: join(SCREENS, '08-mobile-overview.png'), fullPage: true });
});

test('keyboard basics: skip link and current-page navigation are exposed', async ({ page }) => {
  await login(page);
  await page.goto(server.url);
  await expect(page.getByRole('heading', { name: 'Overview', level: 1 })).toBeVisible();
  await page.keyboard.press('Tab');
  await expect(page.locator('.skip-link')).toBeFocused();
  await expect(page.getByRole('link', { name: 'Overview' })).toHaveAttribute('aria-current', 'page');
});

test('first-run setup requires the setup token and creates the administrator', async ({ page }) => {
  const freshDir = await createDataDir();
  const freshServer = await startAppServer(freshDir);
  try {
    await page.goto(freshServer.url);
    await expect(page.getByRole('heading', { name: 'Create your admin account' })).toBeVisible();

    await page.getByLabel('Setup code').fill('wrong-token');
    await page.getByLabel('Username').fill('admin');
    await page.getByLabel('Password', { exact: true }).fill('a-long-and-strong-password');
    await page.getByLabel('Confirm password').fill('a-long-and-strong-password');
    await page.getByRole('button', { name: 'Create account and continue' }).click();
    await expect(page.getByRole('alert')).toContainText('Invalid setup token');

    await page.getByLabel('Setup code').fill('ui-setup-token');
    await page.getByRole('button', { name: 'Create account and continue' }).click();
    await expect(page.getByRole('heading', { name: 'Welcome', level: 1 })).toBeVisible();
    await expect(page.getByRole('heading', { name: "Let's connect Docker" })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Use Docker on this computer' })).toBeVisible();
    await page.screenshot({ path: join(SCREENS, '09-setup-empty.png'), fullPage: true });
  } finally {
    await freshServer.stop();
    await cleanupDataDir(freshDir);
  }
});
