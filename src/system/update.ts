export interface UpdateStatus {
  state: 'unknown' | 'current' | 'available' | 'error';
  currentVersion: string;
  latestVersion: string | null;
  url: string | null;
  checkedAt: string;
  message: string;
}

function numericVersion(value: string): number[] {
  return value
    .replace(/^v/i, '')
    .split(/[.+-]/)
    .map((part) => Number.parseInt(part, 10))
    .filter((part) => Number.isFinite(part));
}

function isNewer(latest: string, current: string): boolean {
  const a = numericVersion(latest);
  const b = numericVersion(current);
  for (let index = 0; index < Math.max(a.length, b.length); index += 1) {
    const left = a[index] ?? 0;
    const right = b[index] ?? 0;
    if (left !== right) return left > right;
  }
  return false;
}

export async function checkForUpdates(
  currentVersion: string,
  fetchImpl: typeof fetch = fetch,
): Promise<UpdateStatus> {
  const checkedAt = new Date().toISOString();
  try {
    const response = await fetchImpl('https://api.github.com/repos/Luriot/DockSentinel/releases/latest', {
      headers: { Accept: 'application/vnd.github+json', 'User-Agent': 'DockSentinel' },
      signal: AbortSignal.timeout(8_000),
    });
    if (response.status === 404) {
      return {
        state: 'unknown',
        currentVersion,
        latestVersion: null,
        url: null,
        checkedAt,
        message: 'No published GitHub release was found.',
      };
    }
    if (!response.ok) {
      return {
        state: 'error',
        currentVersion,
        latestVersion: null,
        url: null,
        checkedAt,
        message: `GitHub returned HTTP ${response.status}.`,
      };
    }
    const data = (await response.json()) as { tag_name?: unknown; html_url?: unknown };
    const latest = typeof data.tag_name === 'string' ? data.tag_name.replace(/^v/i, '') : null;
    if (!latest) {
      return { state: 'unknown', currentVersion, latestVersion: null, url: null, checkedAt, message: 'Release metadata had no version.' };
    }
    const available = isNewer(latest, currentVersion);
    return {
      state: available ? 'available' : 'current',
      currentVersion,
      latestVersion: latest,
      url: typeof data.html_url === 'string' ? data.html_url : null,
      checkedAt,
      message: available ? `Version ${latest} is available.` : 'You are running the latest release.',
    };
  } catch (error) {
    return {
      state: 'error',
      currentVersion,
      latestVersion: null,
      url: null,
      checkedAt,
      message: error instanceof Error ? error.message : 'Update check failed.',
    };
  }
}
