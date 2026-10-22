/** Container labels DockSentinel understands. Everything else is ignored, which keeps labels that
 * may contain credentials (proxy auth, registry config) out of the database and UI. */
const PREFIX = 'docksentinel.';
const ALLOWED = new Set([
  'exposure',
  'monitor',
  'criticality',
  'alert-min-severity',
  'ignore-vulns',
]);

export function filterDocksentinelLabels(labels: Record<string, string> | null | undefined): Record<string, string> {
  const result: Record<string, string> = {};
  if (!labels || typeof labels !== 'object') return result;
  for (const [rawKey, rawValue] of Object.entries(labels)) {
    if (typeof rawValue !== 'string') continue;
    const key = rawKey.toLowerCase();
    if (!key.startsWith(PREFIX)) continue;
    const short = key.slice(PREFIX.length);
    if (ALLOWED.has(short)) result[key] = rawValue.slice(0, 200);
  }
  return result;
}
