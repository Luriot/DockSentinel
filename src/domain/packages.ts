/**
 * Kernel packages describe the host kernel, not something a container image can fix: an image never
 * boots its own kernel. Their findings are stored and filterable, but excluded from counts and alerts
 * by default (they account for a large share of the noise on Debian-based images).
 */
const KERNEL_EXACT = ['linux-libc-dev'];
const KERNEL_PREFIXES = ['linux-image-', 'linux-headers-', 'linux-modules-', 'linux-kbuild-'];

export function isKernelPackage(pkgName: string): boolean {
  const name = pkgName.toLowerCase();
  return KERNEL_EXACT.includes(name) || KERNEL_PREFIXES.some((prefix) => name.startsWith(prefix));
}

/** SQL predicate on a package-name column (e.g. `f.pkg_name`) that keeps non-kernel rows. */
export function nonKernelPackageSql(column: string): string {
  const clauses = KERNEL_EXACT.map((name) => `${column} = '${name}'`);
  for (const prefix of KERNEL_PREFIXES) clauses.push(`${column} LIKE '${prefix}%'`);
  return `NOT (${clauses.join(' OR ')})`;
}

/** Removes findings whose package is configured as ignored (case-insensitive exact match). */
export function filterIgnoredPackages<T extends { pkgName: string }>(findings: T[], ignored: readonly string[]): T[] {
  if (ignored.length === 0) return findings;
  const names = new Set(ignored.map((name) => name.toLowerCase()));
  return findings.filter((finding) => !names.has(finding.pkgName.toLowerCase()));
}
