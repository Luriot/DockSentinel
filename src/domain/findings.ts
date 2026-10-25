import type { Severity } from '../domain/severity.ts';
import { severityRank } from '../domain/severity.ts';

export interface NormalizedFinding {
  target: string;
  class: string | null;
  type: string | null;
  vulnId: string;
  pkgName: string;
  installedVersion: string;
  fixedVersion: string | null;
  severity: Severity;
  status: string | null;
  title: string | null;
  primaryUrl: string | null;
  cvssScore: number | null;
  cvssSource: string | null;
  cvssVector: string | null;
  publishedAt: string | null;
  modifiedAt: string | null;
}

export type TriageStatus = 'none' | 'acknowledged' | 'ignored' | 'false_positive';

export interface StoredFinding {
  id: number;
  target: string;
  vulnId: string;
  pkgName: string;
  installedVersion: string;
  fixedVersion: string | null;
  severity: Severity;
  title: string | null;
  primaryUrl: string | null;
  episode: number;
}

export function findingIdentity(f: {
  target: string;
  vulnId: string;
  pkgName: string;
  installedVersion: string;
}): string {
  return `${f.target}\u0000${f.vulnId}\u0000${f.pkgName}\u0000${f.installedVersion}`;
}

/**
 * Trivy reports the same package/version/CVE once per target (Go binaries, several files). The finding
 * is about the package, so only one row per image is kept: highest severity wins, then the lowest target
 * name, which keeps the choice stable across rescans.
 */
export function dedupeFindings(findings: NormalizedFinding[]): NormalizedFinding[] {
  const byPackage = new Map<string, NormalizedFinding>();
  for (const finding of findings) {
    const key = `${finding.vulnId}\u0000${finding.pkgName}\u0000${finding.installedVersion}`;
    const existing = byPackage.get(key);
    if (!existing) {
      byPackage.set(key, finding);
      continue;
    }
    const stronger =
      severityRank(finding.severity) !== severityRank(existing.severity)
        ? severityRank(finding.severity) > severityRank(existing.severity)
        : finding.target.localeCompare(existing.target) < 0;
    if (stronger) byPackage.set(key, finding);
  }
  return [...byPackage.values()];
}

export interface FindingChange {
  finding: StoredFinding;
  changes: { severity?: { from: Severity; to: Severity }; fixedVersion?: { from: string | null; to: string | null } };
}

export interface FindingDiff {
  appeared: NormalizedFinding[];
  resolved: StoredFinding[];
  changed: FindingChange[];
  unchanged: NormalizedFinding[];
}

/**
 * Compares the previous open findings of an image with a fresh scan result. A finding that is
 * absent from a successfully parsed report is resolved; it is never inferred from a failed scan.
 */
export function diffFindings(previous: StoredFinding[], next: NormalizedFinding[]): FindingDiff {
  const previousByKey = new Map(previous.map((finding) => [findingIdentity(finding), finding]));
  const nextKeys = new Set<string>();
  const appeared: NormalizedFinding[] = [];
  const changed: FindingChange[] = [];
  const unchanged: NormalizedFinding[] = [];

  for (const finding of next) {
    const key = findingIdentity(finding);
    nextKeys.add(key);
    const before = previousByKey.get(key);
    if (!before) {
      appeared.push(finding);
      continue;
    }
    const changes: FindingChange['changes'] = {};
    if (before.severity !== finding.severity) changes.severity = { from: before.severity, to: finding.severity };
    if ((before.fixedVersion ?? null) !== (finding.fixedVersion ?? null)) {
      changes.fixedVersion = { from: before.fixedVersion ?? null, to: finding.fixedVersion ?? null };
    }
    if (Object.keys(changes).length > 0) changed.push({ finding: before, changes });
    else unchanged.push(finding);
  }

  const resolved = previous.filter((finding) => !nextKeys.has(findingIdentity(finding)));
  return { appeared, resolved, changed, unchanged };
}

export interface SeverityCounts {
  CRITICAL: number;
  HIGH: number;
  MEDIUM: number;
  LOW: number;
  UNKNOWN: number;
  TOTAL: number;
  FIXABLE: number;
}

export function countSeverities(findings: readonly NormalizedFinding[]): SeverityCounts {
  const counts: SeverityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0, TOTAL: findings.length, FIXABLE: 0 };
  for (const finding of findings) {
    counts[finding.severity] += 1;
    if (finding.fixedVersion) counts.FIXABLE += 1;
  }
  return counts;
}
