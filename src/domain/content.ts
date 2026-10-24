import type { Severity } from './severity.ts';
import type { SeverityCounts } from './findings.ts';

export type ContentKind = 'misconfiguration' | 'secret';
export type ContentScope = 'image' | 'image-config';

export interface NormalizedContentFinding {
  kind: ContentKind;
  scope: ContentScope;
  ruleId: string;
  category: string | null;
  severity: Severity;
  title: string;
  target: string;
  message: string | null;
  resolution: string | null;
  primaryUrl: string | null;
  startLine: number | null;
  endLine: number | null;
}

export interface ContentFindingRecord extends NormalizedContentFinding {
  id: number;
  imageId: string;
  episode: number;
  firstSeenAt: string;
  lastSeenAt: string;
  lastScanId: number | null;
  resolvedAt: string | null;
}

export function contentIdentity(finding: Pick<NormalizedContentFinding, 'kind' | 'scope' | 'ruleId' | 'target' | 'startLine'>): string {
  // JSON avoids embedded NUL delimiters: node:sqlite can truncate embedded NULs when binding
  // text, which made the stored identity differ from the in-memory identity on some Node versions.
  return JSON.stringify([finding.kind, finding.scope, finding.ruleId, finding.target, finding.startLine ?? 0]);
}

/** Counts content findings in the same shape used by scan rows; fixable is always zero. */
export function countContentSeverities(findings: readonly NormalizedContentFinding[]): SeverityCounts {
  const counts: SeverityCounts = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    UNKNOWN: 0,
    TOTAL: findings.length,
    FIXABLE: 0,
  };
  for (const finding of findings) counts[finding.severity] += 1;
  return counts;
}
