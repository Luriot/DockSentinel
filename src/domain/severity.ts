export const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'] as const;
export type Severity = (typeof SEVERITIES)[number];

const RANK: Record<Severity, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  UNKNOWN: 0,
};

/** Normalises scanner severity strings. Unknown or missing values become UNKNOWN, never a lower real severity. */
export function normalizeSeverity(raw: unknown): Severity {
  if (typeof raw !== 'string') return 'UNKNOWN';
  const value = raw.trim().toUpperCase();
  if (value === 'CRITICAL' || value === 'CRIT') return 'CRITICAL';
  if (value === 'HIGH') return 'HIGH';
  if (value === 'MEDIUM' || value === 'MODERATE' || value === 'MED') return 'MEDIUM';
  if (value === 'LOW') return 'LOW';
  return 'UNKNOWN';
}

export function severityRank(severity: Severity): number {
  return RANK[severity];
}

export function isSeverityAtLeast(severity: Severity, threshold: Severity): boolean {
  return RANK[severity] >= RANK[threshold];
}

export function maxSeverity(a: Severity, b: Severity): Severity {
  return RANK[a] >= RANK[b] ? a : b;
}

export function isSeverity(value: unknown): value is Severity {
  return typeof value === 'string' && (SEVERITIES as readonly string[]).includes(value);
}

