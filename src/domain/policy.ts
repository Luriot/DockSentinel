import { isSeverityAtLeast, maxSeverity, normalizeSeverity, type Severity } from './severity.ts';

export interface WorkloadPolicy {
  monitored: boolean;
  exposure: 'internet' | 'internal' | null;
  criticality: 'critical' | 'high' | 'normal' | 'low' | null;
  minSeverity: Severity | null;
  ignoredVulns: Set<string>;
}

export function parseWorkloadLabels(labels: Record<string, string> | null | undefined): WorkloadPolicy {
  const get = (name: string): string => {
    if (!labels) return '';
    const direct = labels[`docksentinel.${name}`];
    return (direct ?? '').trim();
  };

  const exposureRaw = get('exposure').toLowerCase();
  const exposure =
    exposureRaw === 'internet' || exposureRaw === 'public'
      ? ('internet' as const)
      : exposureRaw === 'internal' || exposureRaw === 'private' || exposureRaw === 'none'
        ? ('internal' as const)
        : null;

  const criticalityRaw = get('criticality').toLowerCase();
  const criticality =
    criticalityRaw === 'critical' || criticalityRaw === 'high' || criticalityRaw === 'normal' || criticalityRaw === 'low'
      ? (criticalityRaw as 'critical' | 'high' | 'normal' | 'low')
      : null;

  const severityRaw = get('alert-min-severity').toUpperCase();
  const minSeverity = isSeverityName(severityRaw) ? normalizeSeverity(severityRaw) : null;

  const ignoredVulns = new Set(
    get('ignore-vulns')
      .split(',')
      .map((value) => value.trim().toUpperCase())
      .filter(Boolean),
  );

  const monitorRaw = get('monitor').toLowerCase();
  const monitored = !(monitorRaw === 'false' || monitorRaw === 'no' || monitorRaw === 'off' || monitorRaw === '0');

  return { monitored, exposure, criticality, minSeverity, ignoredVulns };
}

function isSeverityName(value: string): boolean {
  return value === 'CRITICAL' || value === 'HIGH' || value === 'MEDIUM' || value === 'LOW' || value === 'UNKNOWN';
}

/**
 * Alert threshold resolution: the stricter of the global and per-environment thresholds, unless a
 * workload label overrides it explicitly. Unknown values are ignored rather than lowered.
 */
export function resolveAlertThreshold(global: Severity, environment: Severity, workload: WorkloadPolicy): Severity {
  const base = maxSeverity(global, environment);
  if (workload.minSeverity) return workload.minSeverity;
  return base;
}

export function shouldAlertForFinding(
  severity: Severity,
  threshold: Severity,
  vulnId: string,
  workload: WorkloadPolicy,
): boolean {
  if (!workload.monitored) return false;
  if (workload.ignoredVulns.has(vulnId.toUpperCase())) return false;
  return isSeverityAtLeast(severity, threshold);
}
