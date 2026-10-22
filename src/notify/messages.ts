import type { ContainerSummary } from '../repo/containers.ts';
import type { NormalizedFinding, StoredFinding } from '../domain/findings.ts';
import type { Severity } from '../domain/severity.ts';
import { severityRank } from '../domain/severity.ts';
import type { ScanRecord } from '../repo/scans.ts';

export interface ImageAlertContext {
  imageId: string;
  displayRef: string;
  references: { reference: string; tag: string | null; environmentName: string }[];
  containers: ContainerSummary[];
  environmentNames: string[];
}

export interface BuiltMessage {
  title: string;
  body: string;
  severity: Severity | null;
  priority: number;
  tags: string[];
}

function formatUtc(iso: string | null | undefined): string {
  if (!iso) return 'unknown time';
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return 'unknown time';
  return `${date.toISOString().slice(0, 16).replace('T', ' ')} UTC`;
}

function exposurePhrase(container: ContainerSummary): string {
  if (container.exposure === 'confirmed') return 'Internet exposure declared';
  if (container.exposure === 'potential') return container.exposureReason ?? 'published host port';
  if (container.exposure === 'internal') return 'no published ports';
  return 'not running';
}

function containerSummary(context: ImageAlertContext): string {
  const present = context.containers.filter((container) => container.present);
  if (present.length === 0) return '_No container currently uses this image._';
  const shown = present.slice(0, 4).map(
    (container) =>
      `\`${container.name}\` (${container.environmentName}, ${container.state}, ${exposurePhrase(container)})`,
  );
  const remaining = present.length - 4;
  return shown.join(', ') + (remaining > 0 ? `, +${remaining} more` : '');
}

function linkLine(publicUrl: string | null | undefined, path: string): string | null {
  if (!publicUrl) return null;
  const base = publicUrl.replace(/\/+$/, '');
  return `[Open DockSentinel](${base}${path})`;
}

function severityCounts(findings: { severity: Severity }[]): string {
  const counts = new Map<Severity, number>();
  for (const finding of findings) counts.set(finding.severity, (counts.get(finding.severity) ?? 0) + 1);
  return [...counts.entries()]
    .sort((a, b) => severityRank(b[0]) - severityRank(a[0]))
    .map(([severity, count]) => `${count} ${severity}`)
    .join(', ');
}

function highestSeverity(severities: Severity[]): Severity {
  return severities.reduce<Severity>(
    (highest, current) => (severityRank(current) > severityRank(highest) ? current : highest),
    'UNKNOWN',
  );
}

function findingLine(finding: NormalizedFinding, kev: boolean): string {
  const fix = finding.fixedVersion ? ` → \`${finding.fixedVersion}\`` : ' _(no fix listed)_';
  const link = finding.primaryUrl ? ` — [details](${finding.primaryUrl})` : '';
  const kevMarker = kev ? ' **[known exploited]**' : '';
  return `- **${finding.severity}** \`${finding.vulnId}\` ${finding.pkgName} \`${finding.installedVersion}\`${fix}${kevMarker}${link}`;
}

export function newFindingsMessage(
  context: ImageAlertContext,
  scan: ScanRecord,
  findings: NormalizedFinding[],
  kevIds: Set<string>,
  publicUrl: string | null,
): BuiltMessage {
  const severity = highestSeverity(findings.map((finding) => finding.severity));
  const critical = findings.filter((finding) => finding.severity === 'CRITICAL').length;
  const high = findings.filter((finding) => finding.severity === 'HIGH').length;
  const fixable = findings.filter((finding) => finding.fixedVersion).length;
  const kevCount = findings.filter((finding) => kevIds.has(finding.vulnId)).length;
  const title =
    critical > 0
      ? `${critical} critical${high > 0 ? `, ${high} high` : ''} in ${context.displayRef}`
      : `${high > 0 ? high : findings.length} new ${high > 0 ? 'high' : 'severity'} findings in ${context.displayRef}`;

  const shown = findings.slice(0, 8);
  const lines = [
    `**${severityCounts(findings)} risk findings** were found by a successful scan.`,
    '',
    `**Affected:** ${containerSummary(context)}`,
    `**Image:** \`${context.displayRef}\` (${context.imageId.slice(0, 19)}…)`,
    '',
    ...shown.map((finding) => findingLine(finding, kevIds.has(finding.vulnId))),
  ];
  if (findings.length > shown.length) lines.push(`- _and ${findings.length - shown.length} more in DockSentinel_`);
  lines.push('');
  lines.push(
    `Fix available for ${fixable} of ${findings.length}${kevCount > 0 ? ` · Known exploited: ${kevCount}` : ''}`,
  );
  lines.push(`Verified by a successful Trivy scan at ${formatUtc(scan.finishedAt ?? scan.startedAt)}.`);
  const link = linkLine(publicUrl, `/vulnerabilities?image=${encodeURIComponent(context.imageId)}`);
  if (link) {
    lines.push(link);
    lines.push('');
  }
  lines.push('_Image scan findings only; this is not runtime intrusion detection._');

  return {
    title: title.slice(0, 120),
    body: lines.join('\n'),
    severity,
    priority: severity === 'CRITICAL' ? 5 : severity === 'HIGH' ? 4 : 3,
    tags: severity === 'CRITICAL' ? ['rotating_light'] : severity === 'HIGH' ? ['warning'] : ['information_source'],
  };
}

export function resolvedFindingsMessage(
  context: ImageAlertContext,
  scan: ScanRecord,
  resolved: StoredFinding[],
  publicUrl: string | null,
): BuiltMessage {
  const severity = highestSeverity(resolved.map((finding) => finding.severity));
  const shown = resolved.slice(0, 8);
  const lines = [
    `**${resolved.length} ${resolved.length === 1 ? 'finding is' : 'findings are'} no longer reported** for a previously affected image.`,
    '',
    `**Image:** \`${context.displayRef}\` (${context.imageId.slice(0, 19)}…)`,
    `**Affected:** ${containerSummary(context)}`,
    '',
    ...shown.map(
      (finding) =>
        `- **${finding.severity}** \`${finding.vulnId}\` ${finding.pkgName} \`${finding.installedVersion}\``,
    ),
  ];
  if (resolved.length > shown.length) lines.push(`- _and ${resolved.length - shown.length} more_`);
  lines.push('');
  lines.push(
    `Confirmed by a successful scan at ${formatUtc(scan.finishedAt ?? scan.startedAt)}. A failed scan never reports a fix.`,
  );
  const link = linkLine(publicUrl, `/vulnerabilities?image=${encodeURIComponent(context.imageId)}&state=resolved`);
  if (link) lines.push(link);

  return {
    title: `${resolved.length} ${resolved.length === 1 ? 'finding' : 'findings'} resolved in ${context.displayRef}`.slice(0, 120),
    body: lines.join('\n'),
    severity,
    priority: 3,
    tags: ['white_check_mark'],
  };
}

export function knownExploitedMessage(
  context: ImageAlertContext,
  findings: { vulnId: string; pkgName: string; severity: Severity; title: string | null; primaryUrl: string | null }[],
  publicUrl: string | null,
): BuiltMessage {
  const severity = highestSeverity(findings.map((finding) => finding.severity));
  const shown = findings.slice(0, 8);
  const lines = [
    `**${findings.length} ${findings.length === 1 ? 'vulnerability' : 'vulnerabilities'} in your workloads ${findings.length === 1 ? 'is' : 'are'} listed in CISA's Known Exploited Vulnerabilities catalog.**`,
    '',
    `**Affected:** ${containerSummary(context)}`,
    `**Image:** \`${context.displayRef}\` (${context.imageId.slice(0, 19)}…)`,
    '',
    ...shown.map(
      (finding) =>
        `- **${finding.severity}** \`${finding.vulnId}\` ${finding.pkgName}${finding.title ? ` — ${finding.title.slice(0, 120)}` : ''}${
          finding.primaryUrl ? ` — [details](${finding.primaryUrl})` : ''
        }`,
    ),
  ];
  if (findings.length > shown.length) lines.push(`- _and ${findings.length - shown.length} more_`);
  lines.push('');
  lines.push('Known-exploited findings are prioritised because exploitation has been observed in the wild.');
  const link = linkLine(publicUrl, `/vulnerabilities?kev=true`);
  if (link) lines.push(link);

  return {
    title: `Known exploited vulnerability affects ${context.displayRef}`.slice(0, 120),
    body: lines.join('\n'),
    severity,
    priority: 5,
    tags: ['skull', 'rotating_light'],
  };
}

export function fixesAvailableMessage(
  context: ImageAlertContext,
  findings: NormalizedFinding[],
  publicUrl: string | null,
): BuiltMessage {
  const severity = highestSeverity(findings.map((finding) => finding.severity));
  const shown = findings.slice(0, 8);
  const lines = [
    `**Fixes are now listed for ${findings.length} ${findings.length === 1 ? 'finding' : 'findings'} affecting this image.**`,
    '',
    `**Affected:** ${containerSummary(context)}`,
    `**Image:** \`${context.displayRef}\` (${context.imageId.slice(0, 19)}…)`,
    '',
    ...shown.map(
      (finding) =>
        `- **${finding.severity}** \`${finding.vulnId}\` ${finding.pkgName} \`${finding.installedVersion}\` → \`${finding.fixedVersion ?? 'unknown'}\`${
          finding.primaryUrl ? ` — [details](${finding.primaryUrl})` : ''
        }`,
    ),
  ];
  if (findings.length > shown.length) lines.push(`- _and ${findings.length - shown.length} more_`);
  lines.push('');
  lines.push('Updating the image to a build that includes these fixed package versions clears the findings.');
  const link = linkLine(publicUrl, '/vulnerabilities?fixable=true');
  if (link) lines.push(link);
  return {
    title: `${findings.length} fix${findings.length === 1 ? '' : 'es'} available in ${context.displayRef}`.slice(0, 120),
    body: lines.join('\n'),
    severity,
    priority: severity === 'CRITICAL' ? 4 : 3,
    tags: ['wrench'],
  };
}

export function scanFailedMessage(
  context: ImageAlertContext | null,
  environmentName: string,
  imageRef: string,
  errorCode: string,
  errorMessage: string,
  publicUrl: string | null,
): BuiltMessage {
  const lines = [
    `**A vulnerability scan failed.** Findings from the previous successful scan are kept; this failure must not be read as a clean result.`,
    '',
    `- **Environment:** ${environmentName}`,
    `- **Image:** \`${imageRef}\``,
    ...(context ? [`- **Affected:** ${containerSummary(context)}`] : []),
    `- **Error:** \`${errorCode}\` — ${errorMessage.slice(0, 300)}`,
    '',
    'Use the Scans view to retry. Repeated failures usually indicate an unreachable Docker endpoint, a missing scanner, or a database update problem.',
  ];
  const link = linkLine(publicUrl, '/scans');
  if (link) lines.push(link);
  return {
    title: `Scan failed in ${environmentName}`.slice(0, 120),
    body: lines.join('\n'),
    severity: null,
    priority: 4,
    tags: ['warning'],
  };
}

export function staleScanMessage(
  context: ImageAlertContext,
  lastSuccessAt: string | null,
  publicUrl: string | null,
): BuiltMessage {
  const lines = [
    `**Scan results are stale.** No successful scan has completed within the configured freshness window.`,
    '',
    `- **Image:** \`${context.displayRef}\``,
    `- **Affected:** ${containerSummary(context)}`,
    `- **Last successful scan:** ${formatUtc(lastSuccessAt)}`,
    '',
    'Stale results mean newly disclosed vulnerabilities may not be reflected in this image.',
  ];
  const link = linkLine(publicUrl, '/scans');
  if (link) lines.push(link);
  return {
    title: `Stale scan results for ${context.displayRef}`.slice(0, 120),
    body: lines.join('\n'),
    severity: null,
    priority: 3,
    tags: ['hourglass'],
  };
}

export function testMessage(publicUrl: string | null): BuiltMessage {
  const lines = [
    '**DockSentinel is configured correctly.**',
    '',
    'This is a test notification from your Docker vulnerability monitoring instance.',
    `Sent at ${formatUtc(new Date().toISOString())}.`,
  ];
  const link = linkLine(publicUrl, '/');
  if (link) lines.push('', link);
  return {
    title: 'DockSentinel test notification',
    body: lines.join('\n'),
    severity: null,
    priority: 3,
    tags: ['test_tube'],
  };
}
