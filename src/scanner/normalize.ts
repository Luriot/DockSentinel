import { isValidDateString, parseCvss, validateReference } from './validate.ts';
import { normalizeSeverity, type Severity } from '../domain/severity.ts';
import {
  contentIdentity,
  type ContentScope,
  type NormalizedContentFinding,
} from '../domain/content.ts';

export class InvalidReportError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidReportError';
  }
}

export interface ParsedFinding {
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

export interface ParsedReport {
  findings: ParsedFinding[];
  os: { family: string | null; version: string | null } | null;
  imageId: string | null;
  artifactName: string | null;
  warnings: string[];
}

export interface ParsedContentReport {
  findings: NormalizedContentFinding[];
  warnings: string[];
}

function text(value: unknown, maxLength: number): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  return trimmed.slice(0, maxLength);
}

function requiredText(value: unknown, maxLength: number): string | null {
  const parsed = text(value, maxLength);
  return parsed === null ? null : parsed;
}

function nvdFallback(vulnId: string): string | null {
  return /^CVE-\d{4}-\d{4,}$/i.test(vulnId) ? `https://nvd.nist.gov/vuln/detail/${vulnId.toUpperCase()}` : null;
}

/**
 * Parses Trivy's JSON report. Only a structurally valid report with trustworthy entries is
 * accepted: a malformed or truncated report must fail the scan rather than look clean.
 */
export function parseTrivyReport(rawText: string): ParsedReport {
  let root: unknown;
  try {
    root = JSON.parse(rawText);
  } catch {
    throw new InvalidReportError('Scanner output is not valid JSON');
  }
  if (!root || typeof root !== 'object' || Array.isArray(root)) {
    throw new InvalidReportError('Scanner output is not a JSON object');
  }
  const report = root as Record<string, unknown>;
  const schemaVersion = report.SchemaVersion;
  const artifactName = text(report.ArtifactName, 500);
  const hasTrivyShape = typeof schemaVersion === 'number' || artifactName !== null;
  if (!hasTrivyShape) throw new InvalidReportError('Scanner output does not look like a Trivy report');

  const warnings: string[] = [];
  const results = report.Results;
  const findingsByKey = new Map<string, ParsedFinding>();
  let malformedEntries = 0;
  let validResults = 0;

  if (results !== undefined && results !== null) {
    if (!Array.isArray(results)) throw new InvalidReportError('Scanner report Results is not an array');
    for (const result of results) {
      if (!result || typeof result !== 'object' || Array.isArray(result)) {
        malformedEntries += 1;
        continue;
      }
      const entry = result as Record<string, unknown>;
      const target = requiredText(entry.Target, 500);
      if (!target) {
        malformedEntries += 1;
        continue;
      }
      validResults += 1;
      const classValue = text(entry.Class, 40);
      const typeValue = text(entry.Type, 60);
      const vulnerabilities = entry.Vulnerabilities;
      if (vulnerabilities === undefined || vulnerabilities === null) continue;
      if (!Array.isArray(vulnerabilities)) {
        malformedEntries += 1;
        continue;
      }

      for (const vulnerability of vulnerabilities) {
        if (!vulnerability || typeof vulnerability !== 'object' || Array.isArray(vulnerability)) {
          malformedEntries += 1;
          continue;
        }
        const vuln = vulnerability as Record<string, unknown>;
        const vulnId = requiredText(vuln.VulnerabilityID, 100);
        const pkgName = requiredText(vuln.PkgName, 300);
        if (!vulnId || !pkgName) {
          malformedEntries += 1;
          continue;
        }
        const installedVersion = text(vuln.InstalledVersion, 200) ?? '';
        const id = `${target}\u0000${vulnId}\u0000${pkgName}\u0000${installedVersion}`;
        const cvss = parseCvss(vuln.CVSS);
        const primary = validateReference(vuln.PrimaryURL) ?? nvdFallback(vulnId);

        const parsed: ParsedFinding = {
          target,
          class: classValue,
          type: typeValue,
          vulnId,
          pkgName,
          installedVersion,
          fixedVersion: text(vuln.FixedVersion, 300),
          severity: normalizeSeverity(vuln.Severity),
          status: text(vuln.Status, 60),
          title: text(vuln.Title, 500),
          primaryUrl: primary,
          cvssScore: cvss.score,
          cvssSource: cvss.source,
          cvssVector: cvss.vector,
          publishedAt: isValidDateString(vuln.PublishedDate) ? (vuln.PublishedDate as string) : null,
          modifiedAt: isValidDateString(vuln.LastModifiedDate) ? (vuln.LastModifiedDate as string) : null,
        };

        const existing = findingsByKey.get(id);
        if (existing) {
          // Duplicate identity within one report: keep a deterministic survivor.
          if ((parsed.cvssScore ?? 0) > (existing.cvssScore ?? 0)) findingsByKey.set(id, parsed);
        } else {
          findingsByKey.set(id, parsed);
        }
      }
    }
  }

  if (malformedEntries > 0) warnings.push(`${malformedEntries} malformed scanner ${malformedEntries === 1 ? 'entry was' : 'entries were'} ignored`);
  if (results !== undefined && results !== null && Array.isArray(results) && results.length > 0 && validResults === 0) {
    throw new InvalidReportError('Scanner report contained no usable results');
  }
  if (findingsByKey.size === 0 && malformedEntries > 0) {
    throw new InvalidReportError('Scanner report was malformed and could not be used');
  }

  const metadata = report.Metadata;
  let os: ParsedReport['os'] = null;
  if (metadata && typeof metadata === 'object' && !Array.isArray(metadata)) {
    const osRaw = (metadata as Record<string, unknown>).OS;
    if (osRaw && typeof osRaw === 'object' && !Array.isArray(osRaw)) {
      const osRecord = osRaw as Record<string, unknown>;
      const family = text(osRecord.Family, 60);
      const version = text(osRecord.Name, 60);
      if (family || version) os = { family, version };
    }
  }

  const rawImageId = metadata && typeof metadata === 'object' ? (metadata as Record<string, unknown>).ImageID : null;
  const imageId = typeof rawImageId === 'string' && /^sha256:[a-f0-9]{64}$/i.test(rawImageId) ? rawImageId.toLowerCase() : null;

  return {
    findings: [...findingsByKey.values()],
    os,
    imageId,
    artifactName,
    warnings,
  };
}


function lineNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= 10_000_000 ? value : null;
}

function contentTarget(
  raw: string,
  archive: { path: string; base: string },
): { scope: ContentScope; target: string } {
  let relative = raw;
  if (relative === archive.path) relative = archive.base;
  else if (relative.startsWith(`${archive.path} `)) relative = `${archive.base}${relative.slice(archive.path.length)}`;
  else if (relative.startsWith(`${archive.path}/`)) relative = relative.slice(archive.path.length + 1);
  if (relative === archive.base || relative === '' || relative === 'image config') {
    return { scope: 'image-config', target: 'image config' };
  }
  const target = relative.replace(/^\.?\//, '').slice(0, 500);
  return { scope: 'image', target: target || 'image' };
}

function severityOf(value: unknown): Severity {
  return normalizeSeverity(value);
}

/**
 * Parses only the metadata of Trivy misconfiguration and secret results. The raw `Match`, `Code`
 * and layer contents are deliberately never copied into the returned structure: secrets must not
 * be persisted, logged, shown in the API, or included in notifications.
 */
export function parseTrivyContentReport(
  rawText: string,
  archive: { path: string; base: string },
): ParsedContentReport {
  let root: unknown;
  try {
    root = JSON.parse(rawText);
  } catch {
    throw new InvalidReportError('Scanner output is not valid JSON');
  }
  if (!root || typeof root !== 'object' || Array.isArray(root)) {
    throw new InvalidReportError('Scanner output is not a JSON object');
  }
  const report = root as Record<string, unknown>;
  if (typeof report.SchemaVersion !== 'number' && text(report.ArtifactName, 500) === null) {
    throw new InvalidReportError('Scanner output does not look like a Trivy report');
  }

  const warnings: string[] = [];
  const findings = new Map<string, NormalizedContentFinding>();
  let malformedEntries = 0;
  let validResults = 0;
  const results = report.Results;

  if (results !== undefined && results !== null) {
    if (!Array.isArray(results)) throw new InvalidReportError('Scanner report Results is not an array');
    for (const result of results) {
      if (!result || typeof result !== 'object' || Array.isArray(result)) {
        malformedEntries += 1;
        continue;
      }
      const entry = result as Record<string, unknown>;
      const rawTarget = text(entry.Target, 1000);
      if (!rawTarget) {
        malformedEntries += 1;
        continue;
      }
      validResults += 1;
      const location = contentTarget(rawTarget, archive);

      const misconfigurations = entry.Misconfigurations;
      if (misconfigurations !== undefined && misconfigurations !== null) {
        if (!Array.isArray(misconfigurations)) {
          malformedEntries += 1;
        } else {
          for (const item of misconfigurations) {
            if (!item || typeof item !== 'object' || Array.isArray(item)) {
              malformedEntries += 1;
              continue;
            }
            const record = item as Record<string, unknown>;
            const ruleId = text(record.ID, 100);
            if (!ruleId) {
              malformedEntries += 1;
              continue;
            }
            const cause = record.CauseMetadata;
            const causeRecord =
              cause && typeof cause === 'object' && !Array.isArray(cause) ? (cause as Record<string, unknown>) : null;
            const finding: NormalizedContentFinding = {
              kind: 'misconfiguration',
              scope: location.scope,
              ruleId,
              category: text(record.Type, 120),
              severity: severityOf(record.Severity),
              title: text(record.Title, 500) ?? ruleId,
              target: location.target,
              message: text(record.Message, 1000),
              resolution: text(record.Resolution, 1000),
              primaryUrl: validateReference(record.PrimaryURL),
              startLine: lineNumber(causeRecord?.StartLine),
              endLine: lineNumber(causeRecord?.EndLine),
            };
            keepContentFinding(findings, finding);
          }
        }
      }

      const secrets = entry.Secrets;
      if (secrets !== undefined && secrets !== null) {
        if (!Array.isArray(secrets)) {
          malformedEntries += 1;
        } else {
          for (const item of secrets) {
            if (!item || typeof item !== 'object' || Array.isArray(item)) {
              malformedEntries += 1;
              continue;
            }
            const record = item as Record<string, unknown>;
            const ruleId = text(record.RuleID, 100);
            if (!ruleId) {
              malformedEntries += 1;
              continue;
            }
            const finding: NormalizedContentFinding = {
              kind: 'secret',
              scope: location.scope,
              ruleId,
              category: text(record.Category, 120),
              severity: severityOf(record.Severity),
              title: text(record.Title, 500) ?? ruleId,
              target: location.target,
              message: null,
              resolution: null,
              primaryUrl: null,
              startLine: lineNumber(record.StartLine),
              endLine: lineNumber(record.EndLine),
            };
            keepContentFinding(findings, finding);
          }
        }
      }
    }
  }

  if (malformedEntries > 0) {
    warnings.push(
      `${malformedEntries} malformed scanner ${malformedEntries === 1 ? 'entry was' : 'entries were'} ignored`,
    );
  }
  if (results !== undefined && results !== null && Array.isArray(results) && results.length > 0 && validResults === 0) {
    throw new InvalidReportError('Scanner report contained no usable results');
  }
  if (findings.size === 0 && malformedEntries > 0) {
    throw new InvalidReportError('Scanner report was malformed and could not be used');
  }
  return { findings: [...findings.values()], warnings };
}

function keepContentFinding(map: Map<string, NormalizedContentFinding>, finding: NormalizedContentFinding): void {
  const key = contentIdentity(finding);
  const existing = map.get(key);
  if (!existing || severityRank(finding.severity) > severityRank(existing.severity)) map.set(key, finding);
}

function severityRank(severity: Severity): number {
  return severity === 'CRITICAL' ? 4 : severity === 'HIGH' ? 3 : severity === 'MEDIUM' ? 2 : severity === 'LOW' ? 1 : 0;
}
