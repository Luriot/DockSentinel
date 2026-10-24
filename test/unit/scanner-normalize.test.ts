import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseTrivyReport, InvalidReportError } from '../../src/scanner/normalize.ts';
import { scannerTimeoutMs } from '../../src/scanner/trivy.ts';
import { parseCvss, validateReference } from '../../src/scanner/validate.ts';

function report(results: unknown, extra: Record<string, unknown> = {}): string {
  return JSON.stringify({
    SchemaVersion: 2,
    ArtifactName: 'test:1',
    ArtifactType: 'container_image',
    Metadata: {
      ImageID: `sha256:${'a'.repeat(64)}`,
      OS: { Family: 'debian', Name: '11.7' },
    },
    Results: results,
    ...extra,
  });
}

test('parses a valid report, normalises fields and picks the highest CVSS score', () => {
  const parsed = parseTrivyReport(
    report([
      {
        Target: 'debian 11.7 (debian 11.7)',
        Class: 'os-pkgs',
        Type: 'debian',
        Vulnerabilities: [
          {
            VulnerabilityID: 'CVE-2024-0001',
            PkgName: 'openssl',
            InstalledVersion: '1.1.1k',
            FixedVersion: '1.1.1n',
            Severity: 'high',
            Status: 'fixed',
            Title: 'OpenSSL issue',
            PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2024-0001',
            CVSS: {
              nvd: { V3Score: 7.5, V3Vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' },
              redhat: { V3Score: 8.1, V3Vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H' },
            },
            PublishedDate: '2024-01-01T00:00:00Z',
            LastModifiedDate: '2024-02-01T00:00:00Z',
          },
        ],
      },
    ]),
  );

  assert.equal(parsed.findings.length, 1);
  const finding = parsed.findings[0]!;
  assert.equal(finding.vulnId, 'CVE-2024-0001');
  assert.equal(finding.severity, 'HIGH');
  assert.equal(finding.fixedVersion, '1.1.1n');
  assert.equal(finding.cvssScore, 8.1);
  assert.equal(finding.cvssSource, 'redhat');
  assert.equal(finding.class, 'os-pkgs');
  assert.equal(parsed.os?.family, 'debian');
  assert.equal(parsed.imageId, `sha256:${'a'.repeat(64)}`);
  assert.deepEqual(parsed.warnings, []);
});

test('missing severity becomes UNKNOWN and missing fix becomes null', () => {
  const parsed = parseTrivyReport(
    report([
      {
        Target: 'app/package-lock.json',
        Vulnerabilities: [
          { VulnerabilityID: 'CVE-2024-0002', PkgName: 'lodash', InstalledVersion: '4.17.20' },
          { VulnerabilityID: 'CVE-2024-0003', PkgName: 'lodash', InstalledVersion: '4.17.20', Severity: '', FixedVersion: '   ' },
        ],
      },
    ]),
  );
  assert.equal(parsed.findings.length, 2);
  assert.ok(parsed.findings.every((finding) => finding.severity === 'UNKNOWN'));
  assert.ok(parsed.findings.every((finding) => finding.fixedVersion === null));
});

test('falls back to the NVD link only for CVE identifiers and rejects unsafe URLs', () => {
  const parsed = parseTrivyReport(
    report([
      {
        Target: 'debian',
        Vulnerabilities: [
          {
            VulnerabilityID: 'CVE-2023-12345',
            PkgName: 'curl',
            InstalledVersion: '1',
            PrimaryURL: 'javascript:alert(1)',
          },
          {
            VulnerabilityID: 'GHSA-abcd-1234-efgh',
            PkgName: 'pkg',
            InstalledVersion: '1',
          },
        ],
      },
    ]),
  );
  const cve = parsed.findings.find((finding) => finding.vulnId === 'CVE-2023-12345');
  assert.equal(cve?.primaryUrl, 'https://nvd.nist.gov/vuln/detail/CVE-2023-12345');
  const ghsa = parsed.findings.find((finding) => finding.vulnId === 'GHSA-abcd-1234-efgh');
  assert.equal(ghsa?.primaryUrl, null);
});

test('a clean report with no results is a valid clean scan', () => {
  const parsed = parseTrivyReport(report([]));
  assert.deepEqual(parsed.findings, []);
  assert.deepEqual(parsed.warnings, []);

  const nullResults = parseTrivyReport(
    JSON.stringify({ SchemaVersion: 2, ArtifactName: 'test:1', Results: null }),
  );
  assert.deepEqual(nullResults.findings, []);
});

test('malformed, truncated or untrusted reports fail instead of looking clean', () => {
  assert.throws(() => parseTrivyReport('not json'), InvalidReportError);
  assert.throws(() => parseTrivyReport('{}'), InvalidReportError);
  assert.throws(() => parseTrivyReport(JSON.stringify({ Results: [] })), InvalidReportError);
  assert.throws(() => parseTrivyReport(report({ not: 'an array' })), InvalidReportError);
  assert.throws(
    () => parseTrivyReport(report([{ Class: 'os-pkgs', Vulnerabilities: [] }])),
    InvalidReportError,
    'results without a target are unusable',
  );
  assert.throws(
    () => parseTrivyReport(report([{ Target: 'x', Vulnerabilities: [null, 'bad'] }])),
    InvalidReportError,
    'malformed vulnerabilities with no usable findings must not look clean',
  );
});

test('malformed entries are reported as warnings when good entries exist', () => {
  const parsed = parseTrivyReport(
    report([
      { Target: 'debian', Vulnerabilities: [null] },
      {
        Target: 'alpine',
        Vulnerabilities: [
          { VulnerabilityID: 'CVE-2024-0004', PkgName: 'busybox', InstalledVersion: '1.36' },
        ],
      },
    ]),
  );
  assert.equal(parsed.findings.length, 1);
  assert.equal(parsed.warnings.length, 1);
  assert.match(parsed.warnings[0] ?? '', /malformed/i);
});

test('duplicate identities keep the richer CVSS entry', () => {
  const parsed = parseTrivyReport(
    report([
      {
        Target: 'debian',
        Vulnerabilities: [
          { VulnerabilityID: 'CVE-2024-0005', PkgName: 'pkg', InstalledVersion: '1', CVSS: { nvd: { V3Score: 5.0 } } },
          { VulnerabilityID: 'CVE-2024-0005', PkgName: 'pkg', InstalledVersion: '1', CVSS: { nvd: { V3Score: 9.8 } } },
        ],
      },
    ]),
  );
  assert.equal(parsed.findings.length, 1);
  assert.equal(parsed.findings[0]?.cvssScore, 9.8);
});

test('CVSS and reference helpers reject malformed values', () => {
  assert.deepEqual(parseCvss({ nvd: { V3Score: 15 } }), { score: null, source: null, vector: null });
  assert.deepEqual(parseCvss({ nvd: { V3Score: '9.8' } }), { score: null, source: null, vector: null });
  assert.equal(validateReference('file:///etc/passwd'), null);
  assert.equal(validateReference('https://example.com/advisory'), 'https://example.com/advisory');
});

test('the standard profile honours the configured scan ceiling', () => {
  assert.equal(scannerTimeoutMs('quick', 60 * 60_000), 5 * 60_000);
  assert.equal(scannerTimeoutMs('quick', 60_000), 60_000);
  assert.equal(scannerTimeoutMs('standard', 15 * 60_000), 15 * 60_000);
  assert.equal(scannerTimeoutMs('standard', 45 * 60_000), 45 * 60_000);
});
