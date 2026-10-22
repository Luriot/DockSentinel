import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  isSeverityAtLeast,
  maxSeverity,
  normalizeSeverity,
  severityRank,
} from '../../src/domain/severity.ts';
import { classifyExposure } from '../../src/domain/exposure.ts';
import {
  parseWorkloadLabels,
  resolveAlertThreshold,
  shouldAlertForFinding,
} from '../../src/domain/policy.ts';
import { prioritiseFinding } from '../../src/domain/priority.ts';
import { diffFindings, findingIdentity, type NormalizedFinding, type StoredFinding } from '../../src/domain/findings.ts';

function finding(overrides: Partial<NormalizedFinding> = {}): NormalizedFinding {
  return {
    target: 'debian 11.7',
    class: 'os-pkgs',
    type: 'debian',
    vulnId: 'CVE-2024-0001',
    pkgName: 'openssl',
    installedVersion: '1.1.1k',
    fixedVersion: '1.1.1n',
    severity: 'HIGH',
    status: 'fixed',
    title: 'OpenSSL issue',
    primaryUrl: 'https://example.com',
    cvssScore: 7.5,
    cvssSource: 'nvd',
    cvssVector: null,
    publishedAt: null,
    modifiedAt: null,
    ...overrides,
  };
}

test('severity normalisation never invents a lower severity for unknown input', () => {
  assert.equal(normalizeSeverity('CRITICAL'), 'CRITICAL');
  assert.equal(normalizeSeverity(' crit '), 'CRITICAL');
  assert.equal(normalizeSeverity('moderate'), 'MEDIUM');
  assert.equal(normalizeSeverity(''), 'UNKNOWN');
  assert.equal(normalizeSeverity(null), 'UNKNOWN');
  assert.equal(normalizeSeverity('SOMETHING-NEW'), 'UNKNOWN');
  assert.ok(severityRank('CRITICAL') > severityRank('HIGH'));
  assert.equal(isSeverityAtLeast('MEDIUM', 'HIGH'), false);
  assert.equal(maxSeverity('LOW', 'CRITICAL'), 'CRITICAL');
});

test('exposure classification distinguishes declarations from inferred evidence', () => {
  const running = { state: 'running', ports: [], labels: {} };
  assert.equal(
    classifyExposure({ ...running, labels: { 'docksentinel.exposure': 'internet' } }).state,
    'confirmed',
  );
  assert.equal(
    classifyExposure({
      ...running,
      ports: [{ ip: '0.0.0.0', privatePort: 80, publicPort: 8080, type: 'tcp' }],
    }).state,
    'potential',
  );
  assert.equal(
    classifyExposure({
      ...running,
      ports: [{ ip: '', privatePort: 80, publicPort: 8080, type: 'tcp' }],
    }).state,
    'potential',
  );
  assert.equal(
    classifyExposure({
      ...running,
      ports: [{ ip: '127.0.0.1', privatePort: 80, publicPort: 8080, type: 'tcp' }],
    }).state,
    'internal',
  );
  assert.equal(classifyExposure({ ...running, networkMode: 'host' }).state, 'potential');
  assert.equal(classifyExposure({ ...running, state: 'exited' }).state, 'unknown');
  assert.equal(
    classifyExposure({
      ...running,
      state: 'exited',
      labels: { 'docksentinel.exposure': 'internet' },
    }).state,
    'confirmed',
  );
  assert.equal(classifyExposure({ ...running, labels: { 'docksentinel.exposure': 'internal' } }).state, 'internal');
});

test('workload labels and thresholds are parsed without throwing on junk', () => {
  const policy = parseWorkloadLabels({
    'docksentinel.monitor': 'false',
    'docksentinel.exposure': 'public',
    'docksentinel.criticality': 'critical',
    'docksentinel.alert-min-severity': 'critical',
    'docksentinel.ignore-vulns': 'CVE-1, CVE-2',
  });
  assert.equal(policy.monitored, false);
  assert.equal(policy.exposure, 'internet');
  assert.equal(policy.criticality, 'critical');
  assert.equal(policy.minSeverity, 'CRITICAL');
  assert.ok(policy.ignoredVulns.has('CVE-1'));
  assert.ok(policy.ignoredVulns.has('CVE-2'));

  const junk = parseWorkloadLabels({ 'docksentinel.monitor': 'maybe', 'docksentinel.criticality': 'nope' });
  assert.equal(junk.monitored, true);
  assert.equal(junk.criticality, null);

  assert.equal(resolveAlertThreshold('MEDIUM', 'HIGH', parseWorkloadLabels({})), 'HIGH');
  assert.equal(
    resolveAlertThreshold('CRITICAL', 'HIGH', parseWorkloadLabels({ 'docksentinel.alert-min-severity': 'low' })),
    'LOW',
    'a workload label may explicitly lower its own threshold',
  );
  assert.equal(shouldAlertForFinding('HIGH', 'HIGH', 'CVE-1', parseWorkloadLabels({})), true);
  assert.equal(shouldAlertForFinding('MEDIUM', 'HIGH', 'CVE-1', parseWorkloadLabels({})), false);
  assert.equal(
    shouldAlertForFinding('CRITICAL', 'HIGH', 'CVE-9', parseWorkloadLabels({ 'docksentinel.ignore-vulns': 'CVE-9' })),
    false,
  );
  assert.equal(shouldAlertForFinding('CRITICAL', 'HIGH', 'CVE-1', parseWorkloadLabels({ 'docksentinel.monitor': 'false' })), false);
});

test('priority tiers are transparent and contextual signals only raise priority', () => {
  const criticalKev = prioritiseFinding({
    severity: 'CRITICAL',
    kev: 1,
    hasFix: true,
    running: true,
    exposure: 'confirmed',
  });
  assert.equal(criticalKev.tier, 'P1');
  assert.ok(criticalKev.factors.includes('Known exploited (CISA KEV)'));
  assert.ok(criticalKev.factors.includes('Internet exposure declared'));

  const criticalOnly = prioritiseFinding({
    severity: 'CRITICAL',
    kev: -1,
    hasFix: false,
    running: false,
    exposure: 'unknown',
  });
  assert.equal(criticalOnly.tier, 'P2');

  const highOnly = prioritiseFinding({
    severity: 'HIGH',
    kev: 0,
    hasFix: false,
    running: false,
    exposure: 'unknown',
  });
  assert.equal(highOnly.tier, 'P3');

  const medium = prioritiseFinding({
    severity: 'MEDIUM',
    kev: 0,
    hasFix: true,
    running: true,
    exposure: 'potential',
  });
  assert.equal(medium.tier, 'P3');

  const low = prioritiseFinding({
    severity: 'LOW',
    kev: 0,
    hasFix: false,
    running: false,
    exposure: 'unknown',
  });
  assert.equal(low.tier, 'P4');
});

test('finding diffs detect appeared, resolved, changed and unchanged entries', () => {
  const base = finding();
  const previous: StoredFinding[] = [
    {
      id: 1,
      target: base.target,
      vulnId: base.vulnId,
      pkgName: base.pkgName,
      installedVersion: base.installedVersion,
      fixedVersion: null,
      severity: 'HIGH',
      title: base.title,
      primaryUrl: base.primaryUrl,
      episode: 1,
    },
    {
      id: 2,
      target: 'debian',
      vulnId: 'CVE-OLD',
      pkgName: 'zlib',
      installedVersion: '1',
      fixedVersion: '2',
      severity: 'MEDIUM',
      title: null,
      primaryUrl: null,
      episode: 1,
    },
  ];

  const changed = finding({ fixedVersion: '1.1.1n' });
  const added = finding({ vulnId: 'CVE-2024-9999', pkgName: 'curl' });
  const diff = diffFindings(previous, [changed, added]);

  assert.equal(diff.appeared.length, 1);
  assert.equal(diff.appeared[0]?.vulnId, 'CVE-2024-9999');
  assert.equal(diff.resolved.length, 1);
  assert.equal(diff.resolved[0]?.vulnId, 'CVE-OLD');
  assert.equal(diff.changed.length, 1);
  assert.deepEqual(diff.changed[0]?.changes.fixedVersion, { from: null, to: '1.1.1n' });
  assert.equal(diff.unchanged.length, 0);

  const identical = diffFindings(previous, [finding({ fixedVersion: null })]);
  assert.equal(identical.appeared.length, 0);
  assert.equal(identical.resolved.length, 1);
  assert.equal(identical.changed.length, 0);
  assert.equal(identical.unchanged.length, 1);

  assert.equal(
    findingIdentity({ target: 'a', vulnId: 'b', pkgName: 'c', installedVersion: 'd' }),
    'a\u0000b\u0000c\u0000d',
  );
});
