import test from 'node:test';
import assert from 'node:assert/strict';
import { dedupeFindings, type NormalizedFinding } from '../../src/domain/findings.ts';

function finding(overrides: Partial<NormalizedFinding> = {}): NormalizedFinding {
  return {
    target: 'usr/local/bin/app',
    class: 'lang-pkgs',
    type: 'gobinary',
    vulnId: 'CVE-2026-1111',
    pkgName: 'stdlib',
    installedVersion: 'go1.23',
    fixedVersion: 'go1.23.4',
    severity: 'HIGH',
    status: 'fixed',
    title: 'Go stdlib issue',
    primaryUrl: null,
    cvssScore: null,
    cvssSource: null,
    cvssVector: null,
    publishedAt: null,
    modifiedAt: null,
    ...overrides,
  };
}

test('the same package/CVE reported by several targets is stored once', () => {
  const deduped = dedupeFindings([
    finding({ target: 'usr/local/bin/tool' }),
    finding({ target: 'usr/local/bin/app' }),
    finding({ target: 'usr/local/bin/app', severity: 'CRITICAL' }),
    finding({ vulnId: 'CVE-2026-2222' }),
  ]);
  assert.equal(deduped.length, 2);
  const stdlib = deduped.find((item) => item.vulnId === 'CVE-2026-1111');
  assert.equal(stdlib?.severity, 'CRITICAL', 'the highest severity wins');
  assert.equal(stdlib?.target, 'usr/local/bin/app', 'the lowest target name keeps the choice stable');
});
