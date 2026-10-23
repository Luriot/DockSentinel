import test from 'node:test';
import assert from 'node:assert/strict';
import { parseTrivyContentReport } from '../../src/scanner/normalize.ts';

const RAW_SECRET = 'AKIAFAKEFAKEFAKE1234';
const RAW_TOKEN = 'ghp_FAKEfakeFAKEfakeFAKEfakeFAKEfake1234';
const RAW_CODE = `ENV GITHUB_TOKEN=${RAW_TOKEN}`;

function report(): string {
  return JSON.stringify({
    SchemaVersion: 2,
    ArtifactName: 'image.tar',
    Results: [
      {
        Target: 'C:/tmp/scan/image.tar',
        Class: 'config',
        Type: 'dockerfile',
        Misconfigurations: [
          {
            ID: 'DS-0002',
            Title: 'Image user should not be root',
            Message: 'Last USER command should not be root',
            Resolution: 'Add a non-root USER',
            Severity: 'HIGH',
            PrimaryURL: 'https://avd.aquasec.com/misconfig/ds-0002',
            CauseMetadata: { StartLine: 3, EndLine: 3, Code: { Lines: [{ Content: 'USER root' }] } },
          },
        ],
      },
      {
        Target: '/app/secret.txt',
        Class: 'secret',
        Secrets: [
          {
            RuleID: 'aws-access-key-id',
            Category: 'AWS',
            Severity: 'CRITICAL',
            Title: 'AWS Access Key ID',
            StartLine: 1,
            EndLine: 1,
            Match: RAW_SECRET,
            Code: { Lines: [{ Number: 1, Content: `key = ${RAW_SECRET}` }] },
          },
        ],
      },
      {
        Target: '/app/Dockerfile',
        Class: 'secret',
        Secrets: [
          {
            RuleID: 'github-pat',
            Category: 'GitHub',
            Severity: 'CRITICAL',
            Title: 'GitHub Personal Access Token',
            StartLine: 2,
            EndLine: 2,
            Match: RAW_TOKEN,
            Code: { Lines: [{ Number: 2, Content: RAW_CODE }] },
          },
        ],
      },
    ],
  });
}

test('content parser keeps metadata but never raw secret matches or code', () => {
  const parsed = parseTrivyContentReport(report(), { path: 'C:/tmp/scan/image.tar', base: 'image.tar' });
  assert.equal(parsed.findings.length, 3);
  const misconfig = parsed.findings.find((finding) => finding.kind === 'misconfiguration');
  assert.equal(misconfig?.ruleId, 'DS-0002');
  assert.equal(misconfig?.scope, 'image-config');
  assert.equal(misconfig?.target, 'image config');
  assert.equal(misconfig?.startLine, 3);
  const secrets = parsed.findings.filter((finding) => finding.kind === 'secret');
  assert.equal(secrets.length, 2);
  assert.deepEqual(
    secrets.map((finding) => finding.target).sort(),
    ['app/Dockerfile', 'app/secret.txt'],
  );
  assert.ok(secrets.every((finding) => finding.scope === 'image'));
  assert.ok(secrets.every((finding) => !('match' in finding) && !('code' in finding)));

  const serialized = JSON.stringify(parsed);
  assert.equal(serialized.includes(RAW_SECRET), false);
  assert.equal(serialized.includes(RAW_TOKEN), false);
  assert.equal(serialized.includes(RAW_CODE), false);
});

test('content parser fails closed on malformed reports', () => {
  assert.throws(() => parseTrivyContentReport('not json', { path: 'image.tar', base: 'image.tar' }));
  assert.throws(() =>
    parseTrivyContentReport(
      JSON.stringify({ SchemaVersion: 2, Results: [{ Target: '/app/secret.txt', Secrets: [{ Match: RAW_SECRET }] }] }),
      { path: 'image.tar', base: 'image.tar' },
    ),
  );
  assert.throws(() =>
    parseTrivyContentReport(JSON.stringify({ SchemaVersion: 2, Results: 'nope' }), {
      path: 'image.tar',
      base: 'image.tar',
    }),
  );
});
