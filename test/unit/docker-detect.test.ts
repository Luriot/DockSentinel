import test from 'node:test';
import assert from 'node:assert/strict';
import { startFakeDocker } from '../helpers/fake-docker.ts';
import { detectLocalDocker, localDockerCandidates, localDockerFailure } from '../../src/docker/detect.ts';

test('local Docker candidate defaults cover Windows named pipes and Unix sockets', () => {
  const windows = localDockerCandidates('win32');
  assert.ok(windows.some((candidate) => candidate.address === '//./pipe/dockerDesktopLinuxEngine'));
  assert.ok(windows.some((candidate) => candidate.address === '//./pipe/docker_engine'));
  const linux = localDockerCandidates('linux');
  assert.ok(linux.some((candidate) => candidate.address === '/var/run/docker.sock'));
  assert.ok(linux.every((candidate) => candidate.kind === 'unix'));
});

test('local Docker probing reports reachable and unreachable endpoints', async () => {
  const docker = await startFakeDocker();
  try {
    const reachable = await detectLocalDocker([
      { label: 'Fake Docker', kind: 'tcp', address: `127.0.0.1:${docker.port}` },
    ]);
    assert.equal(reachable[0]?.available, true);
    assert.equal(reachable[0]?.version?.ApiVersion, '1.44');

    const unreachable = await detectLocalDocker([
      { label: 'Closed port', kind: 'tcp', address: '127.0.0.1:1' },
    ]);
    assert.equal(unreachable[0]?.available, false);
    assert.ok(unreachable[0]?.error);
  } finally {
    await docker.close();
  }
});

test('a socket permission error is reported as a permission problem, not a missing Docker', () => {
  const base = { label: 'Local Docker', kind: 'unix' as const, address: '/var/run/docker.sock', available: false, version: null };
  const denied = localDockerFailure([
    { ...base, error: 'Docker API unreachable: connect EACCES /var/run/docker.sock' },
  ]);
  assert.equal(denied.code, 'docker_socket_permission');
  assert.match(denied.message, /group-add/);

  const missing = localDockerFailure([
    { ...base, error: 'Docker API unreachable: connect ECONNREFUSED /var/run/docker.sock' },
  ]);
  assert.equal(missing.code, 'docker_not_found');
  assert.match(missing.message, /\/var\/run\/docker\.sock/);
});
