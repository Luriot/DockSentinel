import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  browserUrl,
  checkDataDir,
  checkWebDist,
  ensureSupportedNode,
  isLoopbackHost,
  listenErrorHint,
  nodeVersionSupported,
  StartupError,
} from '../../src/startup.ts';
import {
  parseChecksums,
  sha256,
  TRIVY_VERSION,
  trivyAssetFor,
  verifyChecksum,
} from '../../scripts/native-setup.ts';

test('Node version gate accepts the supported runtime and rejects old ones', () => {
  assert.equal(nodeVersionSupported('24.12.0'), true);
  assert.equal(nodeVersionSupported('24.11.1'), false);
  assert.equal(nodeVersionSupported('25.0.0'), true);
  assert.equal(nodeVersionSupported('23.9.0'), false);
  assert.throws(() => ensureSupportedNode('22.14.0'), StartupError);
  assert.doesNotThrow(() => ensureSupportedNode('24.12.0'));
});

test('startup preflight reports missing web build and unwritable data folder', async () => {
  const root = await mkdtemp(join(tmpdir(), 'docksentinel-startup-'));
  try {
    await assert.rejects(checkWebDist(root), (error: unknown) => {
      assert.ok(error instanceof StartupError);
      assert.match(error.message, /web interface/);
      assert.match(error.hint ?? '', /native:setup/);
      return true;
    });
    await writeFile(join(root, 'index.html'), '<html></html>');
    await assert.doesNotReject(checkWebDist(root));

    const dataDir = join(root, 'data');
    await assert.doesNotReject(checkDataDir(dataDir));

    const notADirectory = join(root, 'file');
    await writeFile(notADirectory, 'x');
    await assert.rejects(checkDataDir(notADirectory), StartupError);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('listen failures produce actionable messages', () => {
  assert.equal(listenErrorHint(new Error('other'), '127.0.0.1', 8080), null);
  const inUse = listenErrorHint(Object.assign(new Error('in use'), { code: 'EADDRINUSE' }), '127.0.0.1', 8080);
  assert.ok(inUse instanceof StartupError);
  assert.match(inUse.message, /8080/);
  assert.match(inUse.hint ?? '', /PORT=/);
  assert.equal(browserUrl('0.0.0.0', 8080), 'http://127.0.0.1:8080');
  assert.equal(browserUrl('127.0.0.1', 9000), 'http://127.0.0.1:9000');
  assert.equal(isLoopbackHost('127.0.0.1'), true);
  assert.equal(isLoopbackHost('::1'), true);
  assert.equal(isLoopbackHost('0.0.0.0'), false);
});

test('Trivy release selection maps supported platforms and rejects others', () => {
  assert.equal(trivyAssetFor('win32', 'x64').archive, `trivy_${TRIVY_VERSION}_windows-64bit.zip`);
  assert.equal(trivyAssetFor('win32', 'x64').extractedName, 'trivy.exe');
  assert.equal(trivyAssetFor('linux', 'x64').archive, `trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz`);
  assert.equal(trivyAssetFor('linux', 'arm64').archive, `trivy_${TRIVY_VERSION}_Linux-ARM64.tar.gz`);
  assert.equal(trivyAssetFor('darwin', 'arm64').archive, `trivy_${TRIVY_VERSION}_macOS-ARM64.tar.gz`);
  assert.throws(() => trivyAssetFor('freebsd', 'x64'), /No verified Trivy release asset/);
});

test('checksum parsing and verification reject missing or wrong digests', () => {
  const payload = Buffer.from('verified payload');
  const digest = sha256(payload);
  const checksums = parseChecksums(`${digest}  trivy_test.zip\n${'0'.repeat(64)} *other.zip\n`);
  assert.equal(checksums.get('trivy_test.zip'), digest);
  assert.equal(checksums.get('other.zip'), '0'.repeat(64));
  assert.doesNotThrow(() => verifyChecksum(payload, digest, 'trivy_test.zip'));
  assert.throws(() => verifyChecksum(payload, '0'.repeat(64), 'trivy_test.zip'), /Checksum verification failed/);
  assert.throws(() => verifyChecksum(payload, undefined, 'trivy_test.zip'), /No checksum/);
});
