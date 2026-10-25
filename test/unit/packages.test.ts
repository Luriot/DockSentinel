import test from 'node:test';
import assert from 'node:assert/strict';
import { filterIgnoredPackages, isKernelPackage, nonKernelPackageSql } from '../../src/domain/packages.ts';

test('kernel and header packages are recognised, application packages are not', () => {
  for (const name of ['linux-libc-dev', 'linux-image-6.1.0-13-amd64', 'linux-headers-6.1.0-13', 'linux-modules-6.1']) {
    assert.equal(isKernelPackage(name), true, name);
  }
  for (const name of ['openssl', 'linuxptp', 'libssl3', 'curl']) {
    assert.equal(isKernelPackage(name), false, name);
  }
});

test('the SQL predicate keeps non-kernel rows for a given column', () => {
  const sql = nonKernelPackageSql('f.pkg_name');
  assert.match(sql, /^NOT \(/);
  assert.match(sql, /f\.pkg_name = 'linux-libc-dev'/);
  assert.match(sql, /f\.pkg_name LIKE 'linux-image-%'/);
});

test('ignored packages are matched case-insensitively and can be empty', () => {
  const findings = [{ pkgName: 'chromium' }, { pkgName: 'OpenSSL' }, { pkgName: 'curl' }];
  assert.deepEqual(filterIgnoredPackages(findings, []), findings);
  assert.deepEqual(filterIgnoredPackages(findings, ['CHROMIUM', 'openssl']), [{ pkgName: 'curl' }]);
});
