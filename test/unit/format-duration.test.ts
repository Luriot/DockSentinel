import test from 'node:test';
import assert from 'node:assert/strict';
import { formatDuration } from '../../web/src/format.ts';

test('formatDuration carries rounded seconds into the next minute', () => {
  assert.equal(formatDuration(60_000), '1m 0s');
  assert.equal(formatDuration(119_999), '2m 0s');
  assert.equal(formatDuration(3_599_999), '60m 0s');

  for (let ms = 0; ms <= 3_600_000; ms += 997) {
    assert.doesNotMatch(formatDuration(ms), /\d+m 60s/);
  }
});
