import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { verifyBundle } from '../lib/verify.js';
import { VERDICT } from '../lib/verdict.js';

const REPO = path.resolve(import.meta.dirname, '../..');
const GOLDEN = path.join(REPO, 'tests/fixtures/conformance/valid-unattested');
const ATTESTED = path.join(REPO, 'tests/fixtures/conformance/valid-public');

const TERMINAL = new Set(Object.values(VERDICT));

/**
 * A deterministic 32-bit PRNG, seeded from the test name.
 *
 * Deliberately not Math.random: a robustness test that finds a crash on Tuesday
 * and cannot reproduce it on Wednesday is not a test, it is a rumour.
 */
function prng(seed) {
  let state = seed >>> 0;
  return () => {
    state ^= state << 13; state >>>= 0;
    state ^= state >>> 17;
    state ^= state << 5; state >>>= 0;
    return state / 0x100000000;
  };
}

function corrupt(sourceDir, targetDir, random, damageCount) {
  const names = fs.readdirSync(sourceDir);
  for (const name of names) fs.copyFileSync(path.join(sourceDir, name), path.join(targetDir, name));

  for (let i = 0; i < damageCount; i += 1) {
    const name = names[Math.floor(random() * names.length)];
    const file = path.join(targetDir, name);
    const bytes = fs.readFileSync(file);
    if (bytes.length === 0) continue;
    const at = Math.floor(random() * bytes.length);
    const mode = Math.floor(random() * 3);
    if (mode === 0) bytes[at] = Math.floor(random() * 256);
    else if (mode === 1) fs.writeFileSync(file, Buffer.concat([bytes.subarray(0, at), bytes.subarray(at + 1)]));
    else fs.writeFileSync(file, Buffer.concat([bytes.subarray(0, at), Buffer.from([Math.floor(random() * 256)]), bytes.subarray(at)]));
    if (mode === 0) fs.writeFileSync(file, bytes);
  }
}

for (const [label, source] of [['unattested', GOLDEN], ['attested', ATTESTED]]) {
  test(`randomly corrupted ${label} bundles always yield one of the five verdicts`, (t) => {
    const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'mizan-robustness-'));
    t.after(() => fs.rmSync(scratch, { recursive: true, force: true }));

    const random = prng(0xc0ffee ^ label.length);
    for (let round = 0; round < 250; round += 1) {
      const dir = path.join(scratch, `round-${round}`);
      fs.mkdirSync(dir);
      corrupt(source, dir, random, 1 + Math.floor(random() * 4));

      let report;
      assert.doesNotThrow(() => {
        report = verifyBundle(dir, { trustRoots: [] });
      }, `round ${round} crashed the verifier`);

      assert.ok(TERMINAL.has(report.verdict), `round ${round} produced ${report.verdict}`);
      // Nothing that has been damaged may come back clean -- EXPIRED asserts
      // "every required check passed" just as much as VALID does (section 5),
      // so it is exactly as wrong an outcome for corrupted input.
      assert.notEqual(report.verdict, VERDICT.VALID, `round ${round} accepted a corrupted bundle`);
      assert.notEqual(report.verdict, VERDICT.EXPIRED, `round ${round} accepted a corrupted bundle as merely expired`);
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
}

test('a directory that is not a bundle at all is MALFORMED, not a crash', (t) => {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'mizan-empty-'));
  t.after(() => fs.rmSync(scratch, { recursive: true, force: true }));
  assert.equal(verifyBundle(scratch, { trustRoots: [] }).verdict, VERDICT.MALFORMED);
});

test('a path that does not exist is MALFORMED, not a crash', () => {
  const report = verifyBundle(path.join(os.tmpdir(), 'mizan-does-not-exist-1234567890'), { trustRoots: [] });
  assert.equal(report.verdict, VERDICT.MALFORMED);
});

test('files that are not JSON at all are MALFORMED', (t) => {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'mizan-notjson-'));
  t.after(() => fs.rmSync(scratch, { recursive: true, force: true }));
  for (const name of fs.readdirSync(GOLDEN)) {
    fs.writeFileSync(path.join(scratch, name), Buffer.from([0xff, 0xfe, 0x00, 0x01, 0x80]));
  }
  assert.equal(verifyBundle(scratch, { trustRoots: [] }).verdict, VERDICT.MALFORMED);
});
