import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { verifyBundle } from '../lib/verify.js';

const REPO = path.resolve(import.meta.dirname, '../..');
const CONFORMANCE = path.join(REPO, 'tests/fixtures/conformance');
const GOLDEN = path.join(CONFORMANCE, 'valid-unattested');

const spec = JSON.parse(fs.readFileSync(path.join(CONFORMANCE, 'mutation-result.json'), 'utf8'));

function mutate(bytes, offset, operation) {
  switch (operation) {
    case 'flip': {
      const copy = Buffer.from(bytes);
      copy[offset] ^= 0x01;
      return copy;
    }
    case 'delete':
      return Buffer.concat([bytes.subarray(0, offset), bytes.subarray(offset + 1)]);
    case 'insert-space':
      return Buffer.concat([bytes.subarray(0, offset), Buffer.from([0x20]), bytes.subarray(offset)]);
    default:
      throw new Error(`unknown mutation ${operation}`);
  }
}

function materialise(scratch, file, offset, operation) {
  const dir = fs.mkdtempSync(path.join(scratch, 'case-'));
  for (const name of fs.readdirSync(GOLDEN)) {
    const bytes = fs.readFileSync(path.join(GOLDEN, name));
    fs.writeFileSync(path.join(dir, name), name === file ? mutate(bytes, offset, operation) : bytes);
  }
  return dir;
}

// The corpus is 288 single-byte edits to a bundle that is otherwise VALID. It is
// the closest thing available to an adversary who changes exactly one thing, and
// every case carries the verdict the reference verifier produced. Running it here
// keeps the two implementations pinned to each other without either one being
// able to drift silently.
test('288 single-byte mutations produce the recorded verdicts', (t) => {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'mizan-mutation-'));
  t.after(() => fs.rmSync(scratch, { recursive: true, force: true }));

  const wrong = [];
  for (const testCase of spec.cases) {
    const [file, offsetText, operation] = testCase.case.split(':');
    const dir = materialise(scratch, file, Number(offsetText), operation);
    const report = verifyBundle(dir, { trustRoots: [] });
    if (report.verdict !== testCase.verdict) {
      wrong.push(`${testCase.case}: expected ${testCase.verdict}, got ${report.verdict}`);
    }
    fs.rmSync(dir, { recursive: true, force: true });
  }

  assert.deepEqual(wrong, [], `${wrong.length} of ${spec.cases.length} cases disagree`);
});

test('the corpus is the size it claims to be', () => {
  // Guards the test above against silently shrinking: 288 passing cases and
  // 3 passing cases both read as green.
  assert.equal(spec.cases.length, 288);
  assert.equal(spec.cases.length, spec.maximum_verifier_invocations);
  assert.deepEqual(spec.operations, ['flip-low-bit', 'delete', 'insert-space']);
});

test('the one benign mutation is benign for the stated reason', () => {
  // manifest.json is the only file no digest covers, so whitespace inserted
  // outside a string leaves it semantically identical. Everything else in the
  // corpus is caught, and this case documents why this one is not.
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'mizan-benign-'));
  try {
    assert.deepEqual(spec.semantic_survivors, [
      { case: 'manifest.json:34:insert-space', classification: 'benign-semantically-identical' },
    ]);
    const dir = materialise(scratch, 'manifest.json', 34, 'insert-space');
    assert.equal(verifyBundle(dir, { trustRoots: [] }).verdict, 'VALID');
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
});
