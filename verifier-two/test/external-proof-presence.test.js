// Section 2.1 makes `external_proofs` a required member of an ADR_Record at schema 1.3, and
// this verifier used to skip the whole rule the moment the member was absent. A producer that
// dropped the array therefore passed, which is the one outcome a required member must not have.
//
// The bundle is edited at the JSON level and the manifest digests are recomputed, so the run
// reaches the grammar phase rather than stopping at the file inventory.

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

import { verifyBundle } from '../lib/verify.js';
import { VERDICT } from '../lib/verdict.js';

const REPO = path.resolve(import.meta.dirname, '../..');
const GOLDEN = path.join(REPO, 'tests/fixtures/conformance/valid-unattested');

const NON_MANIFEST = ['records.json', 'receipts.json', 'anchors.json', 'checkpoints.json', 'keys.json'];

function bundleWith(scratch, edit) {
  const dir = fs.mkdtempSync(path.join(scratch, 'case-'));
  const documents = {};
  for (const name of fs.readdirSync(GOLDEN)) {
    documents[name] = JSON.parse(fs.readFileSync(path.join(GOLDEN, name), 'utf8'));
  }
  edit(documents);
  for (const name of NON_MANIFEST) {
    const bytes = Buffer.from(JSON.stringify(documents[name]), 'utf8');
    fs.writeFileSync(path.join(dir, name), bytes);
    documents['manifest.json'].files[name] = crypto.createHash('sha256').update(bytes).digest('hex');
  }
  fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify(documents['manifest.json']));
  return dir;
}

test('a schema 1.3 record that omits external_proofs is MALFORMED, not silently accepted', (t) => {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'mizan-proof-presence-'));
  t.after(() => fs.rmSync(scratch, { recursive: true, force: true }));

  const dir = bundleWith(scratch, (documents) => {
    documents['records.json'][0].schema_version = '1.3';
  });

  const report = verifyBundle(dir);
  assert.equal(report.verdict, VERDICT.MALFORMED);
  assert.ok(
    report.findings.some((finding) => /external_proofs/.test(finding.message)),
    `no finding named external_proofs: ${JSON.stringify(report.findings)}`,
  );
});

test('a record below schema 1.3 is not required to carry external_proofs', (t) => {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'mizan-proof-presence-'));
  t.after(() => fs.rmSync(scratch, { recursive: true, force: true }));

  const dir = bundleWith(scratch, (documents) => {
    documents['records.json'][0].schema_version = '1.2';
  });

  const report = verifyBundle(dir);
  assert.ok(
    !report.findings.some((finding) => /external_proofs/.test(finding.message)),
    `unexpected external_proofs finding: ${JSON.stringify(report.findings)}`,
  );
});
