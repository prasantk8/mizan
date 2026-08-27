import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

import { verifyBundle, DEVELOPMENT_CUSTODY_WARNING, LIMITS_OF_A_CLEAN_VERDICT } from '../lib/verify.js';
import { loadTrustRoots } from '../lib/rfc3161.js';
import { VERDICT, EXIT_STATUS } from '../lib/verdict.js';

const REPO = path.resolve(import.meta.dirname, '../..');
const CONFORMANCE = path.join(REPO, 'tests/fixtures/conformance');

const cases = JSON.parse(fs.readFileSync(path.join(CONFORMANCE, 'verdicts.json'), 'utf8'));

function rootsFor(testCase) {
  return testCase.trust_roots.flatMap((relative) =>
    loadTrustRoots(fs.readFileSync(path.resolve(CONFORMANCE, relative), 'utf8')),
  );
}

for (const testCase of cases) {
  test(`conformance: ${testCase.bundle} is ${testCase.verdict}`, () => {
    const report = verifyBundle(path.join(CONFORMANCE, testCase.bundle), {
      trustRoots: rootsFor(testCase),
    });
    assert.equal(
      report.verdict,
      testCase.verdict,
      `findings: ${JSON.stringify(report.findings, null, 2)}`,
    );
    assert.equal(report.exitStatus, EXIT_STATUS[testCase.verdict]);
  });
}

test('section 4: the custody warning is printed verbatim for a development-derived key', () => {
  const report = verifyBundle(path.join(CONFORMANCE, 'valid-unattested'));
  assert.ok(
    report.warnings.includes(DEVELOPMENT_CUSTODY_WARNING),
    'the mandated warning was not emitted',
  );
  // The spec mandates this string exactly. Asserting the literal here means a
  // reworded "improvement" fails the suite instead of quietly softening it.
  assert.equal(
    DEVELOPMENT_CUSTODY_WARNING,
    'KEY CUSTODY: publicly derivable development key — this bundle is forgeable by anyone who reads it.',
  );
});

test('section 6: a clean verdict still reports what it does not prove', () => {
  const report = verifyBundle(path.join(CONFORMANCE, 'valid-unattested'));
  assert.equal(report.verdict, VERDICT.VALID);
  for (const limit of LIMITS_OF_A_CLEAN_VERDICT) {
    assert.ok(report.notes.includes(limit), `missing limitation: ${limit}`);
  }
  assert.ok(
    LIMITS_OF_A_CLEAN_VERDICT.some((limit) => /omitted before it entered the chain/.test(limit)),
    'TM-001 pre-chain omission must be named',
  );
  assert.ok(
    LIMITS_OF_A_CLEAN_VERDICT.some((limit) => /withhold an entire final anchor/.test(limit)),
    'the withheld-final-anchor class must be named',
  );
});

test('section 4: trust roots come from the operator, so an attested bundle alone is CANNOT CHECK', () => {
  // The bundle carries two real public-TSA tokens. Without operator-supplied
  // roots the tokens are unevaluable -- which is not the same as forged, and
  // section 7 says a missing dependency is "neither VALID nor evidence failure".
  const report = verifyBundle(path.join(CONFORMANCE, 'valid-public'), { trustRoots: [] });
  assert.equal(report.verdict, VERDICT.CANNOT_CHECK);
  assert.equal(report.exitStatus, 2);
  assert.ok(
    report.of(VERDICT.CANNOT_CHECK).some((f) => /trust roots/i.test(f.message)),
    'the reason must name the missing trust roots',
  );
  assert.equal(report.of(VERDICT.INVALID).length, 0, 'a missing trust root is not an evidence failure');
});

test('the same bundle becomes VALID once its operator supplies the roots', () => {
  const publicCase = cases.find((c) => c.bundle === 'valid-public');
  const report = verifyBundle(path.join(CONFORMANCE, 'valid-public'), { trustRoots: rootsFor(publicCase) });
  assert.equal(report.verdict, VERDICT.VALID);
  assert.equal(report.derivedAssurance, 'rfc3161');
});
