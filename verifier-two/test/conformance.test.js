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

// Section 2.1's Memtara roots are a second, independent operator input: RFC 8037 JWK Sets, never
// PEM certificates and never bundle members. Reading only `trust_roots` here made this suite
// disagree with `scripts/compare_verifiers.py` on any proof-bearing case -- that gate passes the
// JWKS through, this one silently did not, so the same bundle would be CANNOT CHECK on one side
// and VALID on the other and the corpus would be describing two different questions.
function memtaraRootsFor(testCase) {
  return (testCase.memtara_trust_roots ?? []).map((relative) =>
    JSON.parse(fs.readFileSync(path.resolve(CONFORMANCE, relative), 'utf8')),
  );
}

for (const testCase of cases) {
  // The corpus lists one bundle twice, with and without its Memtara root, because "the same bytes
  // and a different operator environment" is the claim being made. The root count keeps the two
  // test names distinct.
  const roots = (testCase.memtara_trust_roots ?? []).length + testCase.trust_roots.length;
  test(`conformance: ${testCase.bundle} with ${roots} operator root(s) is ${testCase.verdict}`, () => {
    const report = verifyBundle(path.join(CONFORMANCE, testCase.bundle), {
      trustRoots: rootsFor(testCase),
      memtaraTrustRoots: memtaraRootsFor(testCase),
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

const MEMTARA_JWKS = JSON.parse(
  fs.readFileSync(path.join(CONFORMANCE, 'memtara-trust-root.jwks.json'), 'utf8'),
);

test('section 2.1: a Memtara proof without an operator JWKS is CANNOT CHECK, not INVALID', () => {
  // Same distinction as the RFC 3161 case above, and it has to be made separately because it is
  // a separate root: "we hold no key for this issuer" is not "this token is forged".
  const report = verifyBundle(path.join(CONFORMANCE, 'valid-memtara-proof'));
  assert.equal(report.verdict, VERDICT.CANNOT_CHECK);
  assert.equal(report.exitStatus, 2);
  assert.ok(
    report.of(VERDICT.CANNOT_CHECK).some((f) => /memtara-trust-root/.test(f.message)),
    'the reason must name the missing Memtara root',
  );
  assert.equal(report.of(VERDICT.INVALID).length, 0);
});

test('section 2.1: a proof_hash the signed token does not state is INVALID', () => {
  // The fixture is re-signed end to end by scripts/build_memtara_fixtures.py: chain, receipts,
  // anchor and manifest digests all commit the tampered value. If this ever reports MALFORMED or
  // a checksum mismatch, the generator stopped reaching the binding check and the case is vacuous.
  const report = verifyBundle(path.join(CONFORMANCE, 'invalid-memtara-proof-binding'), {
    memtaraTrustRoots: [MEMTARA_JWKS],
  });
  assert.equal(report.verdict, VERDICT.INVALID);
  assert.equal(report.of(VERDICT.MALFORMED).length, 0, 'a re-signed tamper is evidence, not grammar');
  assert.ok(
    report
      .of(VERDICT.INVALID)
      .every((f) => /does not match signed Memtara claim proof_hash/.test(f.message)),
    `some other check failed first: ${JSON.stringify(report.findings)}`,
  );
});

test('section 2.1: an expired Memtara token is still VALID, because history is not re-dated', () => {
  // The committed tokens carry an `exp` in 2026-08 and always will. Section 2.1: expiry governed
  // whether Mizan could accept the token at authorization time; the bundle proves afterwards which
  // signed token the immutable ADR used. A verifier that compared `exp` to its own clock would
  // turn every archived bundle INVALID on a date nobody chose.
  const claims = JSON.parse(
    Buffer.from(
      JSON.parse(
        fs.readFileSync(path.join(CONFORMANCE, 'valid-memtara-proof/records.json'), 'utf8'),
      )[0].external_proofs[0].token.split('.')[1],
      'base64url',
    ).toString('utf8'),
  );
  assert.ok(claims.exp * 1000 < Date.now(), 'the fixture token must already be expired');
  const report = verifyBundle(path.join(CONFORMANCE, 'valid-memtara-proof'), {
    memtaraTrustRoots: [MEMTARA_JWKS],
  });
  assert.equal(report.verdict, VERDICT.VALID);
});
