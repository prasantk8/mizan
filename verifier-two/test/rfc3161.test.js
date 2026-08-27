import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

import { verifyTimestampToken, loadTrustRoots, assertTimeStampingEku, TokenInvalid } from '../lib/rfc3161.js';
import { parseDer, readOid, readInteger, DerError, TAG } from '../lib/der.js';
import { OID } from '../lib/oid.js';
import { jcs } from '../lib/jcs.js';
import { anchorCoreDigest, verifyBundle } from '../lib/verify.js';
import { VERDICT } from '../lib/verdict.js';

const REPO = path.resolve(import.meta.dirname, '../..');
const PUBLIC_TSA = path.join(REPO, 'tests/fixtures/evidence_export/public-tsa');
const ANCHORS = path.join(REPO, 'tests/fixtures/conformance/valid-public/anchors.json');

const anchor = JSON.parse(fs.readFileSync(ANCHORS, 'utf8'))[0];
const coreDigest = Buffer.from(anchorCoreDigest(anchor.payload), 'hex');

const roots = [
  ...loadTrustRoots(fs.readFileSync(path.join(PUBLIC_TSA, 'freetsa-root.pem'), 'utf8')),
  ...loadTrustRoots(fs.readFileSync(path.join(PUBLIC_TSA, 'usertrust-rsa-root.pem'), 'utf8')),
];

function tokenFor(authority) {
  const entry = anchor.attestations.find((a) => a.authority === authority);
  return Buffer.from(entry.evidence, 'base64');
}

// Two independent public TSAs, two different CMS shapes: FreeTSA signs with
// sha512WithRSAEncryption, Sectigo signs with bare rsaEncryption and takes the
// digest from digestAlgorithm. Verifying both is what caught the second form.
for (const authority of ['https://freetsa.org/tsr', 'https://timestamp.sectigo.com']) {
  test(`a real token from ${authority} verifies against operator-supplied roots`, () => {
    const result = verifyTimestampToken(tokenFor(authority), coreDigest, roots);
    assert.equal(result.ok, true, result.reason ?? '');
    assert.ok(result.genTime instanceof Date);
  });

  test(`${authority}: a token over a different digest is rejected`, () => {
    const other = crypto.createHash('sha256').update('a different anchor').digest();
    const result = verifyTimestampToken(tokenFor(authority), other, roots);
    assert.equal(result.ok, false);
    assert.equal(result.canCheck, true, 'a wrong imprint is an evidence failure, not an unevaluable claim');
    assert.match(result.reason, /messageImprint/);
  });

  test(`${authority}: without trust roots the token is unevaluable, not forged`, () => {
    const result = verifyTimestampToken(tokenFor(authority), coreDigest, []);
    assert.equal(result.ok, false);
    assert.equal(result.canCheck, false);
  });

  test(`${authority}: an unrelated trust root does not complete the chain`, () => {
    const wrongRoot = authority.includes('freetsa')
      ? loadTrustRoots(fs.readFileSync(path.join(PUBLIC_TSA, 'usertrust-rsa-root.pem'), 'utf8'))
      : loadTrustRoots(fs.readFileSync(path.join(PUBLIC_TSA, 'freetsa-root.pem'), 'utf8'));
    const result = verifyTimestampToken(tokenFor(authority), coreDigest, wrongRoot);
    assert.equal(result.ok, false);
  });

  test(`${authority}: a single flipped bit in the token is caught`, () => {
    const token = tokenFor(authority);
    // Flip a bit inside the TSTInfo octets rather than in the header, so the
    // token still parses and the signature check is what has to catch it.
    const damaged = Buffer.from(token);
    damaged[Math.floor(damaged.length / 2)] ^= 0x01;
    const result = verifyTimestampToken(damaged, coreDigest, roots);
    assert.equal(result.ok, false);
  });
}

test('RFC 3161 section 2.3: the timestamping EKU must be present, critical, and alone', () => {
  assert.doesNotThrow(() => assertTimeStampingEku({ critical: true, purposes: [OID.timeStamping] }));

  assert.throws(
    () => assertTimeStampingEku({ critical: false, purposes: [OID.timeStamping] }),
    /not critical/,
    'a non-critical extended key usage must be refused',
  );
  assert.throws(
    () => assertTimeStampingEku({ critical: true, purposes: [OID.timeStamping, '1.3.6.1.5.5.7.3.1'] }),
    /not id-kp-timeStamping alone/,
    'a certificate also good for TLS must be refused',
  );
  assert.throws(
    () => assertTimeStampingEku({ critical: true, purposes: ['1.3.6.1.5.5.7.3.1'] }),
    /not id-kp-timeStamping alone/,
  );
  assert.throws(() => assertTimeStampingEku(null), /no extended key usage/);
});

test('the real FreeTSA signer does carry a critical timestamping EKU', () => {
  // Guards the synthetic test above from drifting away from real certificates.
  const result = verifyTimestampToken(tokenFor('https://freetsa.org/tsr'), coreDigest, roots);
  assert.equal(result.ok, true);
});

// --- the DER reader is strict on purpose ------------------------------------

test('DER: indefinite length, non-minimal length and trailing bytes are refused', () => {
  assert.throws(() => parseDer(Buffer.from([0x30, 0x80, 0x00, 0x00])), DerError, 'indefinite length');
  assert.throws(() => parseDer(Buffer.from([0x30, 0x81, 0x01, 0x05])), DerError, 'non-minimal length');
  assert.throws(() => parseDer(Buffer.from([0x05, 0x00, 0x05, 0x00])), DerError, 'trailing bytes');
  assert.throws(() => parseDer(Buffer.from([0x30, 0x05, 0x01])), DerError, 'truncated');
});

test('DER: INTEGER rejects non-minimal encodings and survives large serials', () => {
  assert.equal(readInteger(parseDer(Buffer.from([0x02, 0x01, 0x7f]))), 127n);
  assert.equal(readInteger(parseDer(Buffer.from([0x02, 0x01, 0x80]))), -128n);
  assert.throws(() => readInteger(parseDer(Buffer.from([0x02, 0x02, 0x00, 0x7f]))), DerError);
  // C2E986160DA8E9CD is the FreeTSA serial and exceeds Number.MAX_SAFE_INTEGER.
  const big = parseDer(Buffer.from('0209' + '00c2e986160da8e9cd', 'hex'));
  assert.equal(readInteger(big), 0xc2e986160da8e9cdn);
});

test('DER: OID decoding matches the identifiers this verifier relies on', () => {
  assert.equal(readOid(parseDer(Buffer.from('06092a864886f70d010105', 'hex'))), OID.sha1WithRsa);
  assert.equal(readOid(parseDer(Buffer.from('0609608648016503040201', 'hex'))), OID.sha256);
  assert.equal(readOid(parseDer(Buffer.from('06032b6570', 'hex'))), OID.ed25519);
  assert.equal(readOid(parseDer(Buffer.from('06082b06010505070308', 'hex'))), OID.timeStamping);
});

test('a token whose PKIStatus is not granted carries no usable timestamp', () => {
  // PKIStatus rejection(2) with no token. Section 5's grammar makes this an
  // evidence failure rather than something to read a time out of anyway.
  const rejected = Buffer.from('3006300402020200', 'hex');
  const result = verifyTimestampToken(rejected, coreDigest, roots);
  assert.equal(result.ok, false);
});

// --- the shipped bundles, not just the conformance fixtures ------------------
//
// These two tests exist because CI found a bug that the conformance corpus
// structurally could not reach. Both public TSAs name their ESSCertIDv2 hash
// algorithm explicitly; the committed test TSA omits it and relies on the
// RFC 5035 DEFAULT. verifier-two applied ESSCertID v1's SHA-1 default to
// ESSCertIDv2, so every 32-byte certHash failed a 20-byte comparison and an
// honest token was reported as forged.

const ATTESTED = path.join(REPO, 'tests/fixtures/evidence_export/attested');

test('RFC 5035: an ESSCertIDv2 with no hashAlgorithm defaults to SHA-256, not SHA-1', () => {
  const bundleAnchor = JSON.parse(fs.readFileSync(path.join(ATTESTED, 'bundle/anchors.json'), 'utf8'))[0];
  const entry = (bundleAnchor.attestations ?? bundleAnchor.payload.attestations).find(
    (candidate) => candidate.type === 'rfc3161' && candidate.evidence,
  );
  assert.ok(entry, 'the attested fixture carries an rfc3161 token');

  // Prove the token really does omit hashAlgorithm, so this test cannot pass for
  // the wrong reason if the fixture is ever regenerated with it present. Without
  // this the test would still pass against a token that names SHA-256
  // explicitly, and the DEFAULT -- the thing that broke -- would go unexercised.
  const der = Buffer.from(entry.evidence, 'base64');
  const essCertId = findEssCertIdV2(der);
  assert.ok(essCertId, 'the shipped token carries a signingCertificateV2 attribute');
  assert.ok(
    essCertId.children()[0].is(TAG.OCTET_STRING),
    'the shipped token omits hashAlgorithm and relies on the RFC 5035 DEFAULT',
  );

  const digest = Buffer.from(anchorCoreDigest(bundleAnchor.payload), 'hex');
  const trustRoots = loadTrustRoots(fs.readFileSync(path.join(ATTESTED, 'tsa-root.pem'), 'utf8'));
  const result = verifyTimestampToken(der, digest, trustRoots);

  assert.equal(result.ok, true, `expected the shipped token to verify, got: ${result.reason}`);
});

test('a timestamp whose chain has since expired still verifies, and says so', () => {
  const bundleAnchor = JSON.parse(fs.readFileSync(path.join(ATTESTED, 'bundle/anchors.json'), 'utf8'))[0];
  const entry = (bundleAnchor.attestations ?? bundleAnchor.payload.attestations).find(
    (candidate) => candidate.type === 'rfc3161' && candidate.evidence,
  );
  const digest = Buffer.from(anchorCoreDigest(bundleAnchor.payload), 'hex');
  const trustRoots = loadTrustRoots(fs.readFileSync(path.join(ATTESTED, 'tsa-root.pem'), 'utf8'));
  const result = verifyTimestampToken(Buffer.from(entry.evidence, 'base64'), digest, trustRoots);

  assert.equal(result.ok, true);
  assert.ok(Array.isArray(result.expiredSince));

  // The committed test TSA certificate has a one-day lifetime, so this branch is
  // live from the day after the fixture was generated onward. Asserting on the
  // shape rather than on today's date keeps the test honest before that date
  // too: what must hold is that an expired chain is reported and not silently
  // downgraded to a failure.
  const chainExpired = result.expiredSince.length > 0;
  if (chainExpired) {
    assert.match(result.expiredSince.join(' '), /expired/);
    assert.equal(result.ok, true, 'expiry after genTime does not retract the timestamp');
  }
});

/** Locate the first ESSCertIDv2 inside a token's signingCertificateV2 attribute. */
function findEssCertIdV2(der) {
  let found = null;
  const walk = (node, depth) => {
    if (found || depth > 12) return;
    let children;
    try {
      children = node.children();
    } catch {
      return;
    }
    if (node.is(TAG.SEQUENCE) && children.length === 2 && children[0].is(TAG.OID)) {
      let oid = null;
      try {
        oid = readOid(children[0]);
      } catch {
        oid = null;
      }
      if (oid === OID.signingCertificateV2) {
        // SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2, ... }
        found = children[1].at(0).at(0).at(0);
        return;
      }
    }
    for (const child of children) walk(child, depth + 1);
  };
  walk(parseDer(der), 0);
  return found;
}

test('an expired timestamp chain is reported in the bundle verdict, not only in the token result', () => {
  const dir = path.join(ATTESTED, 'bundle');
  const report = verifyBundle(dir, {
    trustRoots: loadTrustRoots(fs.readFileSync(path.join(ATTESTED, 'tsa-root.pem'), 'utf8')),
  });

  // The committed test TSA certificate has a one-day lifetime and the fixture is
  // committed, so this precondition holds permanently from the day after it was
  // generated. Asserting it rather than skipping on it means a regenerated
  // fixture makes this test fail loudly instead of quietly stopping to test
  // anything.
  const lifetime = report.warnings.filter((w) => /^TIMESTAMP LIFETIME:/.test(w));
  assert.equal(
    lifetime.length,
    1,
    `expected one TIMESTAMP LIFETIME warning, got ${report.warnings.length} warnings: ` +
      report.warnings.join(' | '),
  );
  assert.match(lifetime[0], /valid at .+ and has since expired/);
  assert.match(lifetime[0], /still attests what it always attested/);
  assert.match(lifetime[0], /key compromised after expiry cannot be detected/);

  // And the expiry does not retract the timestamp.
  assert.equal(report.verdict, VERDICT.VALID);
  assert.equal(report.derivedAssurance, 'rfc3161');
});
