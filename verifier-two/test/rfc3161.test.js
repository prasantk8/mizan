import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

import { verifyTimestampToken, loadTrustRoots, assertTimeStampingEku, TokenInvalid } from '../lib/rfc3161.js';
import { parseDer, readOid, readInteger, DerError, TAG } from '../lib/der.js';
import { OID } from '../lib/oid.js';
import { jcs } from '../lib/jcs.js';
import { anchorCoreDigest } from '../lib/verify.js';

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
