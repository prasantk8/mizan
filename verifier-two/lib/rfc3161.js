// RFC 3161 timestamp token verification, over RFC 5652 CMS SignedData.
//
// Three outcomes, and keeping them apart is the point:
//   ok:true                    the token verifies against a supplied trust root
//   ok:false, canCheck:true    the token was evaluated and is wrong
//   ok:false, canCheck:false   this environment cannot evaluate the token
//
// EVIDENCE-BUNDLE-FORMAT.md section 5 makes the third case CANNOT CHECK rather
// than an evidence failure, and section 7 says a missing verifier dependency is
// "neither VALID nor evidence failure". Collapsing it into a failure would report
// a missing trust root as a forged timestamp.

import crypto from 'node:crypto';
import { parseDer, parseSequenceOf, readInteger, readOid, readOctetString, readGeneralizedTime, readTime, TAG, CLASS, DerError } from './der.js';
import { OID, digestName, signatureScheme } from './oid.js';

const MAX_CHAIN_DEPTH = 8;

export class CannotCheck extends Error {}
export class TokenInvalid extends Error {}

/**
 * Verify an RFC 3161 token over an expected SHA-256 digest.
 *
 * @param {Buffer} der           TimeStampResp or bare TimeStampToken bytes
 * @param {Buffer} expectedDigest  the 32 bytes the token must be a timestamp over
 * @param {crypto.X509Certificate[]} trustRoots  operator-supplied roots
 * @returns {{ok: boolean, canCheck: boolean, reason: string|null, genTime: Date|null, tsa: string|null}}
 */
export function verifyTimestampToken(der, expectedDigest, trustRoots) {
  try {
    return { ...check(der, expectedDigest, trustRoots), ok: true, canCheck: true, reason: null };
  } catch (error) {
    if (error instanceof CannotCheck) {
      return { ok: false, canCheck: false, reason: error.message, genTime: null, tsa: null };
    }
    if (error instanceof TokenInvalid || error instanceof DerError) {
      return { ok: false, canCheck: true, reason: error.message, genTime: null, tsa: null };
    }
    // An unexpected failure is a limit of this verifier, not evidence about the
    // bundle. Reporting it as an evidence failure would accuse the bundle of
    // something this code cannot actually establish.
    return {
      ok: false,
      canCheck: false,
      reason: `this verifier could not evaluate the token: ${error.message}`,
      genTime: null,
      tsa: null,
    };
  }
}

function check(der, expectedDigest, trustRoots) {
  const signedData = extractSignedData(der);
  const { eContentType, eContent } = readEncapContentInfo(signedData);

  if (eContentType !== OID.tstInfo) {
    throw new TokenInvalid(`encapsulated content is ${eContentType}, not id-ct-TSTInfo`);
  }

  const tst = readTstInfo(eContent);

  if (tst.imprintAlgorithm !== OID.sha256) {
    throw new TokenInvalid(
      `messageImprint uses ${tst.imprintAlgorithm}; the anchor core digest is SHA-256`,
    );
  }
  if (
    tst.imprint.length !== expectedDigest.length ||
    !crypto.timingSafeEqual(tst.imprint, expectedDigest)
  ) {
    throw new TokenInvalid(
      `messageImprint ${tst.imprint.toString('hex')} does not cover the anchor core digest ` +
        `${expectedDigest.toString('hex')}`,
    );
  }

  const certificates = readCertificates(signedData);
  const signerInfo = readSignerInfo(signedData);

  const signer = findSigner(signerInfo, certificates);
  verifySignedAttributes(signerInfo, eContent, eContentType, signer);
  verifySignature(signerInfo, signer);
  requireTimeStampingEku(signer);

  if (trustRoots.length === 0) {
    throw new CannotCheck('no trust roots supplied; RFC 3161 trust roots come from the operator, never from the bundle');
  }
  buildChain(signer, certificates, trustRoots, tst.genTime);

  return { genTime: tst.genTime, tsa: signer.subject };
}

/** Accept either a TimeStampResp or the bare TimeStampToken inside it. */
function extractSignedData(der) {
  const top = parseDer(der);
  top.expect(TAG.SEQUENCE);
  const first = top.at(0);

  let contentInfo;
  if (first.is(TAG.SEQUENCE)) {
    // TimeStampResp: SEQUENCE { PKIStatusInfo, TimeStampToken OPTIONAL }
    const status = Number(readInteger(first.at(0)));
    if (status !== 0 && status !== 1) {
      throw new TokenInvalid(`PKIStatus is ${status}; only granted(0) and grantedWithMods(1) carry a token`);
    }
    const children = top.children();
    if (children.length < 2) {
      throw new TokenInvalid('TimeStampResp granted a request but carries no token');
    }
    contentInfo = children[1];
  } else if (first.is(TAG.OID)) {
    contentInfo = top;
  } else {
    throw new TokenInvalid('input is neither a TimeStampResp nor a ContentInfo');
  }

  contentInfo.expect(TAG.SEQUENCE);
  const contentType = readOid(contentInfo.at(0));
  if (contentType !== OID.signedData) {
    throw new TokenInvalid(`ContentInfo is ${contentType}, not id-signedData`);
  }
  const explicit = contentInfo.at(1);
  if (!explicit.isContext(0)) throw new TokenInvalid('SignedData is not in the [0] EXPLICIT slot');
  return explicit.at(0).expect(TAG.SEQUENCE);
}

function readEncapContentInfo(signedData) {
  const encap = signedData.at(2).expect(TAG.SEQUENCE);
  const eContentType = readOid(encap.at(0));
  const children = encap.children();
  if (children.length < 2) throw new TokenInvalid('SignedData carries no eContent to verify');
  const explicit = children[1];
  if (!explicit.isContext(0)) throw new TokenInvalid('eContent is not in the [0] EXPLICIT slot');
  return { eContentType, eContent: readOctetString(explicit.at(0)) };
}

function readTstInfo(bytes) {
  const tst = parseDer(bytes).expect(TAG.SEQUENCE);
  const fields = tst.children();

  const version = Number(readInteger(fields[0]));
  if (version !== 1) throw new TokenInvalid(`TSTInfo version ${version} is not v1`);

  readOid(fields[1]); // TSAPolicyId; the operator's policy choice, not ours to judge

  const imprint = fields[2].expect(TAG.SEQUENCE);
  const imprintAlgorithm = readOid(imprint.at(0).expect(TAG.SEQUENCE).at(0));
  const imprintBytes = readOctetString(imprint.at(1));

  readInteger(fields[3]); // serialNumber
  const genTime = readGeneralizedTime(fields[4]);

  return { imprintAlgorithm, imprint: imprintBytes, genTime };
}

function readCertificates(signedData) {
  for (const child of signedData.children()) {
    if (child.isContext(0)) {
      return parseSequenceOf(child.content)
        .filter((node) => node.is(TAG.SEQUENCE))
        .map((node) => {
          try {
            return new crypto.X509Certificate(Buffer.from(node.raw));
          } catch (error) {
            // These bytes came from the bundle. OpenSSL refusing them is a fact
            // about the token, not an internal failure, and it has to arrive as
            // a verdict rather than as a stack trace.
            throw new TokenInvalid(`a certificate in the token could not be parsed: ${error.message}`);
          }
        });
    }
  }
  return [];
}

function readSignerInfo(signedData) {
  const children = signedData.children();
  const set = children[children.length - 1];
  set.expect(TAG.SET);
  const infos = set.children();
  if (infos.length !== 1) {
    throw new TokenInvalid(`expected exactly one SignerInfo, found ${infos.length}`);
  }

  const fields = infos[0].expect(TAG.SEQUENCE).children();
  const info = {
    sid: fields[1],
    digestAlgorithm: readOid(fields[2].expect(TAG.SEQUENCE).at(0)),
    signedAttrs: null,
    signatureAlgorithm: null,
    signature: null,
  };

  let index = 3;
  if (fields[index] && fields[index].isContext(0)) {
    info.signedAttrs = fields[index];
    index += 1;
  }
  info.signatureAlgorithm = fields[index].expect(TAG.SEQUENCE);
  info.signature = readOctetString(fields[index + 1]);
  return info;
}

function findSigner(signerInfo, certificates) {
  const { sid } = signerInfo;

  if (sid.is(TAG.SEQUENCE)) {
    // issuerAndSerialNumber
    const issuerDer = sid.at(0).raw;
    const serial = readInteger(sid.at(1));
    for (const cert of certificates) {
      const tbs = parseDer(Buffer.from(cert.raw)).at(0);
      const fields = tbs.children();
      const offset = fields[0].isContext(0) ? 1 : 0;
      const certSerial = readInteger(fields[offset]);
      const certIssuer = fields[offset + 2].raw;
      if (certSerial === serial && Buffer.from(certIssuer).equals(Buffer.from(issuerDer))) {
        return cert;
      }
    }
    throw new TokenInvalid('no bundled certificate matches the SignerInfo issuerAndSerialNumber');
  }

  if (sid.isContext(0)) {
    // subjectKeyIdentifier
    const wanted = Buffer.from(sid.content);
    for (const cert of certificates) {
      const skid = findExtension(cert, '2.5.29.14');
      if (skid && Buffer.from(readOctetString(parseDer(skid.value))).equals(wanted)) return cert;
    }
    throw new TokenInvalid('no bundled certificate matches the SignerInfo subjectKeyIdentifier');
  }

  throw new TokenInvalid('unrecognised SignerIdentifier form');
}

function verifySignedAttributes(signerInfo, eContent, eContentType, signer) {
  if (!signerInfo.signedAttrs) {
    // RFC 3161 section 2.4.2 requires signed attributes on a timestamp token.
    throw new TokenInvalid('timestamp token has no signed attributes');
  }

  const digest = digestName(signerInfo.digestAlgorithm);
  if (!digest) {
    throw new CannotCheck(`unsupported SignerInfo digest algorithm ${signerInfo.digestAlgorithm}`);
  }

  const attrs = new Map();
  for (const attr of signerInfo.signedAttrs.children()) {
    const type = readOid(attr.expect(TAG.SEQUENCE).at(0));
    attrs.set(type, attr.at(1).expect(TAG.SET));
  }

  const contentTypeAttr = attrs.get(OID.contentType);
  if (!contentTypeAttr) throw new TokenInvalid('signed attributes omit content-type');
  if (readOid(contentTypeAttr.at(0)) !== eContentType) {
    throw new TokenInvalid('signed content-type attribute does not match eContentType');
  }

  const messageDigestAttr = attrs.get(OID.messageDigest);
  if (!messageDigestAttr) throw new TokenInvalid('signed attributes omit message-digest');
  const claimed = readOctetString(messageDigestAttr.at(0));
  const actual = crypto.createHash(digest).update(eContent).digest();
  if (!Buffer.from(claimed).equals(actual)) {
    throw new TokenInvalid('signed message-digest attribute does not cover the TSTInfo');
  }

  // RFC 5035 ESSCertIDv2 binds the signature to one certificate. Without it a
  // token verifies under any certificate carrying the same key.
  const essV2 = attrs.get(OID.signingCertificateV2);
  const essV1 = attrs.get(OID.signingCertificate);
  if (essV2) verifyEssCertId(essV2, signer, true);
  else if (essV1) verifyEssCertId(essV1, signer, false);
}

function verifyEssCertId(attrValue, signer, isV2) {
  const seq = attrValue.at(0).expect(TAG.SEQUENCE);
  const certs = seq.at(0).expect(TAG.SEQUENCE);
  const first = certs.at(0).expect(TAG.SEQUENCE);
  const fields = first.children();

  let algorithm = 'sha1';
  let hashIndex = 0;
  if (isV2 && fields[0].is(TAG.SEQUENCE)) {
    const oid = readOid(fields[0].at(0));
    const name = digestName(oid);
    if (!name) throw new CannotCheck(`unsupported ESSCertIDv2 hash algorithm ${oid}`);
    algorithm = name;
    hashIndex = 1;
  }

  const claimed = Buffer.from(readOctetString(fields[hashIndex]));
  const actual = crypto.createHash(algorithm).update(Buffer.from(signer.raw)).digest();
  if (!claimed.equals(actual)) {
    throw new TokenInvalid('ESSCertID does not identify the certificate that verified the signature');
  }
}

function verifySignature(signerInfo, signer) {
  const algorithmOid = readOid(signerInfo.signatureAlgorithm.at(0));

  // RFC 5652 section 5.3 permits the bare key algorithm here, in which case the
  // digest is the one named in digestAlgorithm rather than baked into the OID.
  // Sectigo's public TSA emits tokens in exactly this form, so a verifier that
  // only understands the combined sha*WithRSA OIDs reports a real public
  // timestamp as unverifiable.
  const scheme =
    algorithmOid === OID.rsaEncryption
      ? { digest: digestName(signerInfo.digestAlgorithm), scheme: 'rsa-pkcs1' }
      : signatureScheme(algorithmOid);

  if (!scheme) throw new CannotCheck(`unsupported signature algorithm ${algorithmOid}`);
  if (scheme.scheme === 'rsa-pkcs1' && !scheme.digest) {
    throw new CannotCheck(`unsupported digest algorithm ${signerInfo.digestAlgorithm}`);
  }

  // RFC 5652 section 5.4: the signature covers the DER SET OF signed attributes,
  // which is the [0] IMPLICIT node re-tagged. The bytes on the wire are tagged
  // A0; signing them as-is is the classic CMS implementation bug.
  const attrs = Buffer.from(signerInfo.signedAttrs.raw);
  const signedBytes = Buffer.concat([Buffer.from([0x31]), attrs.subarray(1)]);

  const signature = Buffer.from(signerInfo.signature);
  const key = signer.publicKey;
  let ok;

  switch (scheme.scheme) {
    case 'rsa-pkcs1':
      ok = crypto.verify(scheme.digest, signedBytes, { key, padding: crypto.constants.RSA_PKCS1_PADDING }, signature);
      break;
    case 'ecdsa':
      ok = crypto.verify(scheme.digest, signedBytes, { key, dsaEncoding: 'der' }, signature);
      break;
    case 'ed25519':
      ok = crypto.verify(null, signedBytes, key, signature);
      break;
    case 'rsa-pss': {
      const params = readPssParameters(signerInfo.signatureAlgorithm);
      ok = crypto.verify(params.digest, signedBytes, {
        key,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: params.saltLength,
      }, signature);
      break;
    }
    default:
      throw new CannotCheck(`unsupported signature scheme ${scheme.scheme}`);
  }

  if (!ok) throw new TokenInvalid('timestamp signature does not verify under the signing certificate');
}

function readPssParameters(algorithmIdentifier) {
  const children = algorithmIdentifier.children();
  let digest = 'sha1';
  let saltLength = 20;
  if (children.length > 1 && children[1].is(TAG.SEQUENCE)) {
    for (const field of children[1].children()) {
      if (field.isContext(0)) {
        const name = digestName(readOid(field.at(0).at(0)));
        if (!name) throw new CannotCheck('unsupported RSASSA-PSS hash algorithm');
        digest = name;
      } else if (field.isContext(2)) {
        saltLength = Number(readInteger(field.at(0)));
      }
    }
  }
  return { digest, saltLength };
}

function requireTimeStampingEku(signer) {
  const extension = findExtension(signer, OID.extKeyUsage);
  assertTimeStampingEku(
    extension && {
      critical: extension.critical,
      purposes: parseDer(extension.value).expect(TAG.SEQUENCE).children().map(readOid),
    },
  );
}

/**
 * RFC 3161 section 2.3: the timestamping certificate MUST have the extended key
 * usage extension, it MUST be critical, and it MUST contain id-kp-timeStamping
 * and nothing else. A TSA certificate that is also good for TLS or code signing
 * is a certificate whose other uses can be turned into timestamps.
 *
 * Separated from certificate parsing so the policy can be exercised without
 * minting a certificate for each way of getting it wrong.
 *
 * @param {{critical: boolean, purposes: string[]}|null|undefined} extension
 */
export function assertTimeStampingEku(extension) {
  if (!extension) {
    throw new TokenInvalid('signing certificate has no extended key usage extension');
  }
  if (!extension.critical) {
    throw new TokenInvalid('extended key usage on the signing certificate is not critical');
  }
  const { purposes } = extension;
  if (purposes.length !== 1 || purposes[0] !== OID.timeStamping) {
    throw new TokenInvalid(
      `signing certificate extended key usage is [${purposes.join(', ')}], not id-kp-timeStamping alone`,
    );
  }
}

function buildChain(signer, bundled, trustRoots, at) {
  const pool = [...bundled, ...trustRoots];
  const rootSet = new Set(trustRoots.map((cert) => cert.fingerprint256));

  let current = signer;
  for (let depth = 0; depth < MAX_CHAIN_DEPTH; depth += 1) {
    requireValidAt(current, at);

    if (rootSet.has(current.fingerprint256)) return;

    const issuer = pool.find(
      (candidate) =>
        candidate.fingerprint256 !== current.fingerprint256 &&
        current.checkIssued(candidate) &&
        current.verify(candidate.publicKey),
    );

    if (!issuer) {
      throw new CannotCheck(
        `no path from "${signer.subject}" to a supplied trust root; stopped at issuer "${current.issuer}"`,
      );
    }
    if (issuer.ca === false) {
      throw new TokenInvalid(`certificate "${issuer.subject}" signed a certificate but is not a CA`);
    }
    current = issuer;
  }
  throw new TokenInvalid(`certificate chain exceeds ${MAX_CHAIN_DEPTH} certificates`);
}

function requireValidAt(cert, at) {
  const from = new Date(cert.validFrom);
  const to = new Date(cert.validTo);
  if (at < from || at > to) {
    throw new TokenInvalid(
      `certificate "${cert.subject}" was not valid at the timestamp's genTime ${at.toISOString()}`,
    );
  }
}

/** Locate an X.509 extension by OID, returning its criticality and inner bytes. */
export function findExtension(cert, oid) {
  const tbs = parseDer(Buffer.from(cert.raw)).expect(TAG.SEQUENCE).at(0).expect(TAG.SEQUENCE);
  for (const field of tbs.children()) {
    if (!field.isContext(3)) continue;
    for (const ext of field.at(0).expect(TAG.SEQUENCE).children()) {
      const fields = ext.expect(TAG.SEQUENCE).children();
      if (readOid(fields[0]) !== oid) continue;
      const critical = fields.length === 3 && fields[1].is(TAG.BOOLEAN) && fields[1].content[0] !== 0;
      return { critical, value: Buffer.from(readOctetString(fields[fields.length - 1])) };
    }
  }
  return null;
}

/** Load every certificate in a PEM file. Trust roots are operator-supplied. */
export function loadTrustRoots(pemText) {
  const blocks = pemText.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
  if (!blocks) return [];
  return blocks.map((block) => new crypto.X509Certificate(block));
}
