// Object identifiers used by RFC 3161 timestamp verification, each written out
// with the name it carries in its defining document so the constant can be
// checked against that document rather than against another implementation.

export const OID = {
  // RFC 5652 CMS
  signedData: '1.2.840.113549.1.7.2',
  contentType: '1.2.840.113549.1.9.3',
  messageDigest: '1.2.840.113549.1.9.4',
  signingTime: '1.2.840.113549.1.9.5',

  // RFC 3161 / RFC 5035
  tstInfo: '1.2.840.113549.1.9.16.1.4',
  signingCertificate: '1.2.840.113549.1.9.16.2.12',
  signingCertificateV2: '1.2.840.113549.1.9.16.2.47',

  // Digest algorithms
  sha1: '1.3.14.3.2.26',
  sha224: '2.16.840.1.101.3.4.2.4',
  sha256: '2.16.840.1.101.3.4.2.1',
  sha384: '2.16.840.1.101.3.4.2.2',
  sha512: '2.16.840.1.101.3.4.2.3',

  // Signature algorithms
  rsaEncryption: '1.2.840.113549.1.1.1',
  sha1WithRsa: '1.2.840.113549.1.1.5',
  sha256WithRsa: '1.2.840.113549.1.1.11',
  sha384WithRsa: '1.2.840.113549.1.1.12',
  sha512WithRsa: '1.2.840.113549.1.1.13',
  rsassaPss: '1.2.840.113549.1.1.10',
  ecdsaWithSha256: '1.2.840.10045.4.3.2',
  ecdsaWithSha384: '1.2.840.10045.4.3.3',
  ecdsaWithSha512: '1.2.840.10045.4.3.4',
  ed25519: '1.3.101.112',

  // X.509 extensions
  extKeyUsage: '2.5.29.37',
  basicConstraints: '2.5.29.19',
  timeStamping: '1.3.6.1.5.5.7.3.8',
};

/** Node's digest name for a digest-algorithm OID, or null if unsupported. */
export function digestName(oid) {
  switch (oid) {
    case OID.sha1: return 'sha1';
    case OID.sha224: return 'sha224';
    case OID.sha256: return 'sha256';
    case OID.sha384: return 'sha384';
    case OID.sha512: return 'sha512';
    default: return null;
  }
}

/**
 * Signature scheme for a signature-algorithm OID.
 * Returns { digest, scheme } or null when this verifier cannot evaluate it —
 * "cannot evaluate" is a distinct outcome from "evaluated and failed".
 */
export function signatureScheme(oid) {
  switch (oid) {
    case OID.sha1WithRsa: return { digest: 'sha1', scheme: 'rsa-pkcs1' };
    case OID.sha256WithRsa: return { digest: 'sha256', scheme: 'rsa-pkcs1' };
    case OID.sha384WithRsa: return { digest: 'sha384', scheme: 'rsa-pkcs1' };
    case OID.sha512WithRsa: return { digest: 'sha512', scheme: 'rsa-pkcs1' };
    case OID.rsassaPss: return { digest: null, scheme: 'rsa-pss' };
    case OID.ecdsaWithSha256: return { digest: 'sha256', scheme: 'ecdsa' };
    case OID.ecdsaWithSha384: return { digest: 'sha384', scheme: 'ecdsa' };
    case OID.ecdsaWithSha512: return { digest: 'sha512', scheme: 'ecdsa' };
    case OID.ed25519: return { digest: null, scheme: 'ed25519' };
    default: return null;
  }
}
