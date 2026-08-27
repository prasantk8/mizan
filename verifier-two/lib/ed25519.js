// Ed25519 verification over raw 32-byte public keys.
//
// keys.json carries the bare key, but Node's crypto wants a SubjectPublicKeyInfo.
// The wrapper below is built from the ASN.1 in RFC 8410 section 4 rather than
// copied as an opaque magic prefix, so it can be checked against that document:
//
//   SEQUENCE (0x30, 42 bytes)
//     SEQUENCE (0x30, 5 bytes)
//       OBJECT IDENTIFIER 1.3.101.112   -- id-Ed25519, encoded 06 03 2b 65 70
//     BIT STRING (0x03, 33 bytes, 0 unused bits)
//       <32 raw key bytes>

import crypto from 'node:crypto';

const SPKI_PREFIX = Buffer.from([
  0x30, 0x2a,             // SEQUENCE, 42 bytes
  0x30, 0x05,             // SEQUENCE, 5 bytes
  0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112
  0x03, 0x21, 0x00,       // BIT STRING, 33 bytes, 0 unused bits
]);

export const PUBLIC_KEY_BYTES = 32;
export const SIGNATURE_BYTES = 64;

/** @param {Buffer} rawPublicKey 32 bytes */
export function importPublicKey(rawPublicKey) {
  if (rawPublicKey.length !== PUBLIC_KEY_BYTES) {
    throw new Error(`Ed25519 public keys are ${PUBLIC_KEY_BYTES} bytes`);
  }
  return crypto.createPublicKey({
    key: Buffer.concat([SPKI_PREFIX, rawPublicKey]),
    format: 'der',
    type: 'spki',
  });
}

/**
 * @param {crypto.KeyObject} publicKey
 * @param {Buffer} message
 * @param {Buffer} signature 64 bytes
 * @returns {boolean}
 */
export function verify(publicKey, message, signature) {
  if (signature.length !== SIGNATURE_BYTES) return false;
  return crypto.verify(null, message, publicKey, signature);
}
