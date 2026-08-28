// Strict decoders for the byte-carrying fields of a bundle.
//
// Node's Buffer.from(text, 'base64') silently discards characters outside the
// alphabet: a signature with a space spliced into it decodes to 63 bytes instead
// of failing. Ed25519 then rejects it, so the verdict happens to come out right,
// but for the wrong reason and only by luck. These decoders fail on the
// malformed input itself.

export class DecodeError extends Error {}

const STANDARD = /^[A-Za-z0-9+/]*={0,2}$/;
const URL_SAFE = /^[A-Za-z0-9\-_]*={0,2}$/;

/**
 * Decode Base64, accepting both the standard and URL-safe alphabets.
 *
 * Section 1 of the spec says only "Base64" and does not name an alphabet. The
 * fixtures use both -- signatures are URL-safe, public keys are standard -- so
 * an implementation that picked one would reject real bundles. See FINDINGS.md
 * S-1: this is a spec defect, and accepting both is the compatible reading, not
 * the correct-by-construction one.
 *
 * @param {unknown} text
 * @param {number} expectedBytes  required decoded length
 * @param {string} label          for the error message
 * @returns {Buffer}
 */
export function decodeBase64(text, expectedBytes, label) {
  if (typeof text !== 'string') {
    throw new DecodeError(`${label} is ${describe(text)}, not a Base64 string`);
  }
  if (!STANDARD.test(text) && !URL_SAFE.test(text)) {
    throw new DecodeError(`${label} contains characters outside the Base64 alphabet`);
  }
  if (text.length % 4 !== 0) {
    throw new DecodeError(`${label} is not a whole number of Base64 quanta`);
  }

  const bytes = Buffer.from(text.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  if (bytes.length !== expectedBytes) {
    throw new DecodeError(
      `${label} decodes to ${bytes.length} bytes; ${expectedBytes} are required`,
    );
  }
  return bytes;
}

const HEX_64 = /^[0-9a-f]{64}$/;

/** A SHA-256 digest as the spec writes them: lowercase hex, exactly 64 chars. */
export function requireSha256Hex(value, label) {
  if (typeof value !== 'string' || !HEX_64.test(value)) {
    throw new DecodeError(
      `${label} is not a lowercase hexadecimal SHA-256 digest: ${describe(value)}`,
    );
  }
  return value;
}

export const ZERO_DIGEST = '0'.repeat(64);

function describe(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'an array';
  if (typeof value === 'object') return 'an object';
  if (typeof value === 'string') return `the string ${JSON.stringify(value.slice(0, 40))}`;
  return String(value);
}
