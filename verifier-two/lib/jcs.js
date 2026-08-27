// RFC 8785 JSON Canonicalization Scheme.
//
// Written from RFC 8785 and EVIDENCE-BUNDLE-FORMAT.md section 1 alone. No Mizan
// source was consulted; see ../README.md for why that matters.
//
// RFC 8785 defines number serialisation as ECMAScript's Number::toString and key
// ordering as ascending UTF-16 code-unit sequence. Both are what a JavaScript
// runtime already does natively, so this module is deliberately thin: the risk in
// a JCS implementation is re-deriving those two rules by hand, not delegating to
// the language that defines them.

/** Thrown when a value cannot appear in canonical JSON at all. */
export class CanonicalizationError extends Error {}

/**
 * Serialise a parsed JSON value to its RFC 8785 canonical UTF-8 bytes.
 * @param {unknown} value
 * @returns {Buffer}
 */
export function jcs(value) {
  return Buffer.from(canonicalize(value), 'utf8');
}

/**
 * Serialise a parsed JSON value to its RFC 8785 canonical form as a string.
 * @param {unknown} value
 * @returns {string}
 */
export function canonicalize(value) {
  if (value === null) return 'null';

  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';

    case 'number':
      if (!Number.isFinite(value)) {
        throw new CanonicalizationError(`non-finite number cannot be canonicalized: ${value}`);
      }
      // RFC 8785 section 3.2.2.3 defers to ECMAScript Number::toString, with the
      // single carve-out that -0 serialises as 0. JSON.stringify implements both.
      return JSON.stringify(value === 0 ? 0 : value);

    case 'string':
      // RFC 8785 section 3.2.2.2 is the JSON string grammar with shortest-form
      // escapes and lowercase \uXXXX. That is exactly JSON.stringify's output,
      // including the well-formed-stringify handling of lone surrogates.
      return JSON.stringify(value);

    case 'object':
      if (Array.isArray(value)) {
        return `[${value.map(canonicalize).join(',')}]`;
      }
      return canonicalizeObject(value);

    default:
      throw new CanonicalizationError(`value of type ${typeof value} is not JSON`);
  }
}

function canonicalizeObject(obj) {
  // RFC 8785 section 3.2.3: sort by UTF-16 code units. The default Array#sort
  // comparator compares strings by UTF-16 code unit, which is the required order
  // and is *not* the same as locale or code-point order.
  const keys = Object.keys(obj).sort();
  const members = keys.map((key) => `${JSON.stringify(key)}:${canonicalize(obj[key])}`);
  return `{${members.join(',')}}`;
}
