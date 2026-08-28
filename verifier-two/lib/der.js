// A minimal, strict DER reader.
//
// Only what RFC 3161 verification needs. Deliberately strict: DER is a canonical
// encoding, and a timestamp token is adversary-supplied input. Indefinite lengths,
// non-minimal lengths and trailing bytes are all rejected rather than tolerated,
// because a parser that accepts two encodings of the same value is a parser an
// attacker can use to make two verifiers disagree.

export class DerError extends Error {}

export const TAG = {
  BOOLEAN: 0x01,
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OID: 0x06,
  UTF8_STRING: 0x0c,
  SEQUENCE: 0x10,
  SET: 0x11,
  PRINTABLE_STRING: 0x13,
  IA5_STRING: 0x16,
  UTC_TIME: 0x17,
  GENERALIZED_TIME: 0x18,
};

export const CLASS = {
  UNIVERSAL: 0,
  APPLICATION: 1,
  CONTEXT: 2,
  PRIVATE: 3,
};

export class DerNode {
  constructor(buffer, start, headerLength, contentLength, tagClass, constructed, tagNumber) {
    this.buffer = buffer;
    this.start = start;
    this.headerLength = headerLength;
    this.contentLength = contentLength;
    this.tagClass = tagClass;
    this.constructed = constructed;
    this.tagNumber = tagNumber;
  }

  /** The complete TLV bytes, header included. Signature inputs need these. */
  get raw() {
    return this.buffer.subarray(this.start, this.start + this.headerLength + this.contentLength);
  }

  /** The value bytes, header excluded. */
  get content() {
    const from = this.start + this.headerLength;
    return this.buffer.subarray(from, from + this.contentLength);
  }

  is(tagNumber, tagClass = CLASS.UNIVERSAL) {
    return this.tagNumber === tagNumber && this.tagClass === tagClass;
  }

  /** Context-specific [n], as used for IMPLICIT and EXPLICIT tagging. */
  isContext(n) {
    return this.tagClass === CLASS.CONTEXT && this.tagNumber === n;
  }

  /** Parse the content as a sequence of TLVs. */
  children() {
    if (!this.constructed) {
      throw new DerError(`tag ${this.tagNumber} is primitive and has no children`);
    }
    return parseSequenceOf(this.content);
  }

  /** Nth child, with a checked expectation so callers do not index blindly. */
  at(index) {
    const kids = this.children();
    if (index >= kids.length) {
      throw new DerError(`expected at least ${index + 1} elements, found ${kids.length}`);
    }
    return kids[index];
  }

  expect(tagNumber, tagClass = CLASS.UNIVERSAL) {
    if (!this.is(tagNumber, tagClass)) {
      throw new DerError(
        `expected tag ${tagClass}/${tagNumber}, found ${this.tagClass}/${this.tagNumber}`,
      );
    }
    return this;
  }
}

/** Parse exactly one DER value, requiring it to consume the whole buffer. */
export function parseDer(buffer) {
  const { node, end } = readNode(buffer, 0);
  if (end !== buffer.length) {
    throw new DerError(`${buffer.length - end} trailing byte(s) after top-level DER value`);
  }
  return node;
}

/** Parse a concatenation of DER values, consuming the whole buffer. */
export function parseSequenceOf(buffer) {
  const nodes = [];
  let offset = 0;
  while (offset < buffer.length) {
    const { node, end } = readNode(buffer, offset);
    nodes.push(node);
    offset = end;
  }
  return nodes;
}

function readNode(buffer, offset) {
  if (offset + 2 > buffer.length) {
    throw new DerError('truncated DER header');
  }

  const identifier = buffer[offset];
  const tagClass = (identifier & 0xc0) >> 6;
  const constructed = (identifier & 0x20) !== 0;
  let tagNumber = identifier & 0x1f;
  let cursor = offset + 1;

  if (tagNumber === 0x1f) {
    // High-tag-number form. Nothing in RFC 3161 or X.509 needs it; refusing it
    // keeps the accepted language small.
    throw new DerError('high-tag-number form is not supported');
  }

  const first = buffer[cursor++];
  let contentLength;
  if (first < 0x80) {
    contentLength = first;
  } else if (first === 0x80) {
    throw new DerError('indefinite length is forbidden in DER');
  } else if (first === 0xff) {
    throw new DerError('reserved length byte 0xff');
  } else {
    const count = first & 0x7f;
    if (count > 4) {
      throw new DerError(`length of ${count} bytes exceeds this reader's limit`);
    }
    if (cursor + count > buffer.length) {
      throw new DerError('truncated DER length');
    }
    contentLength = 0;
    for (let i = 0; i < count; i += 1) {
      contentLength = contentLength * 256 + buffer[cursor + i];
    }
    if (contentLength < 0x80) {
      throw new DerError('non-minimal DER length encoding');
    }
    if (buffer[cursor] === 0x00) {
      throw new DerError('leading zero in DER length');
    }
    cursor += count;
  }

  const headerLength = cursor - offset;
  const end = cursor + contentLength;
  if (end > buffer.length) {
    throw new DerError(
      `DER value claims ${contentLength} content bytes but only ${buffer.length - cursor} remain`,
    );
  }

  return {
    node: new DerNode(buffer, offset, headerLength, contentLength, tagClass, constructed, tagNumber),
    end,
  };
}

/** INTEGER as a BigInt. Serial numbers exceed Number.MAX_SAFE_INTEGER routinely. */
export function readInteger(node) {
  node.expect(TAG.INTEGER);
  const bytes = node.content;
  if (bytes.length === 0) throw new DerError('empty INTEGER');
  if (bytes.length > 1) {
    const lead = bytes[0];
    const next = bytes[1];
    if ((lead === 0x00 && next < 0x80) || (lead === 0xff && next >= 0x80)) {
      throw new DerError('non-minimal INTEGER encoding');
    }
  }
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  if (bytes[0] & 0x80) {
    value -= 1n << BigInt(8 * bytes.length);
  }
  return value;
}

/** OBJECT IDENTIFIER in dotted-decimal form. */
export function readOid(node) {
  node.expect(TAG.OID);
  const bytes = node.content;
  if (bytes.length === 0) throw new DerError('empty OBJECT IDENTIFIER');

  const arcs = [];
  const first = bytes[0];
  arcs.push(Math.floor(first / 40), first % 40);

  let value = 0n;
  let started = false;
  for (let i = 1; i < bytes.length; i += 1) {
    const byte = bytes[i];
    if (!started && byte === 0x80) {
      throw new DerError('non-minimal OID arc encoding');
    }
    started = true;
    value = (value << 7n) | BigInt(byte & 0x7f);
    if ((byte & 0x80) === 0) {
      arcs.push(value.toString());
      value = 0n;
      started = false;
    }
  }
  if (started) throw new DerError('truncated OID arc');
  return arcs.join('.');
}

export function readOctetString(node) {
  node.expect(TAG.OCTET_STRING);
  if (node.constructed) throw new DerError('constructed OCTET STRING is forbidden in DER');
  return node.content;
}

/**
 * GeneralizedTime, restricted to the DER profile RFC 5280 mandates: four-digit
 * year, no fractional-second trailing zeros, and a literal Z. Local-time forms
 * are refused rather than guessed at.
 */
export function readGeneralizedTime(node) {
  node.expect(TAG.GENERALIZED_TIME);
  const text = node.content.toString('ascii');
  const match = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.\d+)?Z$/.exec(text);
  if (!match) throw new DerError(`GeneralizedTime is not in the DER UTC profile: ${text}`);
  const [, y, mo, d, h, mi, s, frac] = match;
  const ms = frac ? Math.round(Number(frac) * 1000) : 0;
  return new Date(Date.UTC(+y, +mo - 1, +d, +h, +mi, +s, ms));
}

/** X.509 validity fields still use UTCTime; the two-digit year pivots at 50. */
export function readUtcTime(node) {
  node.expect(TAG.UTC_TIME);
  const text = node.content.toString('ascii');
  const match = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text);
  if (!match) throw new DerError(`UTCTime is not in the DER profile: ${text}`);
  const [, yy, mo, d, h, mi, s] = match;
  const year = +yy >= 50 ? 1900 + +yy : 2000 + +yy;
  return new Date(Date.UTC(year, +mo - 1, +d, +h, +mi, +s));
}

export function readTime(node) {
  if (node.is(TAG.UTC_TIME)) return readUtcTime(node);
  return readGeneralizedTime(node);
}

/** BIT STRING content with the unused-bit count stripped. */
export function readBitString(node) {
  node.expect(TAG.BIT_STRING);
  const bytes = node.content;
  if (bytes.length === 0) throw new DerError('empty BIT STRING');
  const unused = bytes[0];
  if (unused > 7) throw new DerError(`invalid unused-bit count ${unused}`);
  return { unusedBits: unused, bytes: bytes.subarray(1) };
}
