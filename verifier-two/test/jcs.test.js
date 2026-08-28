import test from 'node:test';
import assert from 'node:assert/strict';
import { canonicalize, CanonicalizationError } from '../lib/jcs.js';

const U0080 = String.fromCharCode(0x80);

// RFC 8785 section 3.2.3, the published sorting example. This vector is the one
// that separates UTF-16 code-unit ordering from code-point ordering: the emoji
// (U+1F600, whose first code unit is D83D) must sort BEFORE U+FB33.
test('RFC 8785 sorts object keys by UTF-16 code unit, not code point', () => {
  const input = JSON.parse(
    '{"\\u20ac":"Euro Sign","\\r":"Carriage Return",' +
      '"\\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One",' +
      '"\\ud83d\\ude00":"Emoji: Grinning Face","\\u0080":"Control",' +
      '"\\u00f6":"Latin Small Letter O With Diaeresis"}',
  );

  const expected =
    '{"\\r":"Carriage Return","1":"One","' + U0080 + '":"Control",' +
    '"ö":"Latin Small Letter O With Diaeresis","€":"Euro Sign",' +
    '"😀":"Emoji: Grinning Face","דּ":"Hebrew Letter Dalet With Dagesh"}';

  assert.equal(canonicalize(input), expected);
});

test('a code-point sort would order this differently', () => {
  // Guards the test above against passing for the wrong reason: if the comparator
  // were "fixed" to sort by code point, U+1F600 would move after U+FB33.
  const byCodePoint = ['😀', 'דּ'].sort(
    (a, b) => a.codePointAt(0) - b.codePointAt(0),
  );
  const byCodeUnit = ['😀', 'דּ'].sort();
  assert.notDeepEqual(byCodePoint, byCodeUnit);
});

// RFC 8785 section 3.2.2.3 number serialisation.
test('numbers use ECMAScript Number::toString', () => {
  const cases = [
    [1e30, '1e+30'],
    [0.000001, '0.000001'],
    [1e-7, '1e-7'],
    [1e21, '1e+21'],
    [1e20, '100000000000000000000'],
    [9007199254740992, '9007199254740992'],
    [-0, '0'],
    [0, '0'],
    [5e-324, '5e-324'],
    [1.7976931348623157e308, '1.7976931348623157e+308'],
    [-1.5, '-1.5'],
  ];
  for (const [value, expected] of cases) {
    assert.equal(canonicalize(value), expected, `canonicalize(${expected})`);
  }
});

test('control characters use shortest-form escapes with lowercase hex', () => {
  assert.equal(canonicalize(String.fromCharCode(0x00)), '"\\u0000"');
  assert.equal(canonicalize(String.fromCharCode(0x1f)), '"\\u001f"');
  assert.equal(canonicalize('\b\t\n\f\r'), '"\\b\\t\\n\\f\\r"');
  assert.equal(canonicalize('"\\'), '"\\"\\\\"');
});

test('U+0080 is a C1 control but is not escaped, because RFC 8785 escapes only below U+0020', () => {
  // Asserted on bytes rather than on JSON.stringify, which is the implementation.
  assert.deepEqual(
    Buffer.from(canonicalize(U0080), 'utf8'),
    Buffer.from([0x22, 0xc2, 0x80, 0x22]),
  );
});

test('nested structure and empty containers', () => {
  assert.equal(canonicalize({}), '{}');
  assert.equal(canonicalize([]), '[]');
  assert.equal(
    canonicalize({ b: [1, { d: null, c: true }], a: 'x' }),
    '{"a":"x","b":[1,{"c":true,"d":null}]}',
  );
});

test('arrays keep their order', () => {
  assert.equal(canonicalize(['b', 'a', 'c']), '["b","a","c"]');
});

test('non-finite numbers are refused rather than silently coerced', () => {
  assert.throws(() => canonicalize(NaN), CanonicalizationError);
  assert.throws(() => canonicalize(Infinity), CanonicalizationError);
});

test('undefined is not JSON', () => {
  assert.throws(() => canonicalize(undefined), CanonicalizationError);
});
