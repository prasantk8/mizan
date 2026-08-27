// Mizan evidence bundle verification, section by section against
// docs/spec/EVIDENCE-BUNDLE-FORMAT.md 1.0.
//
// Written from that document and the conformance fixtures alone. Every constant
// here is traceable to a sentence in the spec or to an RFC; where the spec did
// not supply one, the gap is recorded in FINDINGS.md rather than filled in from
// the reference implementation.

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

import { jcs } from './jcs.js';
import { Report, VERDICT } from './verdict.js';
import { decodeBase64, requireSha256Hex, ZERO_DIGEST, DecodeError } from './codec.js';
import { importPublicKey, verify as ed25519Verify, SIGNATURE_BYTES, PUBLIC_KEY_BYTES } from './ed25519.js';
import { verifyTimestampToken } from './rfc3161.js';

// --- Section 1 constants -----------------------------------------------------

const MANIFEST = 'manifest.json';
const NON_MANIFEST_FILES = Object.freeze([
  'records.json',
  'receipts.json',
  'anchors.json',
  'checkpoints.json',
  'keys.json',
]);
const REQUIRED_FILES = Object.freeze([MANIFEST, ...NON_MANIFEST_FILES]);

const BUNDLE_VERSION = '1.0';
const CANONICALIZATION = 'RFC8785';
const HASH_ALGORITHM = 'SHA-256';

// --- Section 4 constants -----------------------------------------------------

const KEY_MEMBERS = Object.freeze([
  'key_id', 'role', 'custody', 'algorithm', 'public_key',
  'not_before', 'not_after', 'revoked_at',
]);
const KEY_ALGORITHM = 'Ed25519';
const CUSTODY_VALUES = Object.freeze(new Set(['development-derived', 'kms', 'hsm']));

const ROLE_RECEIPT = 'evidence-receipt';
const ROLE_ANCHOR = 'evidence-anchor';

// Section 4 mandates this string exactly. It is asserted verbatim in the test
// suite so a reworded "improvement" fails rather than silently weakening it.
export const DEVELOPMENT_CUSTODY_WARNING =
  'KEY CUSTODY: publicly derivable development key — this bundle is forgeable by anyone who reads it.';

const EXTERNAL_TYPES = Object.freeze(new Set(['rfc3161', 'customer_countersignature']));
const DEVELOPMENT_TYPE = 'none_development';
const DEVELOPMENT_AUTHORITY = 'development';

// Internal only: not one of the four assurance states. Marks an anchor whose
// attestation could not be evaluated here, so that the claimed-versus-derived
// comparison is skipped instead of being decided against the bundle.
const INDETERMINATE = Symbol('indeterminate');

// --- Section 6, reproduced at every clean verdict ----------------------------

export const LIMITS_OF_A_CLEAN_VERDICT = Object.freeze([
  'A valid bundle does NOT prove that a record was not omitted before it entered the chain (TM-001 pre-chain omission).',
  'A valid bundle does NOT prove that the exporting party did not withhold an entire final anchor or history suffix.',
  'RFC 3161 proves an included anchor existed by a time. It does not prove that no later anchor exists.',
  'A bundle does NOT prove when it was recorded after its declared expires_at. Bundle 1.0 claims ' +
    'offline verifiability for the lifetime of the timestamp authority\'s certificate and no longer ' +
    '(ADR-004 G.19); past the horizon a re-check supports only that the signer chains to the ' +
    'operator\'s trust root and the imprint is this anchor, never the time the token asserts.',
]);

/**
 * Verify one bundle directory.
 *
 * @param {string} bundleDir
 * @param {{trustRoots?: import('node:crypto').X509Certificate[]}} [options]
 * @returns {Report}
 */
export function verifyBundle(bundleDir, options = {}) {
  const report = new Report();
  try {
    return runChecks(bundleDir, options, report);
  } catch (error) {
    // A verifier that crashes on hostile input has no verdict, and an auditor
    // reading a stack trace learns nothing about the bundle. Section 5 has a
    // class for exactly this: the environment could not evaluate the claim.
    report.cannotCheck(`this verifier failed while reading the bundle: ${error.message}`);
    return report;
  }
}

function runChecks(bundleDir, options, report) {
  const trustRoots = options.trustRoots ?? [];

  // The order of these phases is itself normative, and the spec does not say so.
  // See FINDINGS.md D-2: running the schema checks before the manifest digests
  // makes a tampered bundle report as MALFORMED ("not a Mizan bundle") when the
  // truth is that it *was* one and someone edited it. Digests cover stored
  // bytes, so once they fail, every later observation about that file's contents
  // describes data already known not to be the producer's.

  // Phase 1 -- encoding and JSON parseability. Nothing can be said about bytes
  // that are not UTF-8 JSON, so this is grammar and it outranks everything.
  const bundle = loadBundle(bundleDir, report);
  if (report.has(VERDICT.MALFORMED)) return report;

  // Phase 2 -- manifest grammar, because the digests live in the manifest and
  // cannot be read from a manifest that does not conform.
  checkManifestGrammar(bundle, report);
  if (report.has(VERDICT.MALFORMED)) return report;

  // Phase 3 -- the file inventory over stored bytes. A mismatch is tamper
  // evidence and stops interpretation of the altered file.
  checkFileDigests(bundle, report);
  if (report.has(VERDICT.INVALID)) {
    warnOnDevelopmentCustody(bundle, report);
    return report;
  }

  // Phase 4 -- the rest of the 1.0 grammar, now over bytes the manifest vouches for.
  checkStructuralGrammar(bundle, report);
  if (report.has(VERDICT.MALFORMED)) return report;

  // Phase 5 -- evidence.
  const keyring = buildKeyring(bundle, report);
  checkRecordChain(bundle, report);
  checkReceipts(bundle, keyring, report);
  const anchorStates = checkAnchors(bundle, keyring, trustRoots, report);
  checkCheckpoints(bundle, report);
  checkAssurance(bundle, anchorStates, report);

  for (const limit of LIMITS_OF_A_CLEAN_VERDICT) report.note(limit);
  return report;
}

/**
 * Section 4's custody warning is a MUST, so it is emitted even on the tamper
 * short-circuit -- but only when keys.json's own digest is intact, since a file
 * the manifest disowns cannot be quoted as fact.
 */
function warnOnDevelopmentCustody(bundle, report) {
  const declared = bundle.json[MANIFEST].files['keys.json'];
  if (sha256Hex(bundle.bytes['keys.json']) !== declared) return;
  const keys = bundle.json['keys.json'];
  if (Array.isArray(keys) && keys.some((key) => isObject(key) && key.custody === 'development-derived')) {
    report.warn(DEVELOPMENT_CUSTODY_WARNING);
  }
}

// =============================================================================
// Section 1 -- loading, encoding, canonicalization
// =============================================================================

function loadBundle(bundleDir, report) {
  const bundle = { dir: bundleDir, bytes: {}, json: {} };

  let entries;
  try {
    entries = fs.readdirSync(bundleDir, { withFileTypes: true });
  } catch (error) {
    report.malformed(`cannot read bundle directory ${bundleDir}: ${error.message}`);
    return bundle;
  }

  const present = new Set(entries.filter((e) => e.isFile()).map((e) => e.name));
  for (const name of REQUIRED_FILES) {
    if (!present.has(name)) report.malformed(`required file ${name} is missing`);
  }
  if (report.has(VERDICT.MALFORMED)) return bundle;

  // Section 1 says a bundle is a directory containing "exactly these six" files.
  // Read strictly, a README would make a bundle MALFORMED. That is almost
  // certainly not the intent, so extra files are reported rather than rejected.
  // See FINDINGS.md S-2.
  for (const name of present) {
    if (!REQUIRED_FILES.includes(name)) {
      report.note(`bundle directory contains an undeclared file: ${name}`);
    }
  }

  for (const name of REQUIRED_FILES) {
    const bytes = fs.readFileSync(path.join(bundleDir, name));
    bundle.bytes[name] = bytes;

    let text;
    try {
      text = decodeUtf8Strict(bytes);
    } catch (error) {
      report.malformed(`${name} is not well-formed UTF-8: ${error.message}`);
      continue;
    }
    if (text.charCodeAt(0) === 0xfeff) {
      report.malformed(`${name} begins with a byte order mark; section 1 forbids a BOM`);
      continue;
    }

    const parsed = parseJsonStrictly(text, name, report);
    if (parsed !== undefined) bundle.json[name] = parsed;
  }

  return bundle;
}

function decodeUtf8Strict(bytes) {
  // TextDecoder with fatal:true rejects the overlong and surrogate encodings
  // that Buffer#toString silently replaces with U+FFFD.
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}

function parseJsonStrictly(text, name, report) {
  const unsafeIntegers = [];
  let value;

  try {
    value = JSON.parse(text, function reviver(key, parsed, context) {
      if (typeof parsed === 'number' && context && typeof context.source === 'string') {
        const source = context.source;
        // A JSON integer larger than 2^53 parses to a different value in a
        // double-based runtime than in one with arbitrary-precision integers,
        // so the two would canonicalize differently and disagree on every hash
        // downstream. The spec sets no bound on integer magnitude; see
        // FINDINGS.md S-3.
        if (!/[.eE]/.test(source) && !Number.isSafeInteger(parsed)) {
          unsafeIntegers.push(source);
        }
      }
      return parsed;
    });
  } catch (error) {
    report.malformed(`${name} is not valid JSON: ${error.message}`);
    return undefined;
  }

  if (unsafeIntegers.length > 0) {
    report.cannotCheck(
      `${name} contains integer literal(s) beyond IEEE-754 exact range ` +
        `(${unsafeIntegers.slice(0, 3).join(', ')}); this runtime cannot canonicalize them faithfully`,
    );
  }
  return value;
}

// =============================================================================
// Grammar -- everything that makes the input not a bundle at all
// =============================================================================

function checkStructuralGrammar(bundle, report) {
  checkRecordsGrammar(bundle, report);
  checkReceiptsGrammar(bundle, report);
  checkKeysGrammar(bundle, report);
  checkAnchorsGrammar(bundle, report);
  checkCheckpointsGrammar(bundle, report);
}

function checkManifestGrammar(bundle, report) {
  const manifest = bundle.json[MANIFEST];
  if (!isObject(manifest)) {
    report.malformed(`${MANIFEST} is not a JSON object`);
    return;
  }

  requireEquals(manifest.bundle_version, BUNDLE_VERSION, 'manifest bundle_version', report);
  requireEquals(manifest.canonicalization, CANONICALIZATION, 'manifest canonicalization', report);
  requireEquals(manifest.hash_algorithm, HASH_ALGORITHM, 'manifest hash_algorithm', report);
  requireString(manifest.tenant_id, 'manifest tenant_id', report);
  requireString(manifest.stream_id, 'manifest stream_id', report);

  const range = manifest.range;
  if (!isObject(range)) {
    report.malformed('manifest range is not an object');
  } else {
    const from = range.from_sequence;
    const to = range.to_sequence;
    if (!isSequence(from)) report.malformed('manifest range.from_sequence is not a non-negative integer');
    if (!isSequence(to)) report.malformed('manifest range.to_sequence is not a non-negative integer');
    if (isSequence(from) && isSequence(to) && to < from) {
      report.malformed(`manifest range ${from}..${to} is inverted`);
    }
  }

  if (!isObject(manifest.assurance)) {
    report.malformed('manifest assurance is not an object');
  }

  const files = manifest.files;
  if (!isObject(files)) {
    report.malformed('manifest files is not an object');
    return;
  }
  const declared = Object.keys(files).sort();
  const expected = [...NON_MANIFEST_FILES].sort();
  if (declared.join(',') !== expected.join(',')) {
    report.malformed(
      `manifest files must list exactly [${expected.join(', ')}]; it lists [${declared.join(', ')}]`,
    );
    return;
  }
  // Section 1 says files "maps each to hex(SHA-256(complete stored file bytes))",
  // which reads as a grammar rule about the manifest. It cannot be one: the
  // invalid-record-checksum fixture has a well-formed digest that does not match
  // and is expected to be INVALID, not MALFORMED. So the sentence states an
  // evidence requirement, and it has to be read that way uniformly -- a digest
  // of the wrong shape fails the same comparison as a digest of the wrong value.
  // Only the JSON type is grammar here. See FINDINGS.md D-3.
  for (const name of NON_MANIFEST_FILES) {
    requireString(files[name], `manifest files["${name}"]`, report);
  }
}

function checkRecordsGrammar(bundle, report) {
  const records = bundle.json['records.json'];
  if (!Array.isArray(records)) {
    report.malformed('records.json is not a JSON array');
    return;
  }
  if (records.length === 0) {
    report.malformed('records.json is empty; section 1 requires a non-empty record array');
    return;
  }
  records.forEach((record, index) => {
    const at = `records[${index}]`;
    if (!isObject(record)) {
      report.malformed(`${at} is not an object`);
      return;
    }
    if (!isSequence(record.sequence_number)) {
      report.malformed(`${at}.sequence_number is not a non-negative integer`);
    }
    requireDigest(record.prev_hash, `${at}.prev_hash`, report);
    requireDigest(record.record_hash, `${at}.record_hash`, report);
    requireString(record.tenant_id, `${at}.tenant_id`, report);
    requireString(record.stream_id, `${at}.stream_id`, report);
  });
}

function checkReceiptsGrammar(bundle, report) {
  const receipts = bundle.json['receipts.json'];
  if (!Array.isArray(receipts)) {
    report.malformed('receipts.json is not a JSON array');
    return;
  }
  receipts.forEach((receipt, index) => {
    const at = `receipts[${index}]`;
    if (!isObject(receipt)) {
      report.malformed(`${at} is not an object`);
      return;
    }
    if (!isObject(receipt.payload)) {
      report.malformed(`${at}.payload is not an object`);
      return;
    }
    const payload = receipt.payload;
    if (!isSequence(payload.sequence_number)) {
      report.malformed(`${at}.payload.sequence_number is not a non-negative integer`);
    }
    requireDigest(payload.record_hash, `${at}.payload.record_hash`, report);
    requireString(payload.tenant_id, `${at}.payload.tenant_id`, report);
    requireString(payload.stream_id, `${at}.payload.stream_id`, report);
    requireString(payload.key_id, `${at}.payload.key_id`, report);
    requireString(payload.object_key, `${at}.payload.object_key`, report);
    requireString(payload.object_version, `${at}.payload.object_version`, report);
    requireString(receipt.signature, `${at}.signature`, report);
  });
}

function checkKeysGrammar(bundle, report) {
  const keys = bundle.json['keys.json'];
  if (!Array.isArray(keys)) {
    report.malformed('keys.json is not a JSON array');
    return;
  }
  keys.forEach((key, index) => {
    const at = `keys[${index}]`;
    if (!isObject(key)) {
      report.malformed(`${at} is not an object`);
      return;
    }
    // Section 4: "Key documents have exactly [these eight members] in version 1.0."
    // Exactly, so a missing member and an extra member are both grammar failures.
    const present = Object.keys(key).sort();
    const expected = [...KEY_MEMBERS].sort();
    if (present.join(',') !== expected.join(',')) {
      report.malformed(
        `${at} must have exactly [${expected.join(', ')}]; it has [${present.join(', ')}]`,
      );
      return;
    }
    requireString(key.key_id, `${at}.key_id`, report);
    requireString(key.role, `${at}.role`, report);
    if (key.algorithm !== KEY_ALGORITHM) {
      report.malformed(`${at}.algorithm is ${JSON.stringify(key.algorithm)}; version 1.0 allows only ${KEY_ALGORITHM}`);
    }
    if (!CUSTODY_VALUES.has(key.custody)) {
      report.malformed(
        `${at}.custody is ${JSON.stringify(key.custody)}; it must be one of ` +
          `${[...CUSTODY_VALUES].join(', ')}`,
      );
    }
    try {
      decodeBase64(key.public_key, PUBLIC_KEY_BYTES, `${at}.public_key`);
    } catch (error) {
      report.malformed(error.message);
    }
    requireNullableTimestamp(key.not_before, `${at}.not_before`, report);
    requireNullableTimestamp(key.not_after, `${at}.not_after`, report);
    requireNullableTimestamp(key.revoked_at, `${at}.revoked_at`, report);
  });

  const ids = keys.filter(isObject).map((key) => key.key_id);
  const duplicates = ids.filter((id, index) => ids.indexOf(id) !== index);
  for (const id of new Set(duplicates)) {
    report.malformed(`keys.json declares key_id ${JSON.stringify(id)} more than once`);
  }
}

function checkAnchorsGrammar(bundle, report) {
  const anchors = bundle.json['anchors.json'];
  if (!Array.isArray(anchors)) {
    report.malformed('anchors.json is not a JSON array');
    return;
  }
  if (anchors.length === 0) {
    report.malformed('anchors.json is empty; section 1 requires a non-empty anchor array');
    return;
  }

  anchors.forEach((anchor, index) => {
    const at = `anchors[${index}]`;
    if (!isObject(anchor)) {
      report.malformed(`${at} is not an object`);
      return;
    }
    const payload = anchor.payload;
    if (!isObject(payload)) {
      report.malformed(`${at}.payload is not an object`);
      return;
    }
    if (!isSequence(payload.anchor_number)) {
      report.malformed(`${at}.payload.anchor_number is not a non-negative integer`);
    }
    if (!isSequence(payload.from_sequence)) {
      report.malformed(`${at}.payload.from_sequence is not a non-negative integer`);
    }
    if (!isSequence(payload.to_sequence)) {
      report.malformed(`${at}.payload.to_sequence is not a non-negative integer`);
    }
    if (!isSequence(payload.covered_record_count)) {
      report.malformed(`${at}.payload.covered_record_count is not a non-negative integer`);
    }
    requireDigest(payload.prev_anchor_hash, `${at}.payload.prev_anchor_hash`, report);
    requireDigest(payload.head_hash, `${at}.payload.head_hash`, report);
    requireString(payload.key_id, `${at}.payload.key_id`, report);
    requireString(payload.tenant_id, `${at}.payload.tenant_id`, report);
    requireString(payload.stream_id, `${at}.payload.stream_id`, report);
    requireString(anchor.signature, `${at}.signature`, report);

    checkAttestationGrammar(anchor, at, report);
  });
}

/**
 * Section 4's location-scoped status grammar.
 *
 * The table is the normative part, and it is scoped by *where* the attestation
 * lives, not by a flat enum. Section 7 says so explicitly: an implementer reading
 * the older flat enum would accept `failed` and the two verifiers would disagree
 * on the same bundle. That is the disagreement this whole exercise exists to
 * prevent, so the check is written directly from the table.
 */
function checkAttestationGrammar(anchor, at, report) {
  const roster = anchor.payload.attestations;
  if (!Array.isArray(roster)) {
    report.malformed(`${at}.payload.attestations is not an array`);
    return;
  }

  const identities = new Set();
  roster.forEach((entry, index) => {
    const where = `${at}.payload.attestations[${index}]`;
    if (!isObject(entry)) {
      report.malformed(`${where} is not an object`);
      return;
    }
    if (!requireString(entry.type, `${where}.type`, report)) return;
    if (!requireString(entry.authority, `${where}.authority`, report)) return;
    if (!requireString(entry.status, `${where}.status`, report)) return;

    const identity = attestationIdentity(entry);
    if (identities.has(identity)) {
      report.malformed(`${at}.payload.attestations declares ${identity} more than once`);
    }
    identities.add(identity);

    checkSignedPayloadStatus(entry, where, report);
  });

  const sidecars = anchor.attestations;
  if (sidecars === undefined) return;
  if (!Array.isArray(sidecars)) {
    report.malformed(`${at}.attestations sidecar is not an array`);
    return;
  }

  const seen = new Set();
  sidecars.forEach((entry, index) => {
    const where = `${at}.attestations[${index}]`;
    if (!isObject(entry)) {
      report.malformed(`${where} is not an object`);
      return;
    }
    if (!requireString(entry.type, `${where}.type`, report)) return;
    if (!requireString(entry.authority, `${where}.authority`, report)) return;
    if (!requireString(entry.status, `${where}.status`, report)) return;

    const identity = attestationIdentity(entry);
    if (!identities.has(identity)) {
      report.malformed(
        `${where} attests ${identity}, which the signed roster does not declare; ` +
          'a sidecar may replace the state of a rostered identity but never extend the roster',
      );
    }
    if (seen.has(identity)) {
      report.malformed(`${at}.attestations replaces ${identity} more than once`);
    }
    seen.add(identity);

    checkSidecarStatus(entry, where, report);
  });
}

function checkSignedPayloadStatus(entry, where, report) {
  const { type, authority, status } = entry;

  // Section 4: expires_at MUST NOT appear anywhere in the signed roster, which
  // is written before any external authority is contacted and therefore cannot
  // know one yet.
  if ('expires_at' in entry) {
    report.malformed(
      `${where} carries expires_at inside the signed payload; the roster is written before any ` +
        'external authority is contacted and cannot know a horizon yet',
    );
  }

  if (status === 'failed') {
    report.malformed(
      `${where} uses status "failed", which section 4 reserves and forbids anywhere in a 1.0 bundle`,
    );
    return;
  }

  if (EXTERNAL_TYPES.has(type)) {
    if (status !== 'pending') {
      report.malformed(
        `${where} is type "${type}" inside the signed payload with status "${status}"; ` +
          'only "pending" is legal there, because the roster is written before any external authority is contacted',
      );
    }
    return;
  }

  if (type === DEVELOPMENT_TYPE) {
    if (status !== 'unattested') {
      report.malformed(`${where} is type "${DEVELOPMENT_TYPE}" with status "${status}"; only "unattested" is legal`);
    }
    if (authority !== DEVELOPMENT_AUTHORITY) {
      report.malformed(
        `${where} is type "${DEVELOPMENT_TYPE}" with authority "${authority}"; ` +
          `section 4 permits it only with authority "${DEVELOPMENT_AUTHORITY}"`,
      );
    }
    return;
  }

  report.malformed(`${where} has attestation type "${type}", which section 4 does not define`);
}

function checkSidecarStatus(entry, where, report) {
  const { type, status } = entry;

  if (type === 'rfc3161') {
    // Section 4: an rfc3161 sidecar MUST carry expires_at. The malformed-
    // missing-expiry conformance fixture is exactly this omission.
    if (!('expires_at' in entry)) {
      report.malformed(`${where} RFC 3161 sidecar does not declare expires_at`);
    } else {
      requireExpiresAt(entry.expires_at, `${where}.expires_at`, report);
    }
  } else if ('expires_at' in entry) {
    // customer_countersignature has no certificate to derive a horizon from.
    report.malformed(
      `${where} carries expires_at but is type "${type}"; only an rfc3161 sidecar has a ` +
        'certificate to derive a horizon from',
    );
  }

  if (status === 'failed') {
    report.malformed(
      `${where} uses status "failed", which section 4 reserves and forbids anywhere in a 1.0 bundle; ` +
        'a failed attempt is transient and is not persisted',
    );
    return;
  }
  if (!EXTERNAL_TYPES.has(type)) {
    report.malformed(
      `${where} is type "${type}"; only ${[...EXTERNAL_TYPES].join(' and ')} produce sidecar outcomes`,
    );
    return;
  }
  if (status !== 'attested') {
    report.malformed(
      `${where} is a sidecar with status "${status}"; only "attested" is legal there, ` +
        'because sidecars store validated outcomes rather than attempts',
    );
  }
}

function checkCheckpointsGrammar(bundle, report) {
  const checkpoints = bundle.json['checkpoints.json'];
  if (!Array.isArray(checkpoints)) {
    report.malformed('checkpoints.json is not a JSON array');
    return;
  }
  checkpoints.forEach((checkpoint, index) => {
    const at = `checkpoints[${index}]`;
    if (!isObject(checkpoint)) {
      report.malformed(`${at} is not an object`);
      return;
    }
    if (!isSequence(checkpoint.from_sequence)) {
      report.malformed(`${at}.from_sequence is not a non-negative integer`);
    }
    if (!isSequence(checkpoint.to_sequence)) {
      report.malformed(`${at}.to_sequence is not a non-negative integer`);
    }
    requireDigest(checkpoint.head_hash, `${at}.head_hash`, report);
    requireDigest(checkpoint.expected_previous, `${at}.expected_previous`, report);
  });
}

// =============================================================================
// Section 1 -- file inventory digests
// =============================================================================

function checkFileDigests(bundle, report) {
  const declared = bundle.json[MANIFEST].files;
  for (const name of NON_MANIFEST_FILES) {
    // Section 1: manifest checksums are the one place source bytes are hashed;
    // everything else hashes a reconstructed JCS projection.
    const actual = sha256Hex(bundle.bytes[name]);
    if (actual !== declared[name]) {
      report.invalid(
        `${name} checksum mismatch: manifest declares ${declared[name]}, stored bytes hash to ${actual}`,
      );
    }
  }
}

// =============================================================================
// Section 4 -- keys
// =============================================================================

function buildKeyring(bundle, report) {
  const keyring = new Map();
  for (const key of bundle.json['keys.json']) {
    let publicKey = null;
    try {
      publicKey = importPublicKey(decodeBase64(key.public_key, PUBLIC_KEY_BYTES, `key ${key.key_id}`));
    } catch (error) {
      report.invalid(`key ${key.key_id} carries an unusable public key: ${error.message}`);
    }
    keyring.set(key.key_id, { ...key, publicKey });
  }

  // Section 4 mandates this warning, verbatim, whenever any key is
  // development-derived. Custody is read from the declared property, never
  // inferred from the key_id.
  if (bundle.json['keys.json'].some((key) => key.custody === 'development-derived')) {
    report.warn(DEVELOPMENT_CUSTODY_WARNING);
  }
  return keyring;
}

/**
 * Resolve a key for a signature, checking role and reporting lifecycle facts.
 *
 * Section 4: "A valid signature under a revoked/expired key is reported with
 * that lifecycle fact and is not silently upgraded to an unqualified pass."
 * Section 5's list of required checks names key *roles*, not key validity
 * windows, so the lifecycle fact is surfaced as a prominent qualification rather
 * than converted into an evidence failure. The spec does not settle which of the
 * five verdicts it produces; see FINDINGS.md S-6.
 */
function resolveKey(keyring, keyId, requiredRole, subject, report) {
  const key = keyring.get(keyId);
  if (!key) {
    report.invalid(`${subject} is signed under key ${JSON.stringify(keyId)}, which keys.json does not contain`);
    return null;
  }
  if (key.role !== requiredRole) {
    report.invalid(
      `${subject} is signed under key ${keyId} with role "${key.role}"; role "${requiredRole}" is required`,
    );
    return null;
  }
  if (!key.publicKey) return null;

  if (key.revoked_at !== null) {
    report.warn(`KEY LIFECYCLE: ${subject} verifies under key ${keyId}, which was revoked at ${key.revoked_at}.`);
  }
  if (key.not_after !== null) {
    report.warn(`KEY LIFECYCLE: ${subject} verifies under key ${keyId}, whose validity ended at ${key.not_after}.`);
  }
  return key;
}

// =============================================================================
// Section 2 -- record chain
// =============================================================================

function checkRecordChain(bundle, report) {
  const records = bundle.json['records.json'];
  const { from_sequence: from, to_sequence: to } = bundle.json[MANIFEST].range;
  const manifest = bundle.json[MANIFEST];

  const expectedCount = to - from + 1;
  if (records.length !== expectedCount) {
    report.invalid(
      `manifest range ${from}..${to} covers ${expectedCount} record(s) but records.json holds ${records.length}`,
    );
  }

  records.forEach((record, index) => {
    const expectedSequence = from + index;
    if (record.sequence_number !== expectedSequence) {
      report.invalid(
        `records[${index}].sequence_number is ${record.sequence_number}; ` +
          `an ordered gapless range starting at ${from} requires ${expectedSequence}`,
      );
    }
    if (record.tenant_id !== manifest.tenant_id) {
      report.invalid(`records[${index}].tenant_id ${record.tenant_id} does not match the manifest tenant`);
    }
    if (record.stream_id !== manifest.stream_id) {
      report.invalid(`records[${index}].stream_id ${record.stream_id} does not match the manifest stream`);
    }

    // Section 2: record_core is every member except record_hash. A closed
    // exclusion rule, so a member added in a later version is committed to
    // automatically rather than silently escaping the hash.
    const core = { ...record };
    delete core.record_hash;
    const computed = sha256Hex(jcs(core));
    if (computed !== record.record_hash) {
      report.invalid(
        `records[${index}] (sequence ${record.sequence_number}) declares record_hash ` +
          `${record.record_hash} but its core canonicalizes to ${computed}`,
      );
    }

    if (index > 0) {
      const previous = records[index - 1];
      if (record.prev_hash !== previous.record_hash) {
        report.invalid(
          `records[${index}].prev_hash ${record.prev_hash} does not link to ` +
            `records[${index - 1}].record_hash ${previous.record_hash}`,
        );
      }
    }
  });

  if (from === 0) {
    if (records[0].prev_hash !== ZERO_DIGEST) {
      report.invalid(
        `a genesis range must open with 64 zeroes; records[0].prev_hash is ${records[0].prev_hash}`,
      );
    }
  } else {
    checkLeftEdge(bundle, records[0], from, report);
  }
}

/**
 * Section 2: for a partial range the left edge is pinned by the signed anchor
 * ending at from_sequence-1. Without it the export could begin anywhere and the
 * prefix would be unconstrained.
 */
function checkLeftEdge(bundle, firstRecord, from, report) {
  const anchors = bundle.json['anchors.json'];
  const pin = anchors.find((anchor) => anchor.payload.to_sequence === from - 1);
  if (!pin) {
    report.invalid(
      `partial range starts at ${from} but no anchor ends at ${from - 1}; ` +
        'section 7 requires a preceding signed anchor to pin the left edge',
    );
    return;
  }
  if (pin.payload.head_hash !== firstRecord.prev_hash) {
    report.invalid(
      `left edge is unpinned: anchor ${pin.payload.anchor_number} head_hash ${pin.payload.head_hash} ` +
        `does not equal records[0].prev_hash ${firstRecord.prev_hash}`,
    );
  }
}

function checkReceipts(bundle, keyring, report) {
  const records = bundle.json['records.json'];
  const receipts = bundle.json['receipts.json'];
  const bySequence = new Map(records.map((record) => [record.sequence_number, record]));

  const covered = new Map();
  receipts.forEach((receipt, index) => {
    const payload = receipt.payload;
    const sequence = payload.sequence_number;
    const at = `receipts[${index}] (sequence ${sequence})`;

    if (covered.has(sequence)) {
      report.invalid(`${at} is a second receipt for sequence ${sequence}; coverage must be one-to-one`);
    }
    covered.set(sequence, receipt);

    const record = bySequence.get(sequence);
    if (!record) {
      report.invalid(`${at} covers a sequence that is not in this export's record range`);
      return;
    }
    if (payload.record_hash !== record.record_hash) {
      report.invalid(
        `${at} binds record_hash ${payload.record_hash} but the record hashes to ${record.record_hash}`,
      );
    }
    if (payload.tenant_id !== record.tenant_id || payload.stream_id !== record.stream_id) {
      report.invalid(`${at} binds a different tenant or stream than the record it covers`);
    }

    const key = resolveKey(keyring, payload.key_id, ROLE_RECEIPT, at, report);
    if (!key) return;

    let signature;
    try {
      signature = decodeBase64(receipt.signature, SIGNATURE_BYTES, `${at}.signature`);
    } catch (error) {
      report.invalid(error.message);
      return;
    }
    if (!ed25519Verify(key.publicKey, jcs(payload), signature)) {
      report.invalid(`${at} signature does not verify under key ${payload.key_id}`);
    }
  });

  for (const sequence of bySequence.keys()) {
    if (!covered.has(sequence)) {
      report.invalid(`no receipt covers record sequence ${sequence}; section 2 requires exactly one`);
    }
  }
}

// =============================================================================
// Section 3 and 4 -- anchor chain, core digest, attestations
// =============================================================================

function checkAnchors(bundle, keyring, trustRoots, report) {
  const anchors = bundle.json['anchors.json'];
  const records = bundle.json['records.json'];
  const manifest = bundle.json[MANIFEST];
  const { from_sequence: rangeFrom, to_sequence: rangeTo } = manifest.range;
  const recordsBySequence = new Map(records.map((record) => [record.sequence_number, record]));

  const states = [];

  anchors.forEach((anchor, index) => {
    const payload = anchor.payload;
    const at = `anchors[${index}] (anchor_number ${payload.anchor_number})`;

    if (payload.anchor_number !== index) {
      report.invalid(
        `${at} is at position ${index}; anchors are ordered from 0 without gaps`,
      );
    }

    // Section 3: anchor zero's prev_anchor_hash is 64 zeroes; every later value
    // is the SHA-256 of the previous anchor's canonicalized *payload*, which is
    // the full payload including attestations -- unlike the core digest.
    if (index === 0) {
      if (payload.prev_anchor_hash !== ZERO_DIGEST) {
        report.invalid(`${at} is the first anchor; prev_anchor_hash must be 64 zeroes`);
      }
      if (payload.from_sequence !== 0) {
        report.invalid(`${at} begins at sequence ${payload.from_sequence}; anchor zero begins at sequence zero`);
      }
    } else {
      const previous = anchors[index - 1].payload;
      const expected = sha256Hex(jcs(previous));
      if (payload.prev_anchor_hash !== expected) {
        report.invalid(
          `${at} prev_anchor_hash ${payload.prev_anchor_hash} does not link to the previous anchor payload (${expected})`,
        );
      }
      if (payload.from_sequence !== previous.to_sequence + 1) {
        report.invalid(
          `${at} begins at ${payload.from_sequence}; dense ranges require ${previous.to_sequence + 1}`,
        );
      }
    }

    const expectedCount = payload.to_sequence - payload.from_sequence + 1;
    if (payload.covered_record_count !== expectedCount) {
      report.invalid(
        `${at} declares covered_record_count ${payload.covered_record_count}; ` +
          `its range ${payload.from_sequence}..${payload.to_sequence} covers ${expectedCount}`,
      );
    }

    if (payload.tenant_id !== manifest.tenant_id || payload.stream_id !== manifest.stream_id) {
      report.invalid(`${at} binds a different tenant or stream than the manifest`);
    }

    // Only anchors whose head lands inside the exported range can be checked
    // against a record; earlier anchors exist to pin the left edge.
    if (payload.to_sequence >= rangeFrom && payload.to_sequence <= rangeTo) {
      const head = recordsBySequence.get(payload.to_sequence);
      if (head && payload.head_hash !== head.record_hash) {
        report.invalid(
          `${at} head_hash ${payload.head_hash} does not equal the record hash at sequence ` +
            `${payload.to_sequence} (${head.record_hash})`,
        );
      }
    }

    verifyAnchorSignature(anchor, at, keyring, report);
    states.push(deriveAnchorState(anchor, at, trustRoots, report));
  });

  const terminal = anchors[anchors.length - 1].payload;
  if (terminal.to_sequence !== rangeTo) {
    report.invalid(
      `the terminal anchor ends at sequence ${terminal.to_sequence}; the manifest range ends at ${rangeTo}`,
    );
  } else {
    const last = records[records.length - 1];
    if (last && terminal.head_hash !== last.record_hash) {
      report.invalid(
        `the terminal anchor head_hash ${terminal.head_hash} does not bind the terminal record ${last.record_hash}`,
      );
    }
  }

  return states;
}

function verifyAnchorSignature(anchor, at, keyring, report) {
  const key = resolveKey(keyring, anchor.payload.key_id, ROLE_ANCHOR, at, report);
  if (!key) return;

  let signature;
  try {
    signature = decodeBase64(anchor.signature, SIGNATURE_BYTES, `${at}.signature`);
  } catch (error) {
    report.invalid(error.message);
    return;
  }
  if (!ed25519Verify(key.publicKey, jcs(anchor.payload), signature)) {
    report.invalid(`${at} signature does not verify under key ${anchor.payload.key_id}`);
  }
}

/**
 * Section 3's closed projection.
 *
 * Start from every member of the signed payload; remove exactly attestations,
 * object_key and object_version. The exclusion set is closed, so a member added
 * in a later payload is included by default. Writing this as a denylist rather
 * than an allowlist is the whole point: an allowlist would silently drop a new
 * member out of the digest.
 */
export function anchorCoreDigest(payload) {
  const core = { ...payload };
  delete core.attestations;
  delete core.object_key;
  delete core.object_version;
  return sha256Hex(jcs(core));
}

function deriveAnchorState(anchor, at, trustRoots, report) {
  const coreDigest = anchorCoreDigest(anchor.payload);

  // The signed roster is authoritative and keyed by (type, authority); a sidecar
  // overlays the state of an identity already in it. Grammar has already refused
  // undeclared and duplicate identities.
  const effective = new Map();
  for (const entry of anchor.payload.attestations) {
    effective.set(attestationIdentity(entry), { ...entry, location: 'payload' });
  }
  for (const entry of anchor.attestations ?? []) {
    effective.set(attestationIdentity(entry), { ...entry, location: 'sidecar' });
  }

  let developmentUnattested = false;
  let anyPending = false;
  let anyVerifiedUnexpired = false;
  let anyVerifiedExpired = false;
  let indeterminate = false;
  // ADR-004 G.19: an anchor's horizon is the LATEST horizon among the
  // authorities carrying it -- a second, later-expiring countersignature buys
  // the anchor more time even if the first authority's window has closed.
  let anchorHorizon = null;
  const now = new Date();

  for (const entry of effective.values()) {
    if (entry.type === DEVELOPMENT_TYPE && entry.status === 'unattested') {
      developmentUnattested = true;
      continue;
    }
    if (entry.status === 'pending') {
      anyPending = true;
      continue;
    }
    if (entry.status !== 'attested') continue;

    if (entry.type === 'customer_countersignature') {
      // Section 3 names the core digest as the customer-countersignature digest
      // but never says how a countersignature is carried or verified, and no
      // fixture exercises one. Guessing would be worse than saying so.
      report.cannotCheck(
        `${at} carries an attested customer_countersignature from ${entry.authority}; ` +
          'the format does not specify how to verify one (FINDINGS.md S-5)',
      );
      indeterminate = true;
      continue;
    }

    // Section 3 defines anchor_core_digest as what the RFC 3161 token covers.
    // The sidecar also restates it; a restatement that disagrees with the
    // computed value is a claim the bundle cannot support.
    if (typeof entry.anchor_digest === 'string' && entry.anchor_digest !== coreDigest) {
      report.invalid(
        `${at} attestation from ${entry.authority} claims anchor_digest ${entry.anchor_digest}; ` +
          `the anchor core canonicalizes to ${coreDigest}`,
      );
      continue;
    }

    if (typeof entry.evidence !== 'string' || entry.evidence.length === 0) {
      report.invalid(`${at} attestation from ${entry.authority} is attested but carries no evidence`);
      continue;
    }

    let token;
    try {
      token = decodeBase64Loose(entry.evidence, `${at} attestation evidence`);
    } catch (error) {
      report.invalid(error.message);
      continue;
    }

    const result = verifyTimestampToken(token, Buffer.from(coreDigest, 'hex'), trustRoots);
    if (result.ok) {
      report.note(`${at} timestamped by ${result.tsa} at ${result.genTime.toISOString()}`);

      // expires_at is a caption, not evidence (section 4): the verifier
      // recomputes the horizon from the token itself and rejects a bundle whose
      // declared value disagrees. Grammar already required the field to be
      // present and well-formed on this sidecar entry before we got here.
      const declared = entry.expires_at ? Date.parse(entry.expires_at) : null;
      if (declared !== null && declared !== result.horizon.getTime()) {
        report.invalid(
          `${at} attestation from ${entry.authority} declares expires_at ${entry.expires_at}; ` +
            `the certification path the token carries gives ${result.horizon.toISOString()}`,
        );
        continue;
      }

      if (anchorHorizon === null || result.horizon.getTime() > anchorHorizon.getTime()) {
        anchorHorizon = result.horizon;
      }
      if (result.horizon.getTime() > now.getTime()) {
        anyVerifiedUnexpired = true;
      } else {
        anyVerifiedExpired = true;
        report.note(
          `${at} attestation from ${entry.authority} passed its horizon ${result.horizon.toISOString()}; ` +
            'the timestamp still attests what it always attested (ADR-004 G.19).',
        );
      }
    } else if (result.canCheck) {
      report.invalid(`${at} RFC 3161 attestation from ${entry.authority} failed: ${result.reason}`);
    } else {
      report.cannotCheck(`${at} RFC 3161 attestation from ${entry.authority}: ${result.reason}`);
      indeterminate = true;
    }
  }

  let state;
  if (developmentUnattested) state = 'unattested';
  else if (anyPending) state = 'pending';
  else if (anyVerifiedUnexpired) state = 'rfc3161';
  else if (anyVerifiedExpired) state = 'expired';
  else if (indeterminate) state = INDETERMINATE;
  else state = 'unattested';

  return { state, horizon: state === 'rfc3161' || state === 'expired' ? anchorHorizon : null };
}

function decodeBase64Loose(text, label) {
  const normalized = text.replace(/-/g, '+').replace(/_/g, '/');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalized) || normalized.length % 4 !== 0) {
    throw new DecodeError(`${label} is not well-formed Base64`);
  }
  return Buffer.from(normalized, 'base64');
}

// =============================================================================
// Section 4 -- assurance
// =============================================================================

function checkAssurance(bundle, anchorStates, report) {
  if (anchorStates.some((entry) => entry.state === INDETERMINATE)) {
    report.cannotCheck(
      'stream assurance cannot be derived here, so the manifest assurance claim was not evaluated',
    );
    return;
  }

  // Section 4: the stream is the weakest anchor. rfc3161 only if every anchor
  // is rfc3161; else expired if every anchor is rfc3161-or-expired and at least
  // one has passed its horizon; else unattested if any anchor is; else pending.
  const states = anchorStates.map((entry) => entry.state);
  let derived;
  if (states.every((state) => state === 'rfc3161')) derived = 'rfc3161';
  else if (states.every((state) => state === 'rfc3161' || state === 'expired') && states.includes('expired')) {
    derived = 'expired';
  } else if (states.some((state) => state === 'unattested')) derived = 'unattested';
  else derived = 'pending';

  report.derivedAssurance = derived;

  // The manifest records what was true at export; a horizon reached since then
  // is a fact about the calendar, not a claim the exporter got wrong, so
  // "expired" reads as "rfc3161" for this comparison only (ADR-004 G.19).
  const comparableDerived = derived === 'expired' ? 'rfc3161' : derived;
  const expected = { anchor_attestation: comparableDerived, external_timestamp: comparableDerived === 'rfc3161' };
  const claimed = bundle.json[MANIFEST].assurance;

  // "MUST equal" is deep equality, so an extra member is a mismatch too.
  if (jcs(claimed).toString() !== jcs(expected).toString()) {
    report.invalid(
      `manifest assurance claims ${JSON.stringify(claimed)}; the bundle's own evidence derives ` +
        `${JSON.stringify(expected)}`,
    );
  }

  if (derived === 'expired') {
    // The stream horizon is the EARLIEST anchor horizon, because every anchor
    // must hold: the stream stops being independently verifiable the moment
    // any one of its anchors does.
    const horizons = anchorStates.filter((entry) => entry.horizon).map((entry) => entry.horizon);
    const streamHorizon = new Date(Math.min(...horizons.map((horizon) => horizon.getTime())));
    report.expire(
      `the stream's independent timestamp horizon ${streamHorizon.toISOString()} has passed; ` +
        'the record chain, receipt signatures, and anchor signatures do not depend on the ' +
        'timestamp authority and still verify (ADR-004 G.19)',
      streamHorizon,
    );
  }
}

// =============================================================================
// Section 4 -- checkpoints (derived index, never a source of assurance)
// =============================================================================

function checkCheckpoints(bundle, report) {
  const checkpoints = bundle.json['checkpoints.json'];
  if (checkpoints.length === 0) return;

  const records = bundle.json['records.json'];
  const { from_sequence: rangeFrom, to_sequence: rangeTo } = bundle.json[MANIFEST].range;
  const bySequence = new Map(records.map((record) => [record.sequence_number, record]));

  checkpoints.forEach((checkpoint, index) => {
    const at = `checkpoints[${index}]`;

    if (index === 0) {
      if (checkpoint.from_sequence !== rangeFrom) {
        report.invalid(`${at} begins at ${checkpoint.from_sequence}; the exported range begins at ${rangeFrom}`);
      }
    } else {
      const previous = checkpoints[index - 1];
      if (checkpoint.from_sequence !== previous.to_sequence + 1) {
        report.invalid(
          `${at} begins at ${checkpoint.from_sequence}; dense ranges require ${previous.to_sequence + 1}`,
        );
      }
    }

    if (checkpoint.to_sequence < checkpoint.from_sequence) {
      report.invalid(`${at} range ${checkpoint.from_sequence}..${checkpoint.to_sequence} is inverted`);
      return;
    }

    const head = bySequence.get(checkpoint.to_sequence);
    if (!head) {
      report.invalid(`${at} ends at sequence ${checkpoint.to_sequence}, which is outside the exported range`);
    } else if (checkpoint.head_hash !== head.record_hash) {
      report.invalid(
        `${at} head_hash ${checkpoint.head_hash} does not equal the record hash at sequence ` +
          `${checkpoint.to_sequence} (${head.record_hash})`,
      );
    }

    const opening = bySequence.get(checkpoint.from_sequence);
    if (!opening) {
      report.invalid(`${at} begins at sequence ${checkpoint.from_sequence}, which is outside the exported range`);
    } else if (checkpoint.expected_previous !== opening.prev_hash) {
      report.invalid(
        `${at} expected_previous ${checkpoint.expected_previous} does not equal the prev_hash at sequence ` +
          `${checkpoint.from_sequence} (${opening.prev_hash})`,
      );
    }
  });

  const last = checkpoints[checkpoints.length - 1];
  if (last.to_sequence !== rangeTo) {
    report.invalid(`the last checkpoint ends at ${last.to_sequence}; the exported range ends at ${rangeTo}`);
  }
}

// =============================================================================
// Small helpers
// =============================================================================

function attestationIdentity(entry) {
  return `(${entry.type}, ${entry.authority})`;
}

function sha256Hex(input) {
  return crypto.createHash('sha256').update(input).digest('hex');
}

function isObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isSequence(value) {
  return Number.isInteger(value) && value >= 0;
}

function requireString(value, label, report) {
  if (typeof value !== 'string') {
    report.malformed(`${label} is not a string`);
    return false;
  }
  return true;
}

function requireEquals(value, expected, label, report) {
  if (value !== expected) {
    report.malformed(`${label} is ${JSON.stringify(value)}; version 1.0 requires ${JSON.stringify(expected)}`);
  }
}

// RFC 3339 UTC to the second: "2036-08-27T19:26:55Z", no fractional seconds, no
// offset other than Z. expires_at is compared against a value recomputed from
// certificate notAfter fields, so accepting any looser form here would let a
// producer's caption disagree with the recomputed value in ways this check
// would never see.
const RFC3339_UTC_SECOND = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

function requireExpiresAt(value, label, report) {
  if (typeof value !== 'string' || !RFC3339_UTC_SECOND.test(value) || Number.isNaN(Date.parse(value))) {
    report.malformed(`${label} is ${JSON.stringify(value)}; expected an RFC 3339 UTC instant to the second`);
    return null;
  }
  return new Date(value);
}

function requireDigest(value, label, report) {
  try {
    requireSha256Hex(value, label);
  } catch (error) {
    report.malformed(error.message);
  }
}

function requireNullableTimestamp(value, label, report) {
  if (value === null) return;
  if (typeof value !== 'string') {
    report.malformed(`${label} is neither null nor an RFC 3339 timestamp`);
    return;
  }
  if (Number.isNaN(Date.parse(value))) {
    report.malformed(`${label} is not a parseable timestamp: ${JSON.stringify(value)}`);
  }
}
