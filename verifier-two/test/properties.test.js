import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

import { verifyBundle, anchorCoreDigest } from '../lib/verify.js';
import { VERDICT } from '../lib/verdict.js';
import { jcs } from '../lib/jcs.js';
import { decodeBase64, DecodeError } from '../lib/codec.js';
import { loadTrustRoots } from '../lib/rfc3161.js';

const REPO = path.resolve(import.meta.dirname, '../..');
const CONFORMANCE = path.join(REPO, 'tests/fixtures/conformance');
const GOLDEN = path.join(CONFORMANCE, 'valid-unattested');

/**
 * Build a bundle from the golden one with JSON-level edits applied, then
 * recompute the manifest file digests.
 *
 * Recomputing matters: it models an adversary who can rewrite the whole bundle
 * but cannot forge a signature. A test that left the digests stale would fail at
 * the checksum every time and never reach the check it claims to exercise.
 */
function bundleWith(scratch, edits) {
  const dir = fs.mkdtempSync(path.join(scratch, 'case-'));
  const documents = {};
  for (const name of fs.readdirSync(GOLDEN)) {
    documents[name] = JSON.parse(fs.readFileSync(path.join(GOLDEN, name), 'utf8'));
  }

  for (const [name, edit] of Object.entries(edits)) edit(documents[name], documents);

  for (const name of ['records.json', 'receipts.json', 'anchors.json', 'checkpoints.json', 'keys.json']) {
    const bytes = Buffer.from(JSON.stringify(documents[name]), 'utf8');
    fs.writeFileSync(path.join(dir, name), bytes);
    documents['manifest.json'].files[name] = crypto.createHash('sha256').update(bytes).digest('hex');
  }
  fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify(documents['manifest.json']));
  return dir;
}

function withScratch(t) {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'mizan-properties-'));
  t.after(() => fs.rmSync(scratch, { recursive: true, force: true }));
  return scratch;
}

// --- section 3: the anchor core projection is a closed exclusion set ---------

const goldenAnchor = JSON.parse(fs.readFileSync(path.join(GOLDEN, 'anchors.json'), 'utf8'))[0];

test('the anchor core digest excludes exactly attestations, object_key and object_version', () => {
  const payload = goldenAnchor.payload;
  const baseline = anchorCoreDigest(payload);

  for (const excluded of ['attestations', 'object_key', 'object_version']) {
    const without = { ...payload };
    delete without[excluded];
    assert.equal(
      anchorCoreDigest(without),
      baseline,
      `removing ${excluded} changed the core digest, so it is not excluded`,
    );
  }
});

test('a member added to the anchor payload is committed to by default', () => {
  // Section 3: "The exclusion set is closed: future payload keys are included
  // unless a later bundle version changes this normative rule." An allowlist
  // projection would let a new member ride inside a signed anchor without
  // appearing in the digest any timestamp covers.
  const payload = goldenAnchor.payload;
  const baseline = anchorCoreDigest(payload);

  for (const added of ['settlement_window', 'zzz_last_alphabetically', 'aaa_first_alphabetically']) {
    assert.notEqual(
      anchorCoreDigest({ ...payload, [added]: 'anything' }),
      baseline,
      `a payload member named ${added} escaped the core digest`,
    );
  }
});

test('every member of the real payload is load-bearing in the core digest', () => {
  const payload = goldenAnchor.payload;
  const baseline = anchorCoreDigest(payload);
  const excluded = new Set(['attestations', 'object_key', 'object_version']);

  for (const member of Object.keys(payload)) {
    if (excluded.has(member)) continue;
    const changed = { ...payload, [member]: `mutated-${member}` };
    assert.notEqual(anchorCoreDigest(changed), baseline, `${member} does not affect the core digest`);
  }
});

test('the anchor chain hash and the anchor core digest are different projections', () => {
  // prev_anchor_hash covers the full signed payload; the timestamp covers the
  // core. If a refactor ever made these the same function, an anchor could be
  // relinked without changing what the TSA attested to.
  const full = crypto.createHash('sha256').update(jcs(goldenAnchor.payload)).digest('hex');
  assert.notEqual(full, anchorCoreDigest(goldenAnchor.payload));
});

// --- section 2: the record core projection ----------------------------------

test('a member added to a record changes its record_hash', (t) => {
  const scratch = withScratch(t);
  const dir = bundleWith(scratch, {
    'records.json': (records) => {
      records[0].smuggled = 'value';
    },
  });
  const report = verifyBundle(dir, { trustRoots: [] });
  assert.equal(report.verdict, VERDICT.INVALID);
  assert.ok(
    report.of(VERDICT.INVALID).some((f) => /record_hash/.test(f.message)),
    'the finding must name the record hash',
  );
});

// --- section 4: the roster is authoritative ---------------------------------

test('a sidecar may not attest an identity the signed roster does not declare', (t) => {
  const scratch = withScratch(t);
  const dir = bundleWith(scratch, {
    'anchors.json': (anchors) => {
      anchors[0].attestations = [
        { type: 'rfc3161', authority: 'https://attacker.example/tsr', status: 'attested', evidence: 'AA==' },
      ];
    },
  });
  const report = verifyBundle(dir, { trustRoots: [] });
  assert.equal(report.verdict, VERDICT.MALFORMED);
  assert.ok(report.of(VERDICT.MALFORMED).some((f) => /roster does not declare/.test(f.message)));
});

test('a sidecar may not carry pending, and the signed payload may not carry attested', (t) => {
  const scratch = withScratch(t);

  const pendingSidecar = bundleWith(scratch, {
    'anchors.json': (anchors) => {
      anchors[0].payload.attestations = [
        { type: 'rfc3161', authority: 'tsa', status: 'pending', evidence: null, obtained_at: null },
      ];
      anchors[0].attestations = [{ type: 'rfc3161', authority: 'tsa', status: 'pending', evidence: null }];
    },
  });
  assert.equal(verifyBundle(pendingSidecar, { trustRoots: [] }).verdict, VERDICT.MALFORMED);

  const attestedPayload = bundleWith(scratch, {
    'anchors.json': (anchors) => {
      anchors[0].payload.attestations = [
        { type: 'rfc3161', authority: 'tsa', status: 'attested', evidence: null, obtained_at: null },
      ];
    },
  });
  assert.equal(verifyBundle(attestedPayload, { trustRoots: [] }).verdict, VERDICT.MALFORMED);
});

test('status "failed" is refused in both locations', (t) => {
  const scratch = withScratch(t);

  for (const location of ['payload', 'sidecar']) {
    const dir = bundleWith(scratch, {
      'anchors.json': (anchors) => {
        anchors[0].payload.attestations = [
          { type: 'rfc3161', authority: 'tsa', status: location === 'payload' ? 'failed' : 'pending', evidence: null },
        ];
        if (location === 'sidecar') {
          anchors[0].attestations = [{ type: 'rfc3161', authority: 'tsa', status: 'failed', evidence: null }];
        }
      },
    });
    const report = verifyBundle(dir, { trustRoots: [] });
    assert.equal(report.verdict, VERDICT.MALFORMED, `status "failed" accepted in the ${location}`);
    assert.ok(report.of(VERDICT.MALFORMED).some((f) => /reserve/.test(f.message)));
  }
});

test('none_development is legal only with authority "development"', (t) => {
  const scratch = withScratch(t);
  const dir = bundleWith(scratch, {
    'anchors.json': (anchors) => {
      anchors[0].payload.attestations = [
        { type: 'none_development', authority: 'production-tsa', status: 'unattested', evidence: null },
      ];
    },
  });
  assert.equal(verifyBundle(dir, { trustRoots: [] }).verdict, VERDICT.MALFORMED);
});

// --- section 4: key documents ------------------------------------------------

test('a key document with an extra or missing member is MALFORMED', (t) => {
  const scratch = withScratch(t);

  const extra = bundleWith(scratch, {
    'keys.json': (keys) => {
      keys[0].trusted = true;
    },
  });
  assert.equal(verifyBundle(extra, { trustRoots: [] }).verdict, VERDICT.MALFORMED);

  const missing = bundleWith(scratch, {
    'keys.json': (keys) => {
      delete keys[0].custody;
    },
  });
  assert.equal(verifyBundle(missing, { trustRoots: [] }).verdict, VERDICT.MALFORMED);
});

test('custody is read from the declared property, never inferred from key_id', (t) => {
  const scratch = withScratch(t);
  // The key ids still say "local://", which is exactly the inference the spec
  // forbids. Declared custody is kms, so no development warning may be printed.
  const dir = bundleWith(scratch, {
    'keys.json': (keys) => {
      for (const key of keys) key.custody = 'kms';
    },
  });
  const report = verifyBundle(dir, { trustRoots: [] });
  assert.equal(report.warnings.filter((w) => /KEY CUSTODY/.test(w)).length, 0);
});

// --- section 4: checkpoints supply no assurance ------------------------------

test('checkpoints cannot raise assurance', (t) => {
  const scratch = withScratch(t);

  const withoutCheckpoints = bundleWith(scratch, { 'checkpoints.json': (_, docs) => { docs['checkpoints.json'] = []; } });
  const stripped = verifyBundle(withoutCheckpoints, { trustRoots: [] });

  const asShipped = verifyBundle(GOLDEN, { trustRoots: [] });
  assert.equal(asShipped.derivedAssurance, 'unattested');
  assert.equal(stripped.derivedAssurance, 'unattested');

  // And a manifest that claims more than the anchors support is INVALID.
  const overclaimed = bundleWith(scratch, {
    'manifest.json': (manifest) => {
      manifest.assurance = { anchor_attestation: 'rfc3161', external_timestamp: true };
    },
  });
  const report = verifyBundle(overclaimed, { trustRoots: [] });
  assert.equal(report.verdict, VERDICT.INVALID);
  assert.ok(report.of(VERDICT.INVALID).some((f) => /assurance/.test(f.message)));
});

// --- trust roots are never taken from the bundle ----------------------------

test('a PEM placed inside the bundle is not treated as a trust root', (t) => {
  const scratch = withScratch(t);
  const dir = fs.mkdtempSync(path.join(scratch, 'planted-'));
  for (const name of fs.readdirSync(path.join(CONFORMANCE, 'valid-public'))) {
    fs.copyFileSync(path.join(CONFORMANCE, 'valid-public', name), path.join(dir, name));
  }
  // Plant the very roots that would make this bundle VALID, inside the bundle.
  fs.copyFileSync(
    path.join(REPO, 'tests/fixtures/evidence_export/public-tsa/freetsa-root.pem'),
    path.join(dir, 'trust-root.pem'),
  );

  const report = verifyBundle(dir, { trustRoots: [] });
  assert.equal(
    report.verdict,
    VERDICT.CANNOT_CHECK,
    'a bundle that can name its own trust root can name one it controls',
  );
});

// --- strict decoding ---------------------------------------------------------

test('Base64 fields are decoded strictly rather than salvaged', () => {
  const good = 'GvSdyO47FqWQNUOJ5rImeBikhUwaBpcOL9Q87a1cHYd30pLTA72C1UBPmkE1etVaedSefzfL_O7PE0a1QbWsBA==';
  assert.equal(decodeBase64(good, 64, 'signature').length, 64);

  // Node's Buffer would silently drop the space and return 63 bytes.
  const withSpace = `${good.slice(0, 20)} ${good.slice(21)}`;
  assert.throws(() => decodeBase64(withSpace, 64, 'signature'), DecodeError);
  assert.equal(Buffer.from(withSpace, 'base64').length, 63, 'the lenient decoder still behaves as described');

  // Padding out to four inserted spaces keeps the length a whole number of
  // quanta AND leaves all 88 alphabet characters intact, so the decoded length
  // is still exactly 64. Neither the quantum check nor the length check can see
  // this one: only the alphabet check can, which is the point of the case.
  const space = String.fromCharCode(0x20);
  const smuggled = good.slice(0, 20) + space.repeat(4) + good.slice(20);
  assert.equal(smuggled.length % 4, 0, 'the smuggled form is still a whole number of quanta');
  assert.equal(
    Buffer.from(smuggled.replace(/-/g, '+').replace(/_/g, '/'), 'base64').length,
    64,
    'the lenient decoder salvages this one into a well-sized signature',
  );
  assert.throws(() => decodeBase64(smuggled, 64, 'signature'), DecodeError);

  assert.throws(() => decodeBase64(good.slice(0, 40), 64, 'signature'), DecodeError);
  assert.throws(() => decodeBase64(null, 64, 'signature'), DecodeError);
});

test('both Base64 alphabets are accepted, because the fixtures use both', () => {
  // Signatures are URL-safe, public keys are standard. See FINDINGS.md S-1.
  const urlSafe = 'GvSdyO47FqWQNUOJ5rImeBikhUwaBpcOL9Q87a1cHYd30pLTA72C1UBPmkE1etVaedSefzfL_O7PE0a1QbWsBA==';
  const standard = 'BrKmMCcT6vWsNiXdZy6eqnvE8YBlAcwWD53nwfVSzTc=';
  assert.ok(/[-_]/.test(urlSafe));
  assert.equal(decodeBase64(urlSafe, 64, 'signature').length, 64);
  assert.equal(decodeBase64(standard, 32, 'public key').length, 32);
});

// --- signatures are actually checked ----------------------------------------

test('a corrupted anchor signature is INVALID, not overlooked', (t) => {
  const scratch = withScratch(t);
  const dir = bundleWith(scratch, {
    'anchors.json': (anchors) => {
      const bytes = decodeBase64(anchors[0].signature, 64, 'signature');
      bytes[0] ^= 0x01;
      anchors[0].signature = bytes.toString('base64');
    },
  });
  const report = verifyBundle(dir, { trustRoots: [] });
  assert.equal(report.verdict, VERDICT.INVALID);
  assert.ok(report.of(VERDICT.INVALID).some((f) => /signature does not verify/.test(f.message)));
});

test('a corrupted receipt signature is INVALID, not overlooked', (t) => {
  const scratch = withScratch(t);
  const dir = bundleWith(scratch, {
    'receipts.json': (receipts) => {
      const bytes = decodeBase64(receipts[0].signature, 64, 'signature');
      bytes[0] ^= 0x01;
      receipts[0].signature = bytes.toString('base64');
    },
  });
  const report = verifyBundle(dir, { trustRoots: [] });
  assert.equal(report.verdict, VERDICT.INVALID);
  assert.ok(
    report.of(VERDICT.INVALID).some((f) => /receipt/.test(f.message) && /signature does not verify/.test(f.message)),
    `expected a receipt signature finding, got: ${report.of(VERDICT.INVALID).map((f) => f.message).join(' | ')}`,
  );
});

test('a receipt signed under the anchor key is refused for its role', (t) => {
  const scratch = withScratch(t);
  const dir = bundleWith(scratch, {
    'receipts.json': (receipts) => {
      receipts[0].payload.key_id = 'local://evidence-anchor/dev-1';
    },
  });
  const report = verifyBundle(dir, { trustRoots: [] });
  assert.equal(report.verdict, VERDICT.INVALID);
  assert.ok(report.of(VERDICT.INVALID).some((f) => /role "evidence-receipt" is required/.test(f.message)));
});

test('receipt coverage must be one-to-one', (t) => {
  const scratch = withScratch(t);

  const missing = bundleWith(scratch, { 'receipts.json': (receipts) => { receipts.pop(); } });
  const dropped = verifyBundle(missing, { trustRoots: [] });
  assert.equal(dropped.verdict, VERDICT.INVALID);
  assert.ok(dropped.of(VERDICT.INVALID).some((f) => /no receipt covers/.test(f.message)));

  const duplicated = bundleWith(scratch, {
    'receipts.json': (receipts) => { receipts.push(structuredClone(receipts[0])); },
  });
  const doubled = verifyBundle(duplicated, { trustRoots: [] });
  assert.equal(doubled.verdict, VERDICT.INVALID);
  assert.ok(doubled.of(VERDICT.INVALID).some((f) => /one-to-one/.test(f.message)));
});

test('an unpinned partial range is INVALID', (t) => {
  const scratch = withScratch(t);
  // Drop records 0 and 1 and move the range start to 2, without supplying an
  // anchor that ends at sequence 1. Section 7 requires that pin to exist.
  const dir = bundleWith(scratch, {
    'records.json': (records, docs) => {
      docs['records.json'] = records.slice(2);
    },
    'receipts.json': (receipts, docs) => {
      docs['receipts.json'] = receipts.filter((r) => r.payload.sequence_number >= 2);
    },
    'checkpoints.json': (checkpoints, docs) => {
      docs['checkpoints.json'] = checkpoints.filter((c) => c.from_sequence >= 2);
    },
    'manifest.json': (manifest) => {
      manifest.range.from_sequence = 2;
    },
  });
  const report = verifyBundle(dir, { trustRoots: [] });
  assert.equal(report.verdict, VERDICT.INVALID);
  assert.ok(
    report.of(VERDICT.INVALID).some((f) => /pin the left edge/.test(f.message)),
    `findings: ${JSON.stringify(report.findings)}`,
  );
});
