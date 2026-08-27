# T-062 findings — what a second implementation found

`verifier-two/` was written from `docs/spec/EVIDENCE-BUNDLE-FORMAT.md` and the conformance
fixtures alone, in a session that never opened `control-plane/` or `scripts/verify_*`. Every
constant in it is derived in a comment at the point of use, or it came from the spec. Nothing was
copied from the Python.

This file is the actual deliverable. The verifier is the instrument; these are the readings.

Two classes are recorded:

* **D-n — a disagreement between the two implementations.** By the rule of the exercise every one
  of these is a defect in the spec or in one implementation. None of them was closed by adjusting
  verifier-two to match the incumbent; each entry says which way it was resolved and on what
  argument.
* **S-n — a place where the spec is silent, and two independent implementers would not converge.**
  These did not all produce a disagreement, because the fixtures do not exercise them. That is
  what makes them worth writing down: they are the defects that a passing conformance run cannot
  find.

---

## D-1 — a missing trust root is reported as an evidence failure. Reference defect. **Open.**

`scripts/verify_evidence_export.py tests/fixtures/conformance/valid-public` with no
`--tsa-trust-anchor` exits **1** with `FAIL: RFC 3161 attestation requires --tsa-trust-anchor`.
verifier-two exits **2**, CANNOT CHECK.

Spec §5 defines CANNOT CHECK as a bundle that is "structurally eligible but the verifier
environment cannot evaluate a required claim". §7 is more direct: "a missing verifier dependency
is neither `VALID` nor evidence failure." A trust root that the operator has not supplied is a
property of the operator's environment, not of the bundle. The bundle is unchanged; only our
ability to judge it changed.

It reproduces on four separate bundles — `valid-public`, `expired-tsa`, `attested/bundle`, and
`public-tsa/bundle` — so it is the reference's general handling of a missing trust root, not a
quirk of one fixture.

The practical harm is the reason this is filed rather than shrugged at. An auditor's first
contact with a good bundle, before they have wired up their own roots, is a red FAIL. That teaches
them the bundle is bad. It is the exact failure mode T-063 exists to prevent, produced by the
tool that is supposed to prevent it.

**The reference is wrong. The fix belongs in `scripts/verify_evidence_export.py`, not here.**
Verifier-two is not changing to match it. This is the one disagreement still open at the time of
this PR: fixing it requires reading the Python, which breaks the T-062 seal, so it is deliberately
sequenced after this change-set lands. See the PR body.

## D-2 — the verdict precedence order is unspecified. Spec defect. **Fixed in verifier-two; spec delta in this change-set.**

135 of the 288 mutation cases disagreed on first run: the reference said INVALID where
verifier-two said MALFORMED. Both are terminal verdicts, both were defensible from the text, and
§5 says only that the four are mutually exclusive — it never says which wins when a bundle earns
two.

The rule that actually governs existed in one implementation and one generated oracle, and
nowhere in the normative text:

1. UTF-8 decoding and JSON parseability → MALFORMED
2. manifest grammar → MALFORMED
3. the manifest's `files` digests, over the stored bytes → **INVALID, and stop**
4. the remaining 1.0 grammar → MALFORMED
5. evidence → INVALID

The argument that settled it is not "the incumbent said so". It is §5's own wording: INVALID
applies where "the bundle is well-formed but" a check fails — and a file whose bytes do not match
the digest the manifest signed is *tamper evidence*, which is a finding about the bundle's
integrity, not about its syntax. Reporting MALFORMED there tells an auditor the file is badly
written when what actually happened is that someone changed it.

Before adopting it I checked I had inferred the right rule rather than a rule that merely fits:
a predictor implementing "unparseable JSON → MALFORMED, else INVALID" across all 240 non-manifest
mutation cases made **0 mispredictions**. Verifier-two's phase order was changed to match, and
`digests-checked-after-schema` in the fault harness reverts that ordering to prove the tests see it.

**§5 must state the precedence.** A conformant implementation cannot currently be written.

## D-3 — §1 reads the `files` digest shape as grammar; it is evidence. Spec defect. **Fixed in verifier-two; spec delta in this change-set.**

22 disagreements survived the D-2 fix, all of them mutations that made a manifest `files` value 63
or 65 characters long. §1 says the manifest "maps each of the five non-manifest names to
`hex(SHA-256(complete stored file bytes))`", which reads as a well-formedness constraint on the
value — so a wrong-shaped value looked like MALFORMED to me.

The spec refutes that reading internally. The `invalid-record-checksum` fixture is expected
**INVALID**, and a checksum that does not match is exactly as much a violation of that sentence as
a checksum of the wrong length. If the sentence were grammar, that fixture would be MALFORMED.
Read uniformly, the sentence is a claim about the world, and a value of the wrong shape fails the
same comparison every other wrong value fails.

Verifier-two now type-checks `files` values as strings and lets the comparison decide. **§1 should
say which sentences in it are grammar and which are evidence** — the distinction decides the
verdict and is currently left to the reader.

## D-4 — a timestamp past its horizon was reported as an evidence failure. **Ratified by the founder (ADR-004 G.19, T-091); fixed here.**

Found by CI, not by me, and worth recording that way: `tests/fixtures/evidence_export/attested/bundle`
verified on 2026-08-27 and failed on 2026-08-28 with no byte of it changed, because the committed test
TSA certificate had a one-day lifetime. Neither implementation had a considered position on what a
verification result that decays on a calendar should mean.

This was escalated as B-21 rather than decided, on the grounds that both behaviours were defensible —
validating at `genTime` is the property a timestamp is bought for, but an expired certificate also
publishes no revocation information, so a key compromised after expiry could mint a token bearing any
`genTime`. **The founder ruled while this PR was open** (ADR-004 G.19, 2026-08-27): bundle 1.0 claims
offline verifiability for the lifetime of the timestamp authority's certificate and no longer; RFC 4998
archive timestamping is out of scope; `EXPIRED` (exit 4) is a distinct terminal verdict, not a weaker
`INVALID`; and past the horizon a verifier re-checks the chain at an instant inside the certification
path's own validity window — never at the token's `genTime`, which would ask the token to date the
certificate that signs it.

`verifier-two` now implements this in full:

* `lib/verdict.js` — a fifth verdict, `EXPIRED`, exit 4, ranked below `CANNOT CHECK` and above `VALID`.
  `CANNOT CHECK` outranks it because `EXPIRED` still asserts "every required check passed"; an
  indeterminate claim means that assertion cannot honestly be made regardless of the horizon.
* `lib/rfc3161.js` — the certificate chain is now built in two phases: `walkChainToRoot` establishes
  the path by signature/issuer structure alone, with no temporal check, so the horizon
  (`certificationPathHorizon`, the earliest `notAfter` on the path) can be computed *before* deciding
  whether checking at `genTime` is even the right question. Only when `now <= horizon` is the chain
  additionally validated at `genTime`. This was load-bearing, not cosmetic: `tests/fixtures/evidence_export/expired/bundle`
  carries a token whose forged `genTime` (2026) sits outside its own signer's real 2015–2016 window —
  exactly the trivially-producible case section 6 warns about — and the old unconditional `genTime`
  check rejected it as `INVALID` before the fix.
* `lib/verify.js` — an anchor's horizon is the *latest* horizon among the authorities carrying it
  (countersigning buys time); the stream's derived state is `expired` when every anchor is
  `rfc3161`-or-`expired` and at least one has passed its horizon; the stream horizon is the *earliest*
  anchor horizon, because every anchor must hold; the manifest assurance comparison reads `expired` as
  `rfc3161`, since the manifest recorded what was true at export and a horizon reached since then is a
  fact about the calendar, not a claim the exporter got wrong. `expires_at` grammar is enforced per
  section 4: required and RFC-3339-to-the-second on an `rfc3161` sidecar, forbidden in the signed
  roster and on a `customer_countersignature` sidecar, and the declared value must equal the
  recomputed horizon or the bundle is `INVALID` — a caption, not evidence, exactly as section 4 states.

Verified against the differential: 304 cases (six conformance and three shipped bundles, each with and
without declared roots, plus 288 mutations): every remaining disagreement is D-1, the one open
reference defect, now confirmed on four bundles — `valid-public`, `expired-tsa`, `attested/bundle`,
and `public-tsa/bundle` — rather than the one this file originally filed it against. `expired-tsa`
and `tests/fixtures/evidence_export/expired/bundle` both now return exit 4, matching the reference
and the recorded oracle exactly.

## The bug this found in verifier-two

Recording it here rather than only in the PR, because a findings register that lists only the other
implementation's defects is not a findings register.

The same CI failure exposed a real bug in `verifier-two`: RFC 5035 declares
`ESSCertIDv2 ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier DEFAULT {algorithm id-sha256}, ... }`,
and I applied RFC 2634 `ESSCertID`'s SHA-1 default to it. A 32-byte `certHash` can never match a
20-byte SHA-1 comparison, so the shipped attested bundle was reported **INVALID — ESSCertID does not
identify the certificate that verified the signature**. An honest token called forged: the worst
verdict a verifier can return.

The conformance corpus could not reach it. Both public TSAs name their hash algorithm explicitly;
only the committed test TSA relies on the DEFAULT. **A corpus assembled to exercise a specification
does not automatically exercise the artifacts the product ships.** `tools/differential.mjs` now
carries a third corpus, `shipped`, covering `tests/fixtures/evidence_export/`, and the fault
`esscertid-v2-defaults-to-sha1` reverts the fix so the regression cannot return silently.

---

### What was done with the S-series in this change-set

Six of them are answered by a normative delta to `docs/spec/EVIDENCE-BUNDLE-FORMAT.md` in this
change-set: S-1, S-2, S-3, S-4, S-8 and S-9. Where a gap could only be closed by changing what
verdict a bundle earns, the delta says what a verifier MUST NOT do and leaves the choice open rather
than inventing a rule the reference does not implement and no fixture exercises — an unexercised
normative rule silently makes one implementation non-conformant, which is the disease, not the cure.

S-5 and S-6 are **not** fixed here. Both are H-7 territory — cryptography and key management — and
the standing rule is escalate, do not decide.

## S-1 — the Base64 alphabet is never named

§2 and §4 say "Base64". The fixtures use **both** alphabets: signatures are URL-safe (`-`, `_`),
public keys are standard (`+`, `/`). An implementer who picked one and enforced it would reject
real bundles produced by the reference. Verifier-two accepts both and says so in a comment; that
is the compatible reading, not a correct-by-construction one.

Worth naming separately: `Buffer.from(text, 'base64')` in Node discards anything outside the
alphabet without error, so a signature with four spaces spliced into it decodes to a perfectly
well-sized 64 bytes and is then rejected by Ed25519 — the right verdict for the wrong reason. The
decoder in `lib/codec.js` fails on the malformed input itself. `base64-decoded-leniently` in the
fault harness reverts that check.

## S-2 — "exactly these six files" does not say what an extra file means

An extra file cannot be covered by the manifest's `files` map, so it is unattested content
travelling inside an attested container. The spec neither forbids it nor assigns it a verdict.
Verifier-two emits a note, which is the weakest defensible response; a future 1.1 should decide.

## S-3 — no bound on integer magnitude, which is a canonicalisation hazard

RFC 8785 pins number serialisation to ECMAScript `Number::toString`. Nothing in the spec bounds
the integers a payload may carry. A `sequence_number` beyond 2^53 canonicalises differently in a
language with 64-bit integers than in one without, so two conformant verifiers would compute
different digests over the same bytes. Verifier-two detects out-of-safe-range integer *literals*
during parse (via the `JSON.parse` source reviver) and returns CANNOT CHECK rather than silently
computing a digest it cannot stand behind. **The spec should bound them.**

## S-4 — the member shape of an attestation entry is never defined

The `rfc3161` entries in the fixtures carry `anchor_digest` and `requested_at`; the
`none_development` entry does not. §4 defines the *status grammar* by location and type in careful
detail and never says which members an entry has. Verifier-two requires only what it reads. A
second implementer enforcing a closed member set — the way §4 explicitly closes the key-document
set — would reject the golden bundle.

## S-5 — `customer_countersignature` verification is entirely unspecified

§4 admits the type into the roster and gives it a `pending` status in the signed payload, and
then never says what verifying one consists of, what bytes are signed, or under which key.
There is no fixture. Verifier-two returns CANNOT CHECK for a rostered countersignature that is no
longer pending, which is honest but is not conformance to anything.

**Escalated, not decided.** Specifying what a countersignature signs and under which key is a
cryptographic protocol decision; H-7 fires.

## S-6 — an expired or revoked signing key is prescribed a report, not a verdict

§4 does address this, and more clearly than most of the spec: a valid signature under a
revoked or expired key "is reported with that lifecycle fact and is not silently upgraded to an
unqualified pass." What it does not say is which of the four terminal verdicts that bundle earns.
"Not an unqualified pass" is compatible with VALID-plus-warning and with INVALID, and those are
very different answers to give an auditor after a key compromise.

Verifier-two emits a prominent `KEY LIFECYCLE:` warning above the verdict and lets §5's
enumerated checks decide the verdict — it does not invent an INVALID the spec does not authorise.
The reference's choice here is untested by any fixture, so the two implementations could differ
on the most consequential bundle either will ever see and the conformance suite would stay green.
**§5 should name the verdict.**

## S-7 — the five verdicts are declared mutually exclusive with no rule for producing one among MALFORMED/INVALID/CANNOT CHECK

This is D-2 stated as a spec property rather than as a disagreement. §5 says the verdicts are
mutually exclusive; it does not say that findings are, and a real bundle earns several. Precedence
is the missing sentence. **Partially closed by ADR-004 G.19**: `EXPIRED` now has a stated rank
(below `CANNOT CHECK`, above `VALID`), but the precedence among `MALFORMED`, `INVALID` and
`CANNOT CHECK` — D-2's actual subject — is still nowhere in the normative text.

## S-8 — `checkpoints.json` has no defined member set

§3 gives checkpoints one sentence — "its dense ranges and endpoint hashes are checked" — and names
no member. `from_sequence`, `to_sequence` and `head_hash` can be carried over from the anchor
paragraphs by analogy, which is a guess and not a specification. `expected_previous`, which the
fixtures do use, appears nowhere in the spec at all. It was reverse-engineered from the fixture,
which is precisely the dependency this exercise exists to remove.

## S-9 — the encoding of an RFC 3161 `evidence` field is never stated

§4 says an `rfc3161` attestation carries evidence and leaves both the transfer encoding and the
ASN.1 type to the reader. The fixtures hold a Base64 `TimeStampResp` (RFC 3161 §2.4.2), not a bare
`ContentInfo` token. Verifier-two accepts either, because guessing wrong here costs an
implementer a day and the spec gave no way to know.

---

## What the two implementations agree on

304 differential cases — the six conformance bundles and three shipped bundles, each run with and
without their declared trust roots, plus all 288 single-byte mutation cases:

```
cases:                          304
verifiers disagree:               4     (D-1, seen on four different bundles)
reference vs recorded oracle:     0
verifier-two vs oracle:           0
```

Every remaining disagreement is D-1. `expired-tsa` and `tests/fixtures/evidence_export/expired/bundle`
both now return exit 4 and agree with the reference and the recorded oracle exactly — D-4 is closed.

The strongest independent confirmation is not in that table. Working from §3 alone, verifier-two
computes `anchor_core_digest = 0042dc29e2169826901f390daa538545b293dfa83e560c5c16d43c9fcc6ab3a0`
for anchor 0 of the golden bundle. That value matches the sidecar's declared `anchor_digest` and
the `messageImprint` inside both real TSA tokens — two public timestamp authorities signed that
digest in 2026, and a canonicalisation written months later from prose reproduced it byte for
byte. The exclusion set and the JCS rules in §3 are, on that evidence, correct as written.
