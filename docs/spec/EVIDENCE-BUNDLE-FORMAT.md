# Mizan Evidence Bundle Format 1.0

Status: normative. “MUST”, “MUST NOT”, and “SHALL” are requirements. This document is sufficient to
implement an independent verifier; Mizan source code is not normative.

## 1. Directory and encoding

A bundle is one directory containing exactly these six required UTF-8 JSON files:

| File | Media type | Value |
|---|---|---|
| `manifest.json` | `application/json` | bundle metadata and file digests |
| `records.json` | `application/json` | non-empty ordered record array |
| `receipts.json` | `application/json` | signed receipt array |
| `anchors.json` | `application/json` | non-empty signed anchor array plus sidecars |
| `checkpoints.json` | `application/json` | unsigned acceleration-index array |
| `keys.json` | `application/json` | verification-key lifecycle array |

All producer-written JSON uses RFC 8785 JSON Canonicalization Scheme (JCS). Whenever this document
says `JCS(x)`, hash or signature input is exactly the bytes emitted by RFC 8785 for the JSON value
`x`, with no BOM, newline, or surrounding bytes. SHA-256 output is lowercase hexadecimal unless a
field explicitly carries binary data as Base64. Verifiers SHALL parse JSON, reconstruct the stated
projection, and canonicalize it; they MUST NOT hash source whitespace except for manifest file
checksums, which cover the complete stored file bytes.

Base64 fields accept both the standard alphabet of RFC 4648 section 4 and the URL-safe alphabet of
section 5; producers may emit either and verifiers MUST accept both. Encoded values are padded to a
whole number of quanta, and a field containing any character outside the chosen alphabet MUST be
refused rather than salvaged — decoders that silently discard such characters produce a well-sized
value from corrupted input and reach the right verdict only by luck. The verdict class of that
refusal follows the phase rule in section 5: `MALFORMED` where the field is part of the grammar
being checked, `INVALID` where it is a signature or other evidence.

Every integer a producer writes MUST be exactly representable as an IEEE 754 double, that is within
the closed range -(2^53-1) to 2^53-1. RFC 8785 defines number serialization as ECMAScript
`Number::toString`, so an integer outside that range canonicalizes differently in a language with
64-bit integers than in one without, and two conformant verifiers would compute different digests
over identical bytes. A verifier that encounters an out-of-range integer literal MUST NOT return
`VALID`; which of the other three verdicts it returns is not yet fixed by this version, because the
answer depends on whether the condition is read as a producer defect or as a limit on the verifier.

The manifest has `bundle_version="1.0"`, `canonicalization="RFC8785"`,
`hash_algorithm="SHA-256"`, tenant and stream identifiers, inclusive `range.from_sequence` and
`range.to_sequence`, an `assurance` claim, and `files`. `files` has exactly the five non-manifest
filenames above, and each value is a string that claims `hex(SHA-256(complete stored file bytes))`.

Two of those requirements are grammar and one is evidence, and the distinction decides the verdict.
The key set of `files` is grammar: a `files` object that does not have exactly the five non-manifest
filenames is `MALFORMED`. The value is evidence: a value that is not the file's digest — for any
reason, including being the wrong length or containing characters outside lowercase hexadecimal — is
`INVALID`, not `MALFORMED`. A stored file whose bytes do not match what the manifest claims is tamper
evidence about the bundle, not a defect in how the bundle was written.

A bundle contains exactly the six files above. Content beyond them cannot be covered by `files` and
is therefore unattested content travelling inside an attested container: a verifier MUST report each
extra entry it finds, and that report does not change the verdict in bundle 1.0, because the manifest
makes no claim about what it does not name. Whether an unattested passenger should instead be grounds
for refusal is an open question for a future version, and is deliberately not decided here.

## 2. Record chain

`records.json` is ordered with no gaps. Record `i` has `sequence_number = range.from_sequence+i`.
Define `record_core(r)` as the object containing every member of `r` except `record_hash`; this is a
closed exclusion rule, so every future member is committed automatically. Then:

`r.record_hash = hex(SHA-256(JCS(record_core(r))))`.

For a genesis range beginning at zero, the first `prev_hash` is 64 ASCII zeroes. Each later record's
`prev_hash` equals the immediately preceding `record_hash`. For a partial range, the left edge is
pinned by the signed anchor ending at `range.from_sequence-1`; its `head_hash` equals the first
record's `prev_hash`.

Exactly one receipt covers every record sequence. Its signed `payload` binds tenant, stream,
sequence, record hash, object key/version, and `key_id`; `signature` is Ed25519 over
`JCS(payload)`. The referenced key MUST exist in `keys.json` with role `evidence-receipt`.

## 3. Anchor chain and the anchor core digest

Anchors are ordered from `anchor_number=0` without gaps. Anchor zero has `prev_anchor_hash` equal to
64 zeroes; each later value equals `hex(SHA-256(JCS(previous anchor payload)))`. Ranges are dense:
anchor zero begins at sequence zero, the next `from_sequence` is the previous `to_sequence+1`, and
`covered_record_count = to_sequence-from_sequence+1`. Every in-range anchor `head_hash` equals the
record hash at its `to_sequence`. The terminal anchor ends at the manifest range end and binds the
terminal record. `signature` is Ed25519 over `JCS(payload)` under a `keys.json` key with role
`evidence-anchor`.

The RFC 3161/customer-countersignature digest is this exact closed projection:

1. Start with every member of the signed anchor `payload`.
2. Remove exactly `attestations`, `object_key`, and `object_version` if present. No other current or
   future member is removed.
3. Compute `anchor_core_digest = hex(SHA-256(JCS(result)))`.

`attestations` is excluded because asynchronous completion must not change its own digest.
`object_key` and `object_version` are excluded because they locate Mizan storage rather than identify
the anchored history and may be assigned after the core is formed. The exclusion set is closed:
future payload keys are included unless a later bundle version changes this normative rule.

## 4. Attestations and assurance

The signed payload contains the authoritative roster, uniquely keyed by `(type, authority)`. An
append-only sidecar in the row may replace the state only for an identity already in that roster; an
undeclared or duplicate identity is invalid. Status grammar is scoped by persistence location:

| Location | Written when | Mutable after | Legal `status` |
|---|---|---|---|
| `attestations[]` inside the signed anchor `payload` | at anchor time, before contacting any external authority | never; the roster is inside the signature | `pending` for `rfc3161` or `customer_countersignature`; `unattested` only for `none_development` with authority `development` |
| append-only `attestations[]` sidecars on the anchor row | after an external outcome validates | never; outcomes are append-only | `attested` for `rfc3161` or `customer_countersignature` |

An `rfc3161` sidecar MUST carry `expires_at`: an RFC 3339 UTC instant to the second, equal to the
earliest `notAfter` among the certificates on the certification path the token itself carries —
the signer named by `id-kp-timeStamping` and its issuers. That is the date on which path validation
starts refusing the token, so it is the date after which the bundle is no longer independently
verifiable. It MUST NOT appear on a `customer_countersignature` sidecar, which has no such
certificate, and MUST NOT appear anywhere in the signed roster, which is written before any token
exists and therefore cannot know one. Bundle 1.0 does not otherwise close the sidecar key set.

`expires_at` is a caption, not evidence: a verifier recomputes the horizon from the token and MUST
reject a bundle whose declared value disagrees. No verdict rests on the declared value.

`failed` is reserved vocabulary and MUST NOT occur anywhere in a bundle version 1.0. Failed attempts
are transient and are not persisted: leaving the sidecar slot empty keeps the signed `pending` entry
retryable. `attested` cannot occur in the signed payload because it is written before external work,
and `pending` cannot occur in a sidecar because sidecars store validated outcomes rather than attempts.
No other type/status/location combination is legal. Trust roots are supplied independently by the verifier's
operator. They MUST NOT be obtained from the bundle. `keys.json` is evidence needed for Mizan and
customer signatures, not a trust-root assertion for RFC 3161.

Per-anchor state is `unattested` if explicitly development-unattested, otherwise `pending` if any
rostered authority remains pending, otherwise `rfc3161` if at least one RFC 3161 token verifies,
otherwise `expired` if at least one verified at an instant inside its own certification path's
validity window but that window has closed, otherwise `unattested`. An anchor's horizon is the
**latest** horizon among the authorities carrying it: countersigning by a second authority buys
time and MUST be reported as having done so. Stream assurance is the weakest anchor: `rfc3161` only
if all anchors are `rfc3161`; else `expired` if every anchor is `rfc3161` or `expired` and at least
one is `expired`; else `unattested` if any is unattested; else `pending`. The stream horizon is the
**earliest** anchor horizon, because every anchor must hold.

The manifest `assurance` object is only a claim under test and MUST equal
`{anchor_attestation: derived_state, external_timestamp: derived_state == "rfc3161"}`, with
`derived_state` read as `rfc3161` when it is `expired`. The manifest records what was true at
export; a horizon reached since then is a fact about the calendar, and reporting it as a mismatched
claim would accuse the exporter of the one thing this verdict exists to rule out.

Key documents have exactly `key_id`, `role`, `custody`, `algorithm`, `public_key`, `not_before`,
`not_after`, and `revoked_at` in version 1.0; `algorithm` is `Ed25519` and `custody` is exactly one of
`development-derived`, `kms`, or `hsm`. Custody is an explicit property of the provider, never inferred
from `key_id`. A verifier MUST print the exact warning `KEY CUSTODY: publicly derivable development key
— this bundle is forgeable by anyone who reads it.` when any key is `development-derived`. A valid
signature under a revoked/expired key is reported with that lifecycle fact and is not silently upgraded
to an unqualified pass.

`checkpoints.json` is an unsigned derived index. Its dense ranges and endpoint hashes are checked,
but it supplies no independent evidence and MUST NOT increase assurance.

An attestation entry, in a signed payload or a sidecar, has `type`, `authority`, `status`, `evidence`
and `obtained_at`. Entries of type `rfc3161` may additionally carry `anchor_digest` and
`requested_at`; no entry carries any other member. `evidence` and `obtained_at` are `null` while a
`pending` or `unattested` entry has nothing to carry. Unlike the key document in this section, this
member set is **not** closed against future versions, and a verifier MUST NOT infer meaning from a
member this document does not name. For an `rfc3161` entry the `evidence` is Base64 and decodes to either an RFC 3161
section 2.4.2 `TimeStampResp` or the bare RFC 5652 `ContentInfo` token inside one; a verifier MUST
accept both encodings. Its `TSTInfo.messageImprint` is compared against the anchor core digest of the
payload the entry attests.

`checkpoints.json` entries have exactly `from_sequence`, `to_sequence`, `head_hash` and
`expected_previous`, carrying the same meanings as in section 3, with `expected_previous` naming the
`prev_hash` the record at `from_sequence` must declare.

## 5. Terminal acceptance

A verifier returns one of five terminal verdicts. `MALFORMED` means the input violates the bundle 1.0
grammar and therefore is not a Mizan bundle. `CANNOT CHECK` means the input is structurally eligible
but the verifier environment cannot evaluate a required claim. `INVALID` means the bundle is
well-formed but one or more evidence checks failed. `EXPIRED` means every required check passed and
the stream's independent timestamp horizon has been reached. `VALID` means every required check
passed and the horizon has not. These classes are mutually exclusive; neither `MALFORMED` nor
`CANNOT CHECK` is an assurance result.

`EXPIRED` is not a weaker `INVALID` and MUST NOT be reported as one. `INVALID` means *this evidence
is not what it claims to be*. `EXPIRED` means it still is, and the independent proof of **when** has
run out while the proof of **what** has not: the record chain, the receipt signatures and the anchor
signatures do not depend on the timestamp authority and MUST still verify. An investigator who
cannot tell "the authority's certificate lapsed in 2029" from "this record was altered" has been
handed the one ambiguity this format exists to remove.

The classes are mutually exclusive but the findings are not: a real bundle can earn several at once,
and the verdict is therefore decided by order of evaluation, not by severity. A verifier MUST
evaluate in these phases and MUST return as soon as a phase produces a finding:

1. UTF-8 decoding and JSON parseability of the six files — a failure here is `MALFORMED`.
2. Manifest grammar, including the `files` key set — `MALFORMED`.
3. The `files` digests, over the complete stored bytes — `INVALID`.
4. The remaining bundle 1.0 grammar of the other five files — `MALFORMED`.
5. Every evidence check in the paragraph below — `INVALID`.

Phase 3 precedes phase 4 deliberately. Once a file's bytes are known not to be the bytes the manifest
vouches for, every grammatical judgement about that file describes an artifact nobody signed, and
reporting `MALFORMED` would tell an auditor the file is badly written when what happened is that
someone changed it. A `CANNOT CHECK` finding raised in any phase is returned only if no phase
produces a `MALFORMED` or `INVALID` finding; `VALID` requires that no phase produced any finding.

A verifier returns `VALID` only after file inventory/digests, record hashes/linkage/range, one-to-one receipt
coverage and signatures, anchor numbering/linkage/density/signatures/head bindings, left and right
edges, attestation roster/cryptography, key roles, checkpoints, and claimed-versus-derived assurance
all pass. The reference CLI maps `VALID`, `INVALID`, `CANNOT CHECK`, `MALFORMED`, and `EXPIRED` to
exit statuses 0, 1, 2, 3, and 4 respectively.

## 6. What this format does not prove

These limitations are as important as acceptance. A valid bundle does **not** prove that a record was
not omitted before it entered the chain. It also does **not** prove that the exporting party did not
withhold an entire final anchor/history suffix. RFC 3161 proves an included anchor existed by a time;
it does not prove no later anchor exists. These are TM-001's pre-chain-omission and withheld-final-
anchor classes. A separately retained inclusion proof can prove a named record must occur in an
anchored history, but cannot by itself prove completeness of events never submitted.

A bundle does **not** prove *when* it was recorded after its declared `expires_at`. Bundle 1.0
claims offline verifiability for the lifetime of the timestamp authority's certificate and no
longer; RFC 4998 / CAdES-A archive timestamping, which is how that claim would be extended, is out
of scope. Past the horizon a verifier may re-check the token at an instant inside the certification
path's own validity window — read from the certificates, never from the token's `genTime`, which
would be asking the token to date the certificate that signs it — and what that supports is that
the signer chains to the operator's trust root and the imprint is this anchor. It does not support
the time the token asserts. Choose an authority whose signer certificate outlives your retention
period; the bundle now states the date, so this is checkable on receipt rather than in year three.

## 7. Decisions made explicit while specifying 1.0

Code had left these points implicit: future anchor keys are included by default because the core rule
is a closed exclusion set; file checksums cover stored bytes while semantic hashes cover JCS; sidecars
overlay only a signed identity rather than extending the roster; partial exports need a preceding
signed anchor; checkpoints never contribute assurance; and a missing verifier dependency is neither
`VALID` nor evidence failure.

`expires_at` is computed from the token's own certificates and excludes the verifier's trust roots,
because the producer writes it when no verifier's roots are known and none can be assumed. An
operator whose trust root expires sooner reaches the horizon sooner; that is a fact about their
trust configuration and the verifier reports it, but it is not something the bundle can state. The
sidecar key set stays open in 1.0: closing it is a defensible separate change, and doing it here
would have made a grammar decision under cover of a lifetime decision.

The location-scoped grammar resolves the earlier flat enum without adding a durable state. This
discrepancy is harmless today only because there is exactly one implementation — which is the precise
condition T-059 exists to end. An independent implementer reading G.2's flat enum would legitimately
accept `failed` and report it as an assurance level. Two conformant verifiers would then return
different verdicts on the same bundle, and the format would have failed at the only job it has.
