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

The manifest has `bundle_version="1.0"`, `canonicalization="RFC8785"`,
`hash_algorithm="SHA-256"`, tenant and stream identifiers, inclusive `range.from_sequence` and
`range.to_sequence`, an `assurance` claim, and `files`. `files` has exactly the five non-manifest
filenames above and maps each to `hex(SHA-256(complete stored file bytes))`.

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
undeclared or duplicate identity is invalid. Legal combinations are:

| `type` | legal `status` | required verification |
|---|---|---|
| `none_development` | `unattested` | authority is `development`; no external assurance |
| `rfc3161` | `pending` | no token is credited |
| `rfc3161` | `attested` | `anchor_digest` equals the core digest and the token verifies under an operator trust root |
| `customer_countersignature` | `pending` | no signature is credited |
| `customer_countersignature` | `attested` | Ed25519 signature over the 32 digest bytes under the named customer key |
| `rfc3161` or `customer_countersignature` | `failed` | named terminal failure; no assurance is credited |

No other type/status combination is legal. Trust roots are supplied independently by the verifier's
operator. They MUST NOT be obtained from the bundle. `keys.json` is evidence needed for Mizan and
customer signatures, not a trust-root assertion for RFC 3161.

Per-anchor state is `unattested` if explicitly development-unattested, otherwise `pending` if any
rostered authority remains pending, otherwise `rfc3161` if at least one RFC 3161 token verifies,
otherwise `unattested`. Stream assurance is the weakest anchor: `rfc3161` only if all anchors are
`rfc3161`; else `unattested` if any is unattested; else `pending`. The manifest `assurance` object is
only a claim under test and MUST equal `{anchor_attestation: derived_state,
external_timestamp: derived_state == "rfc3161"}`.

Key documents have exactly `key_id`, `role`, `algorithm`, `public_key`, `not_before`, `not_after`, and
`revoked_at` in version 1.0; `algorithm` is `Ed25519`. A valid signature under a revoked/expired key is
reported with that lifecycle fact and is not silently upgraded to an unqualified pass.

`checkpoints.json` is an unsigned derived index. Its dense ranges and endpoint hashes are checked,
but it supplies no independent evidence and MUST NOT increase assurance.

## 5. Terminal acceptance

A verifier accepts only after file inventory/digests, record hashes/linkage/range, one-to-one receipt
coverage and signatures, anchor numbering/linkage/density/signatures/head bindings, left and right
edges, attestation roster/cryptography, key roles, checkpoints, and claimed-versus-derived assurance
all pass. Inability to execute RFC 3161 verification is `CANNOT CHECK`, not acceptance and not an
accusation that evidence is invalid.

## 6. What this format does not prove

These limitations are as important as acceptance. A valid bundle does **not** prove that a record was
not omitted before it entered the chain. It also does **not** prove that the exporting party did not
withhold an entire final anchor/history suffix. RFC 3161 proves an included anchor existed by a time;
it does not prove no later anchor exists. These are TM-001's pre-chain-omission and withheld-final-
anchor classes. A separately retained inclusion proof can prove a named record must occur in an
anchored history, but cannot by itself prove completeness of events never submitted.

## 7. Decisions made explicit while specifying 1.0

Code had left these points implicit: future anchor keys are included by default because the core rule
is a closed exclusion set; file checksums cover stored bytes while semantic hashes cover JCS; sidecars
overlay only a signed identity rather than extending the roster; partial exports need a preceding
signed anchor; checkpoints never contribute assurance; and a missing verifier dependency is neither
PASS nor evidence failure. Writing the format exposed one contract/implementation discrepancy:
ADR-004 permits `failed` status, while the current verifier rejects it and T-055 deliberately persists
only successful outcomes. B-14 records that unresolved version-1.0 grammar question; this task does
not silently choose a new state-machine rule.
