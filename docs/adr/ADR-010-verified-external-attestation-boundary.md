# ADR-010: Verified External Attestation Boundary (the Memtara seam)

**Status:** PROPOSED — required by SPEC §0 change control for the `ADR_Record` 1.2→1.3 bump
**Deciders:** Control-plane engineer, Evidence engineer, Security engineer, Tech Lead
**Date:** 2026-09-02
**Spec anchors:** SPEC v1.3 §2.4 (`mapped`), §2 `ADR_Record` (`external_proofs`), §2.0 `ConditionNode` (`eq_field`), `docs/spec/EVIDENCE-BUNDLE-FORMAT.md` §2.1 (bundle 1.1)
**Supersedes nothing. Extends:** ADR-006 (external payload boundary), ADR-004 (audit immutability)
**Trigger:** workplan T-133/T-134/T-135 — an adviser's copilot must not recommend a structured product without a Memtara suitability proof that Mizan verified

## Context

ADR-006 settled how *untrusted* foreign data reaches a decision: it does not. A payload enters as an
inert `ExternalPayloadEnvelope`, and only a named, versioned, scalars-only projection lifts a subset
into `mapped.fields` for evaluation. The premise there is that nothing about the payload's origin can
be established, so the projection is the entire trust story.

The Memtara seam breaks that premise in one specific way, and it is worth being precise about which
way. A Memtara proof token is a compact EdDSA JWS issued by a separately operated service. Its origin
*can* be established — offline, by anyone holding Memtara's public keyset, at authorization time and
again years later from the evidence bundle. The question this ADR settles is whether cryptographic
verification earns the payload a different status than ADR-006 grants, and what exactly it does not
earn.

The commercial reason this matters: UC-2 requires that a *decline* be evidenced as rigorously as an
approval, and that a bank's internal auditor can verify the Mizan decision and the Memtara attestation
from **one** bundle, offline, without either vendor's cooperation. That is only possible if the token
itself — not a hash of it, not an extracted claim — is committed into the immutable record.

Forces:

- A hash or an extracted claim cannot be signature-verified after the fact. Only the token can.
- The verifying party at audit time is not Mizan and is not Memtara. It is a third party with a file.
- Anything a caller can assert, a caller can forge. The header is attacker-reachable.
- Mizan must never become a party that vouches for facts it did not verify (founder ruling,
  2026-09-02: never the AI provider; the same logic applies to never being the attestation provider).

## Options Considered

1. **Verify at the boundary; project the verified claims; commit the token into evidence.**
2. **Treat the token as an ordinary ADR-006 envelope — capture, never evaluate.** Rejected: it makes
   the seam worthless. The entire product claim is that the recommendation tool *cannot run* without a
   suitability proof, which requires the proof to reach policy.
3. **Verify at the boundary but commit only `proof_hash` into evidence.** Rejected: an auditor holding
   the bundle could then confirm only that Mizan claimed to have verified something. The signature
   would be unverifiable forever after. This is precisely the "tamper-evident chain that evidences its
   own assertion" defect the AIHOOTS retirement was about.
4. **Let Memtara call Mizan and assert suitability over a trusted channel.** Rejected: transport
   authentication proves who connected, not what was computed. It also makes the audit story depend on
   Memtara's availability and honesty at audit time rather than at issue time.

## Decision

Adopt **Option 1**, with the trust boundary drawn at three named places.

**1 — Verification is deployment-pinned, never request-directed.** The trusted issuer and the JWKS URL
come from configuration (`MIZAN_MEMTARA_TRUSTED_ISSUER`, `MIZAN_MEMTARA_JWKS_URL`), which must be set
together or not at all. Request material never chooses an issuer or a verification URL. A token
presented when verification is unconfigured is refused; it is not accepted on trust. This is the
distinction between verifying an attestation and relaying one.

**2 — Only verified claims cross into evaluation, and the caller cannot forge that crossing.** The
verified projection lands in `mapped.fields` with `source="memtara"` — the same mechanism ADR-006
established, so the review surface for "what can influence a decision" stays enumerable. Because
`mapped` is also a request-supplied structure, the authorization boundary **strips any
caller-supplied projection claiming `source="memtara"`** before verification runs. Without that strip,
a caller could assert `suitable: true` and satisfy the reference policy without holding a token, which
would make the entire seam decorative. The reference policy
`policies/reference/require_suitability_proof.json` additionally binds the attested `product_isin` to
the tool argument via the new `eq_field` condition operator, so a proof for one product cannot
authorize a recommendation of another.

**3 — A decline is a decision, not an error.** A token asserting `suitable=false` verifies
successfully; it is an authentic attestation of an unfavourable fact. It therefore produces a normal
`DENY` with reason `suitability_declined` and an ADR record of the identical shape to the approval
path. Refusing it at the boundary as an error would destroy the evidence the regulated use case
depends on. A token that fails *verification* is a different thing and is refused at the boundary with
no decision and no record.

**4 — The token is evidence and is committed into the immutable record.** `ADR_Record` bumps to
schema 1.3 with a required `external_proofs[]` array (empty when no proof affected the decision), and
the evidence bundle format bumps to 1.1. Each member carries `issuer`, `proof_hash`, `jti`,
`memtara_chain_head` and the compact `token`. The array is inside the hashed record body, so it is
committed by `record_hash`, the receipt and the anchor. Both offline verifiers check the grammar and,
when the operator supplies Memtara's keyset as a trust root, the signature and the claim binding.
Bundle 1.0 records must not carry the member, so a proof-bearing bundle fails loudly in a 1.0-only
verifier rather than having its new evidence silently ignored.

**Retention consequence.** The token contains attestation claims about a natural person's financial
suitability. It is evidence data: producers must not write it to ordinary application, access or trace
logs, and evidence retention and access controls apply to it. This is a deliberate scope extension
beyond the workplan's `(issuer, proof_hash, jti, chain head)` list, taken because option 3 above is not
auditable, and it is recorded here rather than left implicit.

## What this explicitly does not establish

Recorded as decisions, not as oversights:

- **The Memtara chain head is not signed by the token.** `memtara_chain_head` is observed at issue time
  and committed by Mizan's record hash, so the bundle proves which head Mizan recorded. It does not
  authenticate that head, nor prove the completeness of Memtara's history. Establishing that requires a
  separately retained Memtara checkpoint or evidence export (workplan M-04).
- **Replay defence is per process.** `JtiReplaySet` is an in-memory, tenant-scoped, atomic set. Under
  multiple workers or replicas the same `jti` is claimable once per process. Deployment-wide replay
  refusal requires shared state and is not claimed today.
- **The keyset is fetched once and not refreshed.** A Memtara key rotation is an outage until Mizan
  restarts. A rotation protocol is owed before a pilot depends on it.
- **Historical verification does not compare `exp` to the verifier's clock.** Expiry governed whether
  Mizan could accept the token at authorization time; the bundle proves afterward which signed token
  the immutable record used. Comparing a years-old `exp` to today's clock would make every genuine
  bundle expire.

## Consequences

- (+) A third party holding only the bundle and Memtara's public keyset can verify, offline and
  years later, both that Mizan decided as recorded and that Memtara attested what Mizan relied on.
- (+) Mizan never asserts a suitability fact of its own. It records whose attestation it verified and
  what that attestation said — which is the only defensible position for an evidence plane.
- (+) A decline carries the same evidentiary weight as an approval, which is what a supervisor and a
  regulator actually need.
- (−) The evidence store now holds third-party attestation claims about individuals, with the
  retention and access obligations that implies.
- (−) Two independent verifiers must each track a second issuer's signature scheme; a Memtara format
  change is now a change in three repositories.
- (−) The three limits named above are real and must be closed before "bank-pilot-ready" may be said
  of this seam.
