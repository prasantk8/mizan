# R-003 — Completion Blocker Disposition

**Status:** PROPOSED — HUMAN ratification required
**Date:** 2026-08-25
**Scope:** WORK_LOG B-7, B-8, B-9

This disposition contains the remaining contract choices that implementation cannot safely invent.
Ratification authorizes a SPEC v1.3 amendment and the corresponding completion work.

## B-7 — Independent review authority

Add required `approval_requirements.review` whenever `rejection_mode=review_required`:

- `approver_roles` (non-empty, reviewed role references);
- `quorum` and `expiry_seconds`;
- `distinct_control_domains_required` (constant `true` for review);
- `rejection_mode`, limited to `veto|rejection_quorum` so review cannot recurse;
- `rejection_quorum_count`, required only for rejection quorum;
- `carry_forward_votes`, constant `false`.

A reject atomically closes the deciding epoch and opens a fresh `kind=review` epoch from the review
configuration and a newly captured authority snapshot. Original voters cannot act through the closed
epoch. Review resolution may approve or reject; compliance override remains the already ratified,
fresh-quorum override epoch and never a unilateral mutation.

## B-8 — Transient arguments and genuine execution revalidation

Add `tool.arguments` to EvaluationContext as a transient open JSON object with hard adapter limits:
64 KiB canonical bytes, depth 16, 256 total keys, and finite JSON numbers. This is a narrowly named
second open boundary alongside ExternalPayloadEnvelope. It is never a policy namespace and is never
persisted. The server validates it against the immutable binding profile, computes the binding subset
and `parameters_hash`, and rejects a caller-supplied hash mismatch. `context_hash` canonicalizes the
enriched context after replacing `arguments` with the computed `parameters_hash`.

Add the same bounded `arguments` to ExecuteRequest. Redemption recomputes `parameters_hash` against
the token's pinned profile version. It also reruns authoritative agent/tool/resource/risk enrichment;
any resulting normalized context change requires reauthorization. Caller-only volatile fields remain
excluded by the profile. This makes I-9/I-14 an actual comparison to fresh inputs rather than a token
being compared with the ADR from which it was created.

## B-9 — Semantic policy hash

Define `Policy.content_hash` over the immutable authored policy semantics, excluding
`content_hash`, `status`, `approved_by`, and `approved_at`. Lifecycle transitions mutate only those
excluded governance fields and preserve `(policy_id, version, content_hash)`, so historical ADR
foreign keys remain valid. Any change to name, selectors, conditions, outcome, constraints, approval
requirements, TTL, author, or other semantic content requires a new version and hash. The canonical
hash-basis field list is normative and tested, avoiding ambiguous “metadata” exclusions.

## Ratification

Required roles: Product/Architecture, Cybersecurity, and Compliance/Business. A single authorized
human may explicitly ratify all three roles, as with T-001. Suggested response:

> I ratify R-003 for B-7, B-8, and B-9 in all required roles.
