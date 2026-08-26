# ADR-004: Audit Immutability & Hash-Chaining Strategy

**Status:** ACCEPTED
**Deciders:** Product/Architecture Lead, Cybersecurity Architect
**Date:** 2026-08-25
**Spec anchors:** SPEC_v1 §2.3 (ADR_Record chain fields), §2.5 (AuditTrail), §3 (`/v1/audit/verify`), Invariants I-2, I-11, I-12; PRD §27, §93

## Context

Audit records must be append-only, tamper-evident, timestamped, trace-correlated, exportable, and searchable (PRD §27). The evidence claim ("we can prove what happened") is a primary selling point to audit/risk teams (PRD §26). Threats: a compromised Mizan admin or DBA rewriting history; silent record deletion; disputes over what a record contained; regulator requests years later.

Key forces:

- Postgres is the system of record (PRD §40); tamper-evidence must work there without exotic storage.
- Chain writes sit on the authorization hot path (ADR_Record before HTTP response — Invariant I-1), so hashing must not serialize all throughput onto one lock.
- PII must be redactable from stored payloads without breaking integrity proofs (SPEC §2.5 `payload_hash`).
- Multi-tenant: one tenant's verification must not require another tenant's data (ADR-005).

## Options Considered

1. **Per-tenant SHA-256 hash chain in Postgres + periodic signed anchors to WORM/object storage; append-only enforced by DB privileges and triggers.**
2. **Merkle-tree transparency log (Trillian/ct-style).** Strongest proofs (inclusion + consistency), heavy operational lift for v0.1.
3. **Managed ledger DB (e.g. QLDB-style).** Offloads the problem; breaks cloud-neutrality and on-prem deployment (PRD §41).
4. **Blockchain anchoring.** Rejected: cost/latency/optics; external timestamping achieves the goal.

## Decision (proposed)

Adopt **Option 1 now, with Option 2's proof shape as the evolution path**:

- **Chain construction:** per `(tenant_id, stream)` where stream ∈ {`adr`, `audit`}: `record_hash = SHA-256(canonical_json(record ∖ record_hash))` with `prev_hash` and dense `sequence_number`. Canonicalization: RFC 8785 (JCS).
- **Write path:** single-writer sequencer per tenant-stream (Postgres advisory lock or dedicated sequencer worker) to guarantee dense sequencing without global serialization; hot tenants shard by stream.
- **Append-only enforcement (defense in depth):** (a) runtime DB role has INSERT/SELECT only; (b) `BEFORE UPDATE OR DELETE` triggers raise; (c) WAL-shipped replica retained under separate credentials.
- **Anchoring:** every N minutes or M records, write a signed checkpoint `{tenant, stream, seq_range, head_hash, ts}` — signature via KMS/HSM key — to WORM-capable object storage (S3 Object Lock / equivalent; file target on-prem). Checkpoint emission = `mizan.audit.anchor_written`. Anchors bound the rewrite window: history older than the last anchor cannot be silently rewritten even by a DBA.
- **Redaction-safe integrity:** `payload_hash` commits to pre-redaction content; stored `payload` is post-redaction. Disputes about redacted content are resolvable if the submitting side retained the original (hash matches), while Mizan never stores raw PII in the ledger.
- **Verification:** `/v1/audit/verify` walks any range, recomputing hashes and checking anchors; ships as part of the compliance evidence package. Amendments (approval votes, execution outcomes) are new chained records referencing `decision_id` — never in-place updates.
- **Time:** DB `now()` from NTP-disciplined hosts; each anchor includes an external timestamp; consider RFC 3161 TSA per-anchor for enterprise tier.

## Consequences

- (+) Tamper-evidence with plain Postgres + object storage — deployable in SaaS, private cloud, and on-prem identically.
- (+) Per-tenant chains keep verification tenant-local and exportable (auditor gets records + anchors + verifier tool).
- (−) Sequencer is a throughput choke point per tenant-stream; must be benchmarked against 1k dec/s (mitigation: batch hashing, stream sharding by day).
- (−) Hash chains prove order/integrity, not completeness against a malicious sequencer that drops records *before* chaining; mitigations: client-visible `decision_id` receipts + count reconciliation against Kafka export.
- (~) Migration to Merkle proofs later is additive: anchors become tree heads; record shape doesn't change.

## Compliance Mapping

| Framework | Mapping |
|---|---|
| NIST AI RMF | MEASURE 2.x (traceability of AI decisions), GOVERN 4.2 (documentation/evidence) |
| ISO/IEC 42001 | A.6.2.8 & A.9 (traceability, records for accountability) |
| OWASP Agentic AI | Evidence for #11 data exfiltration & #3 tool misuse investigations |
| Audit/regulatory | Append-only, hash-chained, externally anchored records support banking record-keeping expectations (7y retention class in SPEC §2.5) |

## Open Questions

- [x] Anchor cadence (records vs. time) and per-tier defaults. — **Closed by Amendment G.** Governed by
  `MIZAN_AUDIT_ANCHOR_INTERVAL_SECONDS` (300) and `MIZAN_AUDIT_ANCHOR_INTERVAL_RECORDS` (10000), whichever first.
- [x] RFC 3161 TSA integration in enterprise tier — pilot requirement or later? — **Closed by Amendment G.**
  Not enterprise-tier and not later: TSA attestation is the mandatory floor for every production anchor.
- [x] Do we expose a customer-side verification CLI in v0.1? — **Closed by Amendment G.** Yes, and it is
  the load-bearing deliverable rather than a demo: T-032/T-037.

---

## Amendment A — Evidence pipeline, keyed redaction commitments, gapless sequencing

**Date:** 2026-08-25 · **Trigger:** baseline review R-001 (findings 5, and the "Postgres for everything" and "PII commitment vs. data minimization" paradoxes) · **Spec anchors:** SPEC v1.1 §2.5, §10, Invariants I-11, I-12, I-18, I-19, I-20

Three defects in the original decision, and what replaces them.

### A.1 Postgres privileges are not immutability

Withholding `UPDATE`/`DELETE` from the runtime role protects against a compromised *application*, not against the DB owner, a compromised migration role, a privileged operator, or anyone with filesystem access to the volume. As written, "immutable" over-claimed.

**Amended decision — the write path is a transactional outbox into an external evidence corpus:**

```text
single Postgres txn: ADR row + chain-head lock (sequence, prev_hash, record_hash) + outbox row
  └─ outbox drain (at-least-once, idempotent) ─┬─► Kafka  [delivery, never evidence of record]
                                               └─► immutable object storage: canonical segments
                                                     └─► periodic signed head-hash/Merkle anchors [authoritative]
```

Postgres remains the searchable registry, approval/epoch store, idempotency authority, and query index. The **authoritative evidence corpus is the anchored object store**, because it puts tamper detection outside the Postgres administrative boundary. External anchoring moves from "nice to have" to mandatory: without it, I-11 is only an assertion about grants.

Atomic publication is non-negotiable. Writing to Postgres and Kafka independently creates a dual-write outage mode where evidence and delivery disagree; the outbox is what makes G8 ("append and emit in the same transaction") implementable.

### A.2 A bare pre-redaction hash is both weak and unfalsifiable

v1.0's single `payload_hash` over pre-redaction content had two problems. It leaked: an unsalted SHA-256 over a low-entropy field (a national ID, a phone number, an account number) is recoverable by dictionary attack, so the "integrity proof" was itself a disclosure channel. And it proved the wrong thing: it demonstrated only that a holder of the original can later test equality. It said nothing about whether a PII field was *missed*, whether the DLP policy covered every sensitive path, which policy version ran, or whether the hash was taken before or after a faulty transformation.

**Amended decision — three artefacts instead of one (SPEC §2.5):**

1. `stored_payload_hash` — plain SHA-256 of the **stored, post-redaction** payload. Verifiable by any auditor holding the record; this is what chain verification consumes.
2. `source_commitment` — **HMAC-SHA256** over the pre-redaction canonical payload under a rotated audit key (`MIZAN_AUDIT_HMAC_KEY_REF`), held under separate authority. Keyed, so dictionary attack fails; verification requires the key, which is the point.
3. `redaction` — an attestation: DLP policy id/version/hash, redactor build identity, scanner version and status, coverage profile, and a field-level manifest (JSON Pointer, classification, transformation, keyed per-field commitment). Optional encrypted `evidence_ref` under legal hold with its own short retention.

Honest limitation, stated so nobody over-claims to an auditor: **this still cannot prove that an unrecognised sensitive field was recognised.** Cryptography cannot certify classification coverage. That assurance comes from the coverage profile, a maintained regression corpus, and independent DLP scanning — which is why `redaction.dlp.coverage_profile` is recorded as evidence of *process*, not presented as proof. What the design does guarantee is fail-closed behaviour: a `scan_failed` or incomplete attestation rejects the audit write (I-19, `MIZAN_DLP_FAIL_MODE=reject_write`) rather than silently storing unverified content.

### A.3 Sequence gaps must mean tampering, not rollback

A dense per-stream sequence is hostile to concurrent writers if the number is reserved before commit: a rolled-back transaction leaves exactly the gap I-2 classifies as tampering, producing false alarms that train operators to ignore the alarm.

**Amended decision:** sequence numbers are allocated **inside the committing transaction** by locking the chain-head row (`SELECT … FOR UPDATE` on `chain_heads(stream_id)`), never from a Postgres sequence object or a pre-reservation. An aborted write consumes nothing (V-11, I-20). Throughput is recovered by **sharding streams**, not by loosening the chain: `stream_id = {tenant}:{kind}:{shard}` with `MIZAN_CHAIN_SHARDS_PER_TENANT` (default 4). Chains, anchors, and verification are per stream. Shard count may be raised (additive: new streams, new anchors) but never lowered.

Verification cost is bounded by checkpoints every `MIZAN_HASH_VERIFY_CHECKPOINT_INTERVAL` (default 1000) records, so `/v1/audit/verify` is O(range) and ranges verify in parallel. Full-history replay is never on the interactive path.

### A.4 Consequences of the amendment

- (+) Tamper detection survives a compromised DBA, which the original decision did not honestly provide.
- (+) Redaction evidence has a durable home (policy hashes, field commitments, DLP attestations) without storing raw PII in searchable operational tables.
- (+) Sharded chains give the sequencer a horizontal scaling story against the 1k dec/s target.
- (−) Three storage systems on the evidence path instead of one; the outbox drain becomes a component with its own SLO (`MIZAN_OUTBOX_DRAIN_INTERVAL_MS`).
- (−) Key management grows: an audit HMAC key with rotation, retained for the full verification retention period.
- (~) The Merkle evolution path is unchanged and still additive — anchors become tree roots, record shape does not change.

---

## Amendment B — Typed decision events and execution-gating receipts

**Date:** 2026-08-25 · **Trigger:** baseline review R-002 — undefined ADR amendments and an erasable pre-publication window · **Spec anchors:** SPEC v1.2 §2.12, §10, I-24, I-25, V-19, V-20

The authorization-time `ADR_Record` is one immutable snapshot. Approval votes, epoch resolution, capability issuance, lease lifecycle, and execution outcomes are not partial ADR_Record rewrites and are not full snapshot copies; each is a typed `DecisionEvent`. Events have a dense per-decision sequence and `previous_event_hash`, while also participating in the ordinary tenant ADR stream. Transactional allocation plus idempotency makes reconstruction deterministic under retries and races.

Object-store publication now returns a signed receipt binding `{tenant_id, stream_id, sequence_number, record_hash, object_version}`. The receipt is independently verifiable using the evidence-writer keyset and is recorded by reference, never accepted from the caller. A `financial_write` capability cannot be redeemed until receipts cover both the originating ADR_Record and, where applicable, the deciding approval event. This closes the interval in which Postgres and its outbox could be destroyed after an ALLOW but before evidence escaped the database administrative boundary.

Non-financial actions retain asynchronous publication for latency, bounded by `MIZAN_EVIDENCE_MAX_UNPUBLISHED_SECONDS`. Exceeding that SLO opens the evidence breaker; it is not merely an observability warning.

---

## Implementation Amendment C — Receipt side table and segment publication

**Date:** 2026-08-25 · **Trigger:** T-008 implementation proof · **Spec anchors:** SPEC v1.2 §10, I-24, I-25

An ADR or DecisionEvent cannot be mutated after object publication merely to backfill `immutable_receipt_ref`. Signed receipts therefore live in the append-only `evidence_receipts` relation, uniquely keyed by `(tenant_id, stream_id, sequence_number, record_hash)`. Capability redemption resolves receipt coverage through that relation. A receipt reference embedded at initial record creation remains permitted, but is never required to make an immutable row mutable.

The outbox writer groups ordered records from one stream into RFC 8785 canonical segments. Each record receives a signed receipt binding its exact sequence/hash to the segment's create-only object key and content version. Signed anchors bind a stream range and head hash. The development filesystem adapter uses exclusive creation plus `fsync`; production adapters must provide genuine WORM retention.

The four-shard PostgreSQL sequencer benchmark completed 2,725 operations/second over 2,000 transaction-level allocations with p99 2.0087 ms on the M3 Max development host. This resolves WORK_LOG B-6 for the development baseline; deployment-class Linux sizing must rerun `make benchmark-sequencer`.

DecisionEvent retry identity is the RFC 8785 hash of `(decision_id, event_type, actor, payload)`.
The value is tenant/decision unique and checked before either chain head is locked. An identical retry
returns the existing immutable event; a genuinely different transition receives a new dense sequence.

---

## Implementation Amendment D — Verifiable stored transforms and failure signaling

**Date:** 2026-08-25 · **Trigger:** completion audit found that writers could submit an attestation
whose hash or manifest did not describe the stored payload, and scanner failure signaling was not
wired as a mandatory dependency · **Spec anchors:** SPEC v1.2 §2.5, I-12, I-18, I-19

Before allocating a sequence, the evidence repository recomputes `stored_payload_hash`, requires the
DLP findings count to equal the manifest length, and checks every non-drop replacement against its
declared transformation and field commitment. List drops are performed deepest-first and in numeric
descending-index order; lexical JSON Pointer ordering is unsafe for indexes such as 2 and 10.

Every Redactor must be constructed with a failure-event sink. A scanner failure invokes that sink
with build and coverage metadata only—never the source payload—and then rejects the audit write.
The PostgreSQL sink records `mizan.security.redaction_failed` in the transactional outbox even though
no AuditTrail containing the rejected payload is created. Failure to emit the security event remains
a controlled redaction failure rather than allowing the write.

This validates that declared transforms describe the bytes actually stored. It does not turn DLP
classification into a cryptographic proof: a field the scanner never classified remains a coverage
risk governed by the recorded profile and regression corpus, as stated in Amendment A.

Security notifications share the transactional outbox but are not evidence records until separately
materialized by the security-event consumer. The object evidence publisher therefore selects only
`decision`, `decision_event`, and `audit` aggregate types; otherwise a payload-free SIEM event could
crash or starve immutable segment publication. Execution-token replay emits a payload-free security
notification containing only the decision id, authenticated workload, and a hash of `jti`.

## Implementation Amendment E — request-id races converge on one record

**Date:** 2026-08-25 · **Trigger:** R-004 F-6 · **Spec anchors:** SPEC v1.3.1 §3, I-1

PostgreSQL remains the idempotency authority. Two authorization transactions may both observe no
prior row, but only one may commit `UNIQUE(tenant_id, request_id)`. The loser recognizes only the
named `adr_records_tenant_id_request_id_key` violation (or the deterministic decision-id primary-key
collision for that same request), waits for transaction unwind, re-reads the
winner under tenant RLS, and returns that response when `context_hash` matches. A missing winner or
different context returns 409. Other uniqueness or persistence failures retain their own identity
and must never be translated into idempotent success or generic evidence outage.

The in-memory adapter applies the same atomic check under a lock, keeping unit evidence shape and
concurrency semantics aligned with PostgreSQL. In either adapter exactly one ADR_Record and outbox
event exists for a request id, even when both callers entered evaluation concurrently.

## Implementation Amendment F — in-memory evidence has persisted chain shape

**Date:** 2026-08-25 · **Trigger:** R-004 F-8 · **Spec anchors:** SPEC v1.3.1 I-2, I-13, I-20

The in-memory authorization repository now owns a locked chain head per `(tenant_id, stream_id)`,
assigns the dense sequence and prior hash, and recomputes the canonical record hash after allocation,
matching the PostgreSQL writer's ordering. Unit-level representability and chain properties therefore
exercise the document that is actually stored rather than the service's pre-allocation placeholder.

---

## Amendment G — Key custody and the external attesting party (ratifies B-11 + B-12)

**Date:** 2026-08-25 · **Status:** RATIFIED by the human owner · **Trigger:** R-005 F-13, findings on the
"Evidence Plane First" brief · **Spec anchors:** SPEC v1.3.1 §8, §10, I-11, I-24, I-25 · **Supersedes:**
the "signature via KMS/HSM key" clause of the original Decision, which named a custody model no code implemented

Amendment A stated the doctrine — *"External anchoring moves from 'nice to have' to mandatory: without it,
I-11 is only an assertion about grants."* R-005 found that no code implements it: `OutboxPublisher.anchor()`
signs with an `Ed25519PrivateKey.generate()` created in the process it is attesting for. I-11's second clause
is therefore currently false in the tree. This amendment ratifies both halves of the fix. They are one
decision and are ratified together, because durable custody alone fixes operability and leaves the
evidentiary defect untouched: **a durable key that Mizan controls is still Mizan's word.**

### G.1 Custody (B-11)

**Four key roles**, separately held, separately rotatable, never interchangeable: `evidence-receipt`,
`evidence-anchor`, `execution-token`, `degraded-grant`. A single key serving two roles means one compromise
collapses two guarantees.

- **Custody is KMS/HSM.** Where the provider supports sign-in-place, private key material never enters the
  control-plane process. Where it cannot (on-prem file adapter), a `local://` key reference is permitted
  **only** under `MIZAN_KEY_CUSTODY_MODE=development`. With `MIZAN_ENV=production` and any `local://`
  reference, the control plane **refuses to start**. A dev key that boots in production is the whole defect
  restated, so this is a startup assertion, not a warning.
- **Published verification keyset.** Every `key_id` resolves through a keyset carrying algorithm, public key,
  `not_before`, `not_after` and `revoked_at`, served at `/v1/audit/keys` **and copied into every export
  bundle**. Verifying a five-year-old record must never require the key in use today.
- **Rotation is additive and never retroactive.** New records sign under the new `key_id`; history is left
  alone. **Re-signing history is forbidden** — a re-signed corpus is byte-indistinguishable from a forged one,
  so the operation that would "repair" a rotation is exactly the operation an attacker needs.
- **Compromise semantics — and why G.2 is inseparable from G.1.** If an anchor key is compromised, every
  anchor it ever signed becomes forgeable *retroactively*, and without an independent time source there is no
  way to tell which anchors predate the compromise. An RFC 3161 timestamp converts that from "all history is
  now doubtful" into "history attested before the compromise timestamp remains sound." Custody bounds the
  blast radius; external attestation is what lets you locate its edge.

### G.2 The attesting party (B-12)

**Floor — RFC 3161 timestamping, on every production anchor.** Not an enterprise upsell, not deferred. The
TSA request carries the SHA-256 of the canonical anchor payload and nothing else: no record content, no
payload, no tenant identifier, no PII. What leaves the boundary is a hash and a request for a countersigned
time.

**Enterprise tier — customer countersignature, additive.** The customer's own KMS signs the anchor digest and
the result is recorded as a second attestation. This is the direct answer to "why should I believe your logs":
the answer stops being Mizan's word and becomes the customer's own key. It never replaces the TSA floor.

**Blockchain anchoring remains rejected** (Options Considered #4, unchanged).

- **Anchor payload gains `attestations[]`** — an ordered array, each entry
  `{type, status, authority, obtained_at, evidence}` with `type ∈ {rfc3161, customer_countersignature,
  none_development}` and `status ∈ {attested, pending, failed, unattested}`; `unattested` is valid only with
  `none_development` and is forbidden in production. An array, not a field: two independent
  authorities mean one compromised TSA does not collapse the claim. `MIZAN_ANCHOR_TSA_ENDPOINTS` requires
  ≥1 endpoint in production; two independent authorities are recommended for the enterprise tier.
- **Attestation is asynchronous and is never on the authorization hot path.** A TSA outage must not make a
  decision unrecordable — that would convert an availability failure of a third party into a control-plane
  outage. Anchors are written immediately with `status: pending`.
- **Pending is bounded and alarming, not warning.** Exceeding
  `MIZAN_ANCHOR_ATTESTATION_MAX_PENDING_SECONDS` (default 900) **opens the evidence breaker**, in the same
  escalation class as `MIZAN_EVIDENCE_MAX_UNPUBLISHED_SECONDS`. While any anchor in a stream is `pending`,
  no API, report, or verifier output may describe that stream as externally anchored.
- **Verification is offline, and the trust anchor is not ours to supply.** The export bundle carries the TSA
  token and its full certificate chain; the *pinned trust root is supplied by the verifier's operator*
  (`--tsa-trust-anchor`, defaulting to the system store). A trust root shipped by Mizan inside a Mizan bundle
  returns the auditor to trusting Mizan. The verifier must print which trust root it used.
- **Validate before recording completion.** The asynchronous worker recomputes the anchor imprint and
  validates every returned token against operator-supplied `MIZAN_ANCHOR_TSA_TRUST_ANCHORS` before it may
  append an `attested` sidecar. Invalid responses remain retryable attempts and do not consume the immutable
  `(anchor, authority, type)` sidecar slot; the original signed payload remains the durable pending state and
  stays visible to the pending-SLO breaker. Only an appended `attested` outcome is finalized or counted as a
  completion. Production requires at least one trust root and HTTPS-only TSA endpoints; this validation
  remains outside the authorization hot path.

### G.3 What this buys, and what it does not

Stated plainly so nothing is over-claimed to an auditor:

- (+) A hostile party holding the database **and** the signing key can no longer rewrite history undetected.
  Rewriting requires re-anchoring, re-anchoring requires new timestamps, and new timestamps carry today's
  date against a chain whose earlier anchors carry the original one.
- (+) Verification survives key rotation, key compromise, and Mizan's own disappearance.
- (−) It still does not prove **completeness**: a record dropped before it was ever chained leaves no trace in
  the chain. Partial mitigations: `covered_record_count` and anchor-number continuity (T-030), and
  caller-retained inclusion proofs (T-040), which move a copy of the evidence outside Mizan entirely.
- (−) It does not prevent Mizan from withholding an entire anchor; it makes the gap visible in the anchor
  numbering rather than invisible.
- (−) Operational cost: one timestamp request per anchor per stream shard, at the Amendment-G cadence — for
  four shards at the 300s/10000-record default, on the order of 1,150 timestamps per tenant-day worst case.
  Budget it as a real dependency with an SLO, not as a background nicety.

### G.4 Consequences

- (+) I-11's second clause becomes true in code rather than in prose, and the T-021 reachability gate becomes
  a meaningful test of it rather than a check on a sentence.
- (+) The compliance story stops being "our logs say so" and becomes an artifact a hostile third party can
  check without us.
- (−) Two new external dependencies on the evidence path (KMS, TSA), each with its own availability envelope,
  each capable of opening the evidence breaker.
- (−) Air-gapped deployments cannot reach a public TSA; they require an in-perimeter RFC 3161 authority under
  separate administrative control from the Mizan operator, which must be a documented deployment prerequisite.
  "Same admin signs both" is not external attestation.
- (~) The Merkle evolution path (Options Considered #2) is unchanged and still additive; T-040 takes it.

### G.5 Implementation delta — chained anchor sets (T-030)

Every new anchor signs a zero-based per-stream `anchor_number`, `prev_anchor_hash` over the prior complete
signed payload (all-zero genesis), and `covered_record_count`. The range is dense from the prior anchor's
terminal sequence, and insertion validates/allocates that position while holding the existing stream-head
row lock. The additive database migration leaves legacy anchor rows nullable and identifiable rather than
inventing historical chain metadata; offline verification reports those rows as lacking anchor-chain
coverage. This closes removal, replay, and internal-range-density detection without changing who signs an
anchor, which remains T-033/T-036.

### G.6 Implementation delta — independently runnable export (T-032)

The v1 export is a manifest-bound directory containing canonical records recovered from immutable receipt
objects, signed receipts, the complete chained anchor set, verification checkpoints, and the public keys
needed for those signatures. The standalone verifier imports no Mizan code and needs pinned RFC 8785 and
cryptography packages; RFC 3161 verification additionally requires the OpenSSL 3 CLI. CI runs it in a clean
environment with the network namespace disabled. Until
Amendment G.2 is implemented by T-036, its passing output labels the anchor as Mizan-self-signed and gives
the database-plus-signing-key rewrite limitation equal prominence. This creates portable checkability now
without misrepresenting self-attestation as external proof.

### G.7 Implementation delta — operator export path (T-043)

The installed control-plane package exposes `mizan-export-evidence`, taking an explicit runtime-role DSN,
immutable object-store root, published public keyset, tenant/stream selection, new output directory, and
optional inclusive range. This command is deliberately read-only: it accepts no private key and reconstructs
record documents only from receipt-addressed immutable objects. Deployment authorization and invocation
audit remain operator controls outside the CLI. A live PostgreSQL contract test must traverse authorization,
outbox publication, anchoring, the operator command, and the standalone verifier across subprocess boundaries;
hand-built fixtures alone are not evidence that the production pipeline and portable verifier agree.

### G.8 Implementation delta — exported-range anchor binding (T-042)

Offline verification binds every anchor whose terminal sequence falls within the exported range to that
record's hash, not only the final anchor. For non-genesis exports, the complete anchor set must include the
anchor ending immediately before the range, and its signed `head_hash` must equal the first exported record's
`prev_hash`; the bundle may not establish its own left edge. Export checkpoints remain unsigned derived
indexes for parallel verification and must be labelled as performance aids, never listed as independent
evidence in a successful verdict.

### G.9 Implementation delta — provider seam and dated I-11 waiver (T-033)

Anchoring now calls an `AnchorProvider.attest(anchor_payload)` seam selected by
`MIZAN_ANCHOR_PROVIDER`. The only T-033 implementation is `development-unattested`; it adds an
`attestations[]` entry whose type is `none_development`, status is `unattested`, authority is
`development`, and evidence/time are null. Unknown provider names fail construction and cannot silently
fall back. The offline verifier rejects missing/mislabelled attestation state and prints `UNATTESTED` for
this provider.

Accordingly, I-11 carries a dated 2026-08-25 waiver: runtime append-only controls are achieved, but rewrite
resistance outside the database administrative boundary is conditional and **not achieved** by the
development provider. T-036 alone may lift the waiver after RFC 3161 tokens verify offline against an
operator-supplied trust root. This seam makes no custody decision and supplies no real attesting authority.

### G.10 Implementation delta — custody and additive key history (T-025)

The ratified G.1 contract is implemented by a four-role `KeyProvider`: a development-only local adapter and
a vendor-neutral KMS/HSM sign-in-place adapter whose backend never exposes private material. The roles are
`evidence-receipt`, `evidence-anchor`, `execution-token`, and `degraded-grant`; active references must be
distinct. Startup refuses development custody or any `local://` reference in production.

`GET /v1/audit/keys` publishes the additive verification history with role, algorithm, public bytes,
validity window, and revocation time, and export bundles preserve those same documents. Rotation selects a
new active key ID only for new signatures. Providers expose no re-sign operation, expired/revoked versions
remain published, and the verifier distinguishes cryptographic validity under a revoked key from an
unqualified pass or signature failure. Cloud-vendor selection remains a deployment decision.

### G.11 Implementation delta — external timestamp verification (T-036)

The T-033 I-11 waiver is lifted for production. `Rfc3161AnchorProvider` writes a pending attestation carrying
only the SHA-256 digest of the canonical anchor core, and its worker exchanges an RFC 3161 query with the
configured TSA. Pending age beyond `MIZAN_ANCHOR_ATTESTATION_MAX_PENDING_SECONDS` opens the evidence breaker;
pending output is never called externally anchored. Multiple TSA entries and additive customer
countersignatures are representable in `attestations[]`.

Completion never mutates the signed anchor. Final RFC 3161 tokens and customer countersignatures are written
to the append-only, tenant-scoped `anchor_attestations` sidecar and exported beside the original signed
payload. Assurance is calculated per anchor and the stream takes the weakest result; a mixed stream is never
described as externally anchored. The standalone verifier derives that result only after OpenSSL validates
each RFC 3161 token against operator-supplied trust roots, and rejects any stronger manifest claim.

Offline verification invokes RFC 3161 token validation against trust roots supplied by the operator, checks
the token's message imprint against the independently recomputed anchor digest, and prints the roots used.
Assurance is derived only from successfully validated tokens. The manifest assurance block is merely a claim
under test; any claimed/derived mismatch fails verification. Development remains explicitly unattested and
does not satisfy the production form of I-11.

### G.12 Implementation delta — retryable timestamp attempts (T-055)

The append-only `anchor_attestations` sidecar stores outcomes, not attempts. A validation or transport failure
does not write a `pending` sidecar: the signed anchor payload already supplies the durable pending state, so
leaving the outcome slot empty preserves retryability and keeps the anchor visible to the pending-SLO breaker.
The worker treats only `attested` sidecars as finalized, persists only an `attested` provider result, and counts
only that append as a completion. Diagnostic attempt persistence is deliberately deferred rather than made
mistakable for assurance evidence; adding it later requires a separately keyed append-only relation.

### G.13 Implementation delta — refused attestation appends (T-057)

The append operation reports whether the immutable outcome row was inserted. A uniqueness conflict is
read back and classified semantically, never by JSON or token byte equality. A stored row is a benign
second witness only when its RFC 3161 token validates under the operator-configured roots, its imprint
equals the recomputed closed anchor-core digest, and its document authority matches the immutable slot.
A row that fails validation, commits to another imprint, names another authority, or is non-terminal
opens the named `anchor_attestation_integrity` event and is never counted as completion. Before any TSA
request, a worker takes a transaction-scoped PostgreSQL advisory lease keyed by tenant and anchor,
confirms the anchor remains visible under RLS, and refreshes its sidecars under that lease. Acquisition
is non-blocking. A losing worker therefore neither spends nor discards a token, and the application role
does not need an `UPDATE` grant on the immutable anchor table.
Recovery remains additive; implementations must not update, delete, or upsert the occupied evidence row.

### G.14 Implementation delta — unverifiable is not invalid (T-051)

The standalone verifier exits with `CANNOT CHECK` and a distinct status when the operator's OpenSSL
runtime is missing, cannot execute, or lacks RFC 3161 support. It must not label evidence invalid in
that condition. Bad signatures/tokens, imprint mismatch, an untrusted signer, and an expired TSA
certificate remain evidence failures and are reported as distinct causes. Successful external
assurance is never printed when the RFC 3161 check did not run.

### G.15 Pending ratification (B-14) — location-scoped attestation grammar (T-059)

G.2's flat status enum is narrowed descriptively by persistence location. The signed anchor payload is
created before external contact and admits `pending` for `rfc3161` and `customer_countersignature`, or
`unattested` only for `none_development` under authority `development`. The append-only sidecar stores
validated outcomes and admits only `attested` for an external type. `failed` is reserved vocabulary and
MUST NOT occur in a bundle version 1.0; failed attempts leave the sidecar slot empty and retryable. A
location/type/status violation is `MALFORMED`, distinct from invalid evidence and from `CANNOT CHECK`.
This forbids no state emitted by the implementation. The narrowing remains pending HUMAN ratification
under B-14 and silence does not ratify it.

### G.16 Implementation delta — attestation enforcement runner (T-052)

`mizan-attest-anchors` polls a named tenant stream every 30 seconds by default (or once under an
external scheduler), completes pending RFC 3161 sidecars, and evaluates pending age on every pass
before attempting the TSA. A breach opens a named evidence breaker even if the TSA has recovered;
authorization remains available because attestation stays off its hot path. Transport failures are
limited to `OSError`; programming and contract errors terminate the runner instead of being hidden as
availability faults. A week-long outage therefore produces an explicit breaker-open operational
signal while exports continue to state `pending`, never externally anchored.

### G.17 Normative evidence-bundle format (T-059)

`docs/spec/EVIDENCE-BUNDLE-FORMAT.md` is the normative, implementation-independent definition of
bundle version 1.0. In particular it fixes the anchor core as the closed projection excluding exactly
`attestations`, `object_key`, and `object_version`, followed by RFC 8785 JCS and SHA-256. The committed
conformance corpus is the machine-readable compatibility contract; producer and verifier code are
implementations of this format rather than its source of truth.

### G.18 Implementation delta — explicit key custody (T-053)

Custody, not URI naming, controls production eligibility. `LocalKeyProvider` always has
`development-derived` custody and refuses every production construction regardless of its key IDs.
Published key documents carry required `custody` in `{development-derived, kms, hsm}`; KMS/HSM adapters
receive that value explicitly rather than deriving it from a reference string. Offline verification
reports publicly derivable development custody as forgeable even when every signature is valid.

### G.19 Implementation delta — publication is a process, not a side effect of a request (T-074)

Every amendment above describes publication as asynchronous, and until T-074 nothing performed it
asynchronously. `OutboxPublisher.drain` existed and was only ever called by a test that stood up its
own publisher, so a deployed control plane wrote evidence rows that nothing at rest turned into
receipts. That is not a slow publisher; it is no publisher, and the symptom it produces is remote
from its cause: a financial write refusing on `immutable_receipt_missing` (I-25) with nothing in the
logs connecting the refusal to the absent process. `mizan-drain-outbox` is that process.

Four properties are normative for any drainer, not just this one.

**Failure is isolated to a stream.** A segment that cannot be published has its attempt count
raised and is retried; the other streams in the same batch still publish. Draining a batch as one
unit means one unpublishable record holds every other tenant's evidence behind it.

**Nothing is dropped, and nothing stuck is allowed to mask the alarm.** A row that exceeds
`MIZAN_OUTBOX_MAX_ATTEMPTS` is quarantined: excluded from the head of the batch and from the
publication-lag measurement, never deleted, and reported through the evidence breaker under
`outbox_poisoned`. The lag SLO exists to be alarming when it breaches; a permanently stuck row
pinning it above threshold would retire the one signal that matters.

**Backpressure runs toward the work.** A saturated batch means the backlog is growing faster than
one batch per interval, so the drainer returns immediately instead of sleeping. The bound on that
is fairness — one busy tenant may not starve another tenant's publication SLO — not throughput.

**Events without receipts are still published.** SPEC §4 approval, policy, agent, execution and
security events have external subscribers and no evidence receipt, and `drain` has always ignored
them. They were written, counted against the lag, and delivered to nothing. The drainer now relays
them to the delivery sink and stamps them, at-least-once: the sink is called before the row is
marked, because a duplicated SIEM event is recoverable and a silently dropped one is not.

Tenants are configured (`MIZAN_DRAIN_TENANTS`), never discovered. `mizan.tenants` carries FORCE ROW
LEVEL SECURITY keyed on the current tenant, so a process able to enumerate tenants would already
have crossed the boundary ADR-005 exists to hold. The cost is real and is recorded as blocker
B-19: a tenant absent from the drainer's configuration is never published and never swept, and
nothing in the system currently notices.
