# ADR-004: Audit Immutability & Hash-Chaining Strategy

**Status:** DRAFT
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

- [ ] Anchor cadence (records vs. time) and per-tier defaults.
- [ ] RFC 3161 TSA integration in enterprise tier — pilot requirement or later?
- [ ] Do we expose a customer-side verification CLI in v0.1 (recommended: yes, it demos brilliantly)?

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
