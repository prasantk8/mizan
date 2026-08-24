# R-001 — SPEC v1.0 Baseline Review: Disposition

**Date:** 2026-08-25 · **Reviewed artefact:** SPEC v1.0, ADR-001…005, WORK_LOG, AGENT_ALLOCATION
**Review verdict:** Readiness 3/10, Security Rigor 6/10, Implementability 4/10 — *"not safe to freeze; the invariants are stronger than the schemas and state machines capable of enforcing them."*
**Outcome:** accepted in substance. SPEC v1.1 supersedes v1.0; ADR-006/007/008 added; ADR-003 and ADR-004 amended; WORK_LOG H-1 replaced. v1.0 was never implemented, so no migration is owed.

The core criticism was correct and is worth keeping visible: **v1.0 asserted properties (I-1 evidence completeness, I-10 token binding, I-6 quorum integrity, I-12 redaction) that its own schemas and state machines could not enforce.** Every fix below closes the gap between an assertion and its enforcement point.

## Critical flaws

| # | Finding | Disposition | Where |
|---|---|---|---|
| 1 | `EvaluationContext` could authorize data that cannot produce a valid ADR (nullable `resource_owner`, `data_classification`; optional `delegation_chain`; nullable `parameters_hash`; Money without both fields; conditional Policy fields unenforced) | **Fixed.** Fields made required and non-null; added mandatory fail-closed enrichment (§3.1); `Policy` conditional requirements enforced with `if/then`; `Money` requires both fields; `approver_roles` gets `uniqueItems`; quorum bounded by V-2 at authoring time. New rule 0.7 and Invariant I-13 make representability a testable property. | SPEC §0.7, §2.2, §2.4, §3.1, I-13 |
| 2 | ID type safety disappeared at the authorization boundary (`pol_…` accepted as a `tool.id`) | **Fixed.** All IDs `$ref` typed `$defs` in §2.0; storage additionally enforces typed FKs on `(tenant_id, id)`. Prefixes documented as syntactic tags, not authorization. | SPEC §0.3, §2.0, I-16 |
| 3 | Approval escalation had undefined membership and race semantics; dual control counted role labels | **Fixed via new ADR-007.** Epoch model with immutable eligibility snapshots; `pool_mode` explicit with no default; `carry_forward_votes`; `reset_expiry`; votes cite `epoch_number` (stale → 409); dual control counts **control domains** and the recorded role comes from the snapshot, not client text. Review's correction accepted: the two-role double-vote attack does not work under G3 — the real defect was untrusted role text and label-counting. | SPEC §2.7, §5.2, G3/G4/G9, I-15; ADR-007 |
| 4 | Execution tokens bound unstable/absent data with a hard-coded 300 s TTL | **Fixed via new ADR-008.** Per-tool versioned binding profile (bound vs. volatile pointers, `unknown_pointer_policy: reject`); `parameters_hash` required; configurable `token_ttl_seconds` governs time-to-START; atomic redemption creates a heartbeated `ExecutionLease` governing duration; retries use an idempotency key against the existing lease. | SPEC §2.6, §2.10, §2.11, §5.5, I-14; ADR-008 |
| 5 | Audit correctness and workflow ownership were procedural, not enforceable | **Fixed.** Redaction: `stored_payload_hash` + **keyed** HMAC `source_commitment` + DLP attestation manifest; `scan_failed` rejects the write. Handoff: H-1 replaced with an atomic claim lease + CAS reclaim, plus a CI gate (authoritative, since local hooks are bypassable). | SPEC §2.5, I-12/I-18/I-19; ADR-004 Amendment A.2; WORK_LOG H-1/H-8 |

## Architecture paradoxes

| Paradox | Resolution |
|---|---|
| Closed internal contracts vs. uncontrolled MCP payloads | **ADR-006:** two-stage boundary — size-limited open envelope for capture, allowlisted versioned projection into `mapped.fields` for evaluation. Canonical schemas stay closed. Adapter failure = controlled tool error, never a service fault. Drift is telemetry (`mizan.integration.schema_drift`), not trust. |
| PII commitment vs. data minimization | **ADR-004 A.2:** keyed HMAC commitments (not bare hashes, which leak low-entropy PII to dictionary attack) + policy/version/hash + field manifest + DLP attestation + optional encrypted legal-hold evidence. Stated honestly: cryptography cannot prove an *unknown* sensitive field was recognised — that assurance comes from coverage profiles and regression corpora. |
| "Postgres for everything" vs. a globally ordered immutable chain | **ADR-004 A.1/A.3:** transactional outbox → Kafka (delivery only) → object storage + signed anchors (authoritative evidence). Sequence allocated inside the committing transaction against a locked chain head, so rollback leaves no gap; throughput from stream sharding, not from loosening the chain. Verification checkpointed so `/v1/audit/verify` is O(range). Dev harness: in-memory chain writer + golden vectors + containerized integration suite + 100k fixture — hash semantics are never mocked away. |

Also accepted: runtime `INSERT/SELECT`-only grants are **not** immutability against a DB owner or privileged operator. External anchoring is now mandatory rather than an enhancement, and I-11 says so explicitly.

## Missing configuration

All requested keys exist as schema fields or named configuration in **SPEC §8** (configuration registry) and **§9** (V-rules for cross-field constraints JSON Schema cannot express): `fail_open_allowed`, degraded-mode grants and ceilings, `execution_token_ttl_seconds`, binding profiles and volatile paths, lease TTL/heartbeat/extensions, approval epochs and carry-forward, `rejection_mode`, `override_policy`, redaction policy/key/retention/DLP fail mode, hash and canonicalization identifiers, anchor bucket and cadence, verify checkpoint interval, external payload ceiling. Rule 0.9 makes an unnamed magic number a spec violation.

`rejection_mode` deserves the explicit note the review asked for: `veto` remains the **default** because it is right for sanctions and fraud gates; `rejection_quorum` and `review_required` exist so that legitimate M-of-N business approvals do not get pushed into untracked out-of-band overrides.

## Recommended patch

Adopted verbatim as SPEC §10 (Evidence Pipeline, normative) and ADR-004 Amendment A, including the hard requirement that publication be atomic via outbox with idempotent consumers — never independent dual writes to Postgres and Kafka.

## Not adopted / deferred

| Item | Reason |
|---|---|
| Cancel-and-recreate approvals on escalation | Rejected in favour of epochs (ADR-007 Option 3): loses the audit thread and forbids legitimate carry-forward. |
| Wildcard/subtree binding pointers | Deferred (ADR-008 open question). v0.1 is enumerate-or-reject; revisit past ~20 integrations. |
| Merkle-tree transparency log | Still the evolution path, not v0.1 scope. Anchors become tree roots additively; record shape unchanged. |
| Raising degraded-allow above LOW risk | Not adopted. `risk_ceiling` is a schema constant; changing it is a HUMAN-lane decision requiring a new ADR. |

## Residual risk (stated, not solved)

- **Classification coverage** is a process guarantee, not a cryptographic one (ADR-004 A.2).
- **Completeness against a malicious sequencer** that drops records before chaining remains mitigated, not eliminated: client-visible `decision_id` receipts plus count reconciliation against the exported stream (ADR-004 original consequences, unchanged).
- **Binding-profile mis-scoping** is a real hole — an argument wrongly marked volatile becomes substitutable post-authorization. Mitigated by CLAUDE-lane ownership plus security review of profiles, not by the schema.
- **Control-domain mapping** must be supplied per tenant; until it is, dual control is only as strong as the tenant's role administration.
