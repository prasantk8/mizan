# ADR-008: Execution Token Binding & Long-Running Execution Leases

**Status:** DRAFT
**Deciders:** Product/Architecture Lead, Cybersecurity Architect
**Date:** 2026-08-25
**Spec anchors:** SPEC v1.2 §2.6 (`Tool.binding_profile`, `Tool.execution`), §2.10 (token claims), §2.11 (ExecutionLease), §2.12 (DecisionEvent), §5.5, Invariants I-10/I-14/I-23/I-25, V-8/V-9/V-13/V-17/V-20
**Trigger:** baseline review R-001 — token bound to unstable or absent data; hard-coded 300 s TTL conflates start-time with duration

## Context

v1.0 bound the single-use execution token to `(decision_id, tool_id, parameters_hash)` with a fixed 300-second TTL. `parameters_hash` was nullable and described as "SHA-256 of the exact tool arguments". Both halves fail.

**Binding.** If "exact arguments" includes a timestamp, nonce, trace or session id, presigned URL, or retry counter, then a legitimate retry — the same business action, resent — produces a different hash and is denied. Agents will then either strip fields until it works or stop using the token. If `parameters_hash` is null, different argument sets share the same binding and the anti-drift guarantee evaporates; the implementation has to invent an unstated rule, and two implementations will invent different ones.

**Timing.** 300 seconds is a reasonable *time to start* and a useless *time to finish*. A KYC document extraction or a batch rebalance may run for forty minutes. Making the token live that long widens the replay window for every fast action to fit the slowest one; keeping it short means long jobs cannot be authorized at all.

## Options Considered

1. **Semantic binding profile + token/lease split:** hash a declared subset of stable arguments; redeem the token atomically for a heartbeated lease.
2. **Hash everything, lengthen the TTL.** Breaks retries and widens replay simultaneously.
3. **Hash nothing (bind only decision + tool).** Permits parameter substitution after authorization — the confused-deputy attack the token exists to prevent.
4. **Re-authorize on every retry.** Correct-ish but doubles authorization load, and a network-timeout retry then produces two ADRs for one business action, corrupting the evidence count.

## Decision (proposed)

Adopt **Option 1**.

**Binding profile (per tool, versioned, immutable).** `Tool.binding_profile` declares `bound_pointers` (stable, semantically meaningful arguments: payee, amount, account, scope, document id) and `volatile_pointers` (explicitly excluded: nonces, timestamps, trace/session ids, presigned URLs, retry counters, idempotency keys). `parameters_hash` is the RFC 8785 canonical hash over the **bound subset only**, and it is required, never nullable. Arguments matching neither list follow `unknown_pointer_policy`, default **`reject`** — an unclassified argument may be policy-relevant, so the safe reading is to refuse rather than to ignore. Profiles are published as immutable versions (`/v1/tools/{id}/binding-profile`), and the token carries `(profile_id, profile_version)` so a profile change cannot retroactively alter what an outstanding token means.

The result is the property that makes this usable: **a retry that changes only volatile fields still redeems; a change to any bound field never does** (I-14).

**Token = permission to start.** `ExecutionTokenClaims` (§2.10) binds `jti`, `tenant_id`, `decision_id`, `tool_id`, `parameters_hash`, `binding_profile`, `context_hash`, optional `approval_epoch_id` (so an approved action is bound to the epoch that actually granted it), and optional `constraints_hash`. TTL comes from `Tool.execution.token_ttl_seconds` (default 300, overridable per policy) — named configuration, not a constant in code.

**Lease = permission to continue.** Redemption is a single transaction that CASes `jti` from unconsumed to consumed **and** creates an `ExecutionLease` (V-13). The lease carries `lease_ttl_seconds` (default 900), `heartbeat_interval_seconds` (default 60), and `max_extensions` (default 24), bounding total execution at `lease_ttl × (1 + max_extensions)`. A lapsed lease becomes `LEASE_EXPIRED` and emits an event; it does not silently become an untracked running job.

**Retries are idempotency, not re-authorization.** A repeated `idempotency_key` against the same lease returns the *existing* lease. One business action produces one ADR and one lease regardless of transport-level retries, which keeps the evidence count honest.

## Consequences

- (+) The anti-drift guarantee survives contact with real networks: retries work, substitution does not.
- (+) A forty-minute job needs a 300-second token, not a forty-minute one — the replay window stays small for everything.
- (+) Leases make in-flight executions observable; a hung tool is a visible expired lease rather than an ADR stuck in `EXECUTING` forever.
- (+) Profiles are reviewable artefacts: "which arguments were authorization-relevant for this tool in March" is answerable from the version.
- (−) Every tool now needs a binding profile before it can be registered. `unknown_pointer_policy: reject` means an incomplete profile fails loudly at integration time — deliberate, but it is real onboarding friction, and the SDK must generate a draft profile from the tool schema or teams will list everything as volatile.
- (−) Two new lifecycle objects (token, lease) on the execution path, plus heartbeat traffic proportional to concurrent long-running jobs.
- (−) A mis-scoped profile is a genuine security hole: an argument wrongly marked volatile becomes substitutable after authorization. Profile changes are therefore CLAUDE-lane with security review, and `bound_pointers ∩ volatile_pointers = ∅` is enforced (V-8).
- (~) Nested/dynamic argument structures need pointer discipline; wildcard pointers are deliberately not supported in v0.1 — enumerate or reject.

## Compliance Mapping

| Framework | Mapping |
|---|---|
| NIST AI RMF | MANAGE 2.2 (control of AI actions), MEASURE 2.7 (traceability of executed actions) |
| ISO/IEC 42001 | A.6.2.6 (operational control), A.9.2 (oversight of automated action) |
| OWASP Agentic AI | #3 tool misuse, #6 intent/context drift between decision and execution, #9 replay |
| Banking controls | Payment instruction integrity between authorization and settlement |

## Open Questions

- [ ] Should `bound_pointers` support a wildcard/subtree form for tools with dynamic payloads, or is enumerate-or-reject sustainable past ~20 integrations?
- [ ] Lease extension authority: may the executing agent extend indefinitely up to `max_extensions`, or should extensions past N require a fresh risk check?
- [ ] Do we expose an SDK helper that computes `parameters_hash` client-side from a fetched profile (ergonomic, but the client then chooses the canonicalization — recommend server-side verification always recomputes)?

---

## Amendment A — Capabilities bind the executor, not only the action

**Date:** 2026-08-25 · **Trigger:** baseline review R-002 — a same-tenant workload could redeem another agent's otherwise valid capability · **Spec anchors:** SPEC v1.2 §2.10–§2.12, I-23, V-17

The execution token additionally binds `tenant_id`, `agent_id`, `principal_id`, `delegation_chain_hash`, and `authorized_executor` (a SPIFFE workload identity). Each Tool version carries a reviewed `execution.executor_spiffe_ids` allowlist; the authorization server selects exactly one executor from it, and callers cannot propose or override the value. It has fixed audience `mizan-execution-gateway`; issuer, algorithms, and verification keys come from deployment allowlists, never from token-controlled selection. Redemption verifies all identity bindings against current authenticated context and agent status before atomically consuming `jti`.

The resulting lease copies `redeemed_jti`, agent, principal, and authorized executor. Heartbeat and completion authenticate the peer with mTLS and require the same executor identity. Knowledge of `decision_id` or `lease_id`, or possession of a capability issued to a different workload, is insufficient. Every issuance and lease transition appends a typed `DecisionEvent`, with only a hash of `jti` entering evidence so the bearer value is never logged.
