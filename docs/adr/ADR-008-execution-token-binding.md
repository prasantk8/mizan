# ADR-008: Execution Token Binding & Long-Running Execution Leases

**Status:** ACCEPTED (T-001/R-003 ratified in all required roles)
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

**Token = permission to start.** `ExecutionTokenClaims` (§2.10) binds `jti`, `tenant_id`, `decision_id`, `tool_id`, `parameters_hash`, `binding_profile`, `context_hash`, and optional `approval_epoch_id` (so an approved action is bound to the epoch that actually granted it). TTL comes from `Tool.execution.token_ttl_seconds` (default 300, overridable per policy) — named configuration, not a constant in code.

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

## Implementation Amendment B — Strict claims and durable expiry

**Date:** 2026-08-25 · **Trigger:** completion audit found that signature-valid partial claims
could reach redemption as unhandled lookup failures, and expiry evidence was rolled back with the
HTTP error · **Spec anchors:** SPEC v1.2 §2.10–§2.12, I-10, I-23

The issuer validates the complete `ExecutionTokenClaims` JSON Schema before signing, and the
gateway validates the same closed schema after JWT cryptographic, issuer, audience, and time
checks. Missing, mistyped, wrongly prefixed, or unknown claims fail as a controlled 403. For
approved actions, redemption also reloads the Approval and requires the token's
`approval_epoch_id` to still be the current executable epoch. Every implemented context binding is
revalidated alongside it.

Detecting an expired lease is a state transition, not merely an error response. The service commits
`LEASE_EXPIRED` and its DecisionEvent first, then returns the controlled conflict to the caller, so
the operational state and immutable evidence cannot be rolled back by exception handling.

## Amendment C — Ratified transient arguments and revalidation snapshot

**Date:** 2026-08-25 · **Trigger:** ratified R-003/B-8 · **Spec anchors:** SPEC v1.3 §2.4,
§3.1, I-9, I-14

Authorization accepts bounded transient `tool.arguments` (64 KiB canonical bytes, depth 16, 256
total keys, finite JSON numbers). The server validates pointer classification and computes the bound
subset hash. Raw arguments are removed before context hashing and never enter policy evaluation,
ADR evidence, logs, or operational storage.

## Amendment D — v1 refuses unimplemented decision outcomes

**Date:** 2026-08-25 · **Trigger:** ratified R-004/B-10 Option A · **Spec anchors:** SPEC v1.3.1
§0 rule 2, §2.10, §5.1

v1 issues capabilities only for `ALLOW` and completed approvals. A winning `CONSTRAIN`, `REDACT`,
or `ESCALATE` policy outcome is persisted as a schema-valid DENY ADR_Record and returned as HTTP 501
`NOT_IMPLEMENTED`. No constraint is silently discarded, and the token no longer contains the dead
optional `constraints_hash` claim or pretends to revalidate a field ADR_Record cannot contain.
Constrained execution, including an executor-side enforcement contract, remains T-028/v1.4.

## Amendment E — issuance identity parity and bounded replay evidence

**Date:** 2026-08-25 · **Trigger:** R-004 F-3/F-7/F-10 · **Spec anchors:** SPEC v1.3.1
§2.6, §2.10, §8, I-23, V-17

Capability issuance receives the verified workload SPIFFE identity and requires exact membership in
the tool version's `executor_spiffe_ids`; it never selects array element zero. Redemption applies the
same membership contract, so a second registered executor is first-class while an outsider fails at
both boundaries. Missing or malformed historical delegation objects produce controlled 403 denial.

Replay evidence retains its separate-transaction durability but uses a dedicated pool bounded by
`MIZAN_SECURITY_EVENT_POOL_MAX_SIZE` and
`MIZAN_SECURITY_EVENT_POOL_TIMEOUT_SECONDS`. Saturation increments `security_event_pool_timeout` and
emits an error rather than waiting on, or consuming, the primary execution pool. This deliberately
prefers an alertable missing replay event over a pool-wide deadlock; the token itself remains denied.

The exact normalized context used for authorization—without raw arguments—is persisted atomically in
the immutable, tenant-RLS `authorization_contexts` relation and bound by the same `context_hash` as
the ADR_Record. Redemption requires the arguments again, recomputes the hash using the pinned profile,
and reruns current authoritative agent/tool/resource/risk enrichment against this snapshot. This is
the replayable basis for detecting execution-time drift without retaining raw tool payloads.


## Implementation Amendment — one capability per decision *(pending ratification: B-16)*

**Date:** 2026-08-27 · **Trigger:** Stage 5 acceleration review, T-067 · **Spec anchors:** SPEC v1.3 §3 `/v1/decisions/{id}/execution-token`, V-21, V-23

`ExecutionService.issue` had no caller outside tests, so no route turned an ALLOW or an APPROVED
approval into the capability that ADR-008 binds. `POST /v1/decisions/{decision_id}/execution-token`
is that route, with three properties chosen as the B-16 default:

- **Only the decision's own agent principal may ask.** The requester is taken from the identity
  token and compared to the `agent.id` the ADR_Record names; a mismatch is 403
  `execution_token_requester_mismatch`. Nothing in the request body selects the principal.
- **At most one unconsumed, unexpired token per decision.** A repeat request returns the
  outstanding capability rather than granting a second one, so an ALLOW cannot be spent twice by
  asking twice. Issuance is serialized per decision by a transaction-scoped advisory lock —
  `mizan.adr_records` is append-only and the runtime role holds no `UPDATE` privilege on it, so a
  row lock is not available and must not be reached for.
- **The executor is registry-chosen (V-21).** A caller may name one of the tool version's
  registered `executor_spiffe_ids`; naming anything else is 403, and a tool with several
  registered executors and no named choice is 422 rather than an arbitrary pick.

Idempotency requires that re-encoding stored claims reproduce the original token byte for byte.
Claims come back from JSONB in PostgreSQL's key order, not the order they were written, so the
custody-agnostic signing path canonicalises the JWS payload with RFC 8785 before signing. That
path exists because a KMS or HSM key never leaves its provider: only the signing input crosses the
boundary, which is the seam T-076 needs.

## Implementation Amendment — an authorization is not a permission to act

**Date:** 2026-08-27 · **Trigger:** Stage 5 acceleration, T-070 live gate · **Spec anchors:** SPEC v1.3 §5.4, §8.1, I-25

The MCP Governance Gateway is the first shipped ADR-008 executor that is not a test. Standing it
up against a running control plane surfaced two things this ADR had left implicit.

**A refused capability must refuse the call.** The gateway's first shape treated a failure to
obtain the execution token as a degradation: it recorded the decision, dropped the lease, and
forwarded the call anyway. That is wrong and it was the only fail-open path in the component. An
`ALLOW` says the decision is permitted; the capability says *this* execution, by *this* executor,
on *these* bound arguments, is permitted now. The control plane can and does refuse the second
after granting the first — a delegation edge withdrawn, an executor no longer registered, an
approval receipt not yet durable. An executor that cannot obtain a capability has not been
authorized to act, and must not act. The gateway now returns
`execution_binding_unavailable` and the tool server never hears about the call.

**Arriving before the publisher is not being refused.** I-25 requires a financial write's
ADR_Record and approval evidence to be durably published before redemption, and publication is
asynchronous by design (ADR-004). An executor that redeems within milliseconds of an approval will
therefore see `immutable_receipt_missing` — a statement about *when*, not *whether*. Executors
retry exactly the three publication-pending codes for a bounded window
(`execution_binding_retry_seconds`, default 15s) and treat every other refusal as final on the
first answer. Retrying anything else would convert a denial into a poll.

Neither property changes the control plane. Both are obligations on anything that redeems a
capability, and belong here rather than in the gateway, because the next executor will need them
too.

## Implementation Amendment — a lapsed lease lapses without being asked (T-074)

Amendment A states that a lapsed lease "becomes `LEASE_EXPIRED` and emits an event; it does not
silently become an untracked running job." Until T-074 it did exactly that. The only writer of
`LEASE_EXPIRED` was `_transition_lease`, reached when an executor called `heartbeat` or `complete`
— so a lease whose executor crashed, was killed, or simply never came back stayed `LEASED` forever.
The lease was untracked and the row said it was running.

The expiry sweeper reaches the state at rest, through `save_lease_tx` — the same write the
redemption path performs, promoted to module level rather than copied, because two writers with two
shapes for one row is how a state machine acquires a second opinion. It emits the `LEASE_EXPIRED`
DecisionEvent and the `mizan.execution.lease_expired` outbox row (SPEC §4, previously emitted by
nothing) in that same transaction, and re-checks state and deadline under the row lock so an
executor completing between scan and write keeps its result.
