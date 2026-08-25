# ADR-002: Policy Engine Implementation (In-App Engine vs. OPA/Cedar Sidecar)

**Status:** ACCEPTED
**Deciders:** Product/Architecture Lead, Cybersecurity Architect
**Date:** 2026-08-25
**Spec anchors:** SPEC_v1 §2.2 (Policy), §3 (`/v1/authorize`, `/simulate`), §5.4, §7 (p95 < 50 ms), Invariants I-7, I-8

## Context

The PRD (§40) mandates an "OPA/Cedar-style policy architecture" with a business-friendly authoring layer above it (§89: human-friendly YAML compiled to Cedar/Rego/AST). The backend is Python/FastAPI; pure-Python policy evaluation risks the 50 ms p95 and 500–1000 dec/s targets. The engine must produce **explainable** decisions (every ADR_Record needs `reasons[]` and exact policy versions) and support **simulation** (PRD §90) and **versioning** (PRD §91).

Key forces:

- Latency: policy evaluation is on the hot path of every agent action.
- Explainability: banking auditors need "which condition matched," not just allow/deny.
- Determinism: same context + same policy set ⇒ same decision, always (needed for simulation parity and evidence integrity).
- Neutrality: customers shouldn't need to learn Rego (PRD §89).

## Options Considered

1. **Cedar via in-process bindings (`cedar-py` / Rust FFI).** Formally verified language, fast (<1 ms typical), policy-as-data, native "forbid overrides permit" semantics matching our most-restrictive-wins rule.
2. **OPA as a sidecar/daemon (Go), queried over localhost gRPC/HTTP.** Mature ecosystem, but adds ~1–5 ms IPC per call, a second deployable, and Rego's explainability story requires extra work.
3. **Custom in-app Python AST evaluator.** Full control, easiest to explain decisions, no FFI; but we own correctness, performance, and language design forever — a known trap (PRD §56 spirit: don't rebuild solved infrastructure).

## Decision (proposed)

**Two-layer architecture, Option 1 as the default engine:**

- **Authoring layer (Mizan Policy DSL):** the YAML/JSON condition tree from SPEC §2.2 — this is the *only* format customers touch, and the only format stored as source of truth (`content_hash` computed here).
- **Evaluation layer:** compile the DSL to **Cedar**, evaluated **in-process** via Rust bindings inside the authorization service. Compiled artifacts are content-addressed (`compiled_ref`) and cached in Redis + process memory with version-pinned invalidation on `mizan.policy.transitioned`.
- **Escape hatch:** the compiler interface is engine-neutral (`compile(policy) -> engine_artifact`), so an OPA sidecar backend (Option 2) can be added for customers who standardize on OPA, without changing the authoring layer.
- Decision combination: evaluate all matching policies; combine per SPEC §2.2 priority + most-restrictive-wins; attach per-policy match explanations to `reasons[]`.
- **No matching ACTIVE policy is unconditionally DENY.** This is not tenant-configurable. Its evidence uses `decision_basis=default_deny` and `policies=[]`; therefore default-deny does not require inventing a synthetic policy record (SPEC V-15).

## Consequences

- (+) Sub-millisecond evaluation keeps the 50 ms budget for context assembly, risk scoring, and ADR persistence.
- (+) Cedar's formal model gives free analyzability (future: policy conflict detection, permission-graph queries).
- (+) DSL-as-source keeps auditors and architects in one readable format; simulation and production share one compiler path (zero drift).
- (−) Rust FFI in a Python service complicates the build (wheels, CI matrix) — owned by the Claude Code lane, see AGENT_ALLOCATION.
- (−) Cedar can't express arbitrary computation (e.g. velocity checks); those live in the risk engine and enter policies as context fields — this boundary must be documented to prevent DSL sprawl.
- (~) If Cedar bindings prove immature for a needed feature, fall back to Option 2 behind the same compiler interface; the DSL contract makes this reversible.

## Compliance Mapping

| Framework | Mapping |
|---|---|
| NIST AI RMF | GOVERN 1.4 (policies enforced technically), MANAGE 1.3 (risk-based response) |
| ISO/IEC 42001 | A.6.2 (AI system lifecycle controls), A.8 (documented operational rules) |
| OWASP Agentic AI | Mitigates #2 excessive permissions, #3 tool misuse via explicit deny-by-default policy gates |
| Auditability | Policy `(id, version, content_hash)` pinning in ADR_Records satisfies "which policy version applied on date X" (PRD §91) |

## Open Questions

- [x] Benchmark: `cedarpy` 4.8.7 immutable `PolicySet` measured 6,896 eval/s with p99 0.1741 ms on the M3 Max development host (5,000 iterations, 2026-08-25). The RLS-scoped policy lookup + evaluation integration gate is independently constrained below 50 ms p99. Re-run `make benchmark-policy` on deployment-class Linux before production sizing.
- [x] Deny-by-default semantics: resolved as unconditional DENY in SPEC v1.2; not tenant-configurable.
- [ ] Where do CONSTRAIN/REDACT obligation payloads live in Cedar output (annotations vs. wrapper)?

## Implementation Amendment (2026-08-25)

Each Mizan policy compiles to an independent Cedar `permit` policy whose only purpose is to report whether that policy's condition tree matched. Mizan—not Cedar—then applies the frozen priority and decision-restrictiveness ordering across matches and carries the winning obligation payload. This avoids forcing six Mizan outcomes into Cedar's binary allow/deny result while retaining Cedar parsing, evaluation, diagnostics, and default-deny behavior. Parsed `PolicySet` handles are cached by canonical policy source; ACTIVE status and exact `(policy_id, version, content_hash)` remain part of the returned match evidence.

Policy simulations use this identical compiler after substituting only the lifecycle gate in memory;
the condition tree and semantic content are unchanged. Results are recorded in the tenant-RLS
`policy_simulations` relation so `DRAFT → TESTED` can prove at least one run. Simulation never emits
an ADR_Record or a decision event because it authorizes no action.

### Runtime parity clarification (2026-08-25)

Production authorization and simulation both apply `applies_to` selectors before compiling the
condition tree. The selector inputs are the registry-enriched tool risk tier and the normalized
environment name; caller-provided security fields are not trusted as the tool's risk tier.

JSON fractional numbers are represented by Cedar's `decimal` extension in both policy literals and
evaluation context. Ordered comparisons compile to the decimal methods (`greaterThan`,
`greaterThanOrEqual`, `lessThan`, `lessThanOrEqual`) rather than Cedar's integer operators. Values
must be finite and exactly representable with Cedar's four-digit fractional precision; compilation
fails closed otherwise. Integer values continue to use Cedar `Long` operators.

### Semantic hash and lifecycle amendment (R-003, 2026-08-25)

`Policy.content_hash` commits to the RFC 8785 canonical policy document after excluding exactly
`content_hash`, `status`, `approver`, and `effective_from`. Those four governance fields may change
through the locked lifecycle transition endpoint without breaking historical ADR references. Any
other edit changes the semantic hash and therefore requires a new immutable policy version.

The registry enforces `DRAFT → TESTED → APPROVED → ACTIVE → SUPERSEDED → RETIRED`; TESTED requires
a recorded simulation, APPROVED requires a strongly authenticated human distinct from the author,
and activation records a UTC effective time while atomically superseding an older ACTIVE version.
Each transition verifies that the recomputed semantic hash still equals the stored hash and emits a
transactional outbox event for cache invalidation and audit processing.
