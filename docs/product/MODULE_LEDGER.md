# Module ledger — what is claimed, and what code backs it

**Purpose.** Until T-115 this repository carried twenty-three directories whose entire contents
were a one-line README describing a capability. `security/pii/README.md` read *"CLAUDE-owned PII
classification and protection boundary"* and there was no such code anywhere.
`control-plane/decisions/README.md` described the ADR and evidence work, which actually lives one
level up in `control-plane/mizan_control_plane/evidence.py`. A browsing design partner reads a
directory as shipped surface, and `scripts/validate_baseline.py` *required those directories to
exist* — a gate enforcing the roadmap rather than the product.

The directories are gone. This file replaces them, and it is deliberately harder to read
favourably: every row names the file that backs the claim, or says **none**.

**How to read the status column.**

| status | meaning |
|---|---|
| **shipped** | code exists, has a production caller, and is exercised by a test that would fail without it |
| **wired, unproven** | code exists and is reachable in production, but no test drives it end to end |
| **unwired** | code exists and **nothing in production calls it**. It cannot be relied on |
| **none** | no code. The claim is a roadmap item |

Last verified 2026-08-31 against `main` @ 837f934 (rows touched by T-101/T-102/T-104 re-verified;
cross-product section added the same day). This table is checked by hand; where a row says "unwired",
it was confirmed by searching for callers outside `tests/`, not assumed.

---

## Control plane

| Claim | Backed by | Status |
|---|---|---|
| Authorization decision path | `control-plane/mizan_control_plane/service.py`, `policy_engine.py` (Cedar), `risk.py` | shipped |
| Agent / tool / policy registry | `registry.py`, `app.py` routes, `schema_validation.py` against SPEC §3 | shipped |
| Approvals, epochs, quorum, ADR-007 guards | `approval.py`, `approval_repository.py` | shipped |
| ADR_Records, DecisionEvents, hash chains, outbox | `evidence.py`, `repository.py` | shipped |
| Execution tokens, leases, receipts gate | `execution.py` | shipped |
| Evidence publication and anchoring | `evidence.py::OutboxPublisher`, run by `drain_worker.py` | shipped |
| RFC 3161 attestation | `attestation.py`, run by `attestation_runner.py` | shipped |
| Lease expiry at rest | `execution.py::sweep_expired_leases`, run by `drain_worker.py` | shipped |
| Key custody and published keyset | `keys.py`, `vault_transit.py`, `runtime.py`, `/v1/audit/keys` | shipped for development and production Vault Transit (`custody=kms`); the real-Vault CI gate verifies sign/rotate/history behaviour |
| Durable immutable evidence store | `evidence.py::S3ObjectLockStore`, selected in `runtime.py`; `LocalImmutableObjectStore` remains the development analogue | shipped — Object Lock COMPLIANCE, retention default seven years, exercised live by CI job `evidence-object-lock` (T-104). The `evidence_export.py` CLI still reads the local store only |
| Production mode boots | `app.py` readiness branch under `MIZAN_ENV=production` | shipped — CI job `production-boot` (T-101). A single full-journey production gate does **not** exist yet (workplan T-131) |
| Identity-token key rotation | `auth.py` keyset with `kid` routing, `scripts/identity_key_rotation_drill.py` | shipped — overlap window and rotation drill (T-122) |
| Structured logs and `/metrics` | `observability.py`, `app.py` | shipped |
| Mutual TLS and peer SPIFFE identity | `mtls.py`, `runtime.py` protocol class | shipped |
| Degraded state / signed LOW-risk allow gate | `security/mizan_security/degraded.py`, called by `service.py` | **shipped for truthful healthy/fail-closed state**; the signed LOW-risk degraded-ALLOW gate remains default-off and has no production caller |

## Security

| Claim | Backed by | Status |
|---|---|---|
| Redaction / DLP attestation | `security/mizan_security/redaction.py` | **unwired** — the module and its tests exist; no production code path calls it |
| PII classification boundary | none | **none** — the former `security/pii/` contained one sentence |
| Prompt-injection defence | `tests/adversarial/test_prompt_namespace.py` proves the *policy namespace* cannot be crossed by tool arguments | **none as a module** — the property is tested, there is no engine |
| Behavioural analytics | none | **none** |
| Threat engine | none | **none**. Threat *models* are real documents: TM-001 for the control/evidence plane and a pre-implementation TM-002 skeleton for the Memtara seam |

## Integrations

| Claim | Backed by | Status |
|---|---|---|
| MCP governance gateway | `integrations/mcp/mizan_mcp_gateway/` (`server.py`, `governance.py`, `upstream.py`, …) | shipped |
| External payload envelopes | `integrations/mizan_integrations/external_payload.py` | wired, unproven |
| Memtara proof verification / evidence seam | none | **none** — TM-002 fixes the boundary, but T-133..T-138 have not shipped |
| Kafka, Redis, IAM, SIEM, workflow | none | **none**. Evidence leaves through `mizan.outbox` and the drain worker; there is no broker or SIEM delivery |

## Cross-product (added 2026-08-31, per the two-product decision)

| Claim | Backed by | Status |
|---|---|---|
| Mizan verifies a Memtara proof token (Ed25519 JWS against Memtara's JWKS) | `proofs/memtara.py`, called by the `/v1/authorize` header boundary in `app.py`; adversarial and route tests in `tests/unit/test_memtara_proof.py` and `test_app_routes.py` | **shipped** — bounded deployment-pinned verification and tenant-scoped replay refusal (T-133) |
| A Memtara proof gates a Mizan decision | Typed `MappedInput` projection in `proofs/memtara.py`; field-to-field Cedar binding in `policy_engine.py`; `policies/reference/require_suitability_proof.json`; policy and authorization tests | **shipped** — suitability decline is a normal evidence-bearing DENY (T-134) |
| One evidence bundle carries the Mizan decision and the Memtara proof / chain head | none; `docs/spec/EVIDENCE-BUNDLE-FORMAT.md` has no external-proof field, neither verifier knows one | **none** — workplan T-135, M-04 |
| Mizan delivers a `decision_id` to AIHOOTS | none, and none planned | **retired** — AIHOOTS is not a product (decision record §1) |
| Delegated / standing approvals (“approve once, run for 30 days”) | none; `ExecutionLease` is the opposite (single decision, minutes) and approvals are `UNIQUE (tenant_id, decision_id)` | **none** — workplan T-139, founder-gated |

## SDK and surfaces

| Claim | Backed by | Status |
|---|---|---|
| Python SDK | `sdk/python/mizan/` (`client.py`, `decorator.py`, `adapters.py`, `binding.py`) | shipped |
| TypeScript SDK | none | **none** |
| Java SDK | none | **none** |
| Approver console | `ui/` | wired, unproven — and it takes a pasted bearer JWT into a textarea and keeps it in `sessionStorage`. No IdP, no OIDC, no MFA step-up. Acceptable for a localhost demo, **not** for a pilot |
| Examples | none | **none**. `scripts/demo_walk.py` is the runnable end-to-end path; T-114 owns shipping real `examples/` |
| Policy bundles | none | **none**. Demo policies are seeded by `scripts/seed_demo.py` |

## Evidence and verification

| Claim | Backed by | Status |
|---|---|---|
| Offline verifier | `scripts/verify_evidence_export.py` | shipped |
| Independent second verifier | `verifier-two/` (JavaScript, zero dependencies, written from the spec under seal) | shipped |
| Both verifiers agree | `scripts/compare_verifiers.py`, gated in CI | shipped |
| Bundle export | `control-plane/mizan_control_plane/evidence_export.py` | shipped |
| Merkle inclusion / consistency proofs | none | **none** — T-038/T-039, deferred to CP-G |
| Decision replay | none | **none** — T-044..T-048, parked on B-13 |

---

## What this ledger does not do

It does not say whether a shipped module is *correct*, only that it exists and is called. It is a
map from claim to code, and its value is entirely in the **none** and **unwired** rows — those are
the ones a directory full of one-line READMEs was hiding.
