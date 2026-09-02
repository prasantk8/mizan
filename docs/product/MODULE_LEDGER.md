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

Last verified 2026-09-02 against the WS-2 branch, rebased on `main` @ c1ebb21 (T-120..T-128 merged;
the cross-product section re-verified against the code in that branch, not against the plan). This
table is checked by hand; where a row says "unwired", it was confirmed by searching for callers
outside `tests/`, not assumed.

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
| Redaction / DLP attestation | `security/mizan_security/redaction.py`, and `EvidenceRepository.append_audit` (`control-plane/mizan_control_plane/evidence.py:453`) | **unwired at both ends, and blocked** — the module, the repository method that enforces its attestation, and their tests all exist; neither has a production caller (`append_audit`'s only caller in the tree is `tests/integration/test_authorize_postgres.py`). Wiring is **not** the remaining work: the audit commitment key `MIZAN_AUDIT_HMAC_KEY_REF` has a full contract and no custody (T-054, TM-001 R-2), and giving it custody is a contract change to ADR-004 G.1's ratified four `KeyRole`s — an HMAC key has no `public_key()`, which the `SigningKey` protocol requires. Filed as **B-30** (H-7, key management). Deleting is not the cheap alternative either: invariants **I-12/I-18/I-19** and SPEC §2.5's required `AuditTrail` members would be left unimplemented, which is a §0 change |
| PII classification boundary | none | **none** — the former `security/pii/` contained one sentence |
| Prompt-injection defence | `tests/adversarial/test_prompt_namespace.py` proves the *policy namespace* cannot be crossed by tool arguments | **none as a module** — the property is tested, there is no engine |
| Behavioural analytics | none | **none** |
| Threat engine | none | **none**. Threat *models* are real documents: TM-001 for the control/evidence plane and a pre-implementation TM-002 skeleton for the Memtara seam |

## Integrations

| Claim | Backed by | Status |
|---|---|---|
| MCP governance gateway | `integrations/mcp/mizan_mcp_gateway/` (`server.py`, `governance.py`, `upstream.py`, …) | shipped |
| External payload envelopes | `integrations/mizan_integrations/external_payload.py` | wired, unproven |
| Memtara proof verification / evidence seam | see the Cross-product section below; TM-002 fixes the trust boundary | row-by-row there — this table must not answer the same claim twice |
| Kafka, Redis, IAM, SIEM, workflow | none | **none**. Evidence leaves through `mizan.outbox` and the drain worker; there is no broker or SIEM delivery |

## Cross-product (added 2026-08-31, per the two-product decision)

| Claim | Backed by | Status |
|---|---|---|
| Mizan verifies a Memtara proof token (Ed25519 JWS against Memtara's JWKS) | `proofs/memtara.py`, called by the `/v1/authorize` header boundary in `app.py`; adversarial and route tests in `tests/unit/test_memtara_proof.py` and `test_app_routes.py` | **shipped, with one stated limit** — deployment-pinned issuer and JWKS, bounded token parsing, tenant-scoped `jti` replay refusal (T-133). The replay set is **per process** (`JtiReplaySet` is an in-memory dict): under multiple workers or replicas one `jti` is replayable once per process, so replay defence is not yet a deployment-wide guarantee. The JWKS is fetched once and never refreshed, so a Memtara key rotation is an outage until restart |
| A Memtara proof gates a Mizan decision | Typed `MappedInput` projection in `proofs/memtara.py`; field-to-field Cedar binding in `policy_engine.py`; `policies/reference/require_suitability_proof.json`; policy and authorization tests | **shipped** — suitability decline is a normal evidence-bearing DENY (T-134) |
| One evidence bundle carries the Mizan decision and the Memtara proof / chain head | `external_proofs[]` in `ADR_Record` 1.3 (`service.py`), inside the hashed body so the record hash, receipt and anchor commit it; bundle format 1.1 in `docs/spec/EVIDENCE-BUNDLE-FORMAT.md` §2.1; both verifiers check grammar, signature and claim binding; corpus built by `scripts/build_memtara_fixtures.py` | **shipped** — CI job `offline-evidence-verifier` asserts VALID with the operator's Memtara keyset, CANNOT CHECK without it, INVALID on a re-signed `proof_hash` tamper and MALFORMED under a 1.0 manifest, **each verifier separately** (T-135). The chain head is recorded but not authenticated: current Memtara tokens do not sign it, so completeness of Memtara's history still needs M-04 |
| The SDK and the MCP gateway carry a proof without reading it | `sdk/python/mizan/client.py` and `decorator.py` place the token on a header only, never in the JSON context; `integrations/mcp/mizan_mcp_gateway/server.py` forwards the client's `x-memtara-proof` metadata opaquely | **shipped** — the gateway performs no parse, log, or upstream forward of the token; the negative is asserted in `tests/unit/test_sdk.py` and `test_mcp_gateway.py` (T-136) |
| One command runs the whole two-product journey, with a backup transcript | `scripts/demo_memtara_walk.py` behind `make demo-memtara`, wrapped by `scripts/demo.sh` for the export and both verifiers; `tests/fixtures/demo_memtara/transcript.txt` | **shipped** — the transcript is a recording of a real journey, re-derived against fake Memtara and Mizan edges on every run and compared, so a renamed, reordered or dropped milestone goes red (T-137). The live run needs a running Memtara from its own quickstart; only the walk is recorded, not the export and verifier steps around it |
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
