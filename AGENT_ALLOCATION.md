# Agent Tool Allocation Map — Mizan

Strict lane assignments for multi-agent development. Lanes are enforced by WORK_LOG hooks H-4/H-5. The controlling principle comes from PRD §68/§115: **AI-assisted development used aggressively; product/security decisions stay human-owned.**

## Execution-owner directive (2026-08-25)

The human owner has explicitly assigned **CODEX** as the sole implementation and test agent for the current build. The CLAUDE, CURSOR, and TEST labels below continue to describe the review rigor and merge gates a path requires; they do not reserve work for a particular product or vendor. CODEX may claim any non-HUMAN task and must apply the strictest gate named for that path. Product, approval-semantic, money-movement, cryptographic, key-management, and tenant-isolation decisions remain HUMAN-owned under H-7.

## Lanes

| Lane | Interface | Mandate | Merge gate |
|---|---|---|---|
| **CLAUDE** | Claude Code | Critical-path security & correctness code | Invariant suite green + human security review for crypto/authz/money paths |
| **CURSOR** | Cursor / Codex | Volume code: DAL, CRUD, UI, glue | Lint + tests green; must not touch CLAUDE-owned modules |
| **TEST** | Reasoning/test-gen models | Adversarial & property testing | Tests must map to SPEC invariants/guards; no production code |
| **HUMAN** | Founders | Decisions, ratification, review | — |

## Module Assignment (PRD §116 repo structure × PRD modules)

| PRD Module / Path | Lane | Scope & notes |
|---|---|---|
| `control-plane/authorization/` — `/v1/authorize`, decision combination, execution tokens (SPEC §3, §5.1) | **CLAUDE** | Hot path + security core. p95 50 ms budget owned here. |
| `control-plane/policies/` — Policy DSL, Cedar compiler, simulation, versioning (ADR-002, SPEC §2.2, §5.4) | **CLAUDE** | Compiler correctness is safety-critical; DSL grammar changes need ADR delta. |
| `control-plane/decisions/` — ADR_Record persistence, in-txn sequencer, outbox, object-store segments, signed anchors, `/v1/audit/verify` (ADR-004 + Amendment A, SPEC §2.3, §2.5, §10) | **CLAUDE** | Cryptographic audit trail. Canonicalization (RFC 8785), chain-head locking (V-11), and the outbox drain are CLAUDE-only files. |
| `control-plane/approvals/` — approval + **epoch** SM, eligibility snapshots, escalate/override atomicity, guards G1–G9 (SPEC §2.7, §5.2, ADR-007) | **CLAUDE** | Banking approval semantics; any relaxation of a guard, or any change to rejection/override semantics → HUMAN (B-4). |
| `control-plane/execution/` — binding profiles, token issuance/redemption CAS, execution leases, heartbeats (ADR-008, SPEC §2.6, §2.10, §2.11, §5.5) | **CLAUDE** | A mis-scoped binding profile is a substitution hole: profile changes require security review, same as crypto. |
| `security/redaction/` — DLP attestation, keyed commitments, manifests, reject-on-scan-failure (SPEC §2.5, I-19) | **CLAUDE** | Audit HMAC key handling never leaves this lane. |
| Identity & auth — token validation, token exchange, mTLS/SPIFFE glue (ADR-001) | **CLAUDE** | Zero-trust M2M. Credential handling never leaves this lane. |
| Fail-closed / circuit breakers, degraded-mode WAL (ADR-003) | **CLAUDE** | Failure semantics are security semantics. |
| Tenant isolation primitives — RLS migrations, tenant-scoped Redis/Kafka wrappers, envelope encryption (ADR-005) | **CLAUDE** | CURSOR *consumes* these wrappers; only CLAUDE edits them. |
| `security/pii/`, `security/prompt-security/` (Phase 1) | **CLAUDE** | Detection engines + redaction pipeline (SPEC I-12). |
| `control-plane/agents/`, `control-plane/tools/` — registry CRUD, list/search, pagination | **CURSOR** | Boilerplate on top of CLAUDE-owned repo/tenancy layer. Schema shapes frozen by SPEC §2.1. |
| Data access layer — SQLAlchemy models, migrations *except* RLS/audit tables, repositories | **CURSOR** | Must use tenancy wrapper; raw sessions forbidden by lint rule. |
| `ui/` — dashboard, agent view, action view, approval inbox (PRD §44) | **CURSOR** | React/Next.js. Approval *submission* calls CLAUDE-owned API; UI never implements guard logic. |
| `sdk/{python,typescript,java}` — client generation, ergonomics (PRD §43) | **CURSOR** | Generated from OpenAPI; hand-written auth helpers reviewed by CLAUDE lane. |
| `integrations/{kafka,redis,siem,workflow}` — producers/consumers, connectors | **CURSOR** | Event *shapes* are SPEC §4-frozen; CURSOR wires transport only. The outbox **drain semantics** (ordering, idempotency, at-least-once) are CLAUDE-owned; CURSOR consumes the published client. |
| `integrations/external/` — envelope capture, versioned projections, drift telemetry (ADR-006, SPEC §2.8) | **CURSOR** | Adapters are volume code, but the projection *allowlist* is reviewed by CLAUDE: it defines what can influence a decision (I-17). |
| CI gates — schema validation, `pg_policies` diff, claim-ledger/WORK_LOG enforcement (H-8) | **CURSOR** | Enforcement must live in CI, never only in local hooks (bypassable with `--no-verify`). |
| `examples/{customer-support,wealth-agent}` — demo agents + demo wealth API (PRD §36–38) | **CURSOR** | Demo quality matters (PRD §117) but nothing here is trusted code. |
| Docs — developer/architect docs (PRD §74) | **CURSOR** | Generated from spec where possible. |
| Invariant property tests I-1..I-22 + V-rule tests V-1..V-14 (SPEC §6, §9) | **TEST** | Hypothesis/property-based; each invariant and each V-rule ⇒ ≥1 named test. I-13 (representability) is generative: valid contexts must never fail ADR construction. |
| Approval-SM fuzzing — vote orderings, **epoch races** (vote vs. escalate/override), expiry vs. vote, self-approval, control-domain permutations, carry-forward eligibility (G1–G9) | **TEST** | Model-based testing against §5.2; counterexamples filed as WORK_LOG blockers. |
| Evidence-pipeline tests — golden RFC 8785 vectors, corruption detection, rollback-leaves-no-gap (I-20), checkpointed range verify at 100k records | **TEST** | Hash semantics are never mocked; in-memory chain writer for units, containers for integration. |
| Binding-profile differential tests — volatile-only change redeems, bound-field change never does (I-14) | **TEST** | Retry-drift is the failure mode that kills adoption; test it adversarially. |
| Policy test suites — DSL↔Cedar differential testing, simulation-vs-production parity, conflict/priority edge cases | **TEST** | Zero-drift check: same context must decide identically in `/simulate` and `/authorize`. |
| Security attack suites — prompt-injection corpus, token replay, cross-tenant fuzz, chain-tamper attempts (PRD §39, §62 >90% detection target) | **TEST** | Red-team scenario generation per PRD §35/§104; runs in CI nightly. |
| Load/latency harness — 50 ms p95 @ 500–1000 dec/s validation (SPEC §7) | **TEST** | Gates ADR-002 benchmark (WORK_LOG B-2). |
| ADR ratification, threat model v1, risk formula, approval-guard changes, anything moving money or keys | **HUMAN** | Non-delegable (PRD §68: "architectural decisions stay human-owned"). |

## Cross-Lane Interface Rules

1. **Contracts are the only interface.** Lanes integrate through SPEC_v1 schemas/endpoints/events — never through reading each other's in-progress branches.
2. **CLAUDE exports, CURSOR imports.** Tenancy wrapper, auth middleware, decision client are CLAUDE-published internal packages; CURSOR code depends on them and may not fork or bypass them.
3. **TEST is adversarial, not collaborative.** Test agents get the spec + public interfaces, not implementation hints; a test that peeks at implementation internals to pass is invalid.
4. **Escalation is cheap, drift is expensive.** When lane ownership of a file is ambiguous, default to the more restrictive lane and log it (H-4). Ambiguity itself gets fixed by adding the file/path to this map via HUMAN sign-off.
