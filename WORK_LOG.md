# WORK_LOG — Mizan Agent Handoff Protocol

> **Read this first, write here last.** Every agent session (Claude Code, Cursor/Codex, test generators) MUST: (1) read `Active Task` + `Next Executable Action` before doing anything, (2) obey `SPEC_v1.md` contracts and `AGENT_ALLOCATION.md` lane boundaries, (3) hold a valid claim (H-1) while working, (4) update this file as its final act. Keep entries telegraphic — this file is optimized for low token overhead. Detail belongs in ADRs, spec, or commit messages, not here.

---

## Active Task

`T-005` — Policy DSL parser + compiler/evaluator spike and benchmark.

## Agent Queue

| # | Task | Lane | Depends on | State |
|---|---|---|---|---|
| T-001 | Ratify SPEC v1.2 + ADR-001..008 (incl. R-002 amendments) | HUMAN | — | DONE |
| T-002 | Repo scaffold per PRD §116 (control-plane/, security/, sdk/, examples/, ui/) + CI skeleton | CODEX | T-001 | DONE |
| T-003 | Postgres schema + migrations for §2 domain models (RLS per ADR-005; typed FKs per I-16; DecisionEvent + chain-head tables) | CODEX | T-001 | REVIEW |
| T-004 | `/v1/authorize` walking skeleton: token→tenancy, §3.1 enrichment (fail-closed), evaluate stub, ADR_Record write | CODEX | T-003 | REVIEW |
| T-005 | Policy DSL parser + Cedar compiler spike (ADR-002 benchmark) | CODEX | T-001 | IN_PROGRESS |
| T-006 | Registry CRUD (agents/tools/policies) + list/search endpoints | CODEX | T-003 | READY |
| T-007 | Invariant suite I-1..I-26 (property-based) + V-1..V-21 tests + approval-SM/epoch fuzzer (§5.2 G1–G9) | CODEX | T-004 | READY |
| T-008 | Evidence pipeline: ADR_Record + DecisionEvent sequencers, outbox, immutable receipts, object-store segments, signed anchors, `/v1/audit/verify` (ADR-004 amendments A/B) | CODEX | T-003 | READY |
| T-009 | Approval API + epoch state machine (ADR-007: snapshots, escalate/override atomicity, rejection modes) | CODEX | T-004 | READY |
| T-010 | Dashboard shell + decision/audit views (PRD §44) | CODEX | T-006 | BLOCKED |
| T-011 | Binding profiles + executor-bound token/lease lifecycle (ADR-008), incl. atomic redemption CAS and SPIFFE match (V-13/V-17/V-20) | CODEX | T-004 | READY |
| T-012 | Redaction pipeline: DLP attestation, keyed commitments, manifest, reject-on-scan-failure (I-19) | CODEX | T-008 | BLOCKED |
| T-013 | External payload boundary: parser budgets + envelope disposition + versioned projections + drift telemetry (ADR-006) | CODEX | T-004 | READY |
| T-014 | Claim-ledger CI gate: reject scoped code changes whose change-set does not update WORK_LOG (H-8) | CODEX | T-002 | READY |
| T-015 | Chain-verification perf harness: 100k-record fixture, checkpointed parallel range verify (<10s) | CODEX | T-008 | BLOCKED |

States: `READY → IN_PROGRESS(claim) → REVIEW → DONE` | `BLOCKED(dep)` | `PARKED(reason)`

## Claim Ledger

One row per active claim. A task is `IN_PROGRESS` **iff** it has a live row here. Empty = nothing claimed.

| task_id | claimed_by | claim_token | claim_version | claimed_at | heartbeat_at | lease_expires_at | base_commit |
|---|---|---|---|---|---|---|---|
| T-005 | codex | t005-20260825-231208 | 1 | 2026-08-24T23:12:08Z | 2026-08-24T23:12:08Z | 2026-08-25T03:12:08Z | 4fe339e |

## Blockers & Dependencies

- **B-1 (resolved 2026-08-25):** User ratified T-001 in all required Product/Architecture, Cybersecurity, and Compliance/Business roles. SPEC v1.2, R-002, and ADR-001..008 are accepted as the implementation baseline.
- **B-2:** Cedar binding benchmark (T-005) gates final ADR-002 acceptance. Target: ≥1k eval/s, p99 < 5 ms in-process. Benchmark must include RLS planner overhead (ADR-005) inside the 50 ms budget.
- **B-3 (resolved by T-002):** Git repository initialized on `main`; ratified foundation recorded in root commit `da7c83d`.
- **B-4 (resolved 2026-08-25):** T-001 ratification included Compliance/Business sign-off on ADR-007 `rejection_mode` and override-authority semantics.
- **B-5 (resolved in v1.2):** Control domains come from a reviewed/versioned Mizan role-registry mapping populated from IdP data; epoch snapshots pin the mapping version. Ratification remains under B-4/T-001.
- **B-6:** Sequencer throughput vs. 1k dec/s unproven. T-008 must benchmark sharded streams (`MIZAN_CHAIN_SHARDS_PER_TENANT`) before ADR-004 acceptance.

## Next Executable Action

> **T-005 (CODEX, claimed):** Implement the policy DSL/compiler spike and version-pinned evaluator behind the T-004 repository port, then measure the B-2 throughput/latency target with RLS lookup overhead included.

---

## Transition Hooks (automated handoff, no orchestrator stalls)

**H-1 · Claim (atomic lease).** Work requires a row in the Claim Ledger with `task_id, claimed_by, claim_token, claim_version, claimed_at, heartbeat_at, lease_expires_at, base_commit`. Only the holder of `claim_token` may heartbeat, complete, or release. Default lease 4h; heartbeat by updating `heartbeat_at` in any commit. **Reclaim requires both** an expired `lease_expires_at` **and** a compare-and-swap on `claim_version` (read version N, write N+1 in the same change-set; a losing writer sees N+1 and aborts). No "any agent may reset a stale row" — that permitted duplicate work and competing commits.
**H-2 · Complete:** finishing agent (a) releases its claim row, (b) flips the queue row to `REVIEW`, (c) rewrites `Next Executable Action` to the single best next step (anti-stall — never leave it stale or empty), (d) appends a Log entry, (e) unblocks dependent rows (`BLOCKED(T-00X)` → `READY` when T-00X hits DONE-or-REVIEW if the dependency is interface-only).
**H-3 · Contract touch:** any change to schemas/endpoints/events/state machines/invariants/**config keys** requires an ADR delta *in the same change-set*; otherwise the change is invalid and the next agent reverts it. Spec wins over code, always.
**H-4 · Lane violation:** work outside your lane (per `AGENT_ALLOCATION.md`) → stop, park the task `PARKED(lane)`, note it here. Never "just fix" cross-lane.
**H-5 · Test gate:** CURSOR-lane code merges only with TEST-lane (or pre-existing) tests green. CLAUDE-lane security-critical code additionally requires the invariant suite (T-007 onward) green, including the V-rule tests.
**H-6 · Session end:** final act of every session = update this file. A session that edited code but not WORK_LOG is treated as unfinished.
**H-7 · Human escalation:** decisions touching money movement, approval semantics, crypto, key management, or tenant isolation escalate to HUMAN lane — add a `Blockers` row, park, continue with other READY work (don't idle).
**H-8 · CI enforcement (not honour system):** the repo's CI rejects a change-set that touches lane-scoped code paths without a matching `WORK_LOG.md` update and a live claim row (T-014). A local pre-commit hook may mirror this for fast feedback, but **CI is authoritative** — local hooks are bypassable with `--no-verify`, so they can never be the control.

---

## Log (newest first, one line each: `date · lane · task · what · next`)

- 2026-08-25 · CODEX · T-004 · Added FastAPI authorization core with asymmetric JWT verification, identity-derived tenancy, registry/resource/binding enrichment, RFC8785 hashes, fail-closed risk/evidence handling, deterministic idempotency, default DENY, atomic ADR+outbox Postgres adapter, six unit tests and live RLS-scoped integration round-trip; released claim and unblocked T-007/T-009/T-011/T-013 · next: T-005 CODEX
- 2026-08-25 · CODEX · T-003 · Added PostgreSQL 16 schema/rollback for all SPEC §2 persisted models, typed ID domains/composite FKs, forced RLS on 21 tenant tables, immutable evidence triggers, transaction-safe evidence/DecisionEvent heads, Docker integration profile, and CI contract test; all checks pass; released claim and unblocked T-004/T-006/T-008 · next: T-004 CODEX
- 2026-08-25 · HUMAN · GOVERNANCE · Assigned CODEX as sole implementation/test agent across former CLAUDE/CURSOR/TEST lanes; lane labels now express required rigor, while HUMAN decision gates remain intact; accepted T-002 · next: T-003 CODEX (claimed)
- 2026-08-25 · CURSOR · T-002 · Initialized Git with ratified root baseline; scaffolded PRD §116 product boundaries, lane markers, repository hygiene, dependency-free contract validator, and GitHub Actions CI skeleton; `make check`, Python compile, and whitespace checks pass; released claim and unblocked T-014 · next: T-003 CLAUDE
- 2026-08-25 · HUMAN · T-001 · Ratified SPEC v1.2, R-002, and ADR-001..008 in all required Product/Architecture, Cybersecurity, and Compliance/Business roles; unblocked T-002/T-003/T-005 · next: T-002 CURSOR (claimed)
- 2026-08-25 · CURSOR · T-000c · Applied re-audit R-002: SPEC v1.2 executor-bound capabilities, default-deny evidence, DecisionEvents, immutable receipts, trusted degraded grants/WAL contract, external parser/persistence limits; amended ADR-001/002/003/004/006/007/008; blocked implementation pending ratification · next: T-001 HUMAN
- 2026-08-25 · CLAUDE · T-000b · Applied review R-001: SPEC v1.1 (typed IDs, enrichment, epochs, binding profiles/leases, redaction attestation, config registry §8, V-rules §9, evidence pipeline §10), ADR-006/007/008, ADR-003/004 amendments, H-1 claim leases + H-8 CI gate · next: human ratification (T-001), then T-002
- 2026-08-25 · CLAUDE · T-000 · Generated SPEC_v1.md, ADR-001..005, WORK_LOG.md, AGENT_ALLOCATION.md from PRD v1.0 · next: human ratification (T-001)
