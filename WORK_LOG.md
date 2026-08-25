# WORK_LOG — Mizan Agent Handoff Protocol

> **Read this first, write here last.** Every agent session (Claude Code, Cursor/Codex, test generators) MUST: (1) read `Active Task` + `Next Executable Action` before doing anything, (2) obey `SPEC_v1.md` contracts and `AGENT_ALLOCATION.md` lane boundaries, (3) hold a valid claim (H-1) while working, (4) update this file as its final act. Keep entries telegraphic — this file is optimized for low token overhead. Detail belongs in ADRs, spec, or commit messages, not here.

---

## Active Task

Stage 2 remediation in progress. T-021 and T-016 are in REVIEW; T-017 is the next executable task. B-11 remains isolated to T-025; no active claims.

## Agent Queue

| # | Task | Lane | Depends on | State |
|---|---|---|---|---|
| T-001 | Ratify SPEC v1.2 + ADR-001..008 (incl. R-002 amendments) | HUMAN | — | DONE |
| T-002 | Repo scaffold per PRD §116 (control-plane/, security/, sdk/, examples/, ui/) + CI skeleton | CODEX | T-001 | DONE |
| T-003 | Postgres schema + migrations for §2 domain models (RLS per ADR-005; typed FKs per I-16; DecisionEvent + chain-head tables) | CODEX | T-001 | DONE |
| T-004 | `/v1/authorize` walking skeleton: token→tenancy, §3.1 enrichment (fail-closed), evaluate stub, ADR_Record write | CODEX | T-003 | DONE |
| T-005 | Policy DSL parser + Cedar compiler spike (ADR-002 benchmark) | CODEX | T-001 | DONE |
| T-006 | Registry CRUD (agents/tools/policies) + list/search endpoints | CODEX | T-003 | DONE |
| T-007 | Invariant suite I-1..I-26 (property-based) + V-1..V-21 tests + approval-SM/epoch fuzzer (§5.2 G1–G9) | CODEX | T-004 | DONE |
| T-008 | Evidence pipeline: ADR_Record + DecisionEvent sequencers, outbox, immutable receipts, object-store segments, signed anchors, `/v1/audit/verify` (ADR-004 amendments A/B) | CODEX | T-003 | DONE |
| T-009 | Approval API + epoch state machine (ADR-007: snapshots, escalate/override atomicity, rejection modes) | CODEX | T-004 | DONE |
| T-010 | Dashboard shell + decision/audit views (PRD §44) | CODEX | T-006 | DONE |
| T-011 | Binding profiles + executor-bound token/lease lifecycle (ADR-008), incl. atomic redemption CAS and SPIFFE match (V-13/V-17/V-20) | CODEX | T-004 | DONE |
| T-012 | Redaction pipeline: DLP attestation, keyed commitments, manifest, reject-on-scan-failure (I-19) | CODEX | T-008 | DONE |
| T-013 | External payload boundary: parser budgets + envelope disposition + versioned projections + drift telemetry (ADR-006) | CODEX | T-004 | DONE |
| T-014 | Claim-ledger CI gate: reject scoped code changes whose change-set does not update WORK_LOG (H-8) | CODEX | T-002 | DONE |
| T-015 | Chain-verification perf harness: 100k-record fixture, checkpointed parallel range verify (<10s) | CODEX | T-008 | DONE |
| T-016 | R-004 F-1 (B-10 Option A ratified): reject CONSTRAIN/REDACT/ESCALATE with `NOT_IMPLEMENTED` + auditable DENY; remove dead `constraints_hash` binding (SPEC §0 rule 2) | CODEX | — | REVIEW |
| T-017 | R-004 F-2: `system_fail_closed` evidence on engine/dependency failure; wrap policy evaluation; narrow the blanket handler (I-8/V-15) | CODEX | — | READY |
| T-018 | R-004 F-3/F-7/F-10: bind the real executor at issue, defensive delegation access, bounded security-event connection | CODEX | — | READY |
| T-019 | R-004 F-6: concurrent duplicate `request_id` returns the prior decision, never `evidence_write_failed` | CODEX | — | READY |
| T-020 | R-004 F-5: app-terminated mTLS populates `client_cert_spiffe`; deployment contract + ADR-001 delta (I-23) | CODEX | — | READY |
| T-021 | R-004 F-4: contract drift gates — meta-schema, I-16 typed IDs, SPEC-string reachability, closed-schema producibility; negative fixtures in CI | CODEX | — | REVIEW |
| T-022 | R-004 F-8/F-9: decompose the over-cited integration test, raise `test_execution.py` coverage, re-chain the in-memory repo, reconcile doc drift | CODEX | T-017, T-018 | READY |
| T-023 | Load & latency harness: SPEC §7 p95/throughput/outbox-lag on deployment-class Linux; JSON artifacts (closes B-2/B-6 rerun obligation) | CODEX | T-022 | BLOCKED(T-022) |
| T-024 | Adversarial suite: token replay, cross-tenant fuzz, chain tamper, prompt-injection corpus; nightly CI (PRD §39/§62) | CODEX | T-022 | BLOCKED(T-022) |
| T-025 | Signing-key custody, distribution and rotation across token/receipt/anchor/grant artifacts | CODEX | B-11 | BLOCKED(B-11) |
| T-026 | Outbox drain operations: runner, backpressure, poison handling, lag SLO, SIEM delivery | CODEX | T-022 | BLOCKED(T-022) |
| T-027 | Threat model v1 (`threat-models/` holds only a README) | HUMAN | — | READY |
| T-028 | Constrained-execution specification incl. executor-side enforcement contract (B-10 Option B) | HUMAN | — | PARKED(v1.4) |

States: `READY → IN_PROGRESS(claim) → REVIEW → DONE` | `BLOCKED(dep)` | `PARKED(reason)`

## Claim Ledger

One row per active claim. A task is `IN_PROGRESS` **iff** it has a live row here. Empty = nothing claimed.

| task_id | claimed_by | claim_token | claim_version | claimed_at | heartbeat_at | lease_expires_at | base_commit |
|---|---|---|---|---|---|---|---|

## Blockers & Dependencies

- **B-1 (resolved 2026-08-25):** User ratified T-001 in all required Product/Architecture, Cybersecurity, and Compliance/Business roles. SPEC v1.2, R-002, and ADR-001..008 are accepted as the implementation baseline.
- **B-2 (resolved by T-005):** Cedar 4.8.7 cached handles measured 6,896 eval/s and p99 0.1741 ms over 5,000 evaluations on the M3 Max host. The live PostgreSQL integration suite separately gates RLS-scoped lookup + evaluation below 50 ms p99. ADR-002 is ACCEPTED; deployment-class Linux sizing must rerun the benchmark.
- **B-3 (resolved by T-002):** Git repository initialized on `main`; ratified foundation recorded in root commit `da7c83d`.
- **B-4 (resolved 2026-08-25):** T-001 ratification included Compliance/Business sign-off on ADR-007 `rejection_mode` and override-authority semantics.
- **B-5 (resolved in v1.2):** Control domains come from a reviewed/versioned Mizan role-registry mapping populated from IdP data; epoch snapshots pin the mapping version. Ratification remains under B-4/T-001.
- **B-6 (resolved by T-008):** Four sharded streams measured 2,725 transaction-level allocations/second over 2,000 operations with p99 2.0087 ms on the M3 Max development host. ADR-004 is ACCEPTED; deployment-class Linux sizing must rerun the benchmark.
- **B-7 (resolved 2026-08-25):** R-003 ratified a typed, independently controlled review epoch with no vote carry-forward and no recursive `review_required` rejection.
- **B-8 (resolved 2026-08-25):** R-003 ratified bounded transient tool arguments at authorization/redemption plus fresh authoritative enrichment before execution.
- **B-9 (resolved 2026-08-25):** R-003 ratified a normative semantic policy hash excluding only lifecycle governance fields.
- **R-003 (ratified 2026-08-25):** User ratified B-7/B-8/B-9 in all Product/Architecture, Cybersecurity, and Compliance/Business roles.
- **B-10 (resolved 2026-08-25):** Human owner ratified R-004 **Option A** — the evaluator rejects `CONSTRAIN`/`REDACT`/`ESCALATE` with `NOT_IMPLEMENTED` and an auditable `DENY` ADR_Record, and the dead `constraints_hash` binding is removed. Constrained execution (Option B) is deferred to v1.4 as T-028. T-016 unblocked; CODEX implements Option A exactly and does not extend the `ADR_Record` schema.
- **B-11 (open, HUMAN):** Signing-key custody and rotation. All keys are process-generated (`evidence.py:75`); receipts and anchors become unverifiable across restart. Per H-7 (crypto/key management) the custody model is not CODEX's to choose. Gates T-025 and single-process deployability.
- **R-004 (open, 2026-08-25):** Implementation review of the T-001..T-015 baseline. Ten findings dispositioned in `docs/reviews/R-004-implementation-review-disposition.md`; §0 records which WORK_LOG claims were independently reproduced and which were not.

## Next Executable Action

> **T-017 (R-004 F-2) — claim and implement the system-fail-closed evidence path.** Record risk/policy engine failures as schema-valid DENY ADR_Records with `decision_basis=system_fail_closed`, return controlled Problems, narrow the blanket persistence handler, and add distinct evidence-double-failure telemetry. Then T-018/T-019/T-020 in any order, followed by T-022.

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

- 2026-08-25 · CLAUDE-rigor/CODEX · T-016 · Implemented ratified B-10 Option A across all six decision enums: unsupported winners persist schema-valid DENY evidence then return 501 NOT_IMPLEMENTED; removed both dead ADR constraints reads and the token claim, amended SPEC/ADR-008, retained a dated T-028 constraints_hash waiver; new six-enum test failed for CONSTRAIN/REDACT/ESCALATE on pre-fix `53d1035` and now passes; lint, 97 unit/property, and four live PostgreSQL tests pass · next: T-017 CODEX
- 2026-08-25 · CLAUDE-rigor/CODEX · T-021 · Added blocking Draft 2020-12 meta-schema, I-16 typed-ID, behavioural reachability/dated-waiver, and closed ADR producibility gates with four committed negative fixtures; corrected five typed-ID schema violations with ADR-005 Amendment A; new reachability test failed on pre-fix `4267dac6ddf1c616506a38b3ec490b405e6e5b66` (NOT_IMPLEMENTED and system_fail_closed unreachable) and passes on the change; 91 unit tests and lint/check pass · next: T-016 CODEX
- 2026-08-25 · HUMAN · R-004/B-10 · Ratified Option A: evaluator rejects CONSTRAIN/REDACT/ESCALATE with `NOT_IMPLEMENTED` plus an auditable DENY ADR_Record, dead `constraints_hash` binding removed, constrained execution deferred to v1.4 (T-028 PARKED); T-016 unblocked, B-11 key custody still open · next: T-021 then T-016 CODEX
- 2026-08-25 · CLAUDE · R-004 · Reviewed the T-001..T-015 baseline against SPEC v1.3 and reproduced the lint/86-test/live-Postgres/100k-chain/Cedar/32-commit-ledger claims (sequencer ops/s not retained, superseded by T-023); dispositioned ten findings, headlined by CONSTRAIN/REDACT being unrecordable under the closed ADR_Record schema and `system_fail_closed` existing in SPEC but in zero lines of code; queued T-016..T-028 and filed B-10/B-11 for HUMAN · next: T-021 CODEX
- 2026-08-25 · CODEX · T-007 v1.3 · Closed I-1..I-26/V-1..V-21 and R-003 coverage, added fresh-review-authority property checks, reconciled ratified ADR statuses, and passed baseline/lint/JS, 86 unit/property, four live PostgreSQL, 2,708 ops/s sequencer, 6,018 eval/s policy, and 100k chain verification in 6.424s; all T-001..T-015 DONE · next: new scoped task
- 2026-08-25 · CODEX · T-009 v1.3 · Made review-triggering rejection atomically close the original epoch, snapshot the independently configured authority pool, open an isolated no-carry review epoch, append decision evidence, and enqueue review notification; 85 unit plus four live integration tests pass; task DONE · next: T-007
- 2026-08-25 · CODEX · T-006 v1.3 · Implemented the R-003 semantic policy hash, locked lifecycle endpoint, simulation-before-test and author/approver separation, UTC activation, prior-version supersession, transactional transition events, and lifecycle/hash regression coverage; task DONE · next: T-009
- 2026-08-25 · CODEX · T-011 v1.3 · Required bounded arguments on execute, recomputed the pinned profile hash before both first redemption and idempotent retry, revalidated immutable normalized context against current agent/tool/resource/risk/delegation authority, and rejected changed bound arguments before CAS/lease reuse; 82 unit plus four live integration tests pass; task DONE · next: T-006
- 2026-08-25 · CODEX · T-004 v1.3 · Added the ratified bounded transient argument contract, server-side binding validation/hash, raw-argument exclusion from policy/evidence/context hashes, and immutable tenant-RLS normalized context snapshots; 82 unit plus four live integration tests pass; task DONE · next: T-011
- 2026-08-25 · HUMAN · R-003 · Ratified B-7 typed review authority, B-8 bounded arguments/fresh execution revalidation, and B-9 semantic policy hash in all required roles · next: SPEC v1.3 + T-004 CODEX
- 2026-08-25 · CODEX · T-004 audit · Replaced permissive implementation-only context bags with exact typed customer/business/security/mapped/environment/timestamp models, removed non-schema tool/action fields, generated server trace evidence, and proved the context validates after isolating only the B-8 arguments gap; 80 unit plus four live integration tests pass; PARKED on R-003/B-8 · next: HUMAN ratify R-003
- 2026-08-25 · CODEX · T-007 audit · Reconciled the coverage index after T-011/T-012/T-013 hardening, added durable hashed-jti replay signaling, and separated security notifications from evidence-publisher outbox selection to prevent publication starvation; 79 unit plus four live integration tests pass; PARKED only where B-7/B-8 make complete invariant tests impossible · next: T-004 audit
- 2026-08-25 · CODEX · T-010 audit · Added exact tenant-RLS dashboard aggregates for all seven PRD metrics, responsive control-center cards, agent registry/detail view, active-view refresh, and retained evidence-backed action/audit/verification views; 79 unit plus four live integration tests and JavaScript syntax pass; task DONE · next: T-007 audit
- 2026-08-25 · CODEX · T-013 audit · Normalized telemetry/persistence/parser faults as controlled tool errors, moved timeout enforcement before irreversible persistence, enforced RFC 6901 pointer rules, and deduplicated truncated drift paths; 79 unit tests pass; task DONE · next: T-010 audit
- 2026-08-25 · CODEX · T-012 audit · Recomputed stored-payload hashes, verified manifest counts and concrete transforms, fixed numeric/depth ordering for array drops, and made payload-free redaction-failure outbox signaling a mandatory Redactor dependency; 75 unit plus four live integration tests pass; task DONE · next: T-013 audit
- 2026-08-25 · CODEX · T-011 audit · Enforced the complete closed token-claims schema at issue and redeem, revalidated constraints and live approval epoch, and fixed expired lease state/evidence rollback by committing before the controlled error; 74 unit plus four live integration tests pass; PARKED only on B-8 argument recomputation · next: T-012 audit
- 2026-08-25 · CODEX · T-005 audit · Corrected production/simulation selector parity using registry-enriched risk and normalized environment, added native Cedar decimal encoding/method comparisons with representability rejection, and reran 71 unit plus four live integration tests; benchmark measured 6,991 eval/s at p99 0.1703 ms; task DONE · next: T-011 audit
- 2026-08-25 · CODEX · T-006 audit · Added authenticated agent lifecycle PATCH with real two-token dual control, normative transition graph, versioned immutable binding-profile publication, recorded policy simulation using the production compiler, delegation-edge persistence, and live tests; PARKED policy transition endpoint on content-hash contradiction B-9 · next: T-005 audit
- 2026-08-25 · CODEX · T-003 audit · Removed runtime UPDATE/DELETE grants from immutable evidence, corrected `dgn_*` nonce storage, added receipt/anchor chain FKs, token↔lease relational bindings, approval-state/document checks, and a separately mounted rollback migration with destructive disposable-db verification; live schema/repository/rollback gates pass; task DONE · next: T-005/T-006 audit
- 2026-08-25 · CODEX · T-008/T-015 audit · Replaced helper-only perf proof with the real receipt/object/anchor verifier; deduplicated segment reads, parallelized 100k Ed25519 receipt checks, required matching WORM anchors, handled missing/malformed evidence as controlled failures, and corrected shard default 16→4; actual 100k path passes in 6.409s; 61 unit + four live integration tests pass; both tasks DONE · next: T-003 audit
- 2026-08-25 · CODEX · T-014 · Release audit found CI lacked uv installation and never ran lint/unit/invariant/performance gates; added locked setup-uv jobs for Ruff, 60 unit/property tests, 100k chain benchmark, and live Postgres suite; local equivalents pass; task independently audited DONE · next: T-008 audit
- 2026-08-25 · CODEX · T-007 · Added Hypothesis chain/representability/approval fuzzing and I-1..I-26/V-1..V-21 coverage index; closed delegation, quorum, policy dual-control, binding unknown-field, DecisionEvent retry, external receipt validation, audit-attestation and encrypted degraded-WAL gaps; 60 unit + four live integration tests pass; B-7/B-8 remain contract decisions · next: HUMAN B-7/B-8
- 2026-08-25 · CODEX · T-010 · Added responsive same-origin operator console for decision filters/details, audit browsing and signed-chain verification; implemented missing tenant-RLS decision/audit query endpoints with cursor pagination and live integration assertions; 43 unit + four live integration tests pass · next: T-007 CODEX
- 2026-08-25 · CODEX · T-015 · Added independently anchored checkpoint-range verification with parallel workers and boundary-continuity checks, deterministic 100k fixture, corruption tests and Make target; M3 Max verified 100k in 0.917s vs <10s gate; 43 unit tests pass · next: T-010 CODEX
- 2026-08-25 · CODEX · T-013 · Added bounded streaming identity/gzip decoding, duplicate/non-finite JSON rejection, depth/key/time budgets, SPEC-valid transient envelopes, scalar-only versioned projections, drift telemetry, explicit raw-persistence sinks and operational payload stripping; 42 unit tests pass · next: T-015 CODEX
- 2026-08-25 · CODEX · T-012 · Added rule-based DLP scanner interface, fail-closed redactor, HMAC source/field commitments, stored-payload hash, coverage attestation and manifests, plus atomic redacted AuditTrail/outbox writes; 34 unit + four live integration tests pass · next: T-013 CODEX
- 2026-08-25 · CODEX · T-011 · Added EdDSA execution capabilities, issuer/audience/TTL enforcement, DB-backed single-use CAS, executor SPIFFE binding, agent/context/profile revalidation, financial receipt gating, idempotent leases, bounded heartbeats/completion and same-transaction DecisionEvents; 30 unit + live lifecycle integration tests pass; B-8 remains the argument-recomputation contract gap · next: T-012 CODEX
- 2026-08-25 · CODEX · T-009 · Implemented approval domain/API/storage for eligibility snapshots, control-domain quorum, immutable per-epoch votes, veto/rejection quorum, stale-race rejection, escalation, override, withdrawal and same-transaction DecisionEvents; 28 unit + live integration tests pass; PARKED review_required completion on missing review-authority contract B-7; also recorded T-004 argument-binding contract gap B-8 · next: T-011 CODEX
- 2026-08-25 · CODEX · T-008 · Added dense dual-sequenced DecisionEvents, transactional outbox publisher, RFC8785 immutable segments, append-only Ed25519 receipts, signed anchors, independent object verifier and audit routes; unit/live integration tests pass; four-shard benchmark reached 2,725 ops/s at p99 2.0087 ms; accepted ADR-004, resolved B-6, unblocked T-012/T-015 · next: T-009 CODEX
- 2026-08-25 · CODEX · T-014 · Replaced disabled CI placeholder with per-commit claim-ledger enforcement; scoped commits must update WORK_LOG and contain one live claim or a newest matching REVIEW/DONE handoff; unit tests and full-history validation across seven commits pass · next: T-008 CODEX
- 2026-08-25 · CODEX · T-006 · Added exact SPEC JSON-Schema validation, tenant-scoped agent/tool/policy create/get/list endpoints, canonical content/profile hashes, allowlisted SQL resource mapping, latest-policy selection and keyset cursors; 13 unit and three live Postgres integration tests pass · next: T-014 CODEX
- 2026-08-25 · CODEX · T-005 · Added Cedar 4.8.7 DSL compiler, safe condition translation, immutable PolicySet cache, applies-to selection, Postgres ACTIVE-policy integration, parity/adversarial tests and benchmark; measured 6,896 eval/s at p99 0.1741 ms plus RLS lookup p99 gate <50 ms; accepted ADR-002 and resolved B-2 · next: T-006 CODEX
- 2026-08-25 · CODEX · T-004 · Added FastAPI authorization core with asymmetric JWT verification, identity-derived tenancy, registry/resource/binding enrichment, RFC8785 hashes, fail-closed risk/evidence handling, deterministic idempotency, default DENY, atomic ADR+outbox Postgres adapter, six unit tests and live RLS-scoped integration round-trip; released claim and unblocked T-007/T-009/T-011/T-013 · next: T-005 CODEX
- 2026-08-25 · CODEX · T-003 · Added PostgreSQL 16 schema/rollback for all SPEC §2 persisted models, typed ID domains/composite FKs, forced RLS on 21 tenant tables, immutable evidence triggers, transaction-safe evidence/DecisionEvent heads, Docker integration profile, and CI contract test; all checks pass; released claim and unblocked T-004/T-006/T-008 · next: T-004 CODEX
- 2026-08-25 · HUMAN · GOVERNANCE · Assigned CODEX as sole implementation/test agent across former CLAUDE/CURSOR/TEST lanes; lane labels now express required rigor, while HUMAN decision gates remain intact; accepted T-002 · next: T-003 CODEX (claimed)
- 2026-08-25 · CURSOR · T-002 · Initialized Git with ratified root baseline; scaffolded PRD §116 product boundaries, lane markers, repository hygiene, dependency-free contract validator, and GitHub Actions CI skeleton; `make check`, Python compile, and whitespace checks pass; released claim and unblocked T-014 · next: T-003 CLAUDE
- 2026-08-25 · HUMAN · T-001 · Ratified SPEC v1.2, R-002, and ADR-001..008 in all required Product/Architecture, Cybersecurity, and Compliance/Business roles; unblocked T-002/T-003/T-005 · next: T-002 CURSOR (claimed)
- 2026-08-25 · CURSOR · T-000c · Applied re-audit R-002: SPEC v1.2 executor-bound capabilities, default-deny evidence, DecisionEvents, immutable receipts, trusted degraded grants/WAL contract, external parser/persistence limits; amended ADR-001/002/003/004/006/007/008; blocked implementation pending ratification · next: T-001 HUMAN
- 2026-08-25 · CLAUDE · T-000b · Applied review R-001: SPEC v1.1 (typed IDs, enrichment, epochs, binding profiles/leases, redaction attestation, config registry §8, V-rules §9, evidence pipeline §10), ADR-006/007/008, ADR-003/004 amendments, H-1 claim leases + H-8 CI gate · next: human ratification (T-001), then T-002
- 2026-08-25 · CLAUDE · T-000 · Generated SPEC_v1.md, ADR-001..005, WORK_LOG.md, AGENT_ALLOCATION.md from PRD v1.0 · next: human ratification (T-001)
