# R-004 — Implementation Review Disposition & Stage-2 Work Order

**Status:** OPEN — **B-10 RATIFIED (Option A) 2026-08-25**; B-11 still requires HUMAN ratification; all
other items are executable now
**Date:** 2026-08-25
**Reviewer:** CLAUDE lane (review/orchestration)
**Executor:** CODEX (sole implementation/test agent per the 2026-08-25 execution-owner directive)
**Scope:** Full implementation review of the T-001..T-015 baseline against SPEC v1.3
**Method:** Every WORK_LOG claim was re-run locally; every finding below is anchored to a file and line.

---

## 0. Standing before this review

The baseline is sound. This section is not politeness — it is the reason the remediation below is
narrow rather than structural, and CODEX should not refactor these areas.

**Reproduced independently (not accepted on report):**

| Claim | Result |
|---|---|
| Lint + 86 unit/property tests | PASS — ruff clean, `86 passed in 1.07s` |
| Four live PostgreSQL tests + rollback contract | PASS — `make test-postgres` exit 0 |
| 100k chain verification < 10s (claimed 6.424s) | PASS — reproduced at **6.4798s**, `valid: true` |
| Cedar throughput (claimed 6,018–6,991 eval/s) | PASS — reproduced at **6,244 eval/s**, p99 0.21 ms |
| Claim-ledger CI gate over full history | PASS — validates all **32** commits, not just HEAD |
| `tests/CONTRACT_COVERAGE.md` rows name real tests | PASS — all 15 sampled tests exist and are collected |

**Not reproduced:** the four-shard sequencer figure (2,725 allocations/s, p99 2.0087 ms). The suite
exited 0 so the benchmark ran, but its stdout was not retained in the captured output. This is
recorded as unverified, not as doubted. T-023 supersedes it with a durable artifact.

**Engineering to preserve as-is:**

1. `execution.py::_revalidate` — re-derives delegation authority, agent version, pinned profile,
   executor membership, risk non-increase and approval epoch from authoritative state at redemption,
   and recomputes `context_hash` rather than trusting the stored copy. This is the strongest code in
   the repository and satisfies B-8 beyond its letter.
2. `repository.py::persist_decision` — allocates the sequence under `FOR UPDATE` and **then**
   recomputes `record_hash`, so the placeholder chain fields written by `service._adr_document` are
   discarded before hashing. I-20 is correct. Do not "simplify" this ordering.
3. `execution.py::_record_security_event` — writes replay evidence on a separate connection so it
   survives the outer rollback. Deliberate and right.
4. The PostgreSQL schema's defence in depth: `FORCE ROW LEVEL SECURITY` on all tenant tables,
   `REVOKE UPDATE, DELETE` on the seven immutable tables, **and** `BEFORE UPDATE OR DELETE` triggers.
   Three independent controls for one invariant is the correct posture for evidence.
5. `tests/CONTRACT_COVERAGE.md` opening with "a row is not considered covered merely because it
   appears here." Self-skeptical documentation is rare and is worth keeping.

---

## 1. The pattern to internalize

Findings F-1 and F-2 are the same defect class R-001 was written to eliminate: **the SPEC asserts a
behaviour that no artifact in the system can produce.** Both survived a full test suite, a coverage
index, and a CI gate, because every one of those checks verifies what the code *does* — none verifies
that what the SPEC *promises* is reachable.

The remediation is therefore not just "fix F-1 and F-2." It is T-021: build the gate that would have
caught them. A fix without its gate is a fix that comes back.

**Rule for this stage:** if a SPEC string names a behaviour (`NOT_IMPLEMENTED`, `system_fail_closed`,
`constraints_hash`), there must exist either an implementation that emits it or an explicit,
logged decision that v1 does not. Silence is not an acceptable third state.

---

## 2. Findings and dispositions

Severity ordering is the intended execution order within Stage 1, except that T-021 (F-4) may be
done first if CODEX prefers to land the gate before the fixes it protects.

### F-1 · HIGH · `CONSTRAIN`/`REDACT` are structurally unrecordable and silently degrade
**Task:** T-016 · **READY** — B-10 ratified Option A on 2026-08-25

**Evidence.**
- `SPEC_v1.md` `ADR_Record` is `additionalProperties: false` and declares **no `constraints`
  property**. A CONSTRAIN outcome therefore cannot be represented in evidence at all.
- `execution.py:153` and `execution.py:509`:
  `"constraints_hash": canonical_hash(adr.get("constraints")) if adr.get("constraints") else None`
  — `adr` is the persisted ADR_Record, which has no `constraints` key. Both expressions are
  unreachable; `constraints_hash` is permanently `None` and `_revalidate` compares `None` to `None`.
- `SPEC_v1.md:1399` nonetheless states `CONSTRAIN/REDACT ─► token issued (constraints_hash bound)`.
- `service.py::_combine` returns `winner.decision` for any enum member with no rejection path.
- `SPEC_v1.md:17` requires the unimplemented decision values be "rejected by the evaluator with
  `NOT_IMPLEMENTED`, never dropped." That string occurs in **zero** lines of Python.

**Impact.** A policy returning CONSTRAIN yields a valid, redeemable execution token carrying no
recorded and no enforced constraint — an unconstrained ALLOW wearing a constrained label. For a bank,
that is the worst available failure shape: it is invisible in the audit trail rather than loud.

**Disposition.** **B-10 Option A, ratified 2026-08-25.** The evaluator rejects the three unimplemented
decision values with `NOT_IMPLEMENTED` (HTTP 501) and records an auditable `DENY` ADR_Record; the two
dead `constraints_hash` expressions are deleted; `SPEC_v1.md:1399` is amended. Constrained execution
is deferred to v1.4 (T-028). Implement exactly this — see §4/T-016. Do not extend the `ADR_Record`
schema and do not reopen the choice.

### F-2 · HIGH · `system_fail_closed` has no implementation; engine failure leaves no evidence
**Task:** T-017 · **Executable now** (this is an unimplemented existing contract, not a new one)

**Evidence.**
- `system_fail_closed` appears in `SPEC_v1.md` at lines 472, 480, 481, 1410, 1520 (I-8) and 1630
  (V-15), and in **zero** lines of implementation.
- `service.py:124-127` wraps risk-engine failure as `Problem(503, "risk_engine_unavailable")` and
  returns **without writing an ADR_Record**.
- The `matching_policies` call is **not** wrapped at all, unlike the risk call. `policy_engine.py`
  raises `RuntimeError(f"Cedar evaluation error: ...")`, which escapes as an uncaught 500.

**Impact.** The system fails closed on the allow axis but keeps no record of the denials it caused.
V-15 and I-8 exist precisely to make zero-policy DENYs evidence-representable; the one code path that
needs them does not use them. An auditor asking "show me every request you refused last Tuesday"
gets a silently incomplete answer, and a Cedar diagnostic error additionally leaks a stack trace as a
500 instead of a Problem document.

**Disposition.** Implement. Do not invent the semantics — `SPEC_v1.md:1410` and ADR-003 already
define them. See T-017 acceptance criteria.

### F-3 · MEDIUM · Issuance hardcodes the first executor; redemption accepts any
**Task:** T-018

`execution.py:127` sets `executor = tool["execution"]["executor_spiffe_ids"][0]`, while `_revalidate`
correctly checks `claims["authorized_executor"] not in tool["execution"]["executor_spiffe_ids"]`.
A tool with N authorized executors is single-executor in practice, and the asymmetry will present as
a redemption bug when a legitimate second executor is deployed. The redemption side is right; the
issuance side must learn which executor is actually requesting.

### F-4 · MEDIUM · The promised static drift gates were never built
**Task:** T-021

`scripts/validate_baseline.py` checks exactly three things: 30 README paths exist, fenced ```json
blocks parse, and absolute `$ref`s resolve to a known `$id`. It does **not** call
`Draft202012Validator.check_schema`, so a mistyped or misplaced keyword in SPEC silently becomes a
no-op constraint that every test still passes. There is also no I-16 check for a bare
`{"type": "string"}` in an identifier field, which was the named T-002 deliverable. No WORK_LOG entry
records the reduction in scope.

This is the finding that produced F-1 and F-2. It is the highest-leverage item in this review.

### F-5 · MEDIUM · `client_cert_spiffe` is consumed but never produced
**Task:** T-020

`app.py:69-76` reads `request.scope.get("client_cert_spiffe")` and 401s when absent. Nothing in the
repository sets that scope key: no middleware, no ASGI wiring, no deployment contract. As shipped,
every execution endpoint 401s, and I-23 is demonstrated only where tests inject the scope directly.
The behaviour is fail-closed, so this is a deployability and documentation defect rather than a
vulnerability — but the mTLS termination contract is a security contract and must be written down.

### F-6 · MEDIUM-LOW · Idempotent replay reports an evidence failure
**Task:** T-019

`find_decision_by_request` and `persist_decision` run in separate transactions. Two concurrent
requests with the same `request_id` produce a `UNIQUE(tenant_id, request_id)` violation, which the
blanket `except Exception` at `service.py:158-163` converts into **503 `evidence_write_failed`**.
A well-behaved client retrying under network uncertainty is told the evidence system is broken. That
misroutes incident response toward the audit pipeline — the most expensive possible wrong page.

### F-7 · LOW · Inconsistent defensive access to the same field
**Task:** T-018 (bundled)

`_revalidate` uses `previous_document["delegation"]["allowed_agent_ids"]` bare, where `service.py:46`
uses `.get("delegation", {})` for the same structure. A missing key yields a 500 instead of a 403.

### F-8 · LOW · Test shape hides which invariant broke
**Task:** T-022

`test_authorize_persists_adr_and_outbox_atomically` is roughly 290 lines and is cited in
`CONTRACT_COVERAGE.md` as primary evidence for I-1, I-9, I-10, I-18, I-19, I-23, I-25 and V-19. When
it fails, it will not tell you which of eight invariants regressed. Separately, `test_execution.py`
holds 2 unit tests against 677 lines of the most security-critical module in the system — the live
integration tests carry that weight today, which makes the fast feedback loop blind to it.

Related note: `InMemoryAuthorizationRepository.persist_decision` does not re-chain, so unit-level ADR
documents retain placeholder `sequence_number`/`prev_hash`/`record_hash`. The I-13 representability
property therefore validates a document that differs from the persisted one in three fields.

### F-9 · LOW · Documentation drift
**Task:** T-022 (bundled)

- `AGENT_ALLOCATION.md` TEST lane still mandates `I-1..I-22` / `V-1..V-14` against SPEC v1.3's
  `I-1..I-26` / `V-1..V-21`.
- `app.py:54` declares `FastAPI(version="1.1.0")` against SPEC v1.3.

(The CODEX execution-owner directive **was** propagated correctly to `AGENT_ALLOCATION.md`. This
drift is narrow, not systemic.)

### F-10 · LOW · Nested pool acquisition can deadlock under replay storm
**Task:** T-018 (bundled)

`_record_security_event` takes a second connection from the pool while the caller still holds one.
With `max_size=10`, a sustained replay burst can exhaust the pool and stall both paths. The durability
intent is correct; the resource discipline needs bounding.

---

## 3. Contract decisions requiring HUMAN ratification

Per H-7 these are not CODEX's to invent. Both are filed as WORK_LOG blockers.

### B-10 — Disposition of `CONSTRAIN`, `REDACT`, `ESCALATE` in v1 — **RATIFIED: Option A**

> **Ratified 2026-08-25** by the human owner, who selected **Option A**. Per the R-003 convention a
> single authorized human may ratify all required Product/Architecture, Cybersecurity, and
> Compliance/Business roles. T-016 is unblocked and READY. Option B is deferred to v1.4 as T-028.
> CODEX implements Option A exactly as specified in §4/T-016 and does not revisit the choice.

`SPEC_v1.md:17` says v0.1 implements `ALLOW | DENY | REQUIRE_APPROVAL` and that the remaining three
"MUST be accepted by parsers and rejected by the evaluator with `NOT_IMPLEMENTED`." The
implementation accepts and silently honours all six.

**Option A (RATIFIED) — Honour the existing rule.** The evaluator rejects a winning
`CONSTRAIN`/`REDACT`/`ESCALATE` outcome with a `NOT_IMPLEMENTED` Problem and a `DENY` ADR_Record, so
the refusal is auditable. Policy authoring continues to accept the values; only the evaluator
refuses. Ships in SPEC v1.3.1 as a clarification, not a semantic change. Cost: ~1 day. Removes the
silent-degradation hole immediately and truthfully.

**Option B (DEFERRED to v1.4 — T-028) — Implement constrained execution.** Add `constraints` to `ADR_Record` (schema version
bump), bind `constraints_hash` into token claims, verify it at redemption, and define who enforces
the constraint at the tool boundary — because Mizan issues the token but the executor performs the
action, so enforcement requires an SDK/adapter contract that does not yet exist. This is a genuine
epic touching ADR-008 and the SDK lane, not a fix. Cost: weeks.

**Rationale as ratified.** Shipping a constraint the executor cannot be compelled to honour would be
worse than declining to offer one. v1 declines it truthfully and auditably; v1.4 may implement it
properly once the executor-side enforcement contract exists.

### B-11 — Signing-key custody and rotation

Every signing key in the system is generated in-process: `evidence.py:75` calls
`Ed25519PrivateKey.generate()`, and the execution-token, receipt, anchor and degraded-grant keys have
no persistence, custody, distribution or rotation model. On restart, previously issued receipts and
anchors become unverifiable against the new key.

This is squarely H-7 (crypto and key management). CODEX must not choose a custody model. The decision
needed is: KMS/HSM versus filesystem-with-envelope-encryption; rotation period; whether `key_id` is
already carried in every signed artifact so that historical verification survives rotation (it
appears to be present in receipts — CODEX to confirm across all four artifact types); and whether
verification must succeed against retired keys indefinitely.

Until B-11 is ratified, the system is not deployable beyond a single ephemeral process, regardless of
how correct the cryptography is. Recommend prioritizing this decision.

---

## 4. Stage-2 task specifications

**Global rules of engagement for CODEX.**

1. **One task, one claim, one change-set.** H-1 applies: a live Claim Ledger row before any edit, and
   H-2 on completion. Do not batch T-016..T-022 into a single commit — this review will be validated
   task by task, and a bundled change-set cannot be dispositioned individually.
2. **H-3 is absolute.** Any change to a schema, endpoint, event, state machine, invariant, or config
   key requires an ADR delta in the same change-set. Spec wins over code.
3. **Do not widen scope.** Each task below has an explicit "Out of scope." If you find a defect
   outside it, file it as a WORK_LOG blocker and keep going — do not fix it inline. That is how F-4
   was quietly dropped last time.
4. **Every fix ships with the test that would have caught it.** A green suite that was green before
   the fix means the fix is unverified. State in the WORK_LOG entry which new test fails on the
   pre-fix code — and confirm you actually ran it against the pre-fix code.
5. **Report honestly.** If a task is blocked, park it and say so, as was correctly done for B-7/B-8.
   A PARKED task with a clear reason is a good outcome. A DONE task that quietly omits part of its
   acceptance criteria is not — that is the only thing in this process that cannot be recovered from.
6. **Benchmarks write artifacts.** Any performance claim must emit a JSON file under
   `benchmarks/results/` containing the measurement, host description, and commit SHA. Numbers that
   exist only in a terminal cannot be validated later (see §0, unreproduced sequencer figure).

---

### T-016 · Decision-enum completeness — `READY` (B-10 Option A ratified 2026-08-25)
**Lane rigor:** CLAUDE · **Depends on:** — · **Priority:** HIGH — sequence immediately after T-021

**Objective.** Eliminate the silent degradation of `CONSTRAIN`/`REDACT`/`ESCALATE`.

**Required change** — implement B-10 **Option A** as ratified. Do not implement constrained
execution, and do not extend the `ADR_Record` schema; both belong to T-028 (v1.4).

- `_combine` rejects a winning outcome outside `{ALLOW, DENY, REQUIRE_APPROVAL}` with a Problem whose
  type/code is `NOT_IMPLEMENTED`, HTTP 501.
- The refusal is recorded as a `DENY` ADR_Record so it is auditable, not merely returned.
- Remove the two dead `adr.get("constraints")` expressions at `execution.py:153` and `:509` rather
  than leaving code that reads as if constraints are bound. Dead security code is worse than absent
  security code because it reads as a control during review.
- Amend `SPEC_v1.md:1399`, which currently promises `CONSTRAIN/REDACT ─► token issued`.
- ADR delta required (ADR-002 and/or ADR-008) recording that v1 declines constrained execution and
  why.

**Acceptance criteria.**
- A policy returning CONSTRAIN produces 501 + a persisted DENY ADR_Record that validates against the
  `ADR_Record` schema. Test this at the property level over all six enum values, not with one case.
- `grep -rn "NOT_IMPLEMENTED" --include="*.py"` is non-empty.
- No expression in the codebase reads a `constraints` key from an ADR_Record.

**Out of scope.** Constraint enforcement semantics, SDK/adapter contract, `ADR_Record` schema
extension. Those are Option B / T-028 and are deferred to v1.4 by ratified decision — proposing them
inside T-016 is a scope violation under rule 3, not initiative.

---

### T-017 · `system_fail_closed` evidence path — `READY`
**Lane rigor:** CLAUDE · **Depends on:** —

**Objective.** Make every engine-failure denial evidence-representable, per I-8 / V-15 / SPEC:1410.

**Required change.**
- Wrap the `matching_policies` call the way the risk call is wrapped. A Cedar evaluation error must
  become a Problem, never an uncaught 500.
- Both failure paths write an ADR_Record with `decision=DENY`, `decision_basis=system_fail_closed`,
  `policies=[]`, pinning the evaluator/configuration version through evidence metadata as I-8
  requires.
- Determine the correct HTTP status from the SPEC and ADR-003 rather than reusing 503 by reflex: the
  request was *decided* (denied), not merely unserviceable. Whichever you choose, state the reasoning
  in the WORK_LOG entry.
- Define the terminal case honestly: if the evidence write **also** fails, there is no way to record
  anything, and 503-with-no-record is the only truthful outcome. That path must increment a
  distinct counter and emit an alertable log event, because it is the one state where Mizan denies
  without evidence. Do not hide it inside the generic handler.
- `service.py:158-163`'s blanket `except Exception` must stop swallowing distinguishable failures.
  Narrow it, and let unexpected exception types surface as themselves.

**Acceptance criteria.**
- A unit test injecting a policy-engine `RuntimeError` asserts a Problem response **and** a persisted
  ADR_Record with `decision_basis=system_fail_closed`, validated against the schema.
- Equivalent test for risk-engine failure.
- A test asserting the evidence-write-also-failed path emits the distinct counter/log event.
- `CONTRACT_COVERAGE.md` I-8 and V-15 rows point at these tests, replacing the current
  `default_deny`-only coverage.

**Out of scope.** Circuit-breaker/retry policy for the risk engine. Fail closed, do not add retries.

---

### T-018 · Execution issuance/redemption parity and resource discipline — `READY`
**Lane rigor:** CLAUDE · **Depends on:** — · **Covers:** F-3, F-7, F-10

**Required change.**
- **F-3:** `issue()` must bind the executor that will actually redeem, not `[0]`. The caller's
  verified workload SPIFFE identity is the natural source; if the issuing caller is not the executor,
  the executor must be an explicit, validated request field checked for membership in
  `executor_spiffe_ids`. Choose one, and make issuance and redemption use the *same* membership check
  so the two sides cannot drift again.
- **F-7:** make `_revalidate`'s delegation access defensive, matching `service.py:46`. A malformed
  stored document must yield 403, never 500 — a 500 on a security path is an information leak and an
  availability bug at once.
- **F-10:** bound the security-event connection. A dedicated small pool or an explicit acquisition
  timeout, so a replay storm degrades the event write rather than the whole service. Preserve the
  separate-connection durability property — that part is correct.

**Acceptance criteria.**
- A test with a two-executor tool proves the second executor can be issued a token and redeem it.
- A test proves an executor outside `executor_spiffe_ids` is refused at **both** issue and redeem.
- A test with a delegation-less stored document asserts 403, not 500.
- A concurrency test proves security-event writes cannot exhaust the primary pool.

**Out of scope.** Changing lease/heartbeat semantics or the redemption CAS. That code is correct.

---

### T-019 · Idempotent replay semantics — `READY`
**Lane rigor:** CLAUDE · **Depends on:** —

**Required change.** Catch the `UNIQUE(tenant_id, request_id)` violation specifically, re-read the
prior decision, and return it — a replay is a success, not an evidence failure. If the prior decision
is genuinely unreadable, 409 is the honest answer; 503 `evidence_write_failed` never is.

**Acceptance criteria.** A concurrent-duplicate test (two threads, same `request_id`) asserts both
callers receive the same decision and the same `decision_id`, with exactly one ADR_Record persisted.
Assert the record count — that is the invariant, not the status code.

**Out of scope.** Idempotency-key TTL or cache layers.

---

### T-020 · Workload identity termination contract — `READY`
**Lane rigor:** CLAUDE · **Depends on:** —

**Required change.**
- Implement the ASGI path that populates `client_cert_spiffe` from a verified peer certificate's
  SPIFFE URI SAN, terminated **in-process**. Extract the URI SAN explicitly; do not parse the subject
  DN or accept a CN.
- Do **not** add a trusted-proxy-header path. A header-based identity is only as strong as the proof
  that the header came from the proxy, and that proof does not exist in this repository today. If
  proxy termination is later required it is an ADR-001 delta with its own threat analysis, not a
  convenience flag.
- Document the deployment contract: required TLS configuration, trust bundle, and what happens when a
  peer presents no certificate (401, unchanged).
- ADR-001 delta recording that v1 requires app-terminated mTLS.

**Acceptance criteria.**
- An integration test with a real client certificate reaches an execution endpoint successfully.
- A test with no certificate, and one with a certificate lacking a SPIFFE URI SAN, both 401.
- The deployment contract is written and referenced from the README.

**Out of scope.** SPIFFE/SPIRE agent integration, certificate issuance, rotation.

---

### T-021 · Contract drift gates — `READY` (highest leverage; may be done first)
**Lane rigor:** CLAUDE · **Depends on:** —

**Objective.** Build the gate that would have caught F-1 and F-2, so this defect class stops
recurring.

**Required change** — extend `scripts/validate_baseline.py` with four checks, each failing loudly:

1. **Meta-schema validation.** `Draft202012Validator.check_schema` on every extracted schema. This
   is two lines and it is the single most valuable check in this review.
2. **I-16 identifier typing.** Any property whose name ends in `_id` or `_ids` must resolve to a
   typed `common#/$defs/*` reference, not a bare `{"type": "string"}`. This was the original T-002
   deliverable.
3. **SPEC-string reachability.** For a maintained list of behavioural tokens the SPEC promises —
   at minimum `NOT_IMPLEMENTED`, `system_fail_closed`, `default_deny`, `degraded_grant`,
   `constraints_hash` — assert each is either present in implementation source or listed in an
   explicit, dated `docs/reviews/UNIMPLEMENTED.md` waiver. This is the direct anti-F-1/F-2 control.
4. **Closed-schema producibility.** For each enum value a SPEC decision path can produce, assert the
   corresponding record is representable under the closed `ADR_Record` schema. This is the
   generalization of F-1 and the check that makes the class extinct rather than merely fixed.

Wire all four into CI as a blocking job.

**Acceptance criteria.** Each check must be demonstrated to fail against a deliberately broken
input before being accepted — commit the negative fixtures. A gate never observed failing is not a
gate. Confirm check 3 fails on the pre-T-016/T-017 tree and passes after.

**Out of scope.** Runtime validation changes; `schema_validation.py` behaviour is fine.

---

### T-022 · Test decomposition, execution coverage, and doc reconciliation — `READY`
**Lane rigor:** TEST · **Depends on:** T-017, T-018 (rebase onto their tests) · **Covers:** F-8, F-9

**Required change.**
- Split `test_authorize_persists_adr_and_outbox_atomically` so each of I-1, I-9, I-10, I-18, I-19,
  I-23, I-25 and V-19 has a test that fails for exactly one reason. Shared fixtures, separate
  assertions. A failing test must name the invariant it broke.
- Raise `test_execution.py` unit coverage to match the module's risk: token claim validation, TTL
  clamping, executor membership, each `_revalidate` rejection branch. Every branch that can return
  403 needs a test that reaches it.
- Make `InMemoryAuthorizationRepository.persist_decision` assign chain fields the way the Postgres
  adapter does, so unit-level documents are shaped like persisted ones and I-13 validates what is
  actually stored.
- Reconcile `AGENT_ALLOCATION.md` to I-1..I-26 / V-1..V-21, and `app.py:54` to the SPEC version.
- Update `CONTRACT_COVERAGE.md` to the decomposed test names, preserving its self-caveating header.

**Acceptance criteria.** No single test is cited as primary evidence for more than three contract
rows. `CONTRACT_COVERAGE.md` rows all resolve to collected tests (assert this in CI — it is a
three-line check and it makes the index self-enforcing).

**Out of scope.** Rewriting passing tests that are not over-cited.

---

## 5. Stage 3 — production readiness (queued, specified now so the path is visible)

These are not review findings. They are the gap between "the baseline is correct" and "a bank can run
this." They are specified here so Stage 2 is not designed in ignorance of them.

| Task | Summary | Gate |
|---|---|---|
| **T-023** | Load & latency harness: SPEC §7 targets — `/v1/authorize` p95 < 50 ms simple / < 150 ms complex, 500–1000 dec/s sustained, outbox→Kafka lag p95 < 2 s. Must run on deployment-class Linux, closing the standing B-2/B-6 obligation, and must emit a JSON artifact per rule 6. Supersedes the unreproduced sequencer figure. | TEST |
| **T-024** | Adversarial security suite named in `AGENT_ALLOCATION.md` but never queued: token replay, cross-tenant fuzz, chain-tamper, prompt-injection corpus (PRD §39/§62 >90% detection). Nightly CI. | TEST |
| **T-025** | Key custody, distribution and rotation across all four signed artifact types. **BLOCKED(B-11).** | CLAUDE |
| **T-026** | Outbox drain operations: runner, backpressure, poison-message handling, lag SLO instrumentation, SIEM delivery. | CURSOR |
| **T-027** | Threat model v1 — `threat-models/` contains only a README. Non-delegable per `AGENT_ALLOCATION.md`. | HUMAN |
| **T-028** | Specification work for constrained execution (B-10 Option B), including the executor-side enforcement contract. **DEFERRED to v1.4** by the ratified B-10 decision. Not in Stage 2 or Stage 3 scope. | HUMAN → CLAUDE |

**Sequencing recommendation.** T-021 first (the gate), then **T-016** (now unblocked and the
highest-severity finding — and the gate's §4/check-3 reachability test is what proves it landed),
then T-017/T-018/T-019/T-020 in any order (they are independent), then T-022 to consolidate. Do not start Stage 3 until Stage 2 is
DONE — T-023's numbers are meaningless against a tree that still has F-2 in it, since a fail-closed
path that returns 500 instead of a decision will distort the latency distribution.

---

## 6. How this work will be validated

CODEX should assume every claim below is re-run, because the claims in §0 were.

1. `make check`, lint, full unit/property suite, and `make test-postgres` — re-run, not read.
2. For each finding, the specific `grep`/file:line evidence cited above — re-checked against the new
   tree. A finding is closed when its evidence no longer reproduces, not when a log entry says DONE.
3. For each new test, confirmation it fails on the pre-fix commit. Please make this easy by naming
   the pre-fix SHA in the WORK_LOG entry.
4. `scripts/validate_baseline.py` negative fixtures — each drift gate observed failing.
5. Benchmark artifacts under `benchmarks/results/`, checked for host and commit SHA.
6. Claim Ledger and WORK_LOG discipline across every commit in the range.

A task that lands with its acceptance criteria genuinely met and one criterion honestly parked is a
better outcome than one that lands DONE with a criterion quietly skipped. The former costs a day; the
latter costs the credibility of every other DONE in the log.

---

## 7. Ratification

**B-10 — RATIFIED 2026-08-25 (Option A).** The human owner selected Option A: the evaluator rejects
`CONSTRAIN`/`REDACT`/`ESCALATE` with `NOT_IMPLEMENTED` and an auditable `DENY` ADR_Record; constrained
execution (Option B) is deferred to v1.4 as T-028. T-016 is unblocked and READY.

**B-11 — OPEN.** Signing-key custody and rotation still requires HUMAN sign-off in
Product/Architecture, Cybersecurity, and Compliance/Business roles. It gates T-025 and, in practice,
any deployment beyond a single ephemeral process. Suggested response:

> I ratify R-004 B-11 <chosen custody model> in all required roles.

T-016 through T-022 are all executable immediately. Only T-025 is gated on B-11.
