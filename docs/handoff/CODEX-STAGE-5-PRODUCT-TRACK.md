# CODEX work order — Stage 5, Track B: the loop closes and the product becomes runnable

**Issued:** 2026-08-26 · **Issuer:** CLAUDE lane (acceleration review over head `f4f90a2`) ·
**Ratification:** B-15 (parallel track) pending HUMAN; B-16/B-17/B-18 carry recommended defaults so
work can start on everything that does not depend on them.
**Runs alongside:** `docs/handoff/CODEX-CP-C-RUN-2.md` (Track A). Track A's order is unchanged in
content; T-026 and T-023 are pulled forward into this track as T-074 and week-4 work.

Everything in `CODEX-STAGE-3.md` §2 (one task, one commit; H-3 absolute; rule 6 mechanical;
rules 8–12) applies here unchanged. Track B never touches `evidence.py`, `attestation.py`,
`keys.py`, `canonical.py`, `verify_evidence_export.py`, or bundle format 1.0. If a task needs to,
stop and park it.

---

## 0. Why this order exists

Five audits were run in parallel over `f4f90a2` and their load-bearing findings were verified by
hand. The tree is green — 198 unit/property tests, `make check` five drift gates, the R-007 gate
8/8 at exit 0 — and it is not runnable:

- `create_app()` has no caller outside tests. There is no `__main__`, no module-level `app`, no
  uvicorn reference anywhere in source. Only `mizan-export-evidence` and `mizan-attest-anchors`
  are installed, and the latter raises `TypeError` at startup (`attestation_runner.py:53-57` passes
  `environment=` to `Rfc3161AnchorProvider.__init__`, which does not accept it).
- `ApprovalRepository.create` and `ExecutionService.issue` have no callers outside tests. A
  `REQUIRE_APPROVAL` decision opens nothing, and no route issues an execution token after ALLOW or
  APPROVED. PRD §37 "pause and resume" is not a running property.
- `Redactor` is never instantiated by `app.py` or `service.py`.
- `OutboxPublisher.drain/anchor` have no runtime caller; receipts and anchors are produced only by
  tests and benchmarks.
- Three security findings verified in source (§3, T-077).

The PRD's MVP sentence — *centrally control, authorize and audit an AI agent's access to
enterprise tools* — is what this track makes true as a system rather than as a test suite.

---

## 1. Tasks

Sixteen tasks. Effort is for the first shippable version. "Gate" is the acceptance test that must
fail on the named pre-fix commit (rule 8/9) and pass after.

### T-066 · Runnable service (S/M) — week 1, first

- Add `mizan_control_plane/__main__.py` and a `mizan-control-plane` console script that builds
  `Settings.from_environment()`, constructs the key provider from `MIZAN_KEY_CUSTODY_MODE` +
  `signing_key_refs`, and passes `ExecutionService`, `ObjectEvidenceVerifier` and `KeyProvider`
  into `create_app`. Production (`MIZAN_ENV=production`) **refuses to boot** when any of the three
  is absent; the current 503-on-missing-component behaviour (`app.py:220-223, 294-295, 346-349`)
  stays only for development.
- FastAPI lifespan: open pools once, close every `ConnectionPool` on shutdown (today five pools
  open at construction and never close — `repository.py:26`, `evidence.py:244`,
  `approval_repository.py:19`, `execution.py:94-99`, registry).
- `/health/ready` checks the database (a tenant-less `SELECT 1` as `mizan_app`), the key provider
  (`active_key` for every role), and — in production — the anchor provider configuration.
- Fix the `mizan-attest-anchors` `TypeError`. Gate: a test that invokes `main()` with a stubbed
  repository against `f4f90a2` and fails with `TypeError`.
- Register `MIZAN_DATABASE_URL`, `MIZAN_JWT_ISSUER`, `MIZAN_JWT_AUDIENCE`, `MIZAN_JWT_PUBLIC_KEY`,
  `MIZAN_EVALUATOR_BUILD`, `MIZAN_EVALUATOR_CONFIGURATION_HASH` in SPEC §8 (H-3 — they are read
  today and unregistered).

### T-067 · Close the loop (M) — week 1, needs B-16 (default provided)

- `AuthorizationService.authorize`: when the combined decision is `REQUIRE_APPROVAL`, open the
  Approval (`ApprovalRepository.create`) **in the same transaction** as the ADR_Record, and emit
  `mizan.approval.requested` per SPEC §4.
- `GET /v1/approvals?state=PENDING|…&limit&cursor` — tenant-scoped, I-3 tested, added to SPEC §3.
- `POST /v1/decisions/{decision_id}/execution-token` — issues via `ExecutionService.issue` after
  ALLOW or after the approval reaches APPROVED. Default semantics (B-16): the requesting principal
  must be the decision's own agent principal; exactly one unconsumed token per decision, so a
  repeat call returns the existing token (idempotent); TTL from
  `MIZAN_EXECUTION_TOKEN_DEFAULT_TTL_SECONDS` (SPEC §8, currently unread). Closes the
  one-ALLOW-many-tokens finding.
- ADR delta on ADR-007/ADR-008 in the same change-set (H-3). Stamp `pending ratification (B-16)`.
- Gate: a live-Postgres test walking authorize → pending list → two-domain votes → token → execute
  → complete; on `f4f90a2` it fails at the pending list with 404.

### T-068 · `make demo` bootstrap (S) — week 1

- `compose.yaml` profile `demo`: Postgres (with a named volume), the control plane, the outbox
  drainer (T-074) and — optionally — a local RFC 3161 TSA from the R-007 reproduction.
- `mizan-dev-token`: mints RS256/EdDSA tokens with the claims `TokenVerifier` requires
  (`tenant_id`, `agent_id`, `identity_kind`, `auth_strength`, `roles`). Refuses
  `MIZAN_ENV=production`, and the verifier refuses its issuer in production.
- `scripts/seed_demo.py`: one tenant, one agent (`agt_wealth-advisor`), three tools
  (`portfolio.read`, `riskprofile.read`, `portfolio.rebalance`), two ACTIVE policies
  (read → ALLOW; rebalance → REQUIRE_APPROVAL with two control domains).
- Gate: `make demo` from a clean checkout, then `curl /health/ready` → 200.

### T-069 · Python SDK v0 (S/M) — week 2

- `sdk/python/mizan/`: `MizanClient.authorize(...)` that builds a valid `EvaluationContext` from
  sane inputs (UUIDv7 `request_id`, RFC 3339 ms timestamp, `parameters_hash` per the binding
  profile), `wait_for_approval(decision_id)`, `execution_token(decision_id)`.
- `@mizan.govern(tool_id=...)` decorator; wrappers for Anthropic and OpenAI tool-use handlers;
  a LangChain `BaseTool` adapter. Generated types from the OpenAPI document `create_app` exposes.
- Gate: SDK test suite against `make demo`; the decorator round-trips ALLOW and REQUIRE_APPROVAL.

### T-070 · MCP Governance Gateway v0 (M) — week 2, the headline

- `integrations/mcp/mizan_mcp_gateway/`: an MCP server (stdio and streamable HTTP) that wraps an
  upstream MCP server given by config.
- `tools/list`: pass through; auto-register unknown tools via `POST /v1/tools` under a configured
  operator credential and a declared default `risk_tier` (never below the tool registry floor).
- `tools/call`: build the context (principal from the MCP session/config, agent from gateway
  identity, tool, arguments hashed per binding profile, intent from the client's stated task),
  call `/v1/authorize`; on ALLOW obtain the token (T-067), forward to upstream under a lease,
  `complete` with the outcome; on REQUIRE_APPROVAL block with progress notifications and poll
  until resolved or expired; on DENY return a structured refusal that names the reason class.
- The gateway **never decides**. Every path emits an ADR_Record or refuses. It is the SPIFFE-bound
  executor of ADR-008; in `make demo` the SPIFFE identity comes from the dev token, in production
  from mTLS.
- Gate: Claude Code (or any MCP client) configured with one line calls the demo tools; the
  decision stream shows three ADR records; the rebalance call blocks until the T-072 inbox votes.

### T-071 · PRD §38 demo, end to end (S) — week 2

- `examples/wealth-agent/`: a ~200-line agent (Anthropic tool use by default; OpenAI optional)
  plus a mock wealth API, run through T-070. Scripted run committed as a deterministic transcript;
  recorded walkthrough linked from README.
- Gate: `make demo-run` completes: two ALLOW, one REQUIRE_APPROVAL, approval, execution, export,
  and `verify_evidence_export.py` PASS on the resulting bundle.

### T-072 · Approver inbox (M) — week 2

- `ui/`: Approvals view — pending list with SLA countdown and epoch/quorum state; ADR summary card
  (agent, principal, customer, intent, risk, reasons); vote with justification; escalate/override
  with ADR-007 guards surfaced; decision timeline rendered from DecisionEvents; **Export evidence
  bundle** (T-043 entry point) and **Download verifier** links.
- Keep ADR-009's rules: provider-controlled strings through text nodes; no synthesized history.
- Gate: JS tests over a fixture API; a manual checklist in `ui/README.md` walked once and recorded.

### T-073 · Observability (M) — week 2

- JSON structured logging with request id and tenant id (never payload bodies), `print` removed
  from the runner; OpenTelemetry traces with W3C propagation (today `trace_id` is derived from a
  hash of `request_id`, `service.py:378`); Prometheus `/metrics` exporting the existing
  `failure_counters` and `security_event_counters`; an alert-worthy event when the security-event
  pool drops an event (`execution.py:391-393`).
- Gate: a test asserts a dropped security event increments a metric and logs at ERROR.

### T-074 · Outbox drain worker + expiry sweeper (M) — week 2 (absorbs T-026 scope)

- `mizan-drain-outbox`: iterates tenants/streams, calls `OutboxPublisher.drain` then `anchor` on
  `MIZAN_AUDIT_ANCHOR_INTERVAL_*`, interval from `MIZAN_OUTBOX_DRAIN_INTERVAL_MS`, backpressure,
  poison handling, lag SLO (`MIZAN_EVIDENCE_MAX_UNPUBLISHED_SECONDS`), signal handling.
- Expiry sweeper: a scheduled, outbox-transactional pass that moves open epochs to `EXPIRED` and
  leases to `LEASE_EXPIRED`, emitting `mizan.approval.expired` / `mizan.execution.lease_expired`.
  Today neither state is ever reached at rest.
- Gate: live-Postgres test — an expired epoch is swept and its event lands in the outbox.

### T-075 · Image, deployment profile, migration runner (M) — week 3

- Multi-stage `Dockerfile` (uv, non-root, `openssl` present for `ts -verify`), SBOM and image
  scan in CI; Helm chart or production compose profile with app, drainer, attestation runner,
  migration job; a migration runner with a version table so `0002`/`0003` apply to an existing
  database. Confirm the app connects as `mizan_app`, never `mizan_owner`.
- Gate: CI builds the image and boots it against Postgres to `/health/ready` 200.

### T-076 · One real key backend (L) — week 3, needs B-18

- `KmsHsmBackend` implementation for HashiCorp Vault Transit (native Ed25519), selected by
  `MIZAN_KEY_CUSTODY_MODE=kms` with `custody="kms"`; PKCS#11 (`custody="hsm"`) as the second.
  Note for the founder: AWS KMS, GCP Cloud KMS and Azure Key Vault do not sign Ed25519; choosing
  one of them would reopen the signing algorithm and bundle format 1.0. Do not build that here.
- Gate: integration test against a Vault dev container; production boot with `local://` refs
  still refuses (T-053 behaviour preserved).

### T-077 · Security fixes from the acceleration review (S each) — a–c in week 1, d–f in week 3

All are CLAUDE-gate paths: invariant suite green plus human security review. Each ships with the
pre-fix failing test and SHA.

- **a. Registry write authority** (needs B-17; default: human + MFA only). `POST /v1/agents`,
  `POST /v1/tools`, `POST /v1/tools/{id}/binding-profile`, `POST /v1/policies` currently depend
  only on `tenant_from_token` (`app.py:76-81, 121-126, 141-154, 156-161`). Pre-fix demonstration:
  an `identity_kind:"agent"` token registers a tool permitting itself.
- **b. PATCH dual-control from old ∪ new.** `registry.py:319-322` derives `protected` from the
  incoming document; compute it from both, and re-validate the delegation edge that `create_agent`
  enforces (`registry.py:93-107`). Pre-fix demonstration: single-operator downgrade of a production
  CRITICAL agent to LOW with a tool change in one write.
- **c. `PolicyCompileError` → `system_fail_closed`.** `service.py:152-156` catches
  `RuntimeError`; `PolicyCompileError(ValueError)` from `_cedar_context` (`policy_engine.py:117-124`)
  escapes as a 500 with no ADR. Pre-fix demonstration: `security.anomaly_score: 0.12345`.
- **d. Token hygiene.** Max accepted TTL, `kid`/JWKS rotation, token class claim; dev issuer refused
  in production (`auth.py:18-27`).
- **e. Escalate/override authorization.** `POST /approvals/{id}/escalate` has no authorization
  (`app.py:317-322`); override trusts the `roles` claim without a human/MFA check.
- **f. Body-size cap** and bounded lengths for `resource.id`, `agent.version`, `delegation_chain[]`,
  `principal.role` (`models.py:15-25, 89`).

### T-078 · SPEC §4 event conformance (M) — week 3

- Emit §4 names at the writers (`evidence.py:237`, `registry.py`, `approval_repository.py`);
  registry creates/publishes must write outbox rows (today none do). 4 of 32 names are emitted.
- A gate test enumerates §4 and fails on any spec name with no emitter, and any emitted name not
  in §4. Where the `mizan.decision.*` projection is preferred, amend §4 by ADR instead — but decide,
  do not leave both.

### T-079 · Test and CI honesty (S/M) — week 1

- Unit tests for `auth.py` (issuer/audience/alg confusion, missing claims) — 0% today.
- `app.py` routes through `TestClient(create_app(...))` with injected fakes — 0% today.
- Per-module coverage floors (`mizan_control_plane` ≥ 60% overall; `auth`, `app`, `registry`
  explicit floors) — the only gate today is `execution.py` at 51% vs a 50% floor.
- Run `docs/reviews/reproductions/R-007-cpb-attestation.py` in CI.
- Under `CI=true`, an absent `MIZAN_TEST_DATABASE_URL` fails instead of skipping.
- Fix the three rule-11 tests: `test_veto_and_rejection_quorum_are_distinct`,
  `test_dual_control_counts_distinct_control_domains`,
  `test_real_spiffe_uri_san_reaches_execution_endpoint`.

### T-080 · Config registry reconciliation (S) — week 3

- 30 of 48 SPEC §8 keys are unread. Each becomes either read (with production validation as for
  the anchor keys) or a dated waiver row in `docs/reviews/UNIMPLEMENTED.md`. `is_degraded` is
  hardcoded false in `service.py`; `mizan_security/degraded.py` is unwired — wire it or waive it.

### T-081 · Policy studio v0 (S/M) — week 3

- UI over `POST /v1/policies/{id}/simulate`: pick a draft, replay it over the last N decisions from
  `/v1/decisions`, show every ALLOW↔DENY flip, and the TESTED transition button that the lifecycle
  already gates on a simulation row.

---

## 2. Sequence

```
W1  T-066 → T-077c → T-077a/b → T-068 → T-067 → T-079          (Track A: T-053 ✓commit → T-054 → T-065)
W2  T-069 → T-070 → T-071 → T-072 → T-074 → T-073               (Track A: T-062 → T-063)
W3  T-075 → T-076 → T-077d/e/f → T-078 → T-080 → T-081          (Track A: T-038 → T-039 → T-060)
W4  runbooks · TM-001 ratified · pilot guide · scorecard        (Track A: T-064 → T-040 → T-024 → T-023)
```

Every Friday: the loop demonstrated live, ideally to a design-partner contact. Record shown /
offered / ran-it-themselves per `docs/product/FALSIFICATION_TESTS.md` F-T-1.

## 3. What to park, and how

- Any task that needs `KeyProvider`, approval semantics, or tenant isolation to *change* rather
  than be *used*: park under H-7 with a blocker row. B-16 and B-17 already exist for the two
  known cases.
- T-070 must not grow a local policy cache or a "fast path" that skips `/v1/authorize`. If latency
  forces it, park and report the number with its `benchmarks/results/` artifact.
- If T-076 discovers the pilot mandates a cloud KMS without Ed25519, stop: that is a bundle-format
  decision for the founder, not an adapter.

## 4. Coordination with Track A

Track B claims live in the same Claim Ledger. Track B log entries go under a `### Track B` heading
in the Log so the two streams do not interleave. Merge through pull requests to `main`; do not
commit to `main` directly from two sessions.
