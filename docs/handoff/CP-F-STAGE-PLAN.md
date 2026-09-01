# CP-F — Make the trunk prove the product runs

**Founder stage plan, 2026-08-28.** Supersedes nothing; CP-E's orders remain live and their
unfinished tasks are carried into the waves below. `docs/handoff/PR-PROTOCOL.md` governs how every
task lands and does not change.

---

## 0. The sentence this stage exists to make false

> **The demo passes because it stops immediately before the part that is broken.**

`scripts/demo_walk.py:32-34` ends at `REQUIRE_APPROVAL` and never redeems the execution token. That
is the exact line at which the product stops working, and the demo stops one line earlier.

Three things are true today, each verified in the tree, not reported:

**Mizan cannot start in production, in any configuration.** `config.py:69-72` refuses
`MIZAN_ENV=production` unless custody is not `development`. `runtime.py:37-43` refuses to build a key
provider unless custody *is* `development`. Both shipped manifests set `kms`
(`compose.production.yaml:7`, `charts/mizan/values.yaml:24`). `custody=kms` raises `StartupRefused`;
`custody=development` raises `RuntimeError`; `__main__.py:29-31` turns either into exit 78.
`KmsHsmKeyProvider` exists at `keys.py:129` with no backend behind it anywhere in the tree. There is
no shippable middle. `helm install` crash-loops and so does `docker compose --profile production up`.

**CP-E's own pass criterion is unreachable on a real deployment.** `mizan-drain-outbox` is the
entrypoint of both production manifests (`compose.production.yaml:83`,
`charts/mizan/templates/drainer-deployment.yaml:30`) and is **not** among the five console scripts in
`pyproject.toml:18-23`. It does not exist. Nothing drains, so `mizan.evidence_receipts` is never
written; `execution.py:410-411` requires a receipt for `financial_write`; `execution.py:812-820`
raises 403 `immutable_receipt_missing`. Mizan pauses the payment for a human, the human approves it,
**and Mizan refuses it anyway, permanently.** No receipts means no anchors, no anchors means no RFC
3161 timestamps, and `mizan-export-evidence` then raises "cannot export an empty evidence range" —
there is no bundle for the second verifier to check. CP-E steps 3, 4 and 5 cannot happen.

**The gate that certifies otherwise is a substring search.**
`tests/unit/test_packaging.py:70-97` reads Dockerfile, compose, values and ci.yml **as text** and
asserts substrings — including `assert 'profiles: ["drainer"]' in compose`, which asserts the presence
of the service pointing at the missing binary. No `helm lint` or `helm template` runs anywhere. CI's
only container boot (`ci.yml:126-143`) passes `--env MIZAN_ENV=development`, so the production
readiness checks at `app.py:518-524` never execute. This is the third instance of this repository's
documented failure mode — *a gate that reports a result nobody reproduced* — in the highest-stakes
place it has appeared yet.

**Two more, found on the second pass, and both are the same defect as the first.** The console
scripts do not start from an installed environment: `.venv/bin/mizan-mcp-gateway --help` raises
`ModuleNotFoundError: No module named 'mizan_mcp_gateway'`. The MCP Governance Gateway is Track B's
declared **headline** — the thing that wraps any MCP server and is the ADR-008 executor — and it runs
only under pytest, where the source tree happens to be on `sys.path`. And the drainer is hidden behind
`profiles: ["drainer"]` at `compose.production.yaml:81` while every other service is
`profiles: ["production"]` — a component without which `execution.py:819` refuses every high-risk
financial write is shipped as an **optional** profile.

## 1. And the second thing: nothing merges

Six PRs open. **Zero merged, ever.** `main` @ `f4f90a2` is twenty commits behind `track-b/ui` and
eighteen behind `track-b/stage-5`, and zero ahead of either. Verified 2026-08-28:

| PR | baseline | python | postgres | production-image | offline-verifier | gates |
|---|---|---|---|---|---|---|
| #1 T-087 | fail | fail | pass | — | fail | pass |
| #2 track-b/ui | fail | fail | pass | pass | fail | pass |
| #3 track-b/stage-5 | fail | fail | pass | — | fail | pass |
| #4 T-088 | **pass** | fail | pass | — | fail | pass |
| #5 T-090 | fail | **pass** | pass | — | fail | pass |
| #6 T-091 | fail | fail | pass | — | **pass** | pass |

Read the bold cells. `baseline-contract` fails on `ModuleNotFoundError: No module named 'jsonschema'`
and **#4 fixes it**. `python-contract` fails on the 100k-chain budget set from a laptop and **#5 fixes
it**. `offline-evidence-verifier` fails on `RFC 3161 TSA certificate is expired` and **#6 fixes it**.

Every red job already has its fix. Each fix is in a different unmerged pull request. There is no tree
anywhere in this organisation that is green, and there does not need to be any new engineering to
produce one — only merges. **The constraint is not capability. It is that nothing composes.**

CP-E asked the right question and got the right answer: CI now runs, and it is telling the truth. The
failure is that we built six answers and shipped none of them.

## 2. What CP-F is

CP-F passes when **one person who does not work here**, on a machine that has never run Mizan,
starting from `git clone` of `main` at the stage-closing commit — no branch, no laptop of ours, no
help — completes all seven steps, and **we publish where they got stuck**:

1. They follow `INSTALL.md` and bring the stack up **in production mode** (`MIZAN_ENV=production`,
   real custody). No exit 78. No process started by hand. Every command they run is either printed in
   the quickstart or emitted by the previous step's own output.
2. A governed agent attempts a payment through `mizan-mcp-gateway`, started as an **installed console
   script** — not under pytest, not with a source directory on `sys.path` — and is refused pending
   approval, printing the console URL.
3. They approve it in the browser **by clicking**, not with `curl`. The run resumes, the tool
   executes, and the execution token redeems.
4. With no worker they started themselves, the evidence drains, anchors, and receives an RFC 3161
   token. The run prints the anchor id and the timestamping authority's name.
5. A bundle exports and **both** verifiers — `scripts/verify_evidence_export.py` and `verifier-two`
   under `node` — print the same verdict, the same assurance line and the same NOT COVERED list,
   against trust roots the stranger supplied themselves, with the network off.
6. The bundle states, at equal prominence with the verdict, everything it does not prove — including
   its signing-key custody — and the stranger can point at the sentence in the documentation that told
   them so **before** they ran it.
7. **And CI ran steps 1 through 6, in production mode, on that commit.**

It **fails** if any of these is true: a step needs a command that is neither written down nor printed;
any step works only because a source directory was on `sys.path`; the two verifiers differ on any line
of verdict, assurance or not-covered; the `main` push run for the stage-closing commit is not green on
every job that commit's `ci.yml` declares; or the walkthrough is performed by me or by either engineer.

The instrument is `docs/reviews/CP-F-WALKTHROUGH.md`, written by the observer, naming the machine and
listing every guessed command and every place the documentation was wrong. **Rule 10 binds: an empty
corrections list is evidence the walkthrough was not run, not evidence that it passed.**

Step 7 is what makes this a stage rather than a demo. Steps 1-6 are CP-E's criterion; what CP-E lacked
was any mechanism that would notice when they stopped being true. They were never true, and nothing
noticed for nineteen commits.

**One correction to CP-E's criterion, and it is mine to make.** CP-E required the demo to run against
a real LLM. A stranger on a clean machine does not have a model API key, so as written the criterion
contradicts itself. The gate replays a committed transcript of real `tool_use` blocks and asserts on
decisions, refusal reason classes and ADR_Records — never on model prose. `make demo-run MODEL=live`
re-records it against a real model, and T-071 still does that work. See **B-23**.

## 3. Non-goals — say no now, loudly

CP-F does **not** include, and no engineer should start:

* Multi-region, HA, autoscaling, or any availability work beyond two replicas that do not corrupt
  each other.
* AWS KMS, GCP Cloud KMS, Azure Key Vault. None sign Ed25519; choosing one reopens bundle format 1.0
  (B-18). One backend, Vault Transit, and it must boot.
* **Stage 4 decision replay (T-044..T-048).** Five tasks, none started, gated on a data-residency
  ruling (B-13) that no pilot needs answered. Parked to CP-G.
* T-064 adversarial evidence review, T-040 `make attack`. Both are worth more after T-038/T-039 change
  the hostile-party answer; neither belongs in front of a product that cannot boot.
* The PRD's AI Architecture Copilot and AI Use-Case Factory. There is no code behind either. They are
  roadmap, not product, and listing them as modules costs credibility in a room where the rest is real.
* SOC 2, ISO 27001, pen-test engagement, marketing site.

## 4. What we are killing or declaring finished

| Item | Disposition | Argument |
|---|---|---|
| **T-038, T-039** (RFC 6962 inclusion + consistency proofs) | `DEFERRED(CP-G)` | These are the two tasks that change the hostile-party answer and they are correctly specified. But **you cannot add a field to a format that has three incompatible definitions of itself** — `EVIDENCE-BUNDLE-FORMAT.md` mentions `custody` twice on `track-b/ui` and zero times on `main` and `t-091`. T-110 reconciles the grammar; the proofs follow it, in CP-G. Both verifiers already disclose the omission gap at equal prominence, which is the second-best answer and is shipped. |
| **T-060** (what verification costs) | `DEFERRED(CP-G)` | It is the argument for whether inclusion proofs are the primary auditor interface. Nothing to measure until they exist. |
| **T-064, T-040** | `DEFERRED(CP-G)` | Worth most after T-038/T-039 change the answer. Neither belongs in front of a product that cannot boot. |
| T-044..T-048 (Stage 4 replay) | `PARKED(CP-G)` | Five PROPOSED tasks, zero started, blocked on a data-residency ruling (B-13) no pilot needs answered. A bank asks "can I verify this myself", not "can you recompute it". T-062 answers the first; replay answers neither. Built today, it has an audience of zero — no external party has yet run the verifier at all. |
| T-023 (load & latency harness) | Superseded by **T-116** | A one-off measurement in a file nobody re-runs is exactly how the 100k budget came to be set from a laptop faster than the CI runner. |
| T-026 (outbox drain operations) | `DONE(absorbed by T-074/T-099)` | Already absorbed on paper. Close the row so the queue stops implying two workers. |
| T-080 (config registry reconciliation) | Superseded by **T-109** | Its premise is wrong in both directions — 57 keys not 48, 21 unread not 30, and 16 keys used in shipped artifacts are unregistered. Rewrite rather than close against a bad count. |
| T-081 (policy studio) | **Done enough** | A real feature. No design partner has asked for it and it is not on the stranger's path. It lands with the lane merge and gets no further investment this stage. |
| T-082 as written | Replaced by **T-095** | Its conflict list is a lower bound, not a list — there is a third, an add/add on `tests/unit/test_postgres_skip_guard.py` where both engineers wrote the same guard. Its "360 passed / 35 skipped" is a prediction from a naive resolution. |
| The `drainer` compose profile | **Killed** | A component without which every high-risk financial write is refused is not an optional profile. It moves into `production` under T-099. |
| "A real LLM" as a gate condition | **Killed as a gate**, kept as work | A stranger on a clean machine has no API key. The gate replays a committed transcript of real `tool_use` blocks; `MODEL=live` re-records it. See B-23. |
| Twenty-three stub directories | **Deleted** (T-115) | `sdk/typescript` is 94 bytes, `sdk/java` 88, `integrations/siem` 78, `integrations/kafka` 111. A browsing design partner reads them as shipped surface. This is not tidying — it is a claim we cannot support. |
| The directory-ownership lane model | Dead, confirmed | Withdrawn by PR-PROTOCOL §5. Reduce `AGENT_ALLOCATION.md` to one line pointing there. |

**Closed by T-132:** the console no longer accepts or retains a pasted bearer. Production uses the
customer IdP's OIDC Authorization Code flow with PKCE/state/nonce, an opaque HttpOnly server-side
session, group-to-role/control-domain mapping, and a fresh MFA/hardware step-up immediately before a
HIGH/CRITICAL vote. Logout, revocation and refused expired/revoked sessions leave chained identity
events. Customer IdP registration and group mapping remain installation inputs, not product gaps.

Two things are **finished and must not be rebuilt.** `scripts/migrate.py` is a real versioned runner —
`mizan.schema_migrations`, per-file sha256, `pg_advisory_lock` around the run, checksum enforcement,
refusal on a recorded-but-absent migration, correct initdb adoption — and `ci.yml:109-124` exercises a
genuine upgrade path. The database privilege model is likewise done: `mizan_app` NOLOGIN NOSUPERUSER
NOBYPASSRLS, `FORCE ROW LEVEL SECURITY` on every table, UPDATE and DELETE revoked on the evidence
tables. **The two things that would be unrecoverable in a pilot are the two that are finished.** Worth
saying out loud, because everything else in this document is a defect list.

---

## 5. The targets

New rows for the `Agent Queue`. Numbering continues from T-093; nothing is renumbered. Existing READY
rows keep their numbers and are referenced in `Depends on`, never duplicated.

| # | Task | Lane | Depends on | State |
|---|---|---|---|---|
| T-094 | **The merge train.** Land the open PRs in an order that composes, one at a time, rebasing each on the last: #4 (jsonschema) → #5 (chain budget) → #6 (TSA lifetime) → #1 (PR infrastructure). `main` must end **green on every job its own `ci.yml` declares**. No new engineering: every red job's fix already exists in one of these PRs. A rebase that turns a green job red is a stop-and-report, not a fix-forward | CLAUDE | — | READY |
| T-095 | **Lane integration** (replaces T-082 as written). Land #3 then #2. T-082's conflict prediction is a **lower bound**, not a list: besides `WORK_LOG.md` and `tests/CONTRACT_COVERAGE.md` there is a third — an add/add on `tests/unit/test_postgres_skip_guard.py`, where both engineers wrote the same guard independently. Union it; do not take a side. Re-run with PostgreSQL and assert the **job set**, not just the pass count — a green merge that loses an assertion is the worst outcome and the easiest to miss. Delete both lane branches | CLAUDE | T-094 | BLOCKED(T-094) |
| T-096 | **Something enforces the trunk.** `gh api repos/prasantk8/mizan/branches/main/protection` returns **403 — "Upgrade to GitHub Pro or make this repository public."** Branch protection is unavailable on this plan, so PR-PROTOCOL §7's "`main` protected: CI required, one approving review, linear history, no force-push" describes a control that **cannot be configured**. Per **B-22**: ship the substitute — a `trunk-guard` workflow on `push: [main]` that fails loudly on a red or unreviewed trunk — and, if B-22 rules that way, buy the plan and configure the real thing | CLAUDE | **B-22**, T-094 | BLOCKED(B-22) |
| T-097 | **`WORK_LOG.md` stops serializing every merge.** It is now the most frequently conflicting file in the repository, which PR-PROTOCOL §7 calls correct. It is not: with one PR per task it makes every pair of concurrent tasks conflict on a file neither is about. Split the queue into per-task fragments with a generated index, or install a union merge driver — pick one and say why | CODEX | T-095 | BLOCKED(T-095) |
| T-098 | **Every declared console script starts from an installation.** `.venv/bin/mizan-mcp-gateway --help` raises `ModuleNotFoundError: No module named 'mizan_mcp_gateway'`. Track B's **headline** deliverable runs only under pytest, where the source tree happens to be on `sys.path`. Fix the packaging, then gate it: CI installs the wheel into a clean environment and runs `--help` on **every** `[project.scripts]` entry. Rule 9 — the gate must reject today's tree | CODEX | T-094 | READY |
| T-099 | **`mizan-drain-outbox` exists, and is not optional.** It is the entrypoint at `compose.production.yaml:83` and `charts/mizan/templates/drainer-deployment.yaml:30` and is **not** among the five console scripts in `pyproject.toml:18-23`. Ship T-074's worker as that script, and move the service out of `profiles: ["drainer"]` into `production` — a component without which `execution.py:819` refuses every high-risk financial write is not an optional profile. Rule 8: the pre-fix demonstration is the 403 `immutable_receipt_missing` | CODEX | T-098 | BLOCKED(T-098) |
| T-100 | **The packaging gate resolves what the manifests launch.** `test_packaging.py:70-97` reads YAML **as text** and asserts substrings — including `assert 'profiles: ["drainer"]' in compose`, which asserts the presence of the service pointing at the binary that does not exist. Replace with `helm lint`, `helm template` into rendered manifests, assertions against the rendered objects, and entrypoint resolution from T-098 | CODEX | T-098 | BLOCKED(T-098) |
| T-101 | **Production boots.** `config.py:69-72` refuses `MIZAN_ENV=production` unless custody is not `development`; `runtime.py:37-43` refuses to build a provider unless custody **is** `development`; both manifests ship `kms`; `__main__.py:29-31` turns either into exit 78. Neither guard is wrong — reconcile them so exactly one documented mode boots, and make the refusal name the mode that would work. Rule 8: the test asserts a production-mode `build_runtime` **succeeds** and fails on the pre-fix SHA with the verbatim `StartupRefused` string | CLAUDE | **B-18**, T-102 | BLOCKED(B-18) |
| T-102 | **One key backend that boots** (T-076 delivery). HashiCorp Vault Transit, native Ed25519, `custody=kms`, per B-18. **Integration-tested against a real Vault in CI, not a mock** — a mocked key backend in a stage whose thesis is "the gate must reproduce the result" would be self-refuting. PKCS#11 is not in CP-F | CODEX | **B-18** | BLOCKED(B-18) |
| T-103 | **The demo walks past the cliff.** `demo_walk.py:32-34` ends at `REQUIRE_APPROVAL` — one line before the product stops working. Extend through redemption, the tool call, the receipt, the drain, the anchor, the timestamp and the export, asserting the **artifact each step produces**, not that the step was reached. Rule 8 is unusually clean: this test fails today with a 403, and that body is quoted verbatim in the PR | CLAUDE | T-099 | BLOCKED(T-099) |
| T-104 | **Evidence survives a pod, and the drainer can write it.** `deployment.yaml:84-85` mounts an `emptyDir` at `/app/var/evidence` with `replicaCount: 2`, so a bundle served by pod A cannot read segments written by pod B and a rollout destroys the corpus. The drainer pod meanwhile gets only `MIZAN_ENV` and `MIZAN_DATABASE_URL` under `readOnlyRootFilesystem: true` — no evidence mount, no key refs, no TLS. Ship the substrate ruled in **B-21** and prove it: written through replica A, exported and verified through replica B, surviving deletion of both pods. Chart completeness rides here — ServiceAccount, NetworkPolicy, PDB, resources, probes on the drainer | CODEX | T-099, **B-21** | BLOCKED(B-21) |
| T-105 | **CI proves the product runs.** A `production-e2e` job that boots with `MIZAN_ENV=production` and real custody, drives CP-F steps 2 through 6, and fails on exit 78, a missing receipt, an anchor still `pending`, an empty evidence range, or a verifier disagreement. CI's only container boot today (`ci.yml:126-143`) passes `--env MIZAN_ENV=development`, so `app.py:518-524`'s production readiness checks have **never executed anywhere**. Every production defect in this plan is downstream of that one line. **This job is CP-F step 7** | CLAUDE | T-101, T-104 | BLOCKED(T-101) |
| T-106 | **Anchors stop being permanently pending.** `mizan-attest-anchors` exists (`attestation_runner.py:42-72`) and appears in **no manifest**, and its CLI takes one `--tenant-id`/`--stream-id` pair against a default of four shards per tenant. So on a real deployment every anchor stays `pending` forever and B-12's clause means the product runs and never produces the external timestamp that is its central claim. Make it a managed workload that enumerates tenants and shards itself | CLAUDE | T-099 | BLOCKED(T-099) |
| T-107 | **Observability that keeps its fields.** Zero hits for `structlog\|opentelemetry\|prometheus` anywhere; seven `LOGGER` call sites in the whole control plane; no `/metrics` among 39 routes; counters in-memory and exported nowhere. `execution.py:512-514` passes `tenant_id` and `decision_id` via `extra=` under a bare `basicConfig`, so both are **silently dropped** — the operator investigating a security event gets a line naming neither. Ship JSON logs that keep their fields, `/metrics` over the counters that exist plus outbox depth and anchor lag. Land with T-031/T-083 so `trace_id` is **classified**, not merely populated | CLAUDE | T-094 | READY |
| T-108 | **Expiry happens at rest.** `"EXPIRED"` appears only in membership sets, never in a write. `LEASE_EXPIRED` is written only from an inbound call by the lease's own holder, so a crashed executor's lease never expires. The cause is structural: **no background task of any kind exists in this process** (zero hits for `sweep\|scheduler\|cron\|asyncio.create_task\|threading.Thread`). Ship the outbox-transactional sweeper with its §4 events; test at rest — kill the holder, advance the clock, assert the state | CODEX | T-099 | BLOCKED(T-099) |
| T-109 | **Config reconciliation, and a refusal** (supersedes T-080, whose counts are wrong both ways). SPEC §8 carries **57** unique keys, not 48; **21** are never read, not 30 — including `MIZAN_AUDIT_ANCHOR_BUCKET`, all five `MIZAN_DEGRADED_WAL_*`, `MIZAN_APPROVAL_LEASE_SECONDS`, `MIZAN_DLP_FAIL_MODE`. Conversely **16** keys used in shipped artifacts are unregistered. The failure that matters: `config.py:47-153` never inspects the environment for unknown `MIZAN_*` names, so **an operator who sets a control we do not read gets silence** — they believe DLP fails closed, and it does not. Read or dated-waive each key, then refuse to start on an unknown `MIZAN_*`. Settle the custody vocabulary under **B-20** | CODEX | **B-20** | BLOCKED(B-20) |
| T-110 | **One bundle grammar.** Three refs define bundle 1.0 three incompatible ways — `docs/spec/EVIDENCE-BUNDLE-FORMAT.md` mentions `custody` twice on `track-b/ui` and not at all on `main` or `t-091`. **You cannot add a field to a format that has three definitions of itself**, which is why T-038/T-039 are deferred rather than merely descoped. Reconcile to one normative grammar and one conformance corpus after the merge train, by ADR delta | CODEX | T-095 | BLOCKED(T-095) |
| T-111 | **The second verifier becomes a gate.** `verifier-two/` exists as **eleven untracked files** — the highest-value artifact in the tree, on one machine, that CI has never seen. Commit it, then run **both** verifiers over `tests/fixtures/conformance/` in CI and fail on any disagreement in verdict, assurance line or NOT COVERED list. Every disagreement is a defect in the spec or in one implementation and must be named and classified — patching the new verifier to match the Python defeats the exercise. Sealed: see PR-PROTOCOL §5 | CODEX | T-062, T-110 | BLOCKED(T-062) |
| T-112 | **The security remainder** (T-077 d/e/f, deferred from week 3 and never picked up). (d) token max-TTL, required `kid`, JWKS, token class separating agent from principal; (e) escalate/override authorization at `app.py:317-322`; (f) request body cap and bounded registry document strings. Each with its pre-fix failing test and SHA. **H-7 fires on (e)** — that is approval semantics | CLAUDE | T-095 | BLOCKED(T-095) |
| T-113 | **Backup, restore, retention — currently zero.** A repo-wide search for `retention\|backup\|restore\|pg_dump\|PITR\|object.lock` returns three cosmetic hits, one of which is the literal `"retention_class": "regulatory_7y"` we embed in signed records. `docs/deployment/` contains one file. Ship the runbook **and the drill**: destroy the database and the evidence store, restore both, export from the restored copy, and have the second verifier PASS it. A runbook nobody has executed is a document | CODEX | T-104 | BLOCKED(T-104) |
| T-114 | **A stranger can produce credentials and knows what to type.** `compose.production.yaml:72` mounts `./secrets/tls` and consumes seven PEMs; there is no `secrets/` directory, no `.env.example`, and the only X.509 builders in the tree live inside test files. The chart assumes Secrets `mizan-runtime` and `mizan-tls` documented nowhere. `README.md:34` still says *"No service runtime has been selected by this scaffold."* Ship `scripts/bootstrap_credentials.sh`, `.env.example`, `INSTALL.md`, a customer quickstart README, and runnable code in `examples/` | CODEX | T-101 | BLOCKED(T-101) |
| T-115 | **Delete the scaffolding that reads as a roadmap.** Twenty-three stub directories, including `sdk/typescript` (94 bytes), `sdk/java` (88), `integrations/siem` (78) and `integrations/kafka` (111), plus seven README-only directories under `control-plane/` shadowing real modules one level up. A browsing design partner reads these as shipped surface. Delete them, and replace the PRD's module claims with a ledger that names, for each module, the code that backs it — or says none | CLAUDE | T-095 | BLOCKED(T-095) |
| T-116 | **An SLO measured on every commit** (supersedes T-023). Zero hits for `p95\|threshold\|assert` in `benchmarks/*.py` — they print. `benchmarks/policy_engine.py` measures `compiled.matches` in-process and never issues an HTTP request, so SPEC §7's p95 target for `/v1/authorize` has never been measured over the surface it describes. One committed artifact exists, from a laptop — which is how the 100k budget came to be set from a machine faster than the runner. Assert per runner class, over HTTP, in CI | CLAUDE | T-105 | BLOCKED(T-105) |
| T-117 | **Close CP-F: the stranger walks it.** Execute §2 with someone who is not me and is not either engineer. Time it. Publish `docs/reviews/CP-F-WALKTHROUGH.md` naming the machine and every place the documentation was wrong. The corrections are the deliverable. **An empty corrections list means it was not run** | CLAUDE | T-105, T-114, T-111 | BLOCKED(T-105) |

Also execute the kill list from §4 as part of T-095's WORK_LOG resolution, not as a separate task.

Carried forward from CP-E, unchanged and still owned: **T-062** (sealed — CODEX, fresh session,
before anything else), T-084, T-085, T-071, T-063, T-031/T-083, T-054, T-065, T-078, T-086.
**T-038, T-039, T-060 and T-064 defer to CP-G** — see §4.

---

## 6. Waves

```
WAVE 0 — the trunk, or nothing              [hours, serialized, one engineer]
  CLAUDE: T-094 merge train → T-095 lane integration → T-096 trunk enforcement
  CODEX:  T-062 land verifier-two as a PR   [sealed, fresh session, from hour one]

WAVE 1 — it starts outside the harness
  CODEX:  T-098 console scripts install  ·  T-099 the drain worker  ·  T-100 packaging gate
          T-102 Vault Transit  ·  T-097 WORK_LOG stops serializing
  CLAUDE: T-101 production boots  ·  T-107 observability  ·  T-106 anchors run

WAVE 2 — CI proves it
  CLAUDE: T-103 the demo walks past the cliff  ·  T-105 production-e2e   ← the stage, in one job
  CODEX:  T-104 durable evidence + chart  ·  T-108 expiry sweeper  ·  T-110 one bundle grammar
          T-111 both verifiers gate the corpus

WAVE 3 — a pilot could operate it
  CODEX:  T-114 bootstrap + INSTALL  ·  T-113 restore drill  ·  T-109 config refusal
  CLAUDE: T-112 security remainder  ·  T-115 delete the scaffolding  ·  T-116 continuous SLO

WAVE 4 — CP-E's remainder, now on a trunk that runs
  CODEX:  T-084  ·  T-085  ·  T-063        CLAUDE: T-031/T-083  ·  T-054 → T-065  ·  T-078
  joint:  T-071 the demo, real model, recorded transcript

WAVE 5 — T-117 the stranger walks it        ← CP-F acceptance
```

Wave 0 blocks everything and is not parallelisable. Nobody cuts a Wave 1 branch from a lane head.

## 7. Decisions — six, and four are blocking today

* **B-18 (open since 2026-08-26; now blocking T-101, T-102 and therefore T-105).** *Key backend for
  the pilot.* **Stamped: HashiCorp Vault Transit** (native Ed25519, `custody=kms`); PKCS#11 second and
  out of CP-F. AWS, GCP and Azure KMS do not sign Ed25519 and choosing one reopens bundle format 1.0.
  This is the oldest open decision in the tree and it is why the product cannot boot. H-7.
* **B-20 (new).** *Custody vocabulary.* SPEC §8 says `kms_hsm`; `keys.py:13` says
  `Literal["development-derived", "kms", "hsm"]`; `compose.production.yaml:7` says `kms`. Three
  spellings of one control. **Stamped: `development-derived` | `kms` | `hsm`**, `kms_hsm` retired by
  ADR delta — descriptive, forbidding nothing any implementation has emitted. Blocks T-109. H-7.
* **B-21 (new).** *Evidence durability substrate.* (1) PVC + StatefulSet — simple, single-writer, and
  **not WORM**; (2) S3-compatible object storage with Object Lock — what `MIZAN_AUDIT_ANCHOR_BUCKET`
  was specified as and what `"retention_class": "regulatory_7y"` already claims to a reader of our
  records; (3) both. **Stamped: (2)**, because the compliance claim is already inside records we have
  signed and a PVC cannot support it. Blocks T-104, T-113. H-7.
* **B-22 (new, blocking T-096).** *What enforces `main`, given branch protection is unavailable?*
  `gh api .../branches/main/protection` returns **403: "Upgrade to GitHub Pro or make this repository
  public."** PR-PROTOCOL §7 describes a control that cannot be configured, so today `main` is
  unprotected and the protocol says otherwise — which is our own documented failure mode, applied to
  our process. Options: (a) pay for GitHub Pro, ~$4/month, and configure the real thing; (b) go public
  — blocked until T-065 makes custody a gate, since development keys are `sha256(key_id)` and the
  `key_id` ships in every bundle; (c) ship a `trunk-guard` job that fails loudly after the fact.
  **Recommended: (a) now and (c) anyway**, because a control that costs four dollars and closes the
  gap between what the protocol claims and what is enforced is the cheapest thing in this document.
* **B-23 (new, blocking the T-071/T-117 gate definition).** *Does `make demo-run` require a live LLM
  call to pass CP-F?* CP-E said yes; a stranger on a clean machine has no API key, so as written the
  criterion contradicts itself. **Recommended: the gate replays a committed transcript of real
  `tool_use` blocks** and asserts on decisions, refusal reason classes and ADR_Records, never on prose;
  `make demo-run MODEL=live` re-records it. The point of T-071 — that a model never told about Mizan
  hits a governed tool and explains a structured refusal in its own words — is preserved in the
  recording, not in the gate.
* **B-24 (new).** *What is bundle 1.0, and does 1.1 owe an archive-timestamp chain?* Three refs define
  the format three ways (T-110). Separately, an RFC 3161 token outlives neither its TSA certificate
  nor SHA-256 forever, and we assert seven-year retention. Recommended: reconcile 1.0 descriptively
  under T-110 now; open 1.1's long-term-validation question as a CP-G item with a written answer, not
  silence. Crypto → H-7.
* **B-25 (new, sequencing rather than engineering).** *Who is the pilot, and by when?* There is no
  absolute date anywhere in this tree. Without a named first design partner and a date, "production
  ready as soon as possible" has no failure condition — and a stage without a failure condition is the
  same defect as a test without one.

Still open and unchanged: **B-13** (replay data boundary — parked with Stage 4), **B-15** (parallel
tracks — de facto answered yes; close it), **B-16** and **B-17** (both shipped, neither stamped —
close them or reverse them, but do not leave shipped behaviour resting on silence), **B-19** (registry
read authority), **ADR-004 G.15** (pending ratification under B-14), **TM-001 §6** (three judgement
calls).

Note on B-16 and B-17: they are marked open, and the behaviour they describe is already in the tree.
That is the process equivalent of a claimed-but-underived assurance, and it is mine to fix, not the
engineers'.

## 8. How I will know this stage worked

One sequence, run by someone who does not work here, on a machine we have never touched:

```
$ git clone … && cd mizan && cat INSTALL.md
$ ./scripts/bootstrap_credentials.sh && helm install mizan charts/mizan
$ make demo-run
… agent attempts payment → REQUIRE_APPROVAL → approved in the browser, by clicking
… tool executes → receipt → drain → anchor → RFC 3161 token from <authority>
… bundle exported
$ mizan-verify-two bundle/ --trust-roots ./my-roots/     # network off
PASS  — and the same verdict, assurance line and NOT COVERED list as verify_evidence_export.py
$ gh run list --branch main --limit 1
production-e2e   success
```

If any line fails, CP-F has not passed, regardless of how many tasks are DONE. If the last line is
missing, CP-F has not passed either — that is the line that means it will still be true tomorrow. And
if `docs/reviews/CP-F-WALKTHROUGH.md` has an empty corrections list, the walk was not run.
