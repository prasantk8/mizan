# CLAUDE work order — CP-F

**Read first:** `docs/handoff/CP-F-STAGE-PLAN.md`, then `docs/handoff/PR-PROTOCOL.md`.
Standing rules 6-12 and `CODEX-STAGE-3.md` §2 non-negotiables 1-9 apply unchanged. H-1 claim before
work. H-2's completion report is the PR body. One task, one branch, one PR opened on day one.

Your CP-E order is not cancelled. T-031/T-083, T-054, T-065, T-078 and T-086 carry into Wave 4 — none
of them can be demonstrated on a deployment that exits 78 before it opens a socket, which is why they
now sit behind a trunk that runs.

**One correction to your CP-E order before you start.** It instructed you to set branch protection on
`main`. You cannot: `gh api repos/prasantk8/mizan/branches/main/protection` returns **403 — "Upgrade
to GitHub Pro or make this repository public."** PR-PROTOCOL §7 describes a control that has never
existed. That is our own documented failure mode applied to our own process, and it is T-096.

---

## T-094 — The merge train. First, and nothing else of yours runs while it does.

Six PRs open. **None has ever merged.** `main` is twenty commits behind `track-b/ui`, eighteen behind
`track-b/stage-5`, zero ahead of either. Verified 2026-08-28:

```
#1 T-087   baseline FAIL  python FAIL  postgres pass  offline FAIL   gates pass  completion-report pass
#2 ui      baseline FAIL  python FAIL  postgres pass  offline FAIL   gates pass  image pass
#3 stage-5 baseline FAIL  python FAIL  postgres pass  offline FAIL   gates pass
#4 T-088   baseline PASS  python FAIL  postgres pass  offline FAIL   gates pass
#5 T-090   baseline FAIL  python PASS  postgres pass  offline FAIL   gates pass
#6 T-091   baseline FAIL  python FAIL  postgres pass  offline PASS   gates pass
```

`baseline-contract` dies on `ModuleNotFoundError: No module named 'jsonschema'` at
`scripts/validate_baseline.py:13` — **#4 fixes it**. `python-contract` dies on the 100k-chain budget —
**#5 fixes it**. `offline-evidence-verifier` dies on `FAIL: RFC 3161 TSA certificate is expired` —
**#6 fixes it**.

Every red job already has its fix. Each fix is in a different unmerged PR, and no PR contains another,
so "CI is the arbiter" currently forbids every merge. **There is no engineering here.** The work is
composition, and the reason it has not happened is that we kept opening PRs instead of landing them.

```
#4  →  #5  →  #6  →  #1
```

`#1` goes last of the four so the PR-infrastructure branch lands on a `main` where CI is already
green. Rebase each on the last; merge each before rebasing the next.

Hard rules for the train:

1. **A rebase that turns a green job red is a stop-and-report.** Do not fix it inside the train.
2. **Do not fix four things in one branch to reach green.** That is how a lane accumulates nineteen
   commits, and it is the failure this protocol exists to prevent.
3. `main`'s own push run must be green on **every job that commit's `ci.yml` declares** — not on the
   jobs you remember. Assert the set.

Rule 10 applies hard. This is the first green trunk this repository will have. Write down every
surprise, and specifically anything green on a lane head and red on `main` — that is semantic overlap
announcing itself late.

## T-095 — Lane integration. Replaces T-082 as written.

Land `#3` then `#2`. R-008 built this merge locally and predicted conflicts in `WORK_LOG.md` and
`tests/CONTRACT_COVERAGE.md` only, with 360 passed / 35 skipped.

**That prediction is a lower bound, not a list.** There is a third: an add/add on
`tests/unit/test_postgres_skip_guard.py`, where both engineers independently wrote the same guard.
Union it. Assume there are others and look for them rather than confirming the two you were told about.

* **`tests/CONTRACT_COVERAGE.md` is a union, never a side.** The validator checks index → pytest only,
  so taking one side drops the other lane's rows and nothing notices.
* **`WORK_LOG.md`** — union the queue rows, one Active Task paragraph, every blocker from both sides,
  claim ledger **empty**. Execute stage plan §4's kill list here: park T-038/T-039/T-060/T-064 and
  T-044..T-048 with dated reasons, close T-026 absorbed, close T-023 and T-080 superseded, reduce
  `AGENT_ALLOCATION.md` to a line pointing at PR-PROTOCOL §5.
* Re-run with PostgreSQL and **assert the job set, not the pass count.** A green merge that loses an
  assertion is the worst outcome and the easiest to miss.

Delete both lane branches. From that moment there are no lanes as branches — two engineers and a queue.

**Also: `git add` the CP-E documents.** `PR-PROTOCOL.md`, `CLAUDE-CP-E-RUN.md`, `CODEX-CP-E-RUN.md`
and `R-008-two-lane-review.md` are **untracked**. The process governing every merge is not in the
repository it governs. The CP-F documents go in with them.

## T-096 — Something enforces the trunk. **[B-22]**

Branch protection returns 403 on this plan. So today `main` accepts a direct push, a force-push, and a
merge with a red CI run, while PR-PROTOCOL §7 says otherwise. A protocol that describes an unconfigured
control is the same defect as a gate that reports a result nobody reproduced — ours, about us.

Per B-22, do both: ship a `trunk-guard` workflow on `push: [main]` that fails loudly on a red or
unreviewed trunk, **and** configure real protection once the plan is upgraded. The guard is not a
substitute — it detects after the fact rather than preventing — and the PR must say so rather than
implying the gap is closed.

## T-101 — Production boots. **[B-18 stamped: Vault Transit]**

```python
# config.py:69-72
if environment == "production" and (custody == "development" or any(r.startswith("local://") ...)):
    raise RuntimeError("production refuses development custody and local:// signing keys")

# runtime.py:37-43
if settings.key_custody_mode == "development":
    return LocalKeyProvider(versions, settings.environment)
raise StartupRefused(f"key custody mode {settings.key_custody_mode!r} names no built backend...")
```

`custody=development` fails the first. Anything else fails the second. Both shipped manifests set
`kms`. Every path reaches `__main__.py:29-31` and exit 78. **Nobody has ever run this product in
production mode, including us.** `helm install` crash-loops and so does
`docker compose --profile production up`.

Neither guard is wrong — `runtime.py`'s refusal message is one of the better pieces of engineering
honesty in the tree. CODEX's T-102 gives `kms` a backend; you make the two guards agree that `kms` is
the mode that boots, and make each refusal name the mode that would work.

Rule 8: the test asserts `build_runtime` **succeeds** under `MIZAN_ENV=production` with `custody=kms`,
and fails on the pre-fix SHA with the verbatim `StartupRefused` string quoted in the PR. Rule 9 also
binds — this adds a guarantee, so the demonstration is the new test rejecting today's tree, not an
`ImportError`.

**H-7 fires** if this needs a change to the `KeyProvider` *contract* rather than an addition.

## T-103 — The demo walks past the cliff

`scripts/demo_walk.py:32-34` ends at `REQUIRE_APPROVAL`. That is one line before the product stops
working, and it is why nobody noticed that an approved payment is refused forever with 403
`immutable_receipt_missing` (`execution.py:410-411`, `:812-820`).

Extend through redemption, the tool call, the receipt, the drain, the anchor, the RFC 3161 token and
the export — asserting **the artifact each step produces**, never that the step was reached.

Rule 8 is unusually clean: this test fails today, on `main`, with a 403. Quote the response body
verbatim. A test that fails for the reason the product is broken is worth more than the fix that
follows it.

Sequence after CODEX's T-099. **Do not stub the drainer to make your half green** — a demo that passes
against a stub is precisely the artifact this stage exists to abolish.

## T-105 — CI proves the product runs. **This is the stage.**

A `production-e2e` job that boots with `MIZAN_ENV=production` and real custody, drives CP-F steps 2
through 6, and fails on: exit 78, a missing receipt, an anchor still `pending`, an empty evidence
range, or a disagreement between the two verifiers.

Why this and not a better test suite: CI's only container boot today (`ci.yml:126-143`) passes
`--env MIZAN_ENV=development`, so the production readiness checks at `app.py:518-524` — anchor
provider, mutual TLS — **have never executed anywhere, ever**. Every production defect in this stage
plan is downstream of that one line.

Write the job first and watch it fail for each reason in turn. A red job that fails for the correct
reason is a better work order than this document.

## T-106 — Anchors stop being permanently pending

`mizan-attest-anchors` exists (`attestation_runner.py:42-72`), is a real console script, and appears
in **no manifest**. Its CLI takes a single `--tenant-id`/`--stream-id` pair while
`MIZAN_CHAIN_SHARDS_PER_TENANT` defaults to 4, so an operator would need one hand-started process per
tenant per shard.

On a real deployment every anchor therefore stays `pending` forever, and B-12's clause — *no stream
with a pending attestation may be described as externally anchored* — means **the product runs and
never produces the external timestamp that is its central claim.**

Make it a managed workload that enumerates tenants and shards itself. Do not add a flag an operator
must remember for each shard; a control that depends on remembering is not a control. Test at rest:
two tenants, four shards each, one process, every anchor reaches `verified_external` without anyone
naming a stream.

## T-107 — Observability that keeps its fields

Zero hits for `structlog`, `opentelemetry` or `prometheus` in `control-plane/`, `integrations/`,
`security/` or `pyproject.toml`. Seven `LOGGER` call sites in the entire control plane. No `/metrics`
among `app.py`'s 39 routes. Counters in-memory and exported nowhere.

The defect worth naming, because it is the shape this repository keeps producing:

```python
# execution.py:512-514
LOGGER.error(metric, extra={"tenant_id": ..., "decision_id": ...})
```

Under `__main__.py:25`'s bare `logging.basicConfig` that emits
`ERROR:m:security_event_pool_timeout`. **The tenant and the decision are silently dropped.** The call
site looks correct, the fields are passed, and the operator investigating a security event gets a line
naming neither. It is `trace_id` again: a populated, well-formed thing that answers nothing.

Ship JSON logs that keep their fields, and `/metrics` over the counters that already exist
(`execution.py:130`, `service.py:68`) plus outbox depth and anchor lag — today those counters terminate
in a dict read only by `tests/unit/test_execution.py:137`.

Land with T-031/T-083 so `trace_id` is **classified**: `Recorded`/`Declared` when continued from a
caller, `Recorded`/`Observed` when minted here, inside the signed payload per ADR-010. A hostile agent
choosing its own `traceparent` places its decision inside a victim's investigation, and the record must
say who supplied the field.

The OTel/W3C propagation half can wait — there is no trace consumer yet, and T-083 is about to change
what a `trace_id` claims.

## T-112, T-115, T-116, T-117 — Wave 3 and close

**T-112** is the T-077 security remainder, deferred to "week 3" and never picked up: (d) token
max-TTL, required `kid`, JWKS, and a token class separating agent from principal; (e) escalate/override
authorization at `app.py:317-322`; (f) request body cap and bounded registry document strings. Each
with its pre-fix failing test and SHA. **H-7 fires on (e)** — that is approval semantics.

**T-115** deletes twenty-three stub directories — `sdk/typescript` at 94 bytes, `sdk/java` at 88,
`integrations/siem` at 78, `integrations/kafka` at 111, plus seven README-only directories under
`control-plane/` shadowing real flat modules one level up — and replaces the PRD's module claims with a
ledger naming, for each module, the code that backs it or saying none. A browsing design partner reads
those directories as shipped surface. This is not tidying; it is a claim we cannot support.

**T-116** replaces T-023. `benchmarks/*.py` contain zero occurrences of `p95`, `threshold` or `assert`
— they print. `benchmarks/policy_engine.py` measures `compiled.matches` in-process and never issues an
HTTP request, so SPEC §7's p95 target for `/v1/authorize` has never been measured over the surface it
describes. Assert per runner class, over HTTP, on every commit.

**T-117** is the acceptance walk, and you organize it but do not perform it. It fails if you or CODEX
or I run it. Publish `docs/reviews/CP-F-WALKTHROUGH.md` with the machine named and every guessed
command listed. **An empty corrections list is evidence it was not run.**

---

## Sequence

```
T-094  the merge train            → main green on every job it declares
T-095  lane integration           → both lanes landed, kill list executed, CP-E docs tracked
T-096  trunk enforcement          [B-22]
  → T-107  observability (+T-031/T-083)      [independent of the deployment chain — start early]
  → T-101  production boots        [B-18; needs CODEX's T-102]
  → T-106  anchors as a managed workload
  → T-103  the demo walks past the cliff     [needs CODEX's T-099]
  → T-105  the production-e2e job            ← the stage, in one job
  → T-112  security remainder  ·  T-115  delete the scaffolding  ·  T-116  continuous SLO
  → Wave 4: T-054 → T-065 → T-078 → T-086, and T-071 jointly with CODEX
  → T-117  the stranger walks it             ← CP-F acceptance
```

Full gates before every PR: `ruff check .`, `make check`, `pytest` with PostgreSQL, and
`uv run python docs/reviews/reproductions/R-007-cpb-attestation.py`. A previously-green case going red
is a stop-and-report before the next task starts.

## Escalate, do not decide

H-7 fires on: any `KeyProvider` **contract** change; T-112(e), which is approval semantics; anything
moving tenant isolation; any proposal to widen rather than narrow a ratified grammar; and anything in
the evidence substrate that would change what `retention_class: regulatory_7y` means to a reader of a
record we have already signed.

B-18, B-20, B-21 are stamped; B-22, B-23, B-24 and B-25 are answered or recommended in the stage plan.
If you find a further blocking decision, file it as B-26 and keep working on something else. Do not
idle and do not decide it.

## Review duty

You review CODEX's PRs. On **T-062** and **T-111** you remain permanently disqualified from judging
the implementation against the Python you have read: review its **disagreements** with
`verify_evidence_export.py`, and treat every one as a defect in the spec or in one implementation until
proven otherwise. A disagreement reconciled by patching the new verifier to match the old one destroys
the task, and you are the reviewer most likely to catch that and most likely to cause it.

On everything else in this stage, one question finds the most:
**does this gate reproduce the result, or does it read a file and look for a string?**
