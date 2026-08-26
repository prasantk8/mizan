# CODEX work order — Stage 5, Track B (parallel): everything a human touches, and everything an operator needs to run it

**Issued:** 2026-08-27 · **Issuer:** CLAUDE lane · **Base commit:** `e3c436c` on branch `track-b/stage-5`
**Runs alongside:** CLAUDE, working the same branch's control-plane internals. This order is written
so the two lanes never edit the same file. Read §1 before you write anything.

Everything in `CODEX-STAGE-3.md` §2 (one task, one commit; H-3 absolute; rule 6 mechanical;
rules 8–12) applies unchanged. This track never touches `evidence.py`, `attestation.py`, `keys.py`,
`canonical.py`, `verify_evidence_export.py`, or bundle format 1.0. If a task needs to, stop and park it.

---

## 0. Where the tree actually is

Week 1 of Track B landed. The control plane is a service that starts (`mizan-control-plane`, mTLS
listener, `/health/ready`), the loop closes end to end (authorize → approval → execution token →
lease → complete, gated over real mutual TLS), registry writes require a human operator, there is a
Python SDK, and as of `e3c436c` any MCP tool server can be put behind the control plane by pointing
the client at `mizan-mcp-gateway`. 296 tests pass with PostgreSQL; ruff clean; five drift gates;
R-007 8/8 at exit 0.

What does not exist yet:

- **No human can approve anything.** `POST /v1/approvals/{id}/votes`, `/escalate`, `/override` and
  `/withdraw` are all implemented and all reachable only with `curl`. A REQUIRE_APPROVAL decision
  pauses an agent and there is no screen on which a person learns that, let alone acts. This is the
  single largest gap between the system and the product, and it blocks T-071.
- **No way to see what a draft policy would have done.** `POST /v1/policies/{id}/simulate` exists
  and has no caller; a policy author's only feedback loop is production.
- **Nothing ships.** No image, no SBOM, no scan, no Helm chart, no migration runner — migrations
  `0002` and `0003` can only be applied by hand to a database created before they existed.
- **No adversarial suite.** T-024 has been READY since Stage 3.

Your four tasks, in this order. Do not stop after one — work down the list until your budget is
gone, and leave the tree green at every commit.

---

## 1. Lane boundary (read this before writing)

**Branch.** Work on `track-b/ui`, branched from `e3c436c`. Do not commit to `track-b/stage-5`.

**Files you own.** `ui/**`, `infra/**`, `Dockerfile*`, `.dockerignore`, `charts/**`,
`compose*.yaml`, `.github/workflows/**`, `scripts/validate_ui_contract.py` (new),
`scripts/migrate.py` (new), `tests/adversarial/**` (new), `tests/unit/test_ui_contract.py` (new),
`docs/adr/ADR-009-operator-console-read-model.md`.

**Files CLAUDE holds and you must not edit.** `control-plane/mizan_control_plane/**`,
`integrations/mcp/**`, `sdk/python/**`, `tests/unit/test_mcp_gateway.py`,
`tests/integration/test_mcp_gateway_postgres.py`, `tests/integration/test_closed_loop_postgres.py`,
`tests/integration/test_sdk_postgres.py`.

There is exactly one deliberate exception, in T-081, and it is named there. If any other task
appears to need a control-plane edit, **stop, park the task with a one-line note in WORK_LOG, and
move to the next one.** Do not negotiate the boundary by editing around it.

**Claim ledger.** `scripts/validate_claim_ledger.py` rejects a commit whose WORK_LOG snapshot holds
more than one live claim row. On your branch, keep exactly one row live — your current task — and
never add, edit or remove a row for a CLAUDE task. `WORK_LOG.md` will conflict when the branches
merge; that is expected and CLAUDE resolves it. Keep your log entries and queue-state edits confined
to your own task rows so the conflict stays mechanical.

**Do not take T-073 (observability) or T-074 (outbox drain worker).** CLAUDE is working them; they
touch `app.py`, `service.py`, `execution.py` and `evidence.py`.

---

## 2. T-072 · The approver inbox (L) — first, and the most important thing in this order

An agent has paused. A person has to decide. Today nothing tells them, and if they knew, they would
have to hand-write a JSON vote body. Build the screen.

The existing console (`ui/`) is dependency-free vanilla JS served same-origin by FastAPI's
`StaticFiles` mount at `/`, with a session-storage bearer token. **Keep it that way** — no build
step, no npm, no framework. A bank's security team can read 400 lines of JavaScript; they cannot
read a bundle.

**What the inbox must do.**

1. **Queue.** `GET /v1/approvals?state=PENDING&limit=&cursor=`. One row per approval showing the
   requester, the decision id, the active epoch's `kind` and `epoch_number`, `votes_cast` of
   `quorum`, the eligible `approver_roles`, and a live countdown to `expires_at`. Cursor paging,
   and a state filter that also reaches `APPROVED`/`REJECTED`/`EXPIRED`/`WITHDRAWN` so an approver
   can find what they did yesterday.
2. **The decision card.** Selecting a row loads `GET /v1/approvals/{id}` and
   `GET /v1/decisions/{decision_id}`, and renders what a person needs in order to be accountable
   for the answer: the agent and its delegation chain, the principal on whose behalf it acted, the
   declared `intent`, the tool and its risk tier, the resource and its classification, the matched
   policies with the recorded `reasons`, the risk level with its `floor_source`, and the
   `parameters_hash` with the binding profile version it was computed under. Raw tool arguments are
   never rendered: they are not in the record, and the card must not imply they are.
3. **The timeline.** The `events` array on the decision, newest last, each with its `event_type`,
   actor kind/id, `decision_sequence` and timestamp. This is the audit story of one decision and it
   should read like one.
4. **Acting.** Vote (`APPROVE`/`REJECT`/`ABSTAIN`), escalate, override, withdraw. Every ADR-007
   guard must be **visible before the button is pressed, not discovered from a 409**:
   - the requester may never approve their own request — grey the control and say why;
   - `distinct_control_domains_required` means a second vote from the same control domain does not
     carry the quorum — show the domains already counted;
   - override requires a justification and fresh votes; the form must refuse to submit without one;
   - a vote binds to an epoch — send the `epoch_number` you rendered, and when the server answers
     409 on a stale epoch, say "this request was escalated while you were reading it" and reload,
     not "Request failed (409)".
5. **Evidence.** Link each decision to its export bundle and to the standalone verifier, per the
   existing audit view's conventions.

**ADR-009 rendering rules stay in force.** Read the ADR before you render anything; if you find a
rule the inbox cannot honour, amend the ADR in the same commit (H-3) rather than quietly departing
from it.

**Gate.** There is no JS test runner in this repo and this task does not introduce one. Instead:

- `scripts/validate_ui_contract.py` (new, and added to `make check`): extract every `/v1/...` path
  template and HTTP method the console calls out of `ui/app.js`, load the app's OpenAPI document,
  and fail on any path the API does not serve or any method the route does not accept. A console
  that calls an endpoint that does not exist is a broken product, and today nothing would catch it.
- `tests/unit/test_ui_contract.py` (new): drive `TestClient(create_app())` through the exact
  sequence the inbox performs — list pending, read one approval, read its decision, cast a vote —
  and assert that **every field the inbox renders is present in the response**, by name. Name the
  test for that claim. This is the test that fails when someone renames `votes_cast`.

Both must fail on `e3c436c` (the validator does not exist; the field assertions have no caller) and
pass at your head.

---

## 3. T-081 · Policy studio over `/simulate` (M)

A policy author's current feedback loop is production. Give them the other one.

In the console, a new view over `POST /v1/policies/{policy_id}/simulate`:

- pick a DRAFT policy, pick a window (last N decisions from `GET /v1/decisions`), replay it;
- show every decision whose outcome **flips** under the draft — ALLOW→DENY, DENY→ALLOW,
  anything→REQUIRE_APPROVAL — with the decision card for each flip, because a policy that changes
  nothing and a policy that silently denies a thousand calls look identical in a diff;
- summarise: N replayed, M flipped, broken down by direction;
- a `TESTED` transition button wired to `POST /v1/policies/{policy_id}/transition`, enabled only
  after a replay has been run in this session, with the simulated counts shown next to it.

**The one permitted control-plane edit in this order.** `simulate_policy` takes an
`EvaluationContext`, and the console has no way to obtain the stored, normalized context for a past
decision — it lives in `mizan.authorization_contexts` and no route returns it. Add
`GET /v1/decisions/{decision_id}/context`, tenant-scoped from the token like every other read,
returning the stored normalized context and its `context_hash`. This is a contract change and H-3 is
absolute: SPEC §3 entry, a `ContextResponse` shape if the response is not simply the stored
document, an ADR-009 delta explaining why the read model exposes it, and a `tests/CONTRACT_COVERAGE`
row — all in the same commit. Touch `app.py`, `registry.py` or `evidence.py` **only** for this
route; if you find yourself editing anything else, stop.

**Gate.** An integration test that seeds two decisions with opposite outcomes under a draft policy,
replays them through the new route plus `/simulate`, and asserts the flip set is exactly the one
seeded — including that a decision whose outcome does not change is absent from it.

---

## 4. T-075 · Ship it (M/L)

Nothing in this repository can be deployed by anyone who is not already sitting in it.

- **Image.** Multi-stage `Dockerfile`: build with `uv sync --frozen`, run as a non-root user, no
  build toolchain in the final layer, `openssl` present (the TSA path shells out to it), an explicit
  `HEALTHCHECK` hitting `/health/ready`, and `mizan-control-plane` as the entrypoint. Pin the base
  by digest, not by tag.
- **Migration runner.** `scripts/migrate.py` plus a `mizan.schema_migrations` table recording
  filename, sha256 and applied-at. It must apply `0002` and `0003` to a database created at `0001`,
  refuse to re-apply an already-recorded migration, and refuse outright when a recorded migration's
  file has changed on disk — a migration whose bytes moved after it was applied is a divergence, not
  a no-op. Run it as a job in compose and as a Helm hook.
- **Production profile.** A compose profile and a minimal Helm chart that bring up: migrations →
  control plane (mTLS, real key refs) → drain worker (`mizan-drain-outbox`; it is CLAUDE's T-074 and
  may not exist yet — reference it by name, and make the profile degrade to "not scheduled" rather
  than failing to render). App connects as `mizan_app`, never `mizan_owner`; RLS depends on it.
- **Supply chain.** SBOM (CycloneDX or SPDX) generated in CI and uploaded as an artifact, plus a
  vulnerability scan that fails the build on HIGH/CRITICAL with a dated, justified allowlist file —
  an allowlist without a date is a permanent exception pretending to be a temporary one.

**Gate.** A CI job that builds the image, runs the migration runner against a database provisioned
at `0001` only, boots the container, and asserts `/health/ready` answers 200 — plus a test asserting
the runner refuses a mutated migration file. Rule 6: the SBOM and scan outputs are artifacts, not
claims in a log line.

---

## 5. T-024 · Adversarial suite (M/L)

New directory `tests/adversarial/`, wired into CI as a nightly job (not the PR job).

- **Token replay.** A redeemed execution token, a token past its TTL, a token for another tenant, a
  token whose `kid` names a key that never signed it, a token replayed concurrently against the CAS
  redemption. Each must be refused, and the refusal must be the *specific* one, not a generic 403.
- **Cross-tenant fuzz.** Property-based: for a random pair of tenants and a random read or write,
  every route answers as though the other tenant's object does not exist. Not "403 sometimes" —
  never a leak of existence, including through timing-independent signals like distinct error codes.
- **Chain tamper.** Mutate a record body, a `prev_hash`, a sequence number, a receipt signature, and
  an anchor, one at a time, and assert `/v1/audit/verify` names the *first* broken link in each case.
  There is already a deterministic mutation harness for evidence bundles — read it, and do not
  duplicate its expression (rule 12).
- **Prompt-injection corpus.** A corpus of tool arguments and external payloads that attempt to
  reach the policy namespace: keys that look like context paths, `__proto__`, unicode
  confusables in a tool id, an argument named `agent`. The claim under test is architectural and
  should be stated as such in the test names: tool arguments are never a policy namespace, so no
  argument can change a decision except through the binding profile.

**Gate.** The suite is red on at least one deliberately introduced regression per category — write
that regression, prove the test catches it, revert it, and record the pre-fix SHA in WORK_LOG
(rule 8). A suite that has never failed is a suite that proves nothing.

---

## 6. Definition of done, per commit

One task, one commit. Before each:

```
uv run ruff check .
make check                                    # five drift gates + contract coverage
MIZAN_TEST_DATABASE_URL=... uv run pytest -q   # must be 296+ passed, 0 skipped
uv run python docs/reviews/reproductions/R-007-cpb-attestation.py
```

The commit message says what changed and why, in prose, with the finding that motivated it. The
WORK_LOG entry is your last act: one line, `date · CODEX · task · what · next`, naming the gate and
the measured test count. Rule 10 is not optional — if something did not work, if you parked a task,
if a gate is weaker than it should be, say so in the entry. A clean log that hides a compromise
costs more than the compromise did.
