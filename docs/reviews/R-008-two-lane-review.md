# R-008 — Two-lane review, 2026-08-27

Heads reviewed: `track-b/ui` @ `e8ef4cd` (CODEX lane), `track-b/stage-5` @ `5b72329` (CLAUDE lane).
`main` @ `f4f90a2`, nineteen commits behind both.

Findings are numbered `R-008 F-n`. They are **not** `V-n`: `V-1..V-23` is the SPEC's verification-rule
namespace and R-006/R-007 collided with it. Review findings use `F-n` from here on, as R-004 and R-005 did.

## What I ran

| | Result |
|---|---|
| `ruff check .` on `track-b/ui` | All checks passed |
| `make check` on `track-b/ui` | baseline (30 boundaries, 15 JSON blocks, 14 schema IDs, five drift gates), UI contract, allowlist — all pass |
| `pytest -q` on `track-b/ui` | 292 passed, 30 skipped (no PostgreSQL) |
| `pytest -q tests/adversarial` | 20 collected, 15 passed, 5 skipped, 0.49 s |
| `ruff check .` on `track-b/stage-5` | All checks passed |
| `pytest -q` on `track-b/stage-5` | 340 passed, 29 skipped — consistent with the claimed 369/0 under PostgreSQL |
| **trial merge of both lanes** | conflicts in `WORK_LOG.md` and `tests/CONTRACT_COVERAGE.md` only; `app.py` and `evidence.py` auto-merge |
| `ruff` + `make check` + `pytest` on the **merged** tree | clean, three gates pass, **360 passed / 35 skipped** |

Rule 8 was not re-sampled this cycle; the last sample was at `f06cc95` and held.

---

## F-7 — H-8 says CI is authoritative. CI has never run.

*Found on a second pass, prompted by the question of whether to adopt a pull-request flow. It is the largest
finding in this review and it is numbered last only because that is when I found it.*

```
$ git remote -v
                                    (empty)
$ git for-each-ref --format='%(refname:short) -> %(upstream:short)' refs/heads
main ->
track-b/stage-5 ->
track-b/ui ->
$ gh repo view
no git remotes found
```

`.github/workflows/ci.yml` declares six jobs — `baseline-contract`, `python-contract`, `postgres-contract`,
`production-image`, `offline-evidence-verifier`, `implementation-gates` — and triggers `on: pull_request` and
`push: [main]`. It is a serious workflow: it builds the image, boots it against a real PostgreSQL, asserts
three `schema_migrations` rows, generates a CycloneDX SBOM with digest-pinned syft, scans with digest-pinned
trivy, and runs the offline verifier under `sudo unshare --net`.

**Not one of those jobs has ever executed**, because there is nowhere to push. Nineteen commits of work have
been gated entirely by two engineers running `make check` on their own laptops and reporting the result in
prose — including every claim in this review's own table above, which I ran on this machine.

This is not a gap in the workflow. The workflow is good. It is a gap between a transition hook that says CI
is authoritative and a repository where CI is a document.

Remediation is T-087 and `docs/handoff/PR-PROTOCOL.md`. Checked what a first push would publish: 290 tracked
files, 12 MB of history, three tracked `.pem` files (all public root certificates), no `PRIVATE KEY` block
anywhere in the tree, `.env*` and `var/` ignored. Nothing needs scrubbing. Private repository until T-065
makes custody a gate.

## F-8, F-9, F-10, F-11 — what the first CI run found, one hour after F-7 was written

The remote was created and `main` @ `f4f90a2` pushed at 17:24 UTC on 2026-08-27. Run
[33098206236](https://github.com/prasantk8/mizan/actions/runs/33098206236) is the first execution of
this repository's CI in its history. Five jobs on `main` (`production-image` arrived later, in a lane):
`postgres-contract` and `implementation-gates` green, the other three red. All three failures are live
on **both** lane heads — neither lane fixes any of them.

### F-8 — `make check` does not run on a clean checkout

```
File "scripts/validate_baseline.py", line 13, in <module>
    from jsonschema import Draft202012Validator
ModuleNotFoundError: No module named 'jsonschema'
make: *** [Makefile:6: validate-baseline] Error 1
```

`baseline-contract` does `setup-python` and then `make check`, with **no dependency installation step
at all**. It has never mattered because both engineers have a populated `.venv`. So the gate that both
lanes cite as their evidence — the one quoted in this review's own table — is not runnable by anyone who
has not already built the project. That is the same defect as F-7 one layer down: a check that passes
because of local state rather than because of the tree. It is also a CP-E problem directly, since CP-E
begins with a stranger on a clean machine.

### F-9 — the performance target is a laptop number

```
{"checked_records": 100000, "records_per_second": 6630.86,
 "target_seconds": 10, "verification_seconds": 15.081, "valid": true}
Process completed with exit code 1
```

The chain verified correctly — `valid: true`. It took 15.081 s against a 10 s target on a four-core
GitHub runner. The target was calibrated on developer hardware, and every performance number in this
tree and in `benchmarks/results/` was produced on one of two laptops. Rule 6 requires that a number ship
with its artifact; it does not yet require that the artifact say what produced it, and a threshold that
passes on Apple silicon and fails on the reference runner is a threshold that measures the machine.

This is a decision, not a bug: relax the target to the reference runner, keep the target and mark the
job informational until T-060 measures the shape, or record two thresholds and say which one is the
claim. It should not be resolved by whoever is annoyed by the red first.

### F-10 — the job that proves the headline claim expires after twenty-four hours

```
FAIL: RFC 3161 TSA certificate is expired
```

`tests/fixtures/evidence_export/attested/tsa-root.pem`:

```
subject   = CN=committed-test-tsa
notBefore = Aug 26 16:26:37 2026 GMT
notAfter  = Aug 27 16:26:37 2026 GMT
```

A committed test root with a **twenty-four hour** validity window, in the one job that demonstrates
what Mizan is for. It expired at 16:26 UTC and CI ran at 17:24 UTC. This job could never have passed on
any day but the day the fixture was generated, and nobody could know, because the job had never run.

**Regenerating the fixture with a longer-lived root would turn this green and leave the defect in
place**, so do not do that alone. The defect underneath is in the verifier:

```python
["openssl", "ts", "-verify", "-in", token, "-digest", digest, "-CAfile", trust]
```

There is no `-attime`. `openssl ts -verify` validates the TSA signing chain **as of now**, which asks
whether the timestamp authority's certificate is valid today. That is the wrong question. A timestamp
exists to prove a digest existed at `genTime`; TSA signing certificates are deliberately short-lived
*because* the token carries the time. Verifying as-of-now means every bundle stops verifying on the
TSA's expiry date — valid evidence, valid token, correct chain, FAIL — and for a bank retaining
evidence seven years that is a certainty, not a risk. The fixture merely makes it visible after one day
instead of after three years.

The naive repair is also wrong: validating the chain at the token's own `genTime` trusts the token to
date the certificate that signs it. The sound answer is long-term validation — the trust decision
anchored outside the token, by a later timestamp over the earlier one (RFC 4998 / CAdES-A archive
timestamps) or by an explicit operator policy about the TSA's key. That is a specification question
about what an attestation in bundle 1.0 claims, so **H-3 fires** and this is an **H-7 escalation**: it
is crypto, and it decides whether Mizan's central promise is true after year three.

Until it is answered, the honest position is that a bundle is verifiable offline *for the lifetime of
the timestamp authority's certificate*, and the verifier's LIMITATION block does not currently say so.

### F-11 — a correct guard, wired so that it cannot be satisfied

Found on the lane pull requests
([#2](https://github.com/prasantk8/mizan/pull/2) run
[33098924304](https://github.com/prasantk8/mizan/actions/runs/33098924304),
[#3](https://github.com/prasantk8/mizan/pull/3) run
[33098943863](https://github.com/prasantk8/mizan/actions/runs/33098943863)). This one is not on `main`
— `tests/conftest.py` exists only on the two lane heads, where it is the same blob
`b876d85` in both:

```
322 tests collected in 1.73s
ERROR: CI=true collected 25 PostgreSQL-gated tests with no MIZAN_TEST_DATABASE_URL.
They would be reported as skipped, which is not a pass.
First: tests/integration/test_authorize_postgres.py::test_live_control_plane_end_to_end
Process completed with exit code 4
```

The guard itself is right, and it is rule 9 applied to the test suite: `skipif(not
MIZAN_TEST_DATABASE_URL)` is correct on a laptop and dishonest on a build machine, where it turns "the
database was never provisioned" into a green run. Whoever wrote it was thinking about the right
failure.

It is the wiring that is wrong. The step that trips it is `validate_contract_coverage.py`, which shells
out to `pytest --collect-only -q` to take an inventory of node IDs. **A collection is not a test run.**
Nothing is going to execute, so nothing can be falsely reported as skipped, and the guard's own
premise does not hold. It fires anyway, inside `python-contract` — a job that has no PostgreSQL service
and is never going to have one, because the job that runs the gated tests is `postgres-contract`, which
sets the DSN and does satisfy the guard. So the effect of the guard as wired is that a job which is
already doing the right thing kills a different job for not doing it.

The fix is one condition — exempt `config.option.collectonly` — and it narrows the guard to exactly the
claim its docstring makes. What makes this finding worth writing down rather than just fixing is the
category: F-2 and F-3 are assertions that cannot go red, and F-11 is an assertion that cannot go green.
Both are the same defect seen from opposite sides — a check whose outcome was never observed in the
environment that runs it. There is no local invocation that would have shown it, because no engineer
sets `CI=true` on their own machine.

## F-1 — Two lanes, nineteen commits, and a `main` that has seen none of it

**Structural, and the only finding with a deadline.**

No commit anywhere in this repository has ever run both lanes' code together. I built the merge and ran
it: it is green today — ruff clean, three drift gates, 360 passed. That is the whole point. The
integration is free *right now* and gets more expensive every day it is deferred, and its cost is not
linear, because what makes a two-lane merge dangerous is not textual conflict but semantic overlap that
`git` reports as `Auto-merging`.

The lane boundary was breached. The parallel order said the two lanes "never edit the same file". Five
files overlap, two of them source:

```
SPEC_v1.md
WORK_LOG.md                          (expected, documented, resolved by the second merger)
tests/CONTRACT_COVERAGE.md
control-plane/mizan_control_plane/app.py        <- not expected
control-plane/mizan_control_plane/evidence.py   <- not expected
```

Both source overlaps come from `7bf3303` (T-081, policy studio), which needed a backend read model and
added one. The task genuinely needed it; the boundary did not admit it, and nothing stopped it. A rule
that depends on remembering is not a boundary — which is the same argument T-065 makes about custody.

Note also `tests/CONTRACT_COVERAGE.md`: `793a54a` fixed `validate_contract_coverage.py`, which had only
ever checked `I-n`/`V-n` rows and so had never checked two rows already in the index. Resolving that
conflict by taking one side drops the other lane's rows *silently* and the now-stricter validator will
not notice, because it validates index → pytest, not pytest → index. Union it.

## F-2 — The prompt-injection test asserts nothing about prompt injection

`tests/adversarial/test_prompt_namespace.py::test_tool_arguments_are_never_a_policy_namespace`.

The test stubs the repository with exactly one policy:

```python
repository.policies = [
    PolicyMatch(policy_id="pol_argument-boundary", version=1, content_hash="a" * 64,
                decision="ALLOW" if active("prompt_namespace") else "DENY", priority=100)
]
...
assert response.decision == "DENY"
```

There is no ALLOW rule in the set. No injection — succeeding or failing — can change the outcome, because
there is no outcome for it to change. The assertion holds for a hostile payload, for an empty payload, and
for a control plane in which tool arguments *are* a policy namespace. What it demonstrates is that a stub's
decision propagates to the response.

The test's name is a claim (rule 11) and the claim is untested. The two assertions after it are real and
worth keeping: `"arguments" not in persisted["tool"]`, and the `parameters_hash` equality.

The fix is not a bigger corpus. The policy set must contain an **ALLOW rule that fires on exactly what the
injection forges** — `principal.role == "system-admin"`, `agent.id == "agt_root"` — at a priority that would
win. Then a namespace leak produces ALLOW and the test goes red for the reason its name gives.

## F-3 — The fault switch proves the harness can go red, not the product

`tests/adversarial/regression.py` is the right instinct one layer too high.

```python
if active("chain_tamper"):
    return _AcceptEverythingVerifier()
```

Under the switch the *test* substitutes a verifier that accepts everything. That is a fault in the harness.
It demonstrates that a test asserting rejection fails when nothing rejects, which was not in doubt. The
same is true of the `prompt_namespace` switch, which edits a stub's decision. Only the `token_replay` switch
touches product state (it clears `consumed_at` in PostgreSQL) and that one is a real demonstration.

And nothing ever flips it. `.regression` is a marker file no workflow writes. `adversarial-nightly.yml`
runs `pytest -q tests/adversarial` and never sets a category. So "each adversarial category can go red" is
asserted in a docstring and demonstrated by nobody — rule 9, in the place where rule 9 matters most.

The fix has two halves. The injected fault must be a **regression in product code** — revert the guard the
category exists to prove, run the category, require red. And CI must run it: a job that iterates the four
categories, applies each fault, and **fails if the suite passes**.

## F-4 — 674 lines of the approval surface run in no test

There is no `package.json` anywhere in the tree. No JavaScript runtime executes `ui/app.js` in any test, at
any time, in CI or locally. The screen on which a human approves an AI agent moving money has never been
rendered by anything.

`scripts/validate_ui_contract.py` deserves real credit and does not close this. The
`request(method, contractPath, path)` indirection — declare the OpenAPI template statically, pass the
interpolated URL separately — lets a static checker validate template-literal calls against the live
OpenAPI document, which is a better answer than most teams reach. Two limits:

* It checks the **declaration**, not the call. `request("GET", "/v1/agents", "/v1/admin/anything")` passes.
  Nothing binds argument two to argument three.
* `tests/unit/test_ui_contract.py:316` — `assert rendered_field in source` — is a string search over source
  text. It cannot distinguish a rendered field from a variable name in a comment.

What *is* well tested is the route sequence: `test_approver_inbox_sequence_returns_every_field_the_console_renders`
drives a real `TestClient` and asserts the exact repository call order. That is a real regression test of the
server. It says nothing about whether the ADR-007 guards render, whether an epoch-stale approval is
disabled in the DOM, or whether the override control appears to a principal who may not use it.

## F-5 — The vulnerability allowlist is a time bomb aimed at the wrong target

`infra/supply-chain/.trivyignore.yaml` carries thirteen suppressions. Every one expires `2026-09-03`.
`validate_vulnerability_allowlist.py` is wired into `make check`.

On 2026-09-04, `make check` fails for every developer, on every branch, for every change, because a Debian
`perl-base` CVE note aged out. The weekly-reassessment discipline is correct and I would not weaken it. The
blast radius is wrong: an expired suppression is a supply-chain finding and must fail the **image scan
job**. `make check` should print days remaining and stay green.

(The validator is otherwise good — it requires an RFC 3339 `expired_at` with a real offset and a non-empty
justification, and it rejects a bare date. And the CI job pins syft and trivy by digest, not just the base
image, which is the part most people skip.)

## F-6 — `trace_id` went from false to true-but-unattributed, inside a signed record

T-073 is right about the defect it names. `sha256(request_id)[:32]` was thirty-two well-formed hex
characters belonging to no trace that ever existed, and `observability.py` states the cost correctly: a
populated well-formed field looks like an answer, so it is worse than an absent one.

The replacement is taken from the caller:

```python
incoming = TraceContext.parse(headers.get("traceparent"))
...
"trace_id": trace.trace_id,
"span_id":  trace.span_id,
```

and written into the signed, chained, anchored ADR_Record with nothing recording that the caller supplied
it. A hostile agent sets `traceparent` to a victim's trace id and its decision now sits inside someone
else's investigation. Or it reuses one traceparent across unrelated calls and an investigator reads a causal
link that the party under investigation asserted.

The source comment is honest about this — "Taken from the caller's traceparent now, or minted here when
this decision is the start of the trace." The **record** is not. Both cases serialize identically.

This is exactly the case T-031 was written for (`Observed` vs `Declared`), and T-031 is still `READY`. The
correction is one bit inside the signed payload, and it should land *with* T-031 rather than ahead of it.

---

## Credit, specifically

**CLAUDE lane.** The `observability.py` opening — three claims separated by strength, "a counter is not
evidence: it is unsigned, in-process, resettable and lossy by design", "nothing in this module is ever read
back into a decision" — is the best writing in the tree and it is load-bearing, not decoration; it is what
keeps a metric from becoming an assurance. The three defects `5b72329` discloses that its order did not name
are rule 10 working exactly as intended, and one of them is serious on its own: `_record_security_event` ran
inside the redemption transaction catching `PoolTimeout` alone, so a sink fault turned a **detected replay of
an execution capability** into a 500 — telling the attacker to retry, through the mechanism whose job was to
refuse. From `793a54a`, "anchoring while anything is unpublished swears to a range the stream does not have"
is a real evidence-integrity catch that no work order asked for.

**CODEX lane.** The packaging is the genuine article: digest-pinned base *and* digest-pinned syft and trivy,
uid 65532 with no login shell, a `HEALTHCHECK` that speaks mTLS to its own readiness endpoint, a migration
runner with a version table so `0002`/`0003` reach existing databases, and `mizan_app` as a separate login
role. The `request(method, contractPath, path)` design is a real idea. And the T-081 claim I distrusted most
turns out to be true: `service.py:128` does `context_document["tool"].pop("arguments")` before the context is
hashed or persisted, so `/v1/decisions/{id}/context` genuinely cannot serve raw arguments.

## One process note

The four CODEX commit bodies are single-paragraph outcome summaries. No pre-fix SHA against which a new test
fails (rule 8), no "what did not work" (rule 10), nothing found on the way. Compare `793a54a` and `5b72329`,
which disclose eight defects between them that no order named.

This is not a style preference. F-2 and F-3 are precisely the shape of thing a rule-10 paragraph surfaces
before a reviewer has to find it: an author who has to write down what the fault switch actually injects
notices that it injects a fake fault. Rules 8 and 10 are lane-neutral.

## Hostile-party answer

Still no, and unchanged this cycle — T-038/T-039 have not landed. F-6 adds a small new item to the list of
things such a party controls: a field investigators will read as provenance.
