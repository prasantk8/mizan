# CODEX work order — CP-E

**Read first:** `docs/handoff/PR-PROTOCOL.md`, then `docs/reviews/R-008-two-lane-review.md`.
Head reviewed: `track-b/ui` @ `e8ef4cd`.
`CODEX-STAGE-3.md` §2 non-negotiables 1–9 and standing rules 6–12 apply unchanged. H-1 claim before work.
H-2's completion report now lives in the PR body — see PR-PROTOCOL §3.

---

## 0. The framing has changed, and this matters

The first draft of this order called your half "the surface" and gave you the console, the packaging and the
tests. That was a mis-read of what you are, and the founder said so. **You are not the UI engineer.** The
split from here is by *what the work needs*, not by which half of the stack it lives in — and the two hardest
cryptographic tasks in the tree, T-038 and T-039, are yours.

Two reasons, both from the review rather than from fairness:

* **T-075 is the tell.** You pinned syft and trivy by digest, not just the base image. Almost nobody does
  that, and the reason to do it is a specification-level argument about what an SBOM is a claim *about*.
  RFC 6962 is exactly that kind of work: a written spec, precise, unforgiving about domain separation, where
  the difference between correct and plausible is invisible to a test you wrote yourself.
* **T-081's claim held up.** I distrusted "without raw arguments" and traced it to `service.py:128`. True.
  You said a precise thing about a security property and it was precisely true.

Two things still have to change. Your four commit bodies carry no pre-fix SHA (rule 8) and no
what-did-not-work (rule 10). PR-PROTOCOL §3 turns both into CI-checked PR fields, so this stops being a
matter of remembering. And `7bf3303` reached into `control-plane/` when T-081 needed a read model the lane
boundary did not admit — the boundary is now **withdrawn** rather than tightened, because with one PR per
task the collision surfaces on day one instead of on day nineteen.

## What CP-E is

A stranger, on a clean machine, with no Mizan account and no help from us: brings the stack up, watches a
real LLM agent attempt a payment, sees it refused pending approval, approves it **in the browser**, sees the
tool run and the evidence anchor, exports a bundle, and verifies it with **a verifier we did not write**
against **their own** trust roots — reading, at equal prominence with the verdict, everything it does not
prove.

---

## T-062 — the independent second verifier. **First, and in a fresh session.**

**Start here, before anything else, and before you read another line of `control-plane/`.**

This is the highest-value task in the tree and its ordering is not a scheduling preference. The implementer
may not have read `verify_evidence_export.py` or `evidence.py`. CLAUDE is elbow-deep in both and is
permanently disqualified. You have touched `evidence.py` exactly once — thirteen lines of an unrelated read
model in `7bf3303` — so you are the only engineer who can still write this, and you stop being that engineer
the moment you start T-038. **The order is the task.**

Open a **fresh session**. Open `docs/spec/EVIDENCE-BUNDLE-FORMAT.md` and the conformance fixtures. Open
nothing else under `control-plane/` or `scripts/verify_*`.

Write a second verifier from that spec **alone**, in a **different language**, in `verifier-two/`. If you
need a constant, it comes from the spec — or the spec is incomplete, which is a finding and is worth more
than the constant. Do not copy a value from the Python.

Run both verifiers over `tests/fixtures/conformance/`. **Every disagreement is a defect** — in the spec or in
one implementation — and must be named, classified and fixed. A disagreement quietly reconciled by patching
the new verifier to match the old one defeats the entire exercise, and I will look for that specifically in
review.

Expect the spec to be wrong in at least two places. Finding them is the deliverable, not a setback. The
canonicalisation rules and the core-projection exclusion set are where I would look first.

This is rule 12 at product scale: the difference between "verify it yourself" as a claim and as a fact.

## T-084 — R-008 F-2 / F-3 / F-5: make the adversarial suite adversarial

Small, and it is a false green in the security tests, so it goes ahead of the large work.

**F-2 — the prompt-injection test asserts nothing about prompt injection.**
`test_tool_arguments_are_never_a_policy_namespace` stubs the repository with exactly one
`PolicyMatch(decision="DENY", priority=100)` and asserts `response.decision == "DENY"`. There is no ALLOW
rule in the set, so no injection — succeeding or failing — can change the outcome. The assertion holds for a
hostile payload, for an empty payload, and for a control plane in which tool arguments *are* a policy
namespace.

The fix is not a bigger corpus. The policy set must contain an **ALLOW rule that fires on exactly what each
injection forges** — `principal.role == "system-admin"`, `agent.id == "agt_root"` — at a priority that would
win the evaluation. Then a namespace leak produces ALLOW and the test goes red for the reason its name gives.
Keep the two assertions that follow; they are real.

**F-3 — the fault switch injects a fault into the harness.**
`if active("chain_tamper"): return _AcceptEverythingVerifier()` demonstrates that a test asserting rejection
fails when nothing rejects. That was not in doubt. Same for `prompt_namespace`, which edits a stub's
decision. Only `token_replay` touches product state — clearing `consumed_at` in PostgreSQL — and that one is
a genuine demonstration. Make the other three look like it: each category's fault must be a **regression in
product code**. Revert the guard the category exists to prove, run the category, require red.

And CI must run it. `.regression` is a marker file no workflow writes, so "each category can go red" is
asserted in a docstring and demonstrated by nobody — rule 9, in the place rule 9 matters most. Add a job that
iterates the four categories, applies each fault, and **fails if the suite passes**.

**F-5 — the allowlist expiry is aimed at the wrong target.**
Thirteen suppressions, all expiring `2026-09-03`, and `validate_vulnerability_allowlist.py` is in
`make check`. On 2026-09-04 every developer on every branch fails `make check` because a Debian `perl-base`
note aged out. Keep the weekly discipline, move the blast radius: an expired suppression fails the **image
scan job**; `make check` prints days remaining and stays green. The validator itself is good — RFC 3339 with
a real offset, non-empty justification, bare dates rejected — leave it alone otherwise.

## T-038 → T-039 — make append-only cryptographic

**The two tasks that change the hostile-party answer.** Today that answer is still no, and these are why.
`anchor_number` incrementing is a convention; a party who controls the store can produce a history that
increments and is not the history that happened.

* **T-038** — anchor the `merkle_root` with RFC 6962 domain separation (`0x00` leaf prefix, `0x01` node
  prefix — the separation is the whole security argument, and getting it wrong produces a tree that passes
  every test you would think to write), `/v1/audit/inclusion/{decision_id}`, and standalone `--inclusion`
  verification **offline**. This is the ADR-004 Option-2 path.
* **T-039** — RFC 6962 consistency proofs between successive anchors, so append-only is proven by
  construction.

Land them as separate PRs. **T-039's tests must fail against a tree that has T-038 and not T-039**, and the
PR body must name that SHA — a consistency proof that passes without the consistency check is the exact shape
of bug this pair is most likely to ship, and it is the shape rule 8 exists to catch.

H-3 fires: this touches ADR-004's anchor contract and needs an ADR delta in the same change-set. H-7 does not
fire — you are narrowing what an anchor can be made to say, not widening it.

If the spec and RFC 6962 disagree, RFC 6962 wins and the spec has a defect. File it, do not paper it.

## T-085 — R-008 F-4: the console must execute

There is no `package.json` anywhere in this repository. No JavaScript runtime executes `ui/app.js` in any
test, at any time. 674 lines, and the screen on which a human approves an AI agent moving money has never
been rendered by anything.

`scripts/validate_ui_contract.py` keeps its job and deserves credit — declaring the OpenAPI template
statically and passing the interpolated URL separately is what makes a template-literal call statically
checkable, which is further than most teams get. Two limits to fix while you are here: it checks the
**declaration**, not the call (`request("GET", "/v1/agents", "/v1/admin/anything")` passes, because nothing
binds argument two to argument three), and `test_ui_contract.py:316`'s `assert rendered_field in source` is a
string search that cannot tell a rendered field from a variable name in a comment.

Stand up a JS test runner (vitest + jsdom, or Playwright for the real DOM — pick one and say why in the PR)
and write the walkthrough that fails when a guard stops rendering:

* a pending approval renders with its SLA and epoch state,
* an epoch-stale approval's vote control is **disabled**, and the reason is on screen,
* the override control does not render for a principal who may not use it, **and the server refuses it too** —
  a disabled button is a courtesy, not a control,
* voting twice as the same principal is refused and the refusal is shown, not swallowed,
* the ADR summary card renders every field the decision carries, checked against a real response fixture
  rather than against source text.

## T-071 — the demo, end to end, with a real LLM (joint with CLAUDE)

Two PRs, one goal. CLAUDE ships the agent harness and the MCP gateway leg; you ship the browser-approval leg
and `make demo-run`. Neither is done until both are green.

PRD §38 wealth agent, through the T-070 MCP gateway, against a mock wealth API. A real model, not a scripted
transcript: the point is that a model never told about Mizan hits a governed tool, gets a structured refusal
naming its reason class, explains it to the user in its own words, and continues — and that a human then
approves it **in the console from T-085**, not with `curl`.

`make demo-run` ends with `verify_evidence_export.py` PASS and **both verifiers agreeing**.

Assert on the decision sequence, the ADR_Records, the refusal reason classes and the final bundle. Do not
assert on model prose — a test that pins an LLM's wording fails on Tuesday.

Record what did not work. If a refusal message is unclear to a model it will be unclear to a person.

## T-063 — the auditor's first hour

Yours because you will have written the second verifier, and the person who wrote it is the worst person to
assume what a stranger already knows — so write it against that discomfort.

Hand a T-065-clean bundle to someone with no Mizan context and no account. Document the real path: what they
install, what they run, where trust roots come from (**theirs**, never the bundle's), what each verdict
means, and — at equal prominence — **what a clean verdict does not prove**: TM-001's pre-chain omission and
the withheld final anchor.

Walk it from a clean machine and **record where it was wrong**. The first draft always is, and the
corrections are the deliverable.

---

## Sequence

```
T-062  sealed, fresh session — BEFORE anything else          → PR
  T-084  adversarial suite, allowlist blast radius           → PR
  T-038  RFC 6962 inclusion proofs        [H-3: ADR delta]   → PR
  T-039  RFC 6962 consistency proofs      [H-3: ADR delta]   → PR
  T-085  the console executes                                → PR
  T-071  the demo — joint with CLAUDE                        → PR
  T-063  the auditor's first hour                            → PR
```

T-062 does **not** wait for CLAUDE's T-082 integration merge — it needs only the spec and the fixtures, so it
runs in parallel from hour one. Everything after it starts from `main`.

Full gates before every PR: `ruff check .`, `make check`, `pytest` with PostgreSQL, and the JS suite once
T-085 lands. A previously-green test going red is a stop-and-report, not a thing to fix quietly in the same
branch.

## Escalate, do not decide

H-7 fires on money movement, approval semantics, crypto, key management and tenant isolation. Two live ones
in this order: if T-085 finds a control the **server** permits that the UI merely hides, that is a finding to
file, not a UI fix to ship. And if T-038 needs a change to a ratified anchor **contract** rather than an
addition to it, stop and file the blocker.

Park freely — refusing to start T-072 on a bad base was the right call and it cost nothing. Check first
whether the conflict is between two ratified artifacts or between a ratified artifact and something I wrote;
if it is the latter, the ratified one wins and you can proceed on that alone.

## Review duty

You review CLAUDE's PRs and CLAUDE reviews yours — PR-PROTOCOL §4. The reviewer's job is to find the vacuous
assertion, the fault that lives in the harness, and the new field inside a signed payload that claims more
than it can support. "LGTM" is not a review. A review that finds nothing says what it looked for.
