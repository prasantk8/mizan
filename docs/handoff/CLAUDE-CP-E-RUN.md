# CLAUDE work order — CP-E

**Read first:** `docs/handoff/PR-PROTOCOL.md`, then `docs/reviews/R-008-two-lane-review.md`.
Heads reviewed: `track-b/stage-5` @ `5b72329`, `track-b/ui` @ `e8ef4cd`.
`CODEX-STAGE-3.md` §2 non-negotiables 1–9 and standing rules 6–12 apply unchanged. H-1 claim before work.
H-2's completion report now lives in the PR body — see PR-PROTOCOL §3.

---

## 0. What CP-E is

CP-E passes when a stranger can do this, from a clean machine, with no Mizan account and no help from us:

1. bring the stack up, watch a real LLM agent attempt a payment through the MCP gateway,
2. see it refused pending approval, and approve it **in the browser console**, not with `curl`,
3. see the tool run, the evidence drain, anchor, and get externally timestamped,
4. export a bundle and verify it with a **second verifier we did not write**, against **their own** trust roots,
5. read, at equal prominence with the verdict, everything the bundle does not prove.

CODEX owns the second verifier, the RFC 6962 proof work, the console and the auditor's path
(`docs/handoff/CODEX-CP-E-RUN.md`). You own the record, custody, and getting this repository under a CI that
actually runs. Neither engineer reaches CP-E alone, and the split is by what the work needs, not by which
half of the stack it lives in.

## 1. The boundary is withdrawn, and replaced

The first draft of this order answered R-008 F-1 with a directory-ownership table. That was the right answer
for two branches that never integrated and the wrong answer once every change lands on `main` within a day.
It is **withdrawn**. `docs/handoff/PR-PROTOCOL.md` replaces it: one task, one branch, one PR opened on day
one, CI required, cross-review required, squash-merge, delete.

One sealed boundary survives, and it is not about ownership: **T-062's implementer may not have read
`verify_evidence_export.py` or `evidence.py`.** You have read both. You are permanently disqualified and must
not review that PR's implementation against the Python — review its *disagreements* instead. See
PR-PROTOCOL §5.

---

## T-087 — Put this repository under a CI that runs. **First.**

**The finding this task exists for:** `ci.yml` declares six jobs — `baseline-contract`, `python-contract`,
`postgres-contract`, `production-image`, `offline-evidence-verifier`, `implementation-gates` — and triggers
on `pull_request` and `push: [main]`. `git remote -v` is empty. No branch has an upstream. **None of those
jobs has ever executed.** H-8 says CI is authoritative; nineteen commits have been gated by two people
running `make check` on their own machines and reporting the result in prose.

That is a larger hole than any of F-1 through F-6 and it is why the pull-request approach is worth the
change. Everything below follows from it.

1. **Wait for the founder's stamp on the remote** — visibility and account. Recommended: private, personal
   account, `main` default. PR-PROTOCOL §1 records what I checked: 290 tracked files, three tracked `.pem`
   files all public root certificates, no `PRIVATE KEY` block in the tree, `.env*` and `var/` ignored.
   Nothing in history needs scrubbing. Do not create it yourself.
2. Push `main`, then both lane branches.
3. Add `.github/pull_request_template.md` and the process-gate job per PR-PROTOCOL §3: the job fails a PR
   whose body lacks a resolvable `Pre-fix SHA:` (rule 8) or an empty rule-10 section. This mechanizes R-008's
   process note instead of asking two engineers to remember it — the same move T-065 makes for custody.
4. Branch protection on `main`: CI required, one approving review, linear history, no force-push.
5. Open both integration PRs (T-082).

**Expect red.** Six jobs have never run; `production-image` builds a container, boots it against real
PostgreSQL, asserts three migration rows and scans against a live CVE database, and
`offline-evidence-verifier` runs `sudo unshare --net` on a GitHub runner. Fix forward in **separate PRs, one
per failing job**. Do not fix six things in one branch to get green — that is how a lane accumulates nineteen
commits. If the network-namespace jail fails, understand it before weakening it: the isolation *is* the test.

Rule 10 applies hard here. The first CI run is the most informative event this repository will have this
month; write down everything it says.

## T-082 — Integration, through the PR flow

Both lanes land on `main` as PRs, reviewed. I have already built this merge locally and run it, so you are
not exploring: conflicts are **`WORK_LOG.md` and `tests/CONTRACT_COVERAGE.md` only**; `app.py` and
`evidence.py` auto-merge; the merged tree is ruff clean, passes all three `make check` gates, and runs
**360 passed / 35 skipped** without PostgreSQL.

`app.py` and `evidence.py` reporting `Auto-merging` is the danger, not the relief — semantic overlap does not
announce itself. Read those two diffs by hand.

Three things the resolution must get right:

* **`tests/CONTRACT_COVERAGE.md` is a union, never a side.** `793a54a` made
  `validate_contract_coverage.py` check non-`I`/`V` rows for the first time, and it validates index → pytest
  only. Taking one side drops the other lane's rows and no gate notices.
* **`WORK_LOG.md`** — union the queue rows, reconcile the two Active Task paragraphs into one, keep every
  Blocker from both sides. The claim ledger must come out **empty**.
* Re-run everything **with PostgreSQL**. The skipped 35 are the ones that matter: this is the first time both
  lanes' migrations, RLS policies and repositories have been in one tree.

Then delete both lane branches. From here there are no lanes-as-branches — two engineers and a queue.

If any number is worse than 360 + 29, stop and report before merging. A green merge that loses a test is the
worst outcome and the easiest to miss.

## T-083 — R-008 F-6: say *whose* trace it is (lands with T-031)

Your own defect, from `5b72329`. `trace_id` is now correct and unattributed — taken from the caller's
`traceparent` when present, minted here when absent, and the signed record serializes both identically. An
investigator reads it as provenance; a hostile agent chooses it, places its decision inside a victim's trace,
or asserts a causal link by reusing one traceparent across unrelated calls.

The source comment is honest about this. The record is not.

Do not land a bespoke boolean. This is the case T-031 exists for, T-031 is still `READY`, and the two are one
change:

* implement T-031's provenance tri-state (`Recorded` / `NotApplicable` / `Unpopulated`) with the
  `Observed` / `Declared` qualifier, **inside the signed payload**, per ADR-010,
* classify `trace_id` and `span_id`: continued from a caller is `Recorded`/`Declared`; minted here is
  `Recorded`/`Observed`,
* `NotApplicable` is never inferred (T-031's own rule),
* the verifier reports declared fields as declared. A bundle in which a `Declared` trace reads as established
  fact is the defect; the fix is that the reader can tell.

Test fails on `5b72329`, named in the PR body. Then apply the classification to every other field T-031's
enumeration reaches — `customer`, `intent`, and the enrichment fields are where I expect it to get
interesting.

**H-7 does not fire** — this narrows what a record claims, it does not widen it.

## T-054 — the fifth key role (H-7 trigger)

TM-001 R-2. `MIZAN_AUDIT_HMAC_KEY_REF` has a contract and no custody: not one of ADR-004 G.1's four
`KeyRole`s, no KMS/HSM adapter, no production refusal of development custody, no keyset publication, no
rotation despite §8 promising one.

Add `audit-commitment` as a fifth role, route `security/mizan_security/redaction.py` through the provider,
publish it with its `custody` field, implement the rotation.

**The key MACs; it does not sign.** If `KeyProvider` needs a *contract change* rather than an addition, stop
and file a blocker. Do not widen a ratified crypto contract to make a task fit — that is H-7 and it is the
founder's.

## T-065 — custody as a gate, not a caption

T-053 prints a warning. A warning is advice. Export must **refuse** a bundle whose signing-key custody is
`development-derived` unless an explicit, named override is passed, and the bundle then carries that override
as a field the verifier reports at equal prominence with the verdict.

Prove both directions end to end: refused without the override, clean-but-labelled with it.

This lifts "no bundle leaves the building" from a process rule someone has to remember into a property of the
system — the same move PR-PROTOCOL §3 makes for rules 8 and 10, and the same argument F-1 makes about lane
discipline. It is also what unblocks a public repository, so it is worth more than its position suggests.

## T-078 — SPEC §4 event conformance

Four of thirty-two §4 event names are emitted. Registry creates write no outbox rows at all. T-074 built the
relay, so there is now somewhere for these to go.

Emit at the writers, **or** amend §4 by ADR — an event nobody has ever had a reason to emit may be a
specification defect, and saying so is a legitimate outcome. What is not legitimate is a §4 that lists
thirty-two names when the system emits four.

The gate enumerates both directions: every §4 name has a producer, every producer's name is in §4. Rule 11 —
if you cannot name the subscriber a new event serves, say so in the PR rather than emitting it to satisfy a
count.

## T-071 — the demo (joint with CODEX)

Two PRs, one goal. You ship the agent harness and the MCP gateway leg; CODEX ships the browser-approval leg
and `make demo-run`. Neither is done until both are green. Details in the CODEX order — read it, so the two
halves meet.

## T-060 — what verification costs

After T-038 and T-039 land, because it is the argument for whether inclusion proofs should be the primary
auditor interface, and there is nothing to measure until they exist.

Measure the **shape** — where it breaks and how it degrades — not the largest size that worked. Rule 6: every
number lands with its `benchmarks/results/` artifact. Do not tune in the same change-set.

## T-086 — B-19 read authority (blocked)

B-17 closed registry **writes** to agent principals. `/v1/decisions/{id}/context` (new in `7bf3303`),
`/v1/decisions` and `/v1/audit` are tenant-scoped and role-free, so an `identity_kind: "agent"` token reads
the normalized context of every decision in its tenant: delegation chains, risk scores, deciding policies,
approval history. Raw arguments are excluded — `service.py:128`, I checked, the exclusion is real — so this
is not a payload leak. It is the reconnaissance surface B-17 just closed on the write side.

Blocked on **B-19**. Do not implement the recommended default without the stamp: unlike ADR-004 G.15 this one
*removes* access a caller may already have, so it is not descriptive and silence is not consent.

---

## Sequence

```
T-087  remote + PR infra + first CI run   [needs founder stamp on the remote]
  → T-082  integration, as reviewed PRs
  → T-083  (+T-031) trace provenance
  → T-054  fifth key role                 [H-7 if KeyProvider needs a contract change]
  → T-065  custody as a gate
  → T-078  §4 event conformance
  → T-071  the demo — joint with CODEX
  → T-060  after CODEX lands T-038/T-039
  → T-086  when B-19 lands
```

CODEX starts T-062 in parallel from hour one; it needs only the spec and the fixtures, so it is not blocked
on T-082.

Full gates before every PR: `ruff check .`, `make check`, `pytest` with PostgreSQL, and
`uv run python docs/reviews/reproductions/R-007-cpb-attestation.py` (8/8). A previously-green case going red
is a stop-and-report before the next task starts.

## Escalate, do not decide

H-7 fires on: any `KeyProvider` **contract** change (T-054), anything that moves approval semantics or tenant
isolation, any proposal to widen rather than narrow a ratified grammar, B-19, and the remote's visibility.

Park freely. Check first whether the conflict is between two ratified artifacts or between a ratified
artifact and something I wrote; if it is the latter, the ratified one wins and you can proceed on that alone.

## Review duty

You review CODEX's PRs and CODEX reviews yours — PR-PROTOCOL §4. On T-062 specifically: you are disqualified
from judging its implementation against the Python you have read. Review its **disagreements** with
`verify_evidence_export.py`, and treat every one as a defect in the spec or in one implementation until
proven otherwise. A disagreement reconciled by patching the new verifier to match the old one destroys the
task, and you are the reviewer most likely to catch that and most likely to cause it.

Rule 10 is the part that earns its keep. The eight defects `793a54a` and `5b72329` disclosed that no order
named are why this queue includes the crypto contract work. Keep writing them down — the PR template now has
a field for it.
