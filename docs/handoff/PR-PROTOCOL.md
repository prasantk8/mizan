# The pull-request protocol

Supersedes the directory-ownership table in the first draft of the CP-E orders.
Applies to both lanes from T-087 onward.

---

## 0. Why, in one paragraph

H-8 says CI is authoritative. `.github/workflows/ci.yml` declares six jobs — `baseline-contract`,
`python-contract`, `postgres-contract`, `production-image`, `offline-evidence-verifier`,
`implementation-gates` — and triggers on `pull_request` and `push: [main]`. There is no git remote. No
branch has an upstream. **Not one of those jobs has ever run.** Nineteen commits of work have been gated
entirely by two engineers running `make check` on their own laptops and reporting the result in prose.

The pull-request approach is not a review ritual we are adopting for politeness. It is the mechanism that
makes H-8 true for the first time. Everything else here follows from that.

## 1. The remote

**Needs the founder's stamp before anyone runs it** — creating the repository is outward-facing and I will
not do it unasked. Recommended: **private** repository under the personal account, `main` as default.

I checked what would be published: 290 tracked files, 12 MB of history, three tracked `.pem` files (all
public root certificates — FreeTSA, USERTrust, and the test TSA root), no `PRIVATE KEY` block anywhere in
the tree, `.env*` and `var/` both ignored. Nothing in history needs scrubbing before a first push.

Private is the right default anyway, and not because of secrets. TM-001 R-4 still stands: development
signing keys are `sha256(key_id)` and the `key_id` ships in every bundle. That is a property of the
artifacts, not of the source, but until T-065 makes custody a gate rather than a caption there is no reason
to hand a stranger a repository that can mint a bundle which looks signed.

Revisit visibility after T-065 and T-062 land. An open second verifier is worth more than a closed one.

## 2. One task, one branch, one PR

```
claim (H-1)  →  branch from main  →  work  →  push  →  PR  →  CI green  →  review  →  squash-merge  →  delete branch
```

* Branch names: `t-084-adversarial-fault-injection`. The task ID is the first thing in the name.
* **A PR is opened when the work starts, not when it finishes.** Draft PR, first commit, push. This is what
  replaces the "no more than two unmerged commits" rule: the other lane can see what you are touching from
  the first hour, and R-008 F-1 does not recur because divergence is visible while it is one file deep.
* One task per PR. If a task turns out to be two things, it becomes two PRs, and say so in the report.
* Squash-merge, so `main` has one commit per task and the commit subject is the task.

The long-lived `track-b/stage-5` and `track-b/ui` branches **end** at T-082. Both lanes work from `main`
after that. There are no lanes-as-branches any more; there are two engineers and a queue.

## 3. The PR body is the completion report

H-2's five-part completion protocol moves into the PR body, and this is the part that earns the change.
R-008's process note said CODEX's four commit bodies carried no pre-fix SHA (rule 8) and no what-did-not-work
(rule 10), and that F-2 and F-3 are exactly the shape of thing a rule-10 paragraph surfaces before a reviewer
has to find it. A rule that depends on remembering is not a boundary — the same argument F-1 makes about lane
discipline and T-065 makes about custody. So mechanize it.

`.github/pull_request_template.md`:

```markdown
## Task
T-0XX — <one line>

## What changed
<outcome, not diff summary>

## Rule 8 — the test that fails before the fix
Pre-fix SHA: <sha>
Command:     <exact command>
Result:      <the failure output, verbatim>

## Rule 10 — what did not work
<what was tried and abandoned, what was found on the way, what is still wrong>

## Rule 6 — numbers
<benchmarks/results/ artifact path, or "no numbers claimed">

## H-7
<"does not fire", or the blocker filed>
```

A CI job parses the body and fails the PR if `Pre-fix SHA:` is absent or unresolvable, or if the rule-10
section is empty or says only "nothing". `Result: n/a — no behaviour change` is a legitimate rule-8 answer
for a docs-only PR and the job accepts it; silence is not.

This is rule 9 applied to our own process: the guarantee is demonstrated by rejecting the old output.

## 4. Review

**Each lane reviews the other's PRs. Review is not optional and it is not a rubber stamp.**

The reviewer's job is not to check the diff compiles — CI does that better. It is:

1. **Find the vacuous assertion.** R-008 F-2 is the canonical example: a test whose name is a claim and
   whose body cannot fail. For every new test, ask what state makes it red, and check that state is
   reachable.
2. **Find the fault that is in the harness.** F-3. If a test proves a guard, the injected fault must be in
   the guard.
3. **Ask what the record now claims that it cannot support.** F-6. Any new field inside a signed payload
   gets this question, every time.
4. **Check the name against the behaviour.** Rule 11.

A review that says "LGTM" is not a review and the other lane should say so. A review that finds nothing says
what it looked for and did not find — that is a real review and it is fine.

**GitHub cannot enforce this one, and pretending otherwise would be worse than not trying.** Both
engineers push as the same account, and GitHub does not let an author approve their own pull request. A
`required_approving_review_count` of 1 would therefore block every merge in this repository, not gate
them. So:

* **CI is the enforced gate.** Required status checks, linear history, no force-push — all mechanical,
  all real.
* **Review is an obligation discharged in a comment, not a green check.** The reviewer posts the review
  as a PR comment beginning `REVIEW:` and saying what was looked for. Merging without one is visible in
  the thread forever, which is the enforcement that is actually available.
* A lane may merge after 24 hours with no review, and says so in the thread.

This is a weaker guarantee than branch protection and it should be recorded as weaker. It gets stronger
the moment a second GitHub identity exists, and that is worth doing.

## 5. Ownership

The directory-ownership table is **withdrawn**. It was the right answer for two branches that never
integrated; it is the wrong answer once every change lands on `main` within a day of being started.

Replacing it:

* The claim (H-1) names the directories the task expects to touch. An honest estimate, not a contract.
* If two open PRs touch the same file, the second one to open says so in its body and the reviewers sort it
  out. This is a conversation, not a violation.
* Nobody is forbidden from any part of the codebase. **One exception, below.**

### The one sealed boundary: T-062

The independent second verifier requires an implementer who has not read `verify_evidence_export.py` or
`evidence.py`. This is not a lane rule, an ownership rule, or a matter of politeness — it is the entire
content of the task. A verifier written by someone who has read the implementation verifies the
implementation, not the spec, and the exercise proves nothing.

Therefore **T-062 is scheduled first for whichever engineer has not read those files**, and it is done in a
**fresh session** that opens `docs/spec/EVIDENCE-BUNDLE-FORMAT.md` and nothing else. Once it lands, the seal
is gone and that engineer is free in `evidence.py` like anyone else.

Order matters here in a way it does not anywhere else in this plan. Get it wrong once and the property is
unrecoverable without a third party.

## 6. The first CI run — predicted, then run

I wrote predictions before pushing, and I am keeping them next to the results, because the gap is the
most useful thing in this document.

| Job | Predicted | Actual |
|---|---|---|
| `baseline-contract` | likely green — both lanes run it locally | **red** — `make check` installs nothing |
| `python-contract` | likely green — both lanes run it locally | **red** — 15.081 s against a 10 s target |
| `postgres-contract` | plausible failures, first time in one tree | green |
| `offline-evidence-verifier` | highest risk is the `unshare --net` jail | **red**, and the jail worked fine |
| `implementation-gates` | unknown | green |
| `production-image` | the highest-risk job | did not run — it is not on `main` yet |

I got every prediction wrong that it was possible to get wrong. The two jobs I called safe were the ones
both engineers run daily, and both failed — for reasons that only appear on a machine with no `.venv`
and no developer laptop underneath. The job I called riskiest failed for a reason unrelated to the risk
I named: the network-namespace jail worked on the first attempt, and a committed test certificate with a
twenty-four hour lifetime is what broke it.

That is the whole argument for F-7 in one table. Local confidence was not calibrated, and there was no
way to find that out except by running.

The three failures are R-008 F-8, F-9 and F-10. Fix forward in separate PRs, one per failing job. Do not
fix three things in one branch to get to green; that is precisely how a lane accumulates nineteen
commits. **F-10 must not be resolved by regenerating the fixture** — see the finding.

## 7. What does not change

H-1 claim before work. H-3 contract touch requires an ADR delta in the same change-set. H-7 escalation for
money movement, approval semantics, crypto, key management, tenant isolation. Standing rules 6–12. `main`
protected: CI required, one approving review required, linear history, no force-push.

`WORK_LOG.md` remains the queue and the blocker list. It is now the most frequently conflicting file in the
repository, and that is correct — it is the one file both engineers are supposed to be writing to.
