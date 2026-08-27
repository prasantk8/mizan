## Task
<!-- T-0XX - one line. If this turned out to be two tasks, it is two pull requests; say so. -->

## What changed
<!-- The outcome, not a summary of the diff. What can the system do now that it could not? -->

## Rule 8 - the test that fails before the fix
<!--
Pre-fix SHA is the commit against which the new test fails. Run it there and paste what
came back. A documentation-only change writes `Result: n/a - no behaviour change`; the gate
accepts that only when the diff is documentation only.
-->
Pre-fix SHA:
Command:
Result:

## Rule 10 - what did not work
<!--
What was tried and abandoned, what was found on the way, what is still wrong and why it was
left. R-008 F-2 and F-3 are exactly the shape of thing this section surfaces before a
reviewer has to find it. "Nothing" is not an answer the gate accepts.
-->

## Rule 6 - numbers
<!-- The benchmarks/results/ artifact path for every number claimed, or `no numbers claimed`. -->

## H-7
<!-- `does not fire`, or the blocker filed. Fires on money movement, approval semantics,
crypto, key management, tenant isolation. -->

---

**Reviewer** (PR-PROTOCOL section 4): find the vacuous assertion; find the fault that lives in
the harness; ask what the record now claims that it cannot support; check the name against the
behaviour. "LGTM" is not a review. A review that finds nothing says what it looked for.
