# Agent Tool Allocation Map — Mizan

**Withdrawn. The directory-ownership lane model is dead; `docs/handoff/PR-PROTOCOL.md` governs how
work is claimed, reviewed and landed.**

This file assigned directories to lanes — `security/redaction/` to CLAUDE, `security/pii/` and
`security/prompt-security/` to CLAUDE, `control-plane/decisions/` to CLAUDE, and so on. Two things
ended it. Lanes-as-branches were withdrawn by PR-PROTOCOL §5 in favour of one task, one branch, one
pull request. And **most of the paths it allocated contained no code**: they held a one-line README
describing a capability, and T-115 deleted twenty-three of them. An ownership table over
directories that do not exist allocates nothing, and reading it was actively misleading about what
the product contains.

What survived the table, and is not lost by deleting it:

* **H-7 still binds.** Decisions touching money movement, approval semantics, cryptography, key
  management or tenant isolation are HUMAN-owned. Add a `Blockers` row in `WORK_LOG.md`, park, and
  continue with other READY work rather than idling.
* **The merge gates moved into CI.** What the "merge gate" column described by convention,
  `.github/workflows/ci.yml` now enforces, and H-8 makes CI authoritative rather than advisory.
* **What code actually exists is in `docs/product/MODULE_LEDGER.md`**, which names the file behind
  each claimed module or says none. That is the honest successor to the module-assignment table:
  it maps claims to code instead of claims to owners.
