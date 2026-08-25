# R-006 — Independent Validation of Stage 3 Checkpoint CP-A

**Date:** 2026-08-25 · **Lane:** CLAUDE · **Scope:** commits `81f6a75`, `dede1e3`, `fea9b89`, `686e4a3`
**Head validated:** `686e4a39a07da9f3af6537b0e0e939465a16cf15`
**Verdict:** **T-016, T-029, T-030, T-032 accepted DONE.** Seven findings (V-1..V-7), none blocking the
accepted work, three of them queued as new tasks before T-033.

---

## 1. What was re-run, not read

| Claim | Method | Result |
|---|---|---|
| `make check` passes | re-run | `30 boundaries, 14 JSON blocks, 13 schema IDs; five drift gates proven` — the fifth gate is T-016's |
| 140 unit/property tests pass | re-run | 140 passed |
| Verifier imports no Mizan code | ran under `python -I` with the package path stripped; asserted `sys.modules` | PASS, `[]` mizan modules loaded |
| Golden bundle verifies standalone | ran `scripts/verify_evidence_export.py` on the committed fixture | PASS + three disclosure lines printed |
| Four tamper cases reject distinctly | read the four tests; each mutates the bundle **and refreshes the manifest hash** so the case is not trivially caught by the checksum layer | Correct construction; messages match `tamper-cases.json` |
| T-016 pre-fix SHA `73c7de9` | `git show 73c7de9:...repository.py` | `constraints=doc.get("constraints")` present — the claimed defect existed |
| T-029/T-030/T-032 pre-fix SHAs | `git show <sha>:<path>` for each named module | All three genuinely absent at the named commit — the claims are honest (see **V-7**) |
| `policy_engine.py:166` untouched | commit stat + current source | Untouched; still reads a **Policy** document, correctly |
| `ADR_Record` schema not extended | T-016 SPEC diff | Only the Policy `iff` closure was added. B-10 respected |
| H-3 delta per commit | per-commit stat | T-016 → ADR-002 Amd. B + SPEC; T-030 → ADR-004 G.5 + SPEC §10; T-032 → ADR-004 G.6 + SPEC §10; **T-029 → none (see V-1)** |
| One task, one commit | log | Clean. No bundling |

## 2. Credit where it is due

Three things were done better than specified, and they should survive later refactors:

1. **`export_evidence_bundle` reconstructs records from the immutable object store and explicitly does not
   trust Postgres** (`evidence_export.py:34` — *"Postgres record documents are not trusted"*). Nothing asked
   for that. It is the correct instinct: the mutable store is the one an insider edits.
2. **`record_anchor` validates the anchor's number, range, and previous hash under a `FOR UPDATE` lock on the
   stream head** and raises `409 anchor_head_conflict` rather than the previous `ON CONFLICT DO NOTHING`.
   Silent no-op on a chain insert would have been a hole.
3. **The verifier's `LIMITATION` and `NOT COVERED` lines exist already**, three tasks before T-037 requires
   them, and they name the hostile-party scenario in plain words. That is the product ethos arriving early.

The reporting was also correct in the way that matters most: the T-032 log records that `uv --offline`
installation **failed** because `cffi` was absent from cache and that the network was therefore used before
runtime isolation. That is precisely the kind of disclosure Stage 2's report omitted.

## 3. Findings

### V-1 · Two config keys shipped with no contract delta (H-3) — **must fix**

`MIZAN_BENCHMARK_RESULTS_DIR` and `MIZAN_BENCHMARK_COMMIT_SHA` were introduced in T-029
(`benchmarks/artifacts.py:15,39`; `.github/workflows/ci.yml:51`) and appear in no SPEC section and no ADR.
H-3 says "config keys" without qualification.

**Disposition.** Both halves. The keys get registered in SPEC (T-041), *and* H-3 is amended — **post-hoc, and
recorded as post-hoc** — to require an ADR delta only for config that changes contract-bearing runtime
behaviour, while requiring SPEC registration for every key without exception. A rule that demands an
architecture decision record for a benchmark output directory is a rule engineers learn to route around, and
a rule routed around in small cases stops working in large ones. Nothing becomes unregistered; the ADR
requirement stays where it carries meaning.

### V-2 · The benchmark SHA is forgeable and the worktree is unchecked — **must fix**

`benchmarks/artifacts.py:15` lets `MIZAN_BENCHMARK_COMMIT_SHA` override the commit SHA with any string, and
`scripts/validate_benchmark_artifacts.py:36` only checks that the *filename* matches the *field* — not that
the field names a commit that exists. Separately, nothing records whether the worktree was clean, so a run
with uncommitted edits stamps `HEAD` and produces an artifact naming code that never executed.

This is not a hypothetical. Rule 6 exists so a number in an auditor-facing document can be reproduced. An
artifact whose SHA is unverifiable and whose worktree state is unknown is a number with a plausible string
next to it, which is the exact failure mode the rule was written against. The gate currently validates shape,
not provenance.

**Disposition.** T-041.

### V-3 · The manifest's assurance block is declared, not derived — **design constraint on T-036**

`evidence_export.py:99-102` writes `assurance: {anchor_attestation: "mizan_self_signed", external_timestamp:
false}` as a literal, and the verifier reads it back and reports it. Today that is harmless because the
verifier prints its limitation unconditionally. After T-036 it is not: a one-byte edit to `manifest.json`
would flip a bundle's advertised assurance, and any consumer reading the field — a report, a dashboard, a
future `--report` renderer — would repeat the lie.

**Disposition.** Recorded as a binding constraint on T-036: the verifier must derive assurance **only** from
attestation tokens it has itself validated against an operator-supplied trust root, and must treat the
manifest's `assurance` block as a *claim under test* — a mismatch between claimed and derived assurance is a
verification **failure**, not a warning. Carried into the T-036 row.

### V-4 · Intermediate anchors are not bound to the exported records — **new task**

`scripts/verify_evidence_export.py` cross-checks `head_hash` against the record set for the **terminal anchor
only**. Every earlier anchor is checked for internal consistency (number, previous hash, range, count,
signature) but never against the records the bundle actually contains. And at the left edge:

```python
previous = ZERO_HASH if range_start == 0 else records[0].get("prev_hash")
```

For any bundle that does not start at genesis — which is the ordinary auditor case, *one decision and its
neighbourhood*, not the whole stream — the first `prev_hash` is accepted on the bundle's own say-so. The
anchor whose `to_sequence == range_start - 1` already carries the hash that would pin it, signed, in the same
bundle. It simply is not consulted.

**Disposition.** T-042. Two assertions, both cheap: every anchor whose `to_sequence` lies inside the exported
range must have `head_hash` equal to that record's `record_hash`; and the anchor ending at `range_start - 1`,
when present, must have `head_hash` equal to `records[0].prev_hash`.

### V-5 · `checkpoints.json` is presented as evidence and is not — **new task**

Checkpoints are recomputed from `records.json` at export time (`evidence_export.py:57-70`) and are unsigned.
Anyone who can alter the records can produce matching checkpoints in the same edit. They are a parallel-
verification performance aid, which is what ADR-004 introduced them as. The verifier's success line reads:

> `PASS: The exported records, receipts, checkpoints, and complete anchor chain verified ...`

listing them beside receipts and anchors, which are signed. A careful reader takes that as four independent
confirmations. It is three.

**Disposition.** T-042. Either drop checkpoints from the sentence or label them as what they are. This is a
one-line change and it is worth doing precisely because it is small: the entire premise of T-037 is that this
tool does not overstate, and the first place that premise gets tested is the sentence it prints on success.

### V-6 · The export path has never been run against the real pipeline — **new task, highest value**

`export_evidence_bundle` is exercised only by `build_bundle()` in `tests/unit/test_evidence_export.py`, which
hand-constructs the records, the receipts, and the anchor payload as literals. The repository argument is
duck-typed `Any`. `EvidenceRepository.receipt_rows` (`evidence.py:482`) and `.anchors` (`evidence.py:554`)
happen to satisfy the shape, but **no test exports a stream produced by `EvidenceSequencer` and
`OutboxPublisher.anchor()`**, and there is no CLI or endpoint that produces a bundle at all.

Two consequences. First, the verifier is validated against a fixture written by the same author in the same
week as the verifier, so a divergence between the real anchor payload and the fixture's shape passes CI
silently — the classic self-certifying test. Second, and more plainly: **an operator cannot currently produce
a bundle.** T-032's deliverable is the artifact an auditor holds, and the code path from a live tenant to
that artifact does not exist end to end.

**Disposition.** T-043, sequenced first. One live-PostgreSQL test that authorizes N requests, drains the
outbox, anchors, exports, and runs `scripts/verify_evidence_export.py` **as a subprocess** over the result,
plus the operator entry point that makes a bundle producible. This is the single highest-value missing test
in Stage 3: it is the only thing that connects the verifier to the system it claims to verify.

### V-7 · Three of four pre-fix demonstrations are `ImportError` — **standing rule, no rework**

The pre-fix SHAs were sampled and all four claims are honest. But for T-029, T-030, and T-032 the pre-fix
failure is that the module did not exist yet. That proves the code is new. It does not demonstrate the
defect, and the rule was written to demonstrate defects.

For T-030 the stronger demonstration was available and cheap: take the anchor payload the **pre-fix**
`anchor()` produced — no `anchor_number`, no `prev_anchor_hash`, no `covered_record_count` — and show the new
verifier rejecting it as unverifiable. That establishes the thing worth establishing, which is that the
system's previous output was not checkable.

**Disposition.** No rework of accepted tasks. New standing rule 9, effective from T-033: where a task adds a
*guarantee* rather than fixing a *behaviour*, the required demonstration is that **the new gate rejects the
artifact the old code produced.** The pre-fix SHA line stays; this is added to it.

## 4. The standing question

> Would this survive a hostile party who holds the database and the signing key?

**Still no**, and CODEX said so in every one of the four log lines rather than letting it drift. The verifier
now says it out loud to its own user, which is a better state than silent falsity but is not a yes. T-033
labels the gap in the contract, T-025 gives the key an owner outside the process, and T-036 is where the
answer changes. Nothing before T-036 changes it, and no report should imply otherwise.

Recorded in `docs/product/FALSIFICATION_TESTS.md`.

## 5. Sequence from here

`T-043 → T-042 → T-041 → T-033 → T-025 → T-036 (CP-B) → T-038 → T-039 (CP-C) → T-031 → T-034 → T-035 →
T-024 → T-040 → T-037 (CP-D) → T-026 → T-023`

Twenty tasks. The three corrections come first because each hardens the layer everything above it stands on,
and all three are small. T-043 leads: proving the export path is real costs one test and is the difference
between a verifier that checks Mizan's evidence and a verifier that checks a fixture.
