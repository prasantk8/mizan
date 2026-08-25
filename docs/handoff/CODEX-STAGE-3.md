# CODEX — Stage 3 Work Order: The Evidence Plane Becomes Checkable By A Stranger

**Issued:** 2026-08-25 · **Issuer:** CLAUDE lane (R-005) · **Ratified by:** human owner (R-005 §8)
**Scope:** twenty tasks (seventeen at issue; three inserted at CP-A by R-006), one order, one commit each · **Authority:** `WORK_LOG.md` remains the protocol;
this brief is the stage context that does not fit in it.

---

## 0. Read this first

Read, in this order, before touching anything:

1. `WORK_LOG.md` — *Active Task*, *Agent Queue*, *Next Executable Action*, *Transition Hooks*. Non-optional.
2. `docs/reviews/R-005-evidence-plane-brief-disposition.md` — **§6 and §10 are your task specifications.**
   Where this brief and R-005 disagree, R-005 wins; it is the reviewed document.
3. `docs/adr/ADR-004-audit-immutability.md` — **Amendment G is ratified contract.** Cite it. Do not
   re-decide it, do not improve it, do not substitute a design you prefer. If you believe it is wrong, stop
   and file a blocker; that is a legitimate move and a fast one.
4. `SPEC_v1.md` — contracts. Spec wins over code, always (H-3).

---

## 1. What you are actually building

Stage 2 hardened the control plane. Stage 3 is a different kind of work, and it is worth understanding
before the first commit.

Today Mizan's evidence is produced by Mizan, stored in Mizan's database, signed with a key Mizan generates
in the process being attested for, and verifiable only by logging into Mizan. **That is testimony from a
party to the dispute.** A hostile insider holding the database and the signing process can rewrite history
from genesis, re-sign every record and every anchor, and every verifier in this repository returns *valid*.
Both histories verify. That is not a bug in a function; it is a missing layer.

By the end of Stage 3:

- Anchors chain, count, and order, so removing or replaying one is detectable (T-030).
- An auditor who does not trust Mizan can verify a bundle **offline, in a clean virtualenv, with the network
  off, using two pinned dependencies** (T-032).
- Something outside the Mizan trust boundary signs the anchor — an RFC 3161 timestamp authority, and for
  enterprise, the customer's own key (T-033 → T-025 → T-036).
- A counterparty holds a few hundred bytes that prove *their* decision was in Mizan's anchored history at a
  timestamped moment, verifiable **after Mizan no longer exists** (T-038/T-039).
- Absence is signed and typed, so "no approval recorded" stops rendering identically to "we weren't
  looking" (T-031).
- And a risk officer — not an engineer — can read the verification report, including the part that says
  exactly where the guarantees stop (T-037).

That last property is the product. Everyone's report has "here is what we prove." A report that tells an
examiner precisely what it *cannot* prove is the one an examiner believes about the rest.

---

## 2. Non-negotiables

These are the rules the last stage was validated against; two of them were missed, and both fixes are in
your queue. Assume every claim you make will be re-run.

1. **One task, one commit.** No bundling, no "while I was in there." A change-set that spans two task IDs
   is rejected on sight.
2. **H-3 is absolute.** Any change to a schema, endpoint, event, state machine, or invariant requires the
   ADR delta *in the same change-set*. Spec wins over code. A commit that changes the anchor payload without
   amending ADR-004 and SPEC is invalid and the next agent reverts it. **Config keys** *(clause amended
   post-hoc at CP-A — R-006 V-1)*: **every** key registers in SPEC in the same change-set, no exception; an
   ADR delta is additionally required only where the key changes contract-bearing runtime behaviour.
3. **Every fix ships with the test that fails on the pre-fix commit — and you name that SHA in the WORK_LOG
   line.** This was omitted last stage. It will be sampled again by reverting to the SHA you name and
   running the test. A test that passes on the pre-fix commit is not a regression test; it is decoration.
4. **Rule 6 is mechanical now.** No performance number in any report, commit message, or WORK_LOG line
   without a committed `benchmarks/results/<name>-<sha>.json` carrying the measurement, host description
   (CPU, cores, OS, Python), commit SHA, UTC timestamp, and run parameters. T-029 makes this enforceable;
   after T-029 lands, a terminal-only number is a rejected claim. This is not bureaucracy — the alternative
   is a number nobody can reproduce sitting in a document an auditor reads.
5. **A gate never observed failing is not a gate.** Every negative fixture must be demonstrated failing
   before the fix and passing after. Commit the fixtures.
6. **No scope widening.** Each spec has an explicit *Out of scope*. If closing a task requires something
   outside it, stop, park, report. Parking is cheap; a silent widening costs a review cycle.
7. **Honest reporting.** If a task cannot be completed as specified, say so with the reason and the
   evidence. A stage report with no parked item, no surprise, and no stated limitation is the report most
   likely to be sent back — Stage 2's was, and two findings came out of it.
8. **Lane discipline (H-4)** and **claim discipline (H-1/H-8)** unchanged. CI is authoritative.
9. **A guarantee is demonstrated by rejecting the old output, not by an `ImportError`** *(added by R-006 V-7
   at CP-A)*. Where a task adds a *guarantee* rather than fixing a *behaviour*, the pre-fix demonstration
   must show the **new gate rejecting the artifact the old code produced** — for T-030 that was the anchor
   payload the pre-fix `anchor()` emitted, carrying no `anchor_number`. "The module did not exist yet"
   proves the code is new. The rule exists to demonstrate the defect. Keep the pre-fix SHA line; add this.

---

## 3. The sequence

Twenty tasks — the original seventeen plus T-043/T-042/T-041, inserted at CP-A and numbered 4a/4b/4c because
they harden what T-030 and T-032 just built rather than extending it. **Do not reorder without recording the
reason in the WORK_LOG.** The order is not arbitrary:
each step is additive to the record shape, and nothing later weakens anything earlier.

| # | Task | Spec | Why here |
|---|---|---|---|
| 1 | **T-016** | R-005 §6 | Small, closes the last open Stage-2 finding, unblocks T-019 |
| 2 | **T-029** | R-005 §6 | Trivial, and every later benchmark claim depends on it existing |
| 3 | **T-030** | R-005 §6 | Everything downstream assumes the anchor set is sound |
| 4 | **T-032** | R-005 §6 | The offline verifier is the only forcing function proving the export is complete |
| 4a | **T-043** | R-006 §3 V-6 | *Inserted at CP-A.* The export path has never run against the real pipeline and no operator can produce a bundle — prove T-032 real before building on it |
| 4b | **T-042** | R-006 §3 V-4/V-5 | *Inserted at CP-A.* Bind every in-range anchor to its record, pin the left edge, stop crediting unsigned checkpoints |
| 4c | **T-041** | R-006 §3 V-1/V-2 | *Inserted at CP-A.* A forgeable `commit_sha` makes rule 6 decorative |
| 5 | **T-033** | R-005 §6 | The provider seam, and the mandatory I-11 correction |
| 6 | **T-025** | R-005 §10 | Custody must be real before an external party signs anything |
| 7 | **T-036** | R-005 §10 | RFC 3161 + countersignature — the layer that ends the testimony problem |
| 8 | **T-038** | R-005 §10 | Merkle inclusion — caller-retained proof, the differentiator |
| 9 | **T-039** | R-005 §10 | Consistency proofs — append-only proven, not just numbered |
| 10 | **T-031** | R-005 §6 | Provenance tri-state + new ADR-010 |
| 11 | **T-034** | R-005 §6 | Binding coverage enumeration; needs provenance first |
| 12 | **T-035** | R-005 §6 | Anti-rot gates, protecting everything above |
| 13 | **T-024** | queue | Adversarial suite (already READY, feeds T-040) |
| 14 | **T-040** | R-005 §10 | `make attack` — the drill, over real bundles |
| 15 | **T-037** | R-005 §10 | The auditor's report. Last because it presents everything else |
| 16 | **T-026** | queue | Outbox drain operations |
| 17 | **T-023** | queue | Load/latency on deployment-class Linux — see §6 |

---

## 4. Checkpoints — stop and report

Do **not** run twenty commits unattended. Stop at each checkpoint, report, and wait.

- **CP-A — after T-032.** The anchor is sound and a stranger can verify a bundle. Report: the verifier run
  in a clean virtualenv with the network off, plus each tamper fixture's rejection message.
- **CP-B — after T-036.** The crypto boundary. Highest-risk work in the stage and H-7 territory: report
  before going further, including the egress-boundary test showing the TSA request carries a digest and
  nothing else, and the breaker behaviour under a simulated TSA outage.
- **CP-C — after T-039.** Merkle inclusion and consistency. Report proof sizes with benchmark artifacts and
  the before/after rewrite fixture.
- **CP-D — after T-037.** Stage complete. Full report per §5.

At each checkpoint: update `WORK_LOG.md` (H-2/H-6), release the claim, and state plainly what is done, what
is parked, and what surprised you.

---

## 5. Reporting format

Per task, one WORK_LOG line in house style, plus in the checkpoint report:

```
T-0XX · <one line: what changed>
  Pre-fix SHA:     <sha>   (test <name> observed failing there)
  Contract delta:  <ADR/SPEC touched, or "none — no contract touched">
  Gates:           make check | ruff | N unit/property | M live postgres | <new gates>
  Artifacts:       benchmarks/results/<file>.json   (if any number is claimed)
  Parked/limits:   <what you could not do, and why>  ← this line is never "none" by default
```

Claims that will be re-run on review: every `file:line` you cite, every pre-fix SHA, every gate, every
negative fixture, and the T-032 verifier in a clean virtualenv with the network off. If it cannot be run
that way, T-032 is not done regardless of what its tests report.

---

## 6. Things that will get work rejected

Stated in advance so no one wastes a cycle:

- Touching `policy_engine.py:166` in T-016. That read is from a **policy** document and is legitimate;
  conflating it with the ADR_Record read is how the finding was missed the first time.
- Extending the `ADR_Record` schema in T-016 (B-10 forbids it). T-031 extends it deliberately — that is the
  one task where it is permitted, and it needs a **new ADR-010**, not an amendment.
- A T-032 verifier derived from whatever the export happens to contain. Write the verifier against the
  *desired* guarantees, let it fail, then extend the export until it passes. The other order produces a
  verifier that certifies its own input.
- A T-032 verifier that implies more assurance than exists. Until T-036 lands it must state, in plain
  language, that the anchor signature is Mizan's own.
- Merkle work without RFC 6962 domain separation (`leaf = H(0x00‖x)`, `node = H(0x01‖l‖r)`). Without it a
  leaf and an internal node are confusable and the proof is worthless.
- A T-040 drill reporting 100% caught. It must include the classes that succeed — a record dropped before
  chaining, an anchor withheld entirely — cross-referenced to ADR-004 G.3.
- Shipping a TSA trust root inside a Mizan bundle. That returns the auditor to trusting Mizan.
- Binding a field in T-034 by putting a digest in a column beside the data. Whoever can write the data can
  write the digest in the same statement. Bind inside the chain or inside an anchor.
- Any number in any report without its `benchmarks/results/` artifact (after T-029).
- **T-023 with a substituted number.** If deployment-class Linux is unavailable to you, `PARKED(hardware)`
  with the M3 Max artifact clearly labelled as development-host is the correct and expected outcome. A
  dev-host number presented as a deployment number is the exact failure mode rule 6 exists to prevent.

---

## 7. Where to escalate

File a blocker in `WORK_LOG.md` and park — do not idle, move to the next READY task — if you hit:

- Anything under **H-7**: money movement, approval semantics, crypto design, key management, tenant
  isolation. Note that Amendment G has already ratified the crypto *decisions* for this stage; implementing
  them is yours. A choice Amendment G does not cover is not.
- A contract that cannot be expressed without widening something else. T-031 explicitly instructs you to
  park rather than widen — that instruction generalises.
- More than two unbound fields discovered in T-034's enumeration. Report the enumeration; do not fix them
  all in one change-set. Each unbound field is its own contract question.

---

## 8. The standing question

`docs/product/FALSIFICATION_TESTS.md` records a gate that now applies to every commit in this stage:

> **Would this survive a hostile party who holds the database and the signing key?**

On 2026-08-25 the honest answer for this repository was **no**. Stage 3 is the work that makes it yes. When
you finish a task, ask it. If the answer for the component you just touched is still no, say so in the
report — that is exactly the information this stage exists to surface, and it is worth more than a clean
summary.
