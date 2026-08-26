# Stage 4 Proposal — The Decision Becomes Recomputable

**Status:** PROPOSED 2026-08-25 · **Lane:** CLAUDE (proposal) → HUMAN (B-13) → CODEX (implementation)
**Depends on:** Stage 3 complete through CP-D, and T-031 (provenance tri-state) specifically
**Headline task:** T-044 · Verifiable Decision Replay

---

## 1. The gap Stage 3 does not close

By CP-D, a Mizan decision is hash-chained, receipted, anchored, RFC 3161 timestamped, Merkle-provable, and
verifiable offline by a stranger with two pinned dependencies and the network off. An auditor can establish,
without trusting Mizan, that **Mizan recorded decision D for request R at time T, and nobody has altered it
since.**

That is integrity of the record. It is not fidelity of the decision.

Consider an ADR_Record that is perfectly formed: correctly chained to its neighbours, covered by a signed
receipt, inside a signed anchor, timestamped by an independent authority, with a valid Merkle inclusion
proof. It cites policy `pol_wire_limits` v7, content hash `a3f9…`. It records **ALLOW**.

And policy `pol_wire_limits` v7, applied to that exact context, yields **DENY**.

Every layer built in Stage 3 passes that record. All of them. Chain verification passes because the chain is
intact. Anchor verification passes because the anchor is real. The timestamp passes because the timestamp is
genuine. The inclusion proof passes because the record genuinely is in the tree. The offline verifier prints
`PASS` and an auditor files it.

Nothing in the system re-applies the policy. The auditor takes Mizan's word that the evaluator did its job —
which returns us, one level up, to exactly the problem R-005 identified at the signing key: **testimony from
a party to the dispute.** We moved the trust boundary from "trust our database" to "trust our evaluator." It
is a smaller surface and a real improvement. It is not zero.

This matters most in precisely the case the product exists for. When an agent does something expensive and
the question is *"was it allowed?"*, the failure mode nobody catches is not a tampered log. It is a policy
that did not say what its author believed, or an evaluator that resolved a priority tie the other way, or a
`CONSTRAIN` that silently became an `ALLOW`. Tamper-evidence is the wrong instrument for that; it certifies
that the wrong answer has not been edited since it was written.

## 2. The claim this makes possible

> **Every governance tool can prove its log was not edited. Mizan can prove the decision in the log is the
> decision the policy requires — and name every input you are still taking on trust.**

Both halves matter, and the second is the one that makes the first believable. Nobody in this category ships
either.

## 3. What gets built

### 3.1 The bundle carries what a recomputation needs

The export gains three additions, each pinned by a hash that already exists in the ADR_Record:

| Addition | Pinned by | Already in the record? |
|---|---|---|
| `policies/` — the exact policy documents cited | `(policy_id, version, content_hash)` | **Yes**, I-8 |
| `contexts/` — the canonical `EvaluationContext` per record | `context_hash` | **Yes**, SPEC §2.4 |
| `evaluator.json` — engine, engine version, Cedar version, semantic-hash version | `ADR_Record.evaluator` | **Yes**, SPEC §2.3 |

That the pins already exist is the point. Stage 4 does not invent a new commitment scheme; it ships the
material the existing commitments already bind, which is why this is an additive change and not a redesign.

### 3.2 The verifier gains `--replay`

For each record in the bundle, offline and with the network off:

1. Recompute `context_hash` over the shipped context; it must equal the record's.
2. Recompute each cited policy's `content_hash`; it must equal the pinned value.
3. Re-run the pinned evaluator over the pinned policy set and the context.
4. Assert the recomputed `decision`, the matched policy set, and `decision_basis` equal what is recorded.

Per record, one of exactly three outcomes: **`REPLAYED`**, **`NOT REPLAYABLE`** with a named reason, or
**`DIVERGED`** with the recorded decision, the recomputed decision, and the deciding policy clause.

### 3.3 The honest half — the trusted-input ledger

Not every input is recomputable, and pretending otherwise would be the worst possible outcome here. A risk
score comes from a scoring service. Registry enrichment reflects the registry at evaluation time. These are
Mizan's assertions, not derivations.

So `--replay` prints two lists, and the second is the deliverable:

- **Recomputed:** the decision follows from these policies and these inputs.
- **Still trusted:** these input fields are Mizan's own word — named individually, with their values and
  their provenance class from T-031 (`Observed` = independently attested, e.g. a SPIFFE identity from a peer
  certificate or a countersigned approval; `Declared` = Mizan asserts it).

This converts "trust us" into "trust us about exactly these six fields, and here they are." An auditor can
argue with a list of six fields. They cannot argue with a black box.

### 3.4 Redaction is where this gets hard, and the honest answer is a feature

Contexts contain tool arguments. Tool arguments contain customer data. Shipping plaintext contexts to an
auditor's laptop is not obviously acceptable, and in some deployments it is illegal.

T-012 already built keyed commitments and a DLP attestation path. Replay uses them: redacted fields ship as
**commitments, not plaintext**. Where the policy does not read the field, replay proceeds normally. Where the
policy *does* read a redacted field, the outcome is `NOT REPLAYABLE (policy-relevant field <name> is
redacted)` — a named, specific, honest limitation rather than a silent pass.

That is a better product than a replay that works by exporting everyone's data.

### 3.5 The fixture that is the entire demo

A committed corpus containing one record that is **cryptographically flawless and substantively wrong**:
correctly chained, receipted, anchored, timestamped, inclusion-provable — recording ALLOW where the pinned
policy yields DENY.

Every Stage 3 gate passes it. `--replay` prints `DIVERGED`.

Put that on a screen in front of a risk officer and the conversation changes, because it is the first time
anyone has shown them the difference between *"the log is intact"* and *"the log is right."*

## 4. The primary risk, stated up front

**A replay that flakes is worse than no replay.** A false `DIVERGED` is a machine-generated accusation that
your control plane malfunctioned, delivered to an auditor. The cost of that is not a bug report.

So the determinism boundary is **declared, not discovered.** Before any replay ships, the task enumerates and
pins every source of nondeterminism: Cedar engine version, decimal and float handling (this repo has already
been bitten once — `c93a3b9`, "decimal parity"), set and map iteration order in the canonicalization, policy
priority tie-breaking, and any time-dependent predicate resolved against `effective_from` rather than wall
clock. Anything that cannot be pinned makes the affected record `NOT REPLAYABLE`, explicitly.

If the enumeration finds nondeterminism that cannot be closed, **the correct outcome is to park T-044 and
report it**, not to ship a replay that is usually right. This is stated now, before anyone is invested.

## 5. Decomposition

| Task | What | Lane | Gate |
|---|---|---|---|
| **T-044** | Determinism enumeration + `evaluator.json` pinning contract + **ADR-011**. Produces the list of what is and is not replayable. Ships no replay. | CODEX | The enumeration is the deliverable; a short list is a suspicious list |
| **T-045** | Replay bundle: `policies/`, `contexts/` (commitments per B-13), `evaluator.json`; hashes verified against existing pins | CODEX | Blocked on **B-13** |
| **T-046** | `--replay` in the standalone verifier: three outcomes, per-record, offline | CODEX | Third pinned dependency justified in the ADR or the task parks |
| **T-047** | The trusted-input ledger — `Recomputed` / `Still trusted`, built on T-031's provenance classes | CODEX | Depends on T-031 |
| **T-048** | The divergence corpus + `make replay-attack`: flawless-but-wrong records that every Stage 3 layer passes | CODEX | Must include at least one case `--replay` also misses, per the T-040 rule |

T-044 first and deliberately: it can kill the rest cheaply, which is the point of doing it first.

## 6. What this needs from the owner — B-13

**What may leave the trust boundary in a replay bundle?** Three options:

1. **Commitments only** *(recommended)*. Replay works wherever the policy does not read a redacted field;
   everything else is `NOT REPLAYABLE` with a named reason. Nothing sensitive leaves. Weakest replay
   coverage, strongest data posture, and the limitation is legible.
2. **Plaintext contexts**, full replay coverage, and the export becomes a data-transfer event with all that
   implies for residency and DPAs.
3. **Operator-selectable per export**, defaulting to (1), with plaintext requiring an explicit flag, a named
   authorizing operator, and its own AuditTrail event.

This is adjacent to tenant isolation and is not mine to decide. Filed as **B-13**.

## 7. Falsification test, adopted with the proposal

Per the standing rule in `FALSIFICATION_TESTS.md`, this is written before the work, not after the
disappointment.

**F-T-5 · Nobody replays.** *Observable:* across the first ten bundles delivered to auditors, risk officers,
or external counsel, at least **two** parties run `--replay` on a bundle Mizan did not hand-pick for them.
*If it fails:* recomputation is an engineering aesthetic, not a buying criterion; the trusted-input ledger
may still carry value on its own, and the replay engine should be cut rather than maintained.

## 8. Why this and not the alternatives

Three other directions were considered and are recorded so they are not re-proposed as novel:

- **Witness / non-equivocation network.** RFC 3161 proves *when*; it does not prevent Mizan showing two
  divergent histories to two parties. But T-038's caller-retained inclusion proofs plus T-039's consistency
  proofs already detect split-view *for any party who kept their proof* — which is the party who matters.
  The residual gap is real but much smaller than it appears, and a witness network is a large amount of
  infrastructure for it. **Not now.**
- **Executor attestation** — the executor countersigns what it actually invoked, so the record covers the
  *action* and not only the *permission*. This is genuinely valuable and is the strongest candidate for
  Stage 5. It is second here because it requires executor-side SDK adoption to mean anything, and because it
  overlaps T-028, which is parked for v1.4 pending a human contract decision.
- **Compliance framework mapping** (EU AI Act Art. 12, SOC 2, NIST AI RMF). Real buyer value, low technical
  depth, and it is packaging — it gets stronger the more there is underneath it. **After Stage 4, not
  instead of it.**

The second founder test decides it. *Would this survive a hostile party who holds the database and the
signing key?* Stage 3 makes that answer yes for the record. Stage 4 is what makes it yes for the **decision**
— and it is the last place in the system where the honest answer is still "you have to take our word for it."
