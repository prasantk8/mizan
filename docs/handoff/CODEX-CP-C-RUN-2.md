# CODEX work order — CP-C run, wave 1 resumed

Head reviewed: `f06cc95`. Supersedes the unstarted half of `CODEX-CP-C-RUN.md`; everything that
order said about lane discipline, H-1 claims, H-3 contract deltas and the non-negotiables in
`CODEX-STAGE-3.md` §2 still applies unchanged.

Twelve tasks, five waves, one commit each. **No mandatory stop before CP-C.** Run the full gate at
the end of every wave; a previously-green case going red is a stop-and-report, immediately, before
starting the next task.

---

## 0. Disposition of what came back

**T-057, T-051, T-052 and T-056 are accepted.** Independently re-run at `f06cc95`: 184 passed /
13 skipped, ruff clean, five drift gates proven, seven cases green. Rule 8 sampled directly — both
of T-057's new unit tests fail against `1e7b00e`'s `attestation.py` and `evidence.py` with
`assert 1 == 0`, and the worktree restored clean.

Three things were done better than the order asked. T-057 chose refuse-and-escalate over a
supersession relation and defended it on the correct ground — a supersession row would expand the
evidence format and risk being read as assurance. T-056 shipped tokens from two authorities nobody
here controls, verifying offline against roots nobody here issued; that is the difference between
implementing RFC 3161 and interoperating with it. T-059's draft got the hardest part right: the
closed exclusion rule for `record_core`, so every future member is committed automatically rather
than by an enumeration that rots.

**B-14 is resolved. T-059 is unparked.** See §1. It was correct to stop — the escalation trigger
was real and one half of it was an error in the previous order, not in the code.

**One new finding, V-19, is your wave-1 blocker.** See §2.

---

## 1. B-14 — disposition

You raised two things. They have different answers.

**(a) "The work order mentions four attestation types."** That is an error in the previous order,
line 189, and it is mine. ADR-004 G.2 is ratified and defines exactly three: `rfc3161`,
`customer_countersignature`, `none_development`. The ratified ADR wins over a work order every
time, and you were right to refuse to reconcile them by guessing. Implement three.

**(b) `status: failed`.** Not a contract conflict. A grammar written flat where the system is
layered. There are exactly two places an attestation entry is ever persisted, and each admits a
different subset of `status`:

| Location | Written when | Mutable after | Legal `status` |
|---|---|---|---|
| `attestations[]` inside the **signed anchor payload** | at anchor time, *before* any TSA is contacted | never — it is inside the signature | `pending`; or `unattested`, only with `none_development`, forbidden in production |
| the append-only **`anchor_attestations` sidecar** | when an outcome is final | never — append-only, G.12/G.13 | `attested` only |

There is no third location and no write path that emits `failed`. G.12 already decided that
deliberately: the sidecar stores outcomes, not attempts, and a failed attempt leaves the slot empty
so it stays retryable. `failed` describes a transient in-flight attempt that by construction is
never durable. G.2's enum simply predates G.12 and was never narrowed.

**So: `failed` is reserved vocabulary. It MUST NOT appear in an exported bundle at format 1.0.**
The verifier's refusal to accept it is correct behaviour and does not change.

**But the verifier's message is wrong, and that is the part worth your attention.** A bundle
carrying `failed` gets `anchor N has no verified external attestation` — which tells an auditor the
anchoring is incomplete and to go chase the operations team. The truth is that the file is not a
valid Mizan bundle and someone edited it. That is exactly the mistake T-051 just finished
correcting in a different place: `cannot check` is not `check failed`, and `malformed` is not
`unattested`. Bundle 1.0 needs a **third verdict class**, and the reason is not tidiness:

> This discrepancy is harmless today only because there is exactly one implementation — which is
> the precise condition T-059 exists to end. An independent implementer reading G.2's flat enum
> would legitimately accept `failed` and report it as an assurance level. Two conformant verifiers
> would then return different verdicts on the same bundle, and the format would have failed at the
> only job it has.

Carry that sentence into the spec's rationale. It is the argument for why the grammar is scoped by
location rather than declared once.

**T-059 resumes with three additions and no rework of the draft.** Keep everything already written.

1. **Location-scoped status grammar** — the table above, normative, with the reason each location
   admits what it admits stated in one line so an implementer can check their reasoning rather than
   memorise a list.
2. **A `MALFORMED` verdict distinct from both invalid evidence and `CANNOT CHECK`.** Three
   questions an auditor must be able to tell apart: *is this a Mizan bundle at all* (MALFORMED),
   *can I check it here* (CANNOT CHECK, T-051/G.14), *does it verify* (VALID / INVALID). Wire it
   through the standalone verifier and the conformance runner.
3. **ADR-004 G.15**, recording that `failed` is reserved, that the status grammar is scoped by
   location, and that this narrows G.2 descriptively — it forbids nothing the implementation has
   ever emitted, so no bundle that was valid becomes invalid.

G.15 narrows a ratified enum, so it carries a **HUMAN ratification stamp pending**. Write it,
mark it `pending ratification (B-14)` in the ADR text itself, and proceed — the change describes
what the code already does, so building on it risks nothing. Do not treat silence as ratification;
leave the marker in place until the owner clears it.

Conformance cases the corpus must gain: a bundle carrying `failed` → MALFORMED with that cause
named; a bundle carrying `attested` in the *signed payload* → MALFORMED; a bundle carrying
`unattested` with a production `rfc3161` type → MALFORMED. Each verdict machine-readable, each
running in CI alongside the three you already wired.

---

## 2. V-19 — the tamper alarm that fires on ordinary concurrency

Run this before you read further. It is eight cases now.

```
uv run python docs/reviews/reproductions/R-007-cpb-attestation.py
```

Case 8 is new and it is red:

```
RED    CASE 8  V-19  two healthy workers attest the same anchor concurrently
       two healthy workers, two valid tokens, one slot; the stored token is unchanged
       and the alarms raised were ['anchor_attestation_integrity']
```

T-057 is correct and case 7 is genuinely green. The defect is one call site further on, in how a
refused append is *classified*. `evidence.py:record_anchor_attestation` reads the existing row back
and compares it to the new document with `existing[0] == attestation`. ADR-004 G.13 calls an
identical document "a benign idempotent race".

**That branch is unreachable for `rfc3161`.** An RFC 3161 token carries its own `genTime`, a
TSA-chosen serial number, and optionally a nonce. Two tokens over the *same* imprint from the
*same* authority are never byte-identical — non-determinism is a property of the protocol, not an
accident. So the only classification a concurrent double-pass can reach is `conflict`, which opens
`anchor_attestation_integrity`.

Three facts compose into the severity:

- there is no lease on the anchor — no `FOR UPDATE SKIP LOCKED` anywhere on the pending-anchor read;
- the window between reading the sidecars and appending spans a full TSA network round-trip;
- **T-052 just made the worker run continuously**, so that window opens on every pass.

T-057 defined the integrity signal and T-052 built the thing that trips it. Neither is wrong alone.
The consequence is that the one alarm meaning *someone reached into the immutable evidence store*
is fired by ordinary concurrency, and an alarm that cries wolf is worse than no alarm — operators
learn to clear it, and the real event arrives looking exactly like the noise.

**T-061 fixes it. Both parts are required; neither alone is sufficient.**

**Part 1 — classify semantically, not byte-wise (mandatory).** The integrity question is not *are
these bytes equal*. It is *does the row already in the slot attest this same anchor, from this
authority, validly*. A stored document that validates against the operator's trust roots and whose
imprint equals this anchor's core digest is benign no matter what its bytes are — that is a second
honest witness to the same fact, which is the opposite of tampering. `anchor_attestation_integrity`
is reserved for a stored row that fails validation, or commits to a *different* imprint, or names a
different authority than its key. Those are the only conditions under which a human should be
woken. Note also that the current comparison is fragile even for a genuinely re-persisted identical
document, because the stored side has been through a JSONB round-trip and the new side has not.

**Part 2 — take a lease before spending a token (required, and it is not just an optimisation).**
Without it, every concurrent pass mints a real token, sends a real request to a third party, and
throws the result away. That is wasted TSA quota, avoidable traffic across the trust boundary, and
load on an authority whose availability the SLO breaker depends on. Claim the anchor before
contacting the TSA. If a lease is genuinely unavailable in the runner's deployment shape, say so
explicitly and say what the un-leased cost is per anchor per pass — do not leave it implied.

Constraints, unchanged: the table stays immutable — no `UPDATE`, no `DELETE`, no upsert, no relaxed
grant, and migration `0003` is applied, so it is not edited in place. Do not green case 8 by
weakening or removing the integrity breaker; the alarm must survive, it must just mean something.
Cases 7 and 8 are a pair, exactly as 6 and 7 were: 7 says a refusal must be visible, 8 says a
refusal must not be slandered. Amend G.13 in the same change-set — the "benign idempotent race"
sentence is what encoded the wrong test.

The regression test must fail on `f06cc95` and name that SHA. Live-PostgreSQL coverage is required:
the gate models `ON CONFLICT DO NOTHING` and the read-back by hand, and the JSONB round-trip is
exactly the part a hand model cannot reproduce.

---

## 3. The waves

Each wave ends with the eight-case gate plus `make check`, `ruff`, and the full suite.

### Wave 1 — unpark and repair

| Task | What it is |
|---|---|
| **T-059** | Resume per §1. Location-scoped grammar, `MALFORMED` verdict, G.15, three new conformance cases. Keep the draft. **Still no second implementation in this task.** |
| **T-061** | V-19 per §2. Semantic classification + anchor lease + G.13 amendment. |
| **T-058** | Mutation resistance as a property: for a valid bundle, no single-byte mutation of any file yields exit 0. Seeded, deterministic, bounded, offline, in CI. **Every survivor is a finding** — enumerate and classify each as benign (semantically identical after canonicalisation) or a hole, and file the holes. Do not narrow the sample to reach green. Now that `MALFORMED` exists, a survivor that is *detected but misclassified* is also a finding. |

### Wave 2 — custody, which gates delivery

| Task | What it is |
|---|---|
| **T-053** | `LocalKeyProvider` refuses `environment == "production"` regardless of URI scheme. Add `custody` (`development-derived` / `kms` / `hsm`) to the keyset and to `required_key_fields`. The verifier prints `KEY CUSTODY: publicly derivable development key — this bundle is forgeable by anyone who reads it.` |
| **T-054** | Add `audit-commitment` as a fifth `KeyRole`, route `security/mizan_security/redaction.py` through the provider, publish it with its `custody` field, implement the rotation §8 already promises. The key MACs rather than signs — **if `KeyProvider` needs a contract change rather than an addition, stop and file a blocker under H-7.** |
| **T-065** | **New.** Make custody a gate, not a caption. T-053 prints a warning; a warning is advice. Export MUST refuse to produce a bundle whose signing key custody is `development-derived` unless an explicit, named, logged override is set, and the bundle then carries that override as a field the verifier reports. Prove both directions end to end: a `kms`-custody bundle verifies and is labelled `kms`; a development-custody bundle cannot be produced without the override and is labelled unmistakably when it is. This is what actually lifts *"no bundle leaves the building"* from a process rule someone has to remember into a property of the system. |

### Wave 3 — the independence proof

| Task | What it is |
|---|---|
| **T-062** | **New, and the highest-value item on this list.** Write a **second, independent verifier** from `EVIDENCE-BUNDLE-FORMAT.md` alone. Different language (Go or Rust; pick one and say why). The implementer must not read `scripts/verify_evidence_export.py`, must not read `evidence.py`, and must not copy constants from either — if you need a value, it comes from the spec or the spec is incomplete. Run both verifiers over the full conformance corpus. **Every disagreement is a defect in the spec or in one of the implementations, and each one must be named, classified and fixed** — a disagreement quietly reconciled by patching the new verifier to match the old one defeats the entire exercise, and I will look for that specifically. This is rule 12 at product scale: it is the difference between *"you can verify this yourself"* being a claim and being a fact. Expect the spec to be wrong in at least two places; finding them is the deliverable, not a setback. |
| **T-063** | **New.** The auditor's first hour. Take a real T-065-clean bundle and document the actual path for someone with no Mizan context and no Mizan account: what they install, what command they run, where the trust roots come from (*theirs*, never ours), what each verdict means, and — at equal prominence — **what a clean verdict does not prove** (TM-001 pre-chain omission and a withheld final anchor). Ship the verifier as something a person can actually obtain and run offline. Then walk the procedure yourself, from a clean machine state, and record where it was wrong. The product's central promise currently has no user-facing surface; this is that surface. |

### Wave 4 — the omission hole

| Task | What it is |
|---|---|
| **T-038** | The anti-omission mechanism, not a feature. TM-001 names pre-chain omission and a withheld final anchor as NOT COVERED. A party holding the database *and* the signing key can present a truncated history that is internally perfect and freshly timestamped — an RFC 3161 token proves an anchor existed by time T, never that no other anchor exists. A retained inclusion proof is the only mechanism in this design that lets a third party prove a record **must** be in a chain it does not control. Build it so the proof survives alone: no Mizan code, no network, years later. |
| **T-039** | RFC 6962 consistency proofs: prove an later tree is an extension of an earlier one, so a truncation is detectable by anyone holding any earlier proof. |

### Wave 5 — cost, and the hostile party

| Task | What it is |
|---|---|
| **T-060** | What verification costs and where it stops being linear. Wall clock and peak RSS across at least three orders of magnitude of chain length, artifacts under `benchmarks/results/` per rule 6. State the *shape* (linear in records? memory bounded or proportional?) and **the size at which it breaks**, not the largest size that worked. Contrast with T-038's O(log n) inclusion proof. **Do not tune in the same change-set.** |
| **T-064** | **New.** Adversarial evidence review, under the real threat model: an attacker who holds the database **and** the signing key, and can therefore produce internally consistent forgeries that no mutation test will ever reach. Enumerate every bundle such a party can produce that verifies clean. For each: either it is already a documented NOT COVERED in TM-001, or it is a finding and gets filed. This is the second founder test answered with evidence instead of assertion, and it is deliberately last — it is worth most once T-038 and T-039 have changed the answer. |

---

## 4. Sequence

```
W1  T-059 → T-061 → T-058      → gate
W2  T-053 → T-054 → T-065      → gate
W3  T-062 → T-063              → gate
W4  T-038 → T-039              → gate
W5  T-060 → T-064              → gate, STOP at CP-C
```

Park freely. Twelve tasks is a lot of surface and at least one is wrong as specified; parking with
a stated reason is a result, and the last park was the right call. But check first whether the
conflict is between two ratified artifacts or between a ratified artifact and something I wrote —
if it is the latter, the ratified one wins and you can proceed on that alone.

Escalate under H-7 rather than deciding: any contract *change* to `KeyProvider` (T-054), anything
that moves approval semantics or tenant isolation, and any proposal to widen rather than narrow the
attestation grammar.

## 5. Report format

Per task: the commit SHA and subject; what you chose and what you rejected, with the reason; the
pre-fix SHA the regression test fails against, named; what you could not do and why; and anything
you noticed that is outside the task and not worth doing now. That last line is the one that has
cost a review cycle three times running — T-050's persistence consequence, T-055's write path that
could not fail, and now T-057's byte-comparison. Each was a sentence you could have written for
free, and each cost a full cycle to find from the outside.
