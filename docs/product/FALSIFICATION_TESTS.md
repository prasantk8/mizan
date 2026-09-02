# Falsification Tests — Evidence Plane

**Status:** ADOPTED 2026-08-25 by the human owner (R-005 §8) · **Lane:** HUMAN · **Review cadence:** monthly
**Source:** §08 of the external "Evidence Plane First" brief, adopted verbatim in substance

These are written down now, while they are cheap to accept, and before any pilot can disappoint. A
falsification test that is written after the disappointment is a rationalisation. Each carries an owner, an
observable, a decision date, and what happens when it fires — including the option to stop.

The rule of this file: **a test that fires and is then re-argued is not a test.** Amending a criterion is
permitted; amending it after seeing the result, without recording that the amendment was post-hoc, is not.

---

## F-T-1 · Nobody will run the offline verifier

**Claim under test.** Third-party verifiability is the product's differentiator.

**Observable.** Across fifteen substantive conversations with auditors, risk officers, or external counsel,
at least **three** run `verify_evidence_export.py` on a sample bundle themselves — not watch a demo of it.

**If it fails.** Third-party verifiability is decoration, and this is a logging product competing with
Datadog on Datadog's terms and Datadog's cost base. The wedge is elsewhere.

**Instrumentation.** Track per conversation in the pilot log: shown / offered / ran-it-themselves. The
verifier must never phone home — this is counted by hand, deliberately.

---

## F-T-2 · The record is never asked for

**Claim under test.** The ADR_Record is load-bearing, not ornamental.

**Observable.** Twelve months of design-partner traffic produce at least **one** ADR pulled in response to a
real question: an exam, an incident, a dispute, a claim. Not a test, not a demo, not a QBR slide.

**If it fails.** The artifact is not load-bearing whatever its cryptographic properties, and the engineering
depth in the evidence plane is not what the money is for.

---

## F-T-3 · The security review passes without it

**Claim under test.** Evidence is the actual constraint on agent deployment, not a preference.

**Observable.** For design partners blocked on a security review: does the blocked owner get through on a
policy document and two screenshots?

**If it fails.** Evidence was never the constraint. The wedge is somewhere else and the ninety-day sequencing
argument is void.

---

## F-T-4 · The only excited room is internal audit

**Claim under test.** This is a growth product, not a cost-centre product.

**Observable.** Which function sponsors the spend — the business line deploying agents, or internal audit?
Count sponsors, not enthusiasts.

**If it fails.** It is a cost-centre product. Price it, staff it, and forecast it as one — deliberately and
in the open — or stop. The failure mode to avoid is running a cost-centre product on growth-product
assumptions and calling the shortfall a sales problem.

---

## F-T-5 · Nobody replays *(adopted 2026-08-25 with the Stage 4 proposal, before the work)*

**Claim under test.** Recomputing the decision — not merely proving the record is intact — is a buying
criterion.

**Observable.** Across the first ten bundles delivered to auditors, risk officers, or external counsel, at
least **two** parties run `--replay` on a bundle Mizan did not hand-pick for them.

**If it fails.** Recomputation is an engineering aesthetic, not a buying criterion. The trusted-input ledger
(T-047) may still carry value on its own — it is the half that names what you are trusting us about — and in
that case the replay engine should be **cut rather than maintained**, since a replay nobody runs is a
correctness liability with no offsetting demand.

**Note.** This is written before T-044 begins, per the rule at the top of this file. `docs/product/STAGE-4-DECISION-REPLAY.md` §4 states the primary risk in the same spirit: a replay that flakes is worse than no replay, because a false `DIVERGED` is a machine-generated accusation delivered to an auditor.

---

## F-T-6 · Nobody values the proof *(adopted 2026-08-31 with the two-product decision, before the seam work)*

**Claim under test.** A client-side suitability proof (Memtara) is a buying criterion for an advised-sales
desk, not an engineering aesthetic.

**Observable.** Across the first **six** wealth or private-banking conversations in which UC-2 is shown,
at least **two** compliance or risk officers state, unprompted or on the qualifying question, that the
proof changes a control outcome they are measured on — the suitability file they must keep, the record a
regulator asks for, or the decline they cannot currently evidence.

**If it fails.** Memtara has no commercial role in this market. Stop the seam work after T-133 (the
verification library is cheap to keep), do not build T-135, remove UC-2 from the catalogue, and sell Mizan
alone. The engineering already done is not a reason to keep selling it.

**Instrumentation.** The catalogue's UC-2 qualifying questions, recorded per conversation in the pilot log
alongside the F-T-1 verifier columns. Count officers, not enthusiasm.

---

## F-T-7 · The private-stack message attracts the wrong buyer *(adopted 2026-09-02 with the positioning evaluation, before the work)*

**Claim under test.** The umbrella sentence *"Enterprise-grade, private, auditable AI for firms that
can't afford to get it wrong"* attracts a buyer who wants their agents governed — not one who wants a
model hosted, and not internal audit alone.

**Owner.** Founder, with PO instrumenting. **Decision date:** 2026-10-31, in
`DECISION-2026-10-31-PRIVATE-STACK-POSITIONING.md` (T-149).

**Observable.** Across the twenty already-planned problem interviews, with variant A (the current
wedge, *"control before action, proof after"*) and variant B (the sentence) rotated between them
(T-147), **either** of these fires the test:

1. **≥ 5** variant-B conversations produce a model-hosting expectation — the prospect asks about
   model SLAs, fine-tuning, GPU pricing, inference cost, or which model we supply — where a
   model-hosting expectation is logged the first time the prospect raises it unprompted, not when we
   correct it; **or**
2. internal audit is the only sponsor in **≥ half** of the variant-B conversations, which is F-T-4's
   observable counted for variant B specifically.

Fewer than fifteen conversations by the decision date is **not** a pass. It is an unread test, and
T-149 must record it as such rather than adopting the sentence by default.

**If it fails.** The umbrella positioning is wrong for this buyer, whatever it does for a general
audience. Rule **Adapt** — fall back to *"auditable AI operations"*, which claims the operations and
not the intelligence — or **Abandon** and stay with the wedge. In either case the sentence does not
become umbrella copy, and the claims-register rows added by T-141 stay HYPOTHESIS or are withdrawn.
A demo that impressed people is not a counter-argument: the observable counts expectations and
sponsors, not admiration.

**Instrumentation.** Four fields per conversation in the pilot log, defined by T-147 and recorded
alongside the F-T-1 verifier columns: *variant shown* (A/B), *sponsor role*, *model-hosting
expectation* (y/n), *asked-for-pilot* (y/n). F-T-4's audit-only sponsorship field is reused rather
than duplicated. Counting is by hand, per conversation, on the day.

**Note.** Adopted before T-141, T-144 or any external use of the sentence, per the rule at the top of
this file. The second observable deliberately overlaps F-T-4: if the audit-only trap is real, this
test should be capable of detecting that the *sentence* deepened it, which requires counting the same
thing under a variant label.

---

## The second founder test

PRD §81 asks whether a feature makes agents safer, more controllable, more observable, or more provable.
For the evidence plane, and **only** for the evidence plane, a second test applies:

> **Would this survive a hostile party who holds the database and the signing key?**

Registries, dashboards, and copilots are convenience, and convenience is allowed to be trusted. The evidence
plane is the one component whose entire reason for existing is that it must hold when the party producing it
is the party under suspicion.

Applied honestly on 2026-08-25 the answer was **no** — anchors were signed with an in-process ephemeral key
(R-005 F-13). ADR-004 Amendment G is the correction. Re-apply this test at every stage gate, and record the
answer here even when it is unflattering.

| Date | Answer | Basis |
|---|---|---|
| 2026-08-25 | **No** | `OutboxPublisher.anchor()` signs with `Ed25519PrivateKey.generate()`; no external attestation exists (R-005 F-13/F-14) |
| 2026-08-25 (CP-A) | **No** | Unchanged, and now stated by the tool itself: `verify_evidence_export.py` prints *"a party holding Mizan's database and signing key could rebuild and re-sign this history."* Anchors chain, order, and verify offline (T-030/T-032), which makes omission and replay visible — but the signer is still inside the boundary. Saying it out loud is better than silent falsity; it is not a yes (R-006 §4) |
| 2026-08-26 (CP-B) | **No — but for a different reason than yesterday** | The mechanism now provably works: R-007 minted a real RFC 3161 token from a standards-compliant TSA over the digest the verifier independently reconstructs, and the standalone verifier PASSed a real bundle with nothing stubbed, withdrawing its own hostile-party limitation line. That is the first evidence in this repository that the answer *can* be yes. It is still no for two non-cryptographic reasons: R-007 **V-11** — a stream with one authority still pending is reported as externally anchored, so the tool does not reliably establish the coverage it claims — and **V-13** — no deployed Mizan can finalize an attested anchor at all, because nothing runs the attestation worker. A better *no*: the gap moved from cryptography to wiring and reporting. Do not round it up (R-007 §4) |
| _pending T-049/T-050_ | — | Re-apply after the two CP-B blockers close and CP-B is re-run |

---

## Note on the source brief's metrics

The brief's own §03 reports that evidence would have changed the outcome in **1 of 11** incidents and changed
only the *cost of proving what happened* in 8 of 11. That is a real business, and it is not
"we prevent the incident." Any strategic decision taken on the strength of this document must be taken with
that number in view. The brief deserves credit for leading with it.

Metrics quoted from the source repository (`memtara-zkp`) are **unverified in this tree** and must not be
re-quoted to a customer — see R-005 §3 R-7.
