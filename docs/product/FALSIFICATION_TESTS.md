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
| _pending T-036_ | — | Re-apply once RFC 3161 attestation and offline verification are live |

---

## Note on the source brief's metrics

The brief's own §03 reports that evidence would have changed the outcome in **1 of 11** incidents and changed
only the *cost of proving what happened* in 8 of 11. That is a real business, and it is not
"we prevent the incident." Any strategic decision taken on the strength of this document must be taken with
that number in view. The brief deserves credit for leading with it.

Metrics quoted from the source repository (`memtara-zkp`) are **unverified in this tree** and must not be
re-quoted to a customer — see R-005 §3 R-7.
