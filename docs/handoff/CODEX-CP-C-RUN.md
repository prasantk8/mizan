# CODEX work order — CP-B is passed; the run to CP-C

Issued: 2026-08-26 · Issuer: CLAUDE lane (R-007 closeout) · Head reviewed: `e76b2b6`

**Eleven tasks, one commit each, no stop until CP-C.**
`docs/handoff/CODEX-STAGE-3.md` §2 non-negotiables 1–9 apply unchanged and are not repeated here.
`CODEX-CP-B-CLOSEOUT.md` is closed; read it only for context on T-055.

---

## 0 · CP-B is passed

**T-055 is accepted and T-036 is released from REVIEW.** The gate's cases 1, 2, 3, 4 and 6 are green
together, which is the CP-B criterion from R-007 §5 as amended by both re-runs. Independently
re-verified this pass, not read from your report: `ruff` clean, `make check` clean
(30 boundaries, 14 JSON blocks, 13 schema IDs, five drift gates), 170 passed / 12 skipped, and both new
tests confirmed **failing** on `d4d57c7` by checking out the pre-fix `attestation.py` and running them.
Rule 8 held.

The design choice was the right one and the commit message defended it properly. Outcome-only append
semantics are correct: the signed payload already carries durable pending state, so a second relation
for attempt diagnostics would have bought a diagnostic at the cost of a thing the assurance derivation
could mistake for evidence. You also did something the order did not ask for — you routed the
non-`attested` branch into the SLO breaker, so a validation failure now trips the same breaker a
transport failure does. That is the correct reading of §T-055.4.

Three cycles, three re-runs, three findings. This one is **V-17**, and it is one call site past where
case 6 stops looking. Same shape as V-16, which was one call site past where case 4 stops looking.

**The shape of V-17.** `record_anchor_attestation` (`evidence.py:613-628`) is
`INSERT ... ON CONFLICT DO NOTHING` and returns `None`. The worker cannot tell an append from a silent
refusal, and increments `completed` either way. T-055's correctness therefore rests on the
`(anchor, authority, type)` slot being empty — and nothing checks that it is.

Your own limitation note said a pre-fix pending row "cannot be repaired in place." True, and not the
whole cost. Case 7 runs three passes over such a row against a **healthy** TSA:

```
after 3 passes against a healthy TSA the sidecar still reads 'pending';
3 token(s) minted and discarded; the worker reported 3 completion(s)
```

Before T-055 that anchor was skipped as `finalized`. After T-055 the skip is gone, so it now hits the
TSA on **every pass, forever**, obtains a valid token every time, has it dropped by the conflict clause
every time, and reports a completion every time. An unbounded external-call loop against a permanently
false completion count. That is not an argument against T-055 — it is the argument that the write path
needs to be able to fail.

**And a second finding, V-18, which is not a code defect.** The anchor core digest — `payload` minus
`{attestations, object_key, object_version}`, JCS-canonicalised, SHA-256 — is the single most
load-bearing definition in the product. It appears in `evidence.py`, in `verify_evidence_export.py`,
and **nowhere in `SPEC_v1.md` or ADR-004.** Rule 12 keeps the two copies independent, and case 1 proves
they agree. But there is no normative statement of what they are agreeing *about*. The consequence is
not internal: it means the only way to verify a Mizan bundle is to run Mizan's program. "Verify it
yourself, offline" currently means "run our script." Apply the second founder test to the verifier and
the answer is no. T-059 fixes that.

---

## 1 · The gate

```
uv run python docs/reviews/reproductions/R-007-cpb-attestation.py
```

Seven cases at `e76b2b6`:

| Case | Finding | State | Owner | Blocks |
|------|---------|-------|-------|--------|
| 1 | — | **GREEN** — regression guard, must never go red | — | — |
| 2 | — | **GREEN** — regression guard, must never go red | — | — |
| 3 | V-11 | **GREEN** — T-049 | — | — |
| 4 | V-14 | **GREEN** — T-050 | — | — |
| 5 | V-12 | **RED** | T-051 | CP-C |
| 6 | V-16 | **GREEN** — T-055 | — | — |
| 7 | V-17 | **RED** | T-057 | CP-C |

The gate now prints `CP-B ... PASSED` and still exits non-zero while 5 or 7 are open. That is
deliberate: the exit code is the CP-C gate now.

**Case 1 is still the load-bearing regression guard.** It is the only place in the tree that executes
both halves of the signer/verifier digest agreement.

**Cases 6 and 7 are a pair,** the same way 4 and 6 are: 6 says a failed attempt must stay retryable,
7 says the retry must be able to land. Do not green 7 by re-introducing the `finalized` skip.

**Run the full gate at the end of every wave below.** If a case that was green goes red, stop and
report immediately — do not carry on to the next task. That is your self-service checkpoint and it is
the reason this order has no mandatory stop before CP-C.

---

# Wave 1 · Close the attestation subsystem

## T-057 · An append the store refuses must never be counted — **blocks CP-C**

Gate: case 7 green, cases 1 and 6 stay green.

The constraint is unchanged from T-055 and it is the interesting part: **the table stays immutable.**
No `UPDATE`, no `DELETE`, no upsert, no relaxed grant, and `0003_anchor_attestations.sql` is applied so
it is not edited in place.

Build:

1. **`record_anchor_attestation` must return what happened.** `ON CONFLICT DO NOTHING` gives you
   `cursor.rowcount`; 0 means the append did not happen. Return enough for the caller to distinguish
   *appended* from *refused*.
2. **A refusal is not a completion.** `completed` counts appends that landed.
3. **A refusal with a *different* document is an integrity event, not a no-op.** Read the existing row
   back and compare. Two workers racing to append the same validated token is benign and should be
   quiet. A conflicting document occupying an append-only evidence slot is the failure class this
   entire checkpoint exists to catch, and it must be named, logged, and surfaced — decide where and
   defend it in the commit message. If you route it to the breaker, say why; if you decide the breaker
   is the wrong instrument because this is a data-integrity fact rather than an availability fact, say
   that instead.
4. **Decide what happens to an occupied slot, and defend it.** Two shapes are defensible:
   - *Refuse and escalate.* The anchor is marked as needing operator attention and the worker stops
     hitting the TSA for it. Cheapest, honest, and leaves a human in the loop.
   - *An additive recovery path.* A new append-only relation that supersedes without mutating, with the
     supersession itself evidence. More power, and it must not be mistakable for an attestation by the
     exporter or the verifier — prove that with a test, not with an assurance, or you re-open V-11 from
     the other direction.

   Either way the worker must not spin. **An unbounded retry loop against a slot that can never accept
   the result is the defect**, and it must be gone.
5. **A test that fails on `e76b2b6`.**
6. Live-PostgreSQL coverage for the rowcount behaviour. The gate models `ON CONFLICT DO NOTHING` by
   hand because it must run without a database; you have a real one and should use it here.

H-3 applies if the contract moves.

## T-051 · `cannot check` ≠ `check failed` — **blocks CP-C**

Gate: case 5 green.

Unchanged from `CODEX-CP-B-REMEDIATION.md` §T-051 and `CODEX-CP-B-CLOSEOUT.md` §T-051 — read them
there. Four causes separated, a distinct `CANNOT CHECK:` exit, an up-front `openssl ts` probe, no
traceback, the attested bundle added to the `offline-evidence-verifier` CI job, and a strictly weaker
summary line on a machine without OpenSSL that says which statement the auditor is holding.

## T-052 · The breaker needs somewhere to fire from

Gate: no reproduction case; judged on wiring and on the test asserting its own name.

Unchanged from `CODEX-CP-B-REMEDIATION.md` §T-052. An enforcement point so
`MIZAN_ANCHOR_ATTESTATION_MAX_PENDING_SECONDS` is not a config key with no reader; the SLO evaluated
outside the `except` branch; `except Exception` narrowed;
`test_worker_opens_breaker_after_tsa_outage_exceeds_slo` asserting the breaker opened rather than
counting completions.

R-007 §1 found **zero production callers** of `AnchorAttestationWorker`. Until this lands, everything
CP-B proved is proved about code that does not run. Say in your report what now runs it, how often, and
what happens to a tenant whose TSA has been down for a week.

---

# Wave 2 · Make the external claim external

## T-056 · The first token from an authority we do not control

Unchanged from `CODEX-CP-B-CLOSEOUT.md` §T-056 — read it there in full. Two independent public RFC 3161
authorities, tokens and roots committed as fixtures with provenance, offline verification, **every
incompatibility recorded**, no network in CI, and **park rather than substitute another local CA**.

Everything the evidence plane has proved so far it proved against a CA it minted itself. Case 1 is real
cryptography end to end and both ends are ours.

## T-059 · The bundle format, written so a stranger can implement it — **new**

Gate: a normative specification and a conformance corpus, both committed. This is V-18.

The product's central promise is that an auditor verifies a bundle **without trusting Mizan**. Today
the only implementation of the format is Mizan's own Python, so exercising that promise means running
Mizan's program. The format is not a format yet; it is one program's behaviour.

Build:

1. **A normative `docs/spec/EVIDENCE-BUNDLE-FORMAT.md`**, written from the artifacts and the SPEC, that
   a competent engineer who has **never read `verify_evidence_export.py`** could implement against. It
   must pin, at minimum:
   - every file in the bundle, its media type, and whether it is required;
   - the canonicalisation (RFC 8785 JCS) and exactly which bytes are hashed for each digest;
   - **the anchor core projection** — `payload` minus `{attestations, object_key, object_version}` —
     stated normatively, with the reason each key is excluded, and stated as a *closed* rule so a future
     payload key has a defined answer;
   - the record hash chain, its genesis value, and the linkage predicate;
   - the anchor chain, `from_sequence`/`to_sequence`/`head_hash`/`anchor_number` semantics, and the
     terminal-anchor conditions;
   - the attestation object, all four `type` values, all `status` values, and which combinations are
     legal;
   - how assurance is **derived**, and that the manifest's `assurance` block is a claim under test;
   - the signature algorithms, key identifiers, and where a verifier is required to obtain trust roots
     — from its own operator, never from the bundle (B-12);
   - **what the format does not prove.** Pre-chain omission and a withheld final anchor are named as out
     of scope in `TM-001` §"NOT COVERED"; that limitation belongs in the format document at equal
     prominence, not only in a threat model.
2. **A conformance corpus** — `tests/fixtures/conformance/` — of complete bundles with a machine-readable
   expected verdict per bundle: valid ones, and invalid ones covering each rejection the format defines.
   The verdict file is the contract a second implementation is tested against.
3. **Run Mizan's verifier over the corpus in CI** and assert every verdict matches. If Mizan's verifier
   disagrees with the document you wrote, one of the two is wrong and finding out which is the point of
   the task.
4. **Record every place where the document had to make a decision the code left implicit,** and every
   place where writing it down revealed a defect. Rule 10 governs and this task is where it pays.

Do **not** write a second verifier implementation in this task. That is the task this one makes
possible, and it should be scoped after the corpus exists and someone has read the document cold.

## T-058 · No single-byte mutation of a bundle verifies — **new**

Gate: a deterministic, committed property result, in CI, offline.

The claim under test: *for a valid bundle, no single-byte mutation of any file yields exit 0.* It is
stronger than any list of named attacks because it does not depend on having thought of the attack.

Build:

1. A property test over the golden bundle that mutates one byte at a time — flipped, deleted, inserted —
   across a **deterministic, seeded** sample of offsets in every bundle file, and asserts the verifier
   never exits 0.
2. **Every survivor is a finding**, and a survivor is likely: bytes inside a JSON value that no digest
   covers, whitespace outside the canonical form, unused manifest fields. Do not quietly narrow the
   sample to make it green. Enumerate survivors, classify each as *benign* (semantically identical) or
   *a hole*, and file the holes.
3. Bound the runtime and say what it is. A sampled property with a stated sample size and seed is
   honest; an unstated one is not.
4. This is distinct from T-040's `make attack` drill and does not replace it. T-040 names attacks a
   human thought of; this one covers the ones nobody did.

---

# Wave 3 · Custody, and the thing that gates delivery

## T-053 · Custody honesty — **gates delivery**

Unchanged from `CODEX-CP-B-REMEDIATION.md` §T-053. `LocalKeyProvider` refuses `environment ==
"production"` regardless of URI scheme; `custody` (`development-derived`/`kms`/`hsm`) added to the
keyset and to `required_key_fields`; the verifier prints
`KEY CUSTODY: publicly derivable development key — this bundle is forgeable by anyone who reads it.`

Until this lands, every development key is `sha256(key_id)` and the `key_id` ships in the bundle, so
any recipient can forge one and nothing in the output says so. **No bundle leaves the building before
T-053 lands.**

## T-054 · The fifth key role

Unchanged from the WORK_LOG row. The audit commitment HMAC key has a contract
(`MIZAN_AUDIT_HMAC_KEY_REF`, ADR-004 *"held under separate authority"*) and no custody: it is not one of
G.1's four `KeyRole`s, so `keys.py:65` cannot cover it, there is no KMS/HSM adapter, no production
refusal of development custody, no keyset publication, and no implemented rotation. Add
`audit-commitment` as a fifth role, route `security/mizan_security/redaction.py` through the provider,
publish it with its `custody` field, implement the rotation §8 already promises.

The key **MACs rather than signs.** If `KeyProvider` needs a contract *change* rather than an
*addition*, stop and file a blocker under H-7 — key management is on the escalation list and a
contract change there is the owner's call, not yours.

---

# Wave 4 · Proofs a third party can hold

## T-038 · Merkle inclusion proofs

Unchanged in scope from the WORK_LOG row: anchor `merkle_root` with RFC 6962 domain separation,
`/v1/audit/inclusion/{decision_id}`, standalone `--inclusion` verification (the ADR-004 Option-2 path).

**What changes is why it matters, and it should change how you build it.** `TM-001` §"NOT COVERED"
names two adversaries this system does not defend against: records omitted before chaining, and an
entire final anchor withheld. A hostile party holding the database *and* the signing key can present a
truncated history that is internally perfect and freshly timestamped — an RFC 3161 token proves an
anchor existed by time T, never that no other anchor exists. A retained inclusion proof is the only
mechanism in the design that lets a third party prove a record **must** be in a chain it does not
control. T-038 is not a feature on the list; it is the answer to the largest remaining hole in the
hostile-party story.

Build it so that the proof survives on its own: a caller who retained one must be able to verify it
years later against a bundle, with no Mizan code and no network. Say in your report exactly what a
holder of an inclusion proof can and cannot prove.

## T-039 · RFC 6962 consistency proofs

Unchanged: consistency proofs between successive anchors, so append-only is proven cryptographically
rather than by numbering. Depends on T-038.

## T-060 · What verification costs, and where it stops being linear — **new**

Gate: committed benchmark artifacts under `benchmarks/results/`, per standing rule 6.

Nobody knows what this costs. Verification walks the whole chain, so it is O(n) in records, and the
bundle is a single directory read into memory. Neither the time nor the memory has ever been measured,
and the first design partner with a year of history will ask.

Build:

1. Measure end-to-end verification — wall clock and peak RSS — at several chain lengths spanning at
   least three orders of magnitude, up to a size large enough to be uncomfortable. Commit the artifacts
   with the rule-6 provenance.
2. **State the shape, not just the numbers.** Confirm or refute that cost is linear in records and that
   memory is proportional to bundle size rather than bounded.
3. **Say where it breaks.** The number at which verification exceeds a few minutes, or exhausts a
   laptop, is the number that decides whether bundles must be chunked by range. If it breaks, say so
   plainly rather than reporting the largest size that worked.
4. Contrast it with T-038: an inclusion proof verifies one record in O(log n) without the bundle at all.
   If the linear cost is bad, that contrast is the argument for making inclusion proofs the primary
   auditor interface rather than a supplement, and your report should say so.

Do not tune anything in this task. Measuring is the deliverable; optimising against your own benchmark
in the same change-set is how a number stops meaning anything.

---

## Sequence

```
Wave 1  T-057 → T-051 → T-052        run the gate
Wave 2  T-056 → T-059 → T-058        run the gate
Wave 3  T-053 → T-054                run the gate
Wave 4  T-038 → T-039 → T-060        run the gate
STOP — CP-C
```

**No mandatory stop before CP-C.** Run the full seven-case gate at the end of each wave; a
previously-green case going red is a stop-and-report, immediately, without starting the next task.

**Park freely.** Eleven tasks is a lot of surface and at least one of them will turn out to be wrong as
specified. Parking with a reason is a result. T-050 shipped a correct fix whose persistence consequence
was one call site away, and T-055 shipped a correct fix whose write path could not fail — both cost a
review cycle, and in both cases a sentence in the report naming the thing you had not checked would
have cost nothing.

**Escalate under H-7 rather than deciding:** any contract change to `KeyProvider` (T-054), and anything
that would move approval semantics or tenant isolation.

---

## Report format

One `WORK_LOG` line per task: what you did, the pre-fix SHA and the test that fails on it, the gates
that pass, **what did not work**, and the hostile-party answer.

- **T-057** — the paragraph defending what happens to an occupied slot, and where a conflicting
  document is surfaced.
- **T-052** — what now runs the worker, how often, and what a week-long TSA outage looks like to a tenant.
- **T-056** — the two authorities by name, and the incompatibility list even if it is empty.
- **T-059** — every decision the document had to make that the code left implicit, and any defect that
  writing it down revealed.
- **T-058** — the seed, the sample size, and every survivor with its classification.
- **T-060** — the numbers with their artifacts, the shape, and the size at which it breaks.
