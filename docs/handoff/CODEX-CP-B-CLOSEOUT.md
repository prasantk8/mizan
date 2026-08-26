# CODEX work order — CP-B closeout and the first external claim

Issued: 2026-08-26 · Issuer: CLAUDE lane (R-007 re-run) · Head reviewed: `d4d57c7`

Four tasks, **T-055, T-051, T-052, T-056**, one commit each.
`docs/handoff/CODEX-STAGE-3.md` §2 non-negotiables 1–9 apply unchanged and are not repeated here.
The previous order, `CODEX-CP-B-REMEDIATION.md`, is closed; read it only for context on T-049/T-050.

---

## 0 · Where you stand

**T-049 and T-050 are accepted.** Both defects were real, both fixes are correct, and both were
demonstrated against real pre-fix commits. The signed roster is now authoritative, the union is keyed
by `(type, authority)` in both implementations, the two implementations were kept independent as
rule 12 requires, and the worker verifies a token against an operator-supplied root before it will
write `attested`. Production now refuses plaintext TSA endpoints and refuses to start without a trust
root. That is four contract-bearing improvements in two commits and none of them were hedged.

**CP-B still does not pass, and it is now for one reason instead of two.**

The re-run did what it said it would: it opened a path the reproduction script did not cover, and it
found a defect that **T-050 introduced**. It is recorded as **V-16** and it is case 6 of the gate.

The shape of it. T-050 correctly stopped `obtain()` from raising and had it return a `pending` dict
carrying a named `failure_reason`. That is the right provider-level answer and case 4 is green because
of it. But the worker at `attestation.py:175` records **every** return value unconditionally, and the
store it records into is `mizan.anchor_attestations`, whose primary key is
`(tenant_id, anchor_id, authority, attestation_type)`, whose `INSERT` is `ON CONFLICT DO NOTHING`, and
whose `UPDATE`/`DELETE` are revoked *and* rejected by trigger. So the first transient TSA fault writes
a permanent `pending` row. From then on:

- the retry never happens — `attestation.py:165` sees the pair in `finalized` and `continue`s;
- if it did happen, the successful row would be silently swallowed by `ON CONFLICT DO NOTHING`;
- there is no repair path, because the table is correctly immutable;
- `completed += 1` counts the failure as a completion, so the worker reports progress it did not make;
- and the anchor no longer looks pending to the SLO breaker, so the one mechanism that exists to notice
  a stalled attestation is exactly the mechanism this state hides it from.

**A single network blip permanently bars an anchor from ever satisfying I-11.** Not degrades it —
bars it. The evidence plane's whole claim is that external anchoring is eventually achieved for every
production anchor; this makes "eventually" unreachable for any anchor unlucky in its first attempt.

The gate reproduces it in eight lines of output. Two ordinary worker passes against a TSA that fails
once and then works — the ordinary shape of a transient fault — and the counter says **one TSA call
was made**. The retry did not fail. The retry did not happen.

There is a committed test that asserts this behaviour:
`test_worker_records_validation_failure_as_named_pending_sidecar` (`tests/unit/test_attestation.py:264`).
It is not a bad test; it accurately describes what the code does. It is a test that never asked what
happens on the *second* pass. Rule 11 says a test's name is a claim — this one's claim is true and too
small. When you fix V-16 that test must change with it, and the change must be visible in the diff.

---

## 1 · The gate

```
uv run python docs/reviews/reproductions/R-007-cpb-attestation.py
```

Six cases at `d4d57c7`:

| Case | Finding | State | Owner |
|------|---------|-------|-------|
| 1 | — | **GREEN** — regression guard, must never go red | — |
| 2 | — | **GREEN** — regression guard, must never go red | — |
| 3 | V-11 | **GREEN** — T-049 closed it | — |
| 4 | V-14 | **GREEN** — T-050 closed it | — |
| 5 | V-12 | **RED** | T-051 |
| 6 | V-16 | **RED** | T-055 |

**Case 1 is still the load-bearing regression guard.** It is the only place in the tree that executes
both halves of the signer/verifier digest agreement. If it goes red, the two sides have stopped
hashing the same thing and nothing in `tests/` will tell you.

**Cases 4 and 6 are a pair and must be read together.** Case 4 says a bad token must not become
`attested`. Case 6 says it must not become *permanent* either. A fix that reverts T-050 to make case 6
green turns case 4 red, and that is not a fix — it is a trade. Both must be green at once.

---

## T-055 · A failed attempt must stay retryable — **blocks CP-B**

Gate: case 6 green, cases 1 and 4 stay green.

The constraint that makes this interesting: **you may not make the sidecar table mutable.** Its
immutability is not incidental, it is the thing an auditor is being asked to trust. `UPDATE`/`DELETE`
are revoked, forced RLS is on, and the trigger rejects both. Any design that reaches for an update, a
delete, an upsert, or a relaxed grant is wrong regardless of how well it works. Solve it inside
append-only semantics.

Build:

1. **Decide where a failed attempt lives, and defend the choice in one paragraph in the commit
   message.** Two shapes are defensible and you should pick deliberately, not by whichever is easier:
   - *Do not persist failures at all.* The worker records only terminal states; a failure is left
     pending in the signed payload and retried next pass, which is what the SLO breaker already
     expects to see. Simplest, and it discards the diagnostic.
   - *Persist attempts separately from outcomes.* Failures go somewhere with an attempt identity in
     the key so each is its own append-only row, and the `(authority, type)` sidecar slot stays free
     for the eventual token. Keeps the diagnostic, costs a migration and an ADR-004 delta.

   If you choose the second, the attempt record must never be mistakable for an attestation by the
   exporter or the verifier — a diagnostic that leaks into the assurance derivation would re-open
   V-11 from the other direction. Prove that with a test, not with an assurance.

2. **`finalized` must mean finalized.** Whatever you choose, the skip at `attestation.py:164-166` must
   key on states that are actually terminal. A `pending` sidecar is not a terminal state and must not
   suppress the retry.

3. **`completed` must count completions.** A failed attempt is not a completion. The return value
   feeds operational reporting; today it says work was done that was not done. Consider returning
   enough for a caller to tell attested from attempted, and say in the commit message what you chose.

4. **The pending anchor must remain visible to the breaker.** V-13/T-052 will wire the breaker to a
   real caller. Make sure that when it does, an anchor that has been failing for longer than
   `MIZAN_ANCHOR_ATTESTATION_MAX_PENDING_SECONDS` is still *findable* as pending. If your design hides
   it, T-052 inherits a breaker that cannot fire and we are back where R-007 started.

5. **A test that fails on `d4d57c7`** and demonstrates the retry succeeding after a transient failure.
   Not a mock that returns garbage once — the gate already does this with a real TSA over real HTTP
   and it is fine to build the unit test in the same shape at a smaller scale.

Do **not** change `0003_anchor_attestations.sql` in place. It is applied. A new migration if you need
one, and H-3 applies: an ADR-004 delta in the same change-set if the contract moves.

---

## T-051 · `cannot check` ≠ `check failed`

Gate: case 5 green. Depends on T-049, which is done, so this is unblocked.

Unchanged from `CODEX-CP-B-REMEDIATION.md` §T-051 — read it there. The four causes to separate, the
distinct `CANNOT CHECK:` exit, the up-front `openssl ts` probe, and the attested bundle added to the
`offline-evidence-verifier` CI job.

One addition from the re-run. The verifier now prints pending authorities by name, which is a real
improvement. Extend the same honesty to this failure: when the verifier cannot check a token, the
summary line must not read as though it checked and found nothing wrong. An auditor who runs the tool
on a machine without OpenSSL must end up with a strictly weaker statement than one who has it, and the
output must say which one they are holding.

---

## T-052 · The breaker needs somewhere to fire from

Gate: no reproduction case. This one is judged on wiring and on the test asserting its own name.

Unchanged from `CODEX-CP-B-REMEDIATION.md` §T-052. Three parts: an enforcement point so
`MIZAN_ANCHOR_ATTESTATION_MAX_PENDING_SECONDS` is not a config key with no reader; the SLO evaluated
outside the `except` branch at `attestation.py:129-136` so a slow success trips it as well as a
raising failure; and `test_worker_opens_breaker_after_tsa_outage_exceeds_slo`
(`tests/unit/test_attestation.py:221-239`) asserting that the breaker opened rather than counting
completions.

Sequence T-052 **after** T-055. The breaker's job is to notice anchors stuck pending, and T-055 decides
what a stuck anchor looks like. Wiring it first means wiring it to a state machine that is about to
move.

---

## T-056 · The first token from an authority we do not control

Gate: a committed, reproducible interoperability result. This is TM-001 R-6, promoted from unqueued.

Everything the evidence plane has proved so far, it proved against a certificate authority it minted
itself. Case 1 is real cryptography end to end — and both ends are ours. Until a token issued by a TSA
Mizan does not operate verifies under a trust root Mizan did not create, **"externally anchored" is an
untested claim**, and it is the central claim of the product.

This is the task that converts an implementation into evidence.

Build:

1. **Obtain a real token from at least two independent public RFC 3161 authorities** over a digest this
   repository computes. Free public TSAs exist; pick two run by different organisations, because one is
   a sample and two is interoperability.
2. **Commit the tokens and the trust roots as fixtures**, with their provenance recorded: which
   authority, fetched when, from which URL, and the root's own fingerprint. The tokens are timestamps
   over a digest — they carry no customer data and are safe to commit. Record in the fixture README
   that the roots are committed *for the test's benefit only*, and that a real verifier still takes its
   roots from its own operator (B-12) and must never take them from a bundle.
3. **Run the standalone verifier against a bundle carrying those tokens**, offline, with no network, and
   commit the result. This is the artifact.
4. **Record every incompatibility you hit, in the commit message and in the fixture README.** Policy
   OIDs, hash algorithm negotiation, `-cert` handling, chain construction, TSAs that require an
   `Accept` header or reject a request without a nonce, tokens that verify under `openssl ts -verify`
   only with `-untrusted`. Rule 10 governs and this task is where it pays: the incompatibilities are
   more valuable than the successes, because they are what an operator will hit on their own TSA.
5. **Do not put the network in CI.** The fetch is a one-time recorded act; the committed fixtures are
   what CI verifies, forever, offline. A test that reaches a public TSA on every run is a test that
   goes red when someone else's service has an outage.
6. If a public TSA cannot be reached from your environment at all, **park the task and say so** — do not
   substitute another locally minted CA and call it interoperability. That is the one substitution that
   would make this task worthless.

When this lands, the honest sentence changes from *"we implement RFC 3161"* to *"tokens from two
authorities we do not control verify offline against roots we did not issue."* Those are different
products.

---

## Sequence

```
T-055 → STOP, re-run CP-B → T-051 → T-052 → T-056 → T-053 → T-054 → T-038 → T-039 (CP-C)
```

**Stop after T-055 and report.** CP-B is a checkpoint, not a formality: it gets re-run against a
six-case gate the moment its last blocker is claimed to be closed, and the re-run has now found a new
defect twice in a row. Running past it means building on a state that has an even chance of moving.

If T-055 lands and the re-run passes, the remaining four are yours in order without a further stop.

**Still do not start T-038.** Merkle inclusion builds a caller-retained proof on top of the anchor's
attestation state. T-055 is a change to what that state can be. Building the proof first would put a
stale state machine inside artifacts held by third parties.

**T-053 still gates delivery.** Until it ships, every development key is `sha256(key_id)` and the
`key_id` ships in the bundle, so any recipient can forge one and nothing in the output says so.
Do not send a bundle to anyone outside the building before T-053 lands.

---

## Report format

One `WORK_LOG` line per task: what you did, the pre-fix SHA and the test that fails on it, the gates
that pass, **what did not work**, and the hostile-party answer.

For T-055 add the paragraph defending your choice of where a failed attempt lives.
For T-056 add the incompatibility list even if it is empty, and say explicitly which two authorities
issued the tokens.

If a task cannot close as specified, park it and say why. Parking is cheap. T-050 shipped a correct fix
whose persistence consequence was one call site away, and it cost a review cycle to find — a sentence
in the report saying *"I record the pending result and I have not checked what the store does with it"*
would have cost nothing.
