# R-007 — Independent Validation of Stage 3 Checkpoint CP-B

**Date:** 2026-08-26 · **Lane:** CLAUDE · **Scope:** commit `94bb25e` (T-036), the crypto boundary
**Head validated:** `94bb25ec4debbab25d97d826b3b811d32f4b0cc5`
**Verdict:** **T-036 held in REVIEW — the cryptography is accepted, the reporting is not.** The core claim was
independently reproduced end to end for the first time. Five findings (V-11..V-15); **V-11 and V-14 block the
CP-B pass**, because both cause the system to assert external anchoring it does not have.

---

## 1. What was re-run, not read

| Claim | Method | Result |
|---|---|---|
| `make check` passes | re-run | `30 boundaries, 14 JSON blocks, 13 schema IDs; five drift gates proven` |
| 163 unit/property tests pass | re-run | 163 passed |
| **A real RFC 3161 token verifies inside a real bundle** | built a local standards-compliant TSA, minted a token over the digest **the verifier itself reconstructs**, built a bundle through `build_bundle`/`export_evidence_bundle`, ran `verify_evidence_export.py` as a **subprocess** with no monkeypatching on either side | **PASS**, exit 0, `ANCHOR 0 ATTESTATION: RFC3161`, `ASSURANCE DERIVED: rfc3161`, `LIMITATION` line correctly withdrawn |
| Forgery is actually detected | same bundle, unrelated CA as `--tsa-trust-anchor` | `FAIL: RFC 3161 token verification failed`, exit 1 |
| Rule-9 pre-fix demonstration on `2e4e81e` | `git archive 2e4e81e` of the golden bundle → today's verifier | Pre-fix manifest is `{'anchor_attestation': 'mizan_self_signed', 'external_timestamp': False}`; rejected with **exactly** the claimed message, `manifest assurance claim does not match verified attestations`. **Honest** |
| T-032's offline guarantee survives T-036 | golden bundle under `python -I` with `mizan_control_plane` asserted unimportable | PASS; correctly self-labels `UNATTESTED` and prints the hostile-party limitation |
| Sidecar is genuinely append-only | read `0003_anchor_attestations.sql` + the schema-contract delta | Trigger **and** grant **and** forced RLS **and** typed `tenant_id` **and** FK to `evidence_anchors` |
| Attestation worker runs in production | `grep -rn` for `AnchorAttestationWorker`, `pending_attestation_breaker_open`, `anchor_attestation_max_pending_seconds` across the tree | **Zero production callers** (see **V-13**) |
| H-3 delta per commit | commit stat | ADR-004 **G.11** + SPEC + migration + schema contract, all in the same change-set. Compliant |

The signer/verifier digest agreement is the load-bearing fact and it had never been executed anywhere:
`test_real_rfc3161_response_verifies_offline` tests `verify_rfc3161` against a hand-made digest, and the
mixed-anchor test monkeypatches `verify_rfc3161` to a no-op with `anchor_digest: "placeholder"`. Each stubs
one side. Row 3 above is the first execution of both sides together, and it holds.

## 2. Credit where it is due

1. **The cryptographic core is real.** `OutboxPublisher.anchor()`'s `anchor_core` and the verifier's
   independent reconstruction (`payload` minus `attestations`/`object_key`/`object_version`) produce the same
   digest, and `openssl ts -verify -digest` binds the token's message imprint to it. Case 1 and Case 2 above
   are the difference between a claim and a demonstration.
2. **The sidecar migration exceeds its requirement.** Append-only is enforced twice — a `BEFORE UPDATE OR
   DELETE` trigger *and* `REVOKE UPDATE, DELETE` — under forced RLS with a typed tenant and a real foreign
   key. Completion never rewrites the signed payload, which is the property that makes asynchronous
   attestation safe at all.
3. **V-8 and V-9 were carried forward unfixed and said so.** The report names both defects it did not close
   rather than quietly patching them at a checkpoint whose entire subject is key custody. That is standing
   rule 10 working as intended, and it is why the rest of the report was read in good faith.
4. **The limitation line is conditional now, not decorative.** It withdraws when — and only when — every
   anchor carries a verified token. The tool changes its own story on evidence.

## 3. Findings

### V-11 · A pending co-authority is dropped, and the stream is then called externally anchored — **blocks CP-B**

`verify_evidence_export.py:184` and `evidence_export.py:106` both read
`row.get("attestations") or payload.get("attestations")`. The moment **any** sidecar row exists, every pending
marker inside the **Mizan-signed** payload is discarded.

Reproduced. Two authorities configured, both pending in the signed anchor; authority A completes and its
sidecar row is appended exactly as `AnchorAttestationWorker` would append it. Authority B is still pending.
The verifier prints:

```
ANCHOR 0 ATTESTATION: RFC3161.
ASSURANCE DERIVED: rfc3161.
```

exit 0, and the `LIMITATION` line is **withdrawn**. This directly contradicts ADR-004 **G.11**, written in
this same commit — *"pending output is never called externally anchored"*, *"a mixed stream is never described
as externally anchored"* — and B-12 as ratified.

It is V-10 re-created one level down: V-10 was attestation-by-omission across **anchors**, and the line that
fixed it introduced attestation-by-omission across **authorities**. Worse, the evidence of incompleteness is
not missing — it is present, signed by Mizan, and thrown away by the `or`.

**And the V-3 cross-check cannot catch it**, because the exporter and the verifier contain the *identical*
expression: both derive the same wrong answer, so claimed and derived agree. A cross-check between two copies
of one bug is not a cross-check.

**Fix.** The signed payload is the authoritative roster of expected authorities — that is what signing it is
for. Union the sidecar over the payload keyed by `(type, authority)`; any authority declared in the signed
payload without a verified sidecar token is `pending`. Ship the mixed-**authority** fixture alongside the
existing mixed-anchor one.

> **Addendum, 2026-08-26, while writing the T-049 work order — V-11 is two defects, and the union alone does
> not close it.** `verify_evidence_export.py:224-230` ranks `verified_external` **above** `pending` within a
> single anchor. Union the two lists and the anchor carries `[attested_A, pending_B]`, so both flags are true
> and `rfc3161` still wins. `evidence_export.py:109-117` has the same ordering. The precedence must invert at
> the anchor level, matching the rule the stream already applies across anchors: the weakest state wins. One
> verified token does not cover an anchor whose signed payload demanded two. Recorded here rather than
> silently folded into the fix, because a reviewer who reports a finding less precisely than they later
> understand it has moved work onto the implementer and called it a review.

### V-14 · The control plane records `attested` without validating the token — **blocks CP-B**

`attestation.py:40-63`. `obtain()` POSTs the query, reads the response, and returns
`pending | {"status": "attested", "evidence": <whatever came back>}`. It never checks the message imprint,
never checks the TSA signature, and never sees a trust root. `urllib.request` is given the configured
endpoint with no scheme restriction, so `http://` is accepted and a network position is enough to induce this.

The repo's own test demonstrates it: `test_tsa_egress_contains_digest_and_no_anchor_payload` returns
`b"tsa-response"` and that string becomes an attestation of `status: "attested"`.

`evidence_export.py:109-117` then derives the manifest's assurance from that **status field**. So every
Mizan-side surface — the manifest, and any API or dashboard built on the same rows — can assert external
anchoring on unvalidated bytes. Only the offline verifier catches it, and only if the auditor supplies a root.

This is V-3 recurring one level in. V-3 is genuinely closed **at the verifier** — the pre-fix rejection above
proves it — and re-opens **inside the trust boundary**, which is the harder half: the party making the claim
is the party who skipped the check.

**Fix.** Validate before recording: recompute the imprint, verify the token against the operator's configured
roots, and only then write `attested`. A token that does not validate stays `pending` with a named reason.
Refuse non-TLS TSA endpoints in production.

### V-12 · The verifier crashes instead of failing when OpenSSL is absent — **must fix**

Reproduced by running the attested bundle with `PATH=/nonexistent`:

```
Traceback (most recent call last):
  File ".../verify_evidence_export.py", line 313, in main
  File ".../verify_evidence_export.py", line 208, in verify_bundle
```

`subprocess.run` raises `FileNotFoundError`; `main()` catches only `VerificationFailure`. The tool whose
entire premise is *"a stranger can check this"* hands the stranger a Python stack trace.

Two compounding problems:

- **Four distinct causes print one message.** A forged token, the wrong trust root, a missing binary, and an
  expired TSA certificate all yield `RFC 3161 token verification failed`. An auditor cannot separate *"Mizan's
  evidence is bad"* from *"my laptop is missing a tool"* — and the damaging reading is the one they will
  take. Stage 4's rule already anticipates exactly this shape: a false accusation is worse than no check.
- **CI never exercises the path.** The `offline-evidence-verifier` job installs only `rfc8785==0.1.4` and
  `cryptography==50.0.0` and runs only the **unattested** golden bundle. The RFC 3161 branch is never executed
  in the declared minimal environment — which is precisely the environment where this traceback appears.

In fairness, the OpenSSL 3 CLI dependency **is** declared in the ADR-004 G.6 delta, so H-3 is satisfied. But
it is declared in a document the auditor never reads. It is absent from the bundle, from the verifier's own
output, and from the CI environment that exists to prove the dependency list is honest.

**Fix.** Catch `FileNotFoundError` and `OSError` into a distinct `VerificationFailure`; separate
"cannot check" from "check failed" in both the exit code and the text; probe for `openssl ts` support up
front; add an attested bundle to the CI offline job with the toolchain it actually needs declared.

### V-13 · The attestation worker exists and nothing runs it; the SLO config is dead — **must fix before any production external-anchoring claim**

`AnchorAttestationWorker`, `pending_attestation_breaker_open`, `Settings.anchor_attestation_max_pending_seconds`
and `Settings.anchor_tsa_endpoints` have **no callers outside `attestation.py` and its unit test**. Only
`Rfc3161AnchorProvider` is wired, through `evidence.py:17`. There is one console script,
`mizan-export-evidence`, and no attestation runner.

So in a real deployment: anchors are written `pending`, nothing completes them, the breaker never opens, and
every export reads `pending` forever. B-12's ratified clause — *breaching
`MIZAN_ANCHOR_ATTESTATION_MAX_PENDING_SECONDS` opens the evidence breaker* — has no enforcement point
anywhere in the tree.

Two mitigations, stated so this is not read as worse than it is. The failure is **safe**: absent a runner the
system under-claims rather than over-claims. And `OutboxPublisher` likewise has no production runner, which is
a known gap tracked as **T-026** — "no runner" is this repo's existing operational shape, not a new sin. The
difference is that the drain has a task and the attestation worker does not, and the breaker contract is
unenforced rather than merely unscheduled.

Also: the breaker is evaluated **only inside the `except` branch** (`attestation.py:129-136`). A stalled
pipeline — worker crashed, scheduler off, deploy gap — is the likelier outage and never opens it, because
nothing raises. And a bare `except Exception: continue` makes a programming error indistinguishable from a
TSA outage.

### V-15 · A test asserts a guarantee it does not check — **standing rule, no rework**

`test_attestation.py:221-239`, `test_worker_opens_breaker_after_tsa_outage_exceeds_slo`, collects `opened`
into a list and then asserts only `process(...) == 0`. It never asserts `opened` is non-empty. The guarantee
in its own name is untested. Combined with V-13, the breaker is verified neither in a unit test nor in a
running system.

Worth a standing rule, since this is the second checkpoint to find a test that names more than it checks:
**11. A test's name is a claim. If the name says the system does X, the body must assert X.**

## 4. The standing question

> *Would this survive a hostile party who holds the database and the signing key?*

CODEX answered: *"yes only for every finalized anchor covered by an independently trusted RFC 3161 token,
while incomplete/pending streams remain no."* That is the right shape of answer and the mechanism behind it is
now proven — Case 1 is the first evidence in this repository's history that the answer can ever be yes.

But for the tree as it stands the honest answer is **still no**, for two reasons that are not cryptographic:

1. **V-11** means the verifier can report a stream as fully covered when it is not, so "for every finalized
   anchor" is not something the tool reliably establishes.
2. **V-13** means no deployed Mizan can currently produce a finalized attested anchor at all.

This is a much better *no* than yesterday's. Yesterday the signer was inside the boundary and there was no
mechanism. Today the mechanism works and the remaining gap is wiring and reporting. Say it that way; do not
round it up.

## 5. Sequence from here

CP-B does **not** pass yet. The two blocking findings both produce a false claim of external anchoring, which
is the exact defect class this checkpoint exists to stop.

| Task | What | Lane | Gate |
|---|---|---|---|
| **T-049** | V-11: authority-roster union — the signed payload is authoritative; any declared authority without a verified sidecar token is `pending`. Mixed-**authority** fixture. Fix both copies of the expression | CODEX | Blocks CP-B |
| **T-050** | V-14: validate the token before writing `attested`; refuse non-TLS TSA endpoints in production | CODEX | Blocks CP-B |
| **T-051** | V-12: `cannot check` ≠ `check failed`, distinguishable causes, no traceback, attested bundle in the CI offline job | CODEX | Before CP-C |
| **T-052** | V-13 + V-15: attestation runner and breaker wiring (may be merged into T-026 by the owner), and the test that asserts its own name | CODEX | Before CP-C |
| **T-053** | V-8 + V-9 custody honesty: refuse `production` regardless of URI scheme; add `custody` to the keyset, require it in the verifier, print `KEY CUSTODY: publicly derivable development key — this bundle is forgeable by anyone who reads it.` | CODEX | **Before any bundle leaves the building** |

T-049 and T-050 first, then re-run this checkpoint. T-053 is not CP-B-blocking but it gates delivery: until it
ships, any staging bundle handed to a design partner is forgeable by its recipient, and the bundle does not
say so.

The work order is `docs/handoff/CODEX-CP-B-REMEDIATION.md`. The findings above are executable as
`docs/reviews/reproductions/R-007-cpb-attestation.py` — five cases, two green regression guards and three red
findings, which is the acceptance gate for T-049, T-050 and T-051. It lives outside `tests/` so `pytest` does
not collect it and CI does not go red on findings that are open by design. Case 1 is the only place in the
tree that executes both halves of the digest agreement; if it ever goes red, the signer and the verifier have
stopped agreeing on what they hash and nothing in `tests/` will say so.

## 6. Disposition of findings carried into CP-B

| Finding | Status | Basis |
|---|---|---|
| **V-3** manifest assurance declared not derived | **Closed at the verifier; re-opened inside the boundary as V-14** | Pre-fix `2e4e81e` bundle rejected with the exact claimed message; `test_manifest_cannot_declare_stronger_assurance_than_verified` passes |
| **V-10** partial attestation reads as attestation | **Closed per anchor; re-opened per authority as V-11** | Mixed-anchor reporting verified, and Case 1 supplies the real-crypto evidence its monkeypatched test could not |
| **V-8** `LocalKeyProvider` refuses by URI prefix, not custody | **Open** — `keys.py:62` unchanged; queued as T-053 | Confirmed in the current tree. Disclosed, not silently fixed |
| **V-9** development private keys are `sha256(key_id)` | **Open** — `keys.py:75` unchanged; queued as T-053 | Confirmed in the current tree. Disclosed, not silently fixed |

V-8 and V-9 were filed as H-7 territory. On review they are **not** human decisions: Amendment G.1 already
ratified that custody, not naming, is the rule, and V-9's fix is disclosure rather than policy. Both are
engineering tasks. Nothing in CP-B is waiting on a human.

---

## 7. CP-B re-run — 2026-08-26, head `d4d57c7`

**CP-B does not pass.** One blocker remains where there were two.

**T-049 and T-050 are accepted DONE.** V-11 and V-14 no longer reproduce. The signed roster is
authoritative in both implementations, the union is keyed by `(type, authority)`, an undeclared sidecar
authority is a verification failure, and `pending` now outranks `verified_external` within an anchor. The
worker verifies a token against an operator-supplied root before writing `attested`. Two improvements were
delivered beyond the order: production refuses plaintext TSA endpoints, and the verifier names pending
authorities in its per-anchor line. The two implementations were kept independent — rule 12 held.

**V-16 · a transient TSA failure is written as a terminal fact — introduced by T-050, blocks CP-B.**

`obtain()` correctly stopped raising and now returns a `pending` dict with a named `failure_reason`. The
worker at `attestation.py:175` records **every** return value. The store is `mizan.anchor_attestations`:
PK `(tenant_id, anchor_id, authority, attestation_type)`, `INSERT ... ON CONFLICT DO NOTHING`, `UPDATE` and
`DELETE` revoked *and* rejected by trigger. Therefore one bad response writes a permanent `pending` row, and
from that point:

- the retry is skipped — `attestation.py:164-166` finds the pair in `finalized` and continues;
- a successful token, if one were ever obtained, is silently swallowed by the conflict clause;
- there is no repair path, because the table is correctly immutable;
- `completed += 1` counts the failure as a completion;
- the anchor stops looking pending to the pending-SLO breaker — the single mechanism that exists to notice
  a stalled attestation is the one this state hides it from.

**A single network blip permanently bars an anchor from ever satisfying I-11.** Not degrades — bars.

Reproduced as **case 6** of the gate: two ordinary worker passes against a TSA that returns garbage once and
then mints real tokens, with a store reproducing the migration's exact key and conflict semantics, and
nothing monkeypatched on either side. The counter reports **one** TSA call. The retry did not fail; it did
not happen.

Cases 4 and 6 are a pair. Case 4 says a bad token must not become `attested`; case 6 says it must not become
permanent either. A change that greens 6 by reverting T-050 reddens 4, and that is a trade rather than a fix.

`test_worker_records_validation_failure_as_named_pending_sidecar` (`tests/unit/test_attestation.py:264`) is
not a bad test. It describes what the code does, accurately. Its claim is true and too small: it never asked
what the second pass does. Rule 11 governs the fix — the test changes with the behaviour, visibly.

**Limitations of this re-run.** `make check` and the live-PostgreSQL gates were not re-run; CODEX's report of
them is accepted, not reproduced. The V-16 store semantics are reproduced by hand from
`0003_anchor_attestations.sql` rather than against a live table — the right shape for a gate that must run
without Postgres, and one step removed from the real `ON CONFLICT`. The T-049/T-050 pre-fix SHAs were not
sampled; the gate's own case 3 and case 4 transitions were taken as the demonstration.

**Hostile-party answer: still no.** For one wiring reason now, rather than two reporting ones.

Work order: `docs/handoff/CODEX-CP-B-CLOSEOUT.md` — T-055 (blocker), T-051, T-052, T-056.

---

## 8. CP-B closeout — 2026-08-26, head `e76b2b6`

**CP-B is PASSED. T-055 and T-036 are accepted DONE.**

Gate cases 1, 2, 3, 4 and 6 are green together, which is the §5 criterion as amended by both re-runs.

**What was reproduced rather than read.** The previous re-run disclosed that it had accepted `make check`
and the supporting gates from CODEX's report. That limitation is closed here. `ruff check .` clean;
`make check` clean — 30 boundaries, 14 JSON blocks, 13 schema IDs, five drift gates; 170 passed / 12
skipped. Rule 8 was sampled directly: `d4d57c7`'s `attestation.py` was checked back out and **both** new
tests fail against it — `test_worker_does_not_persist_validation_failure_and_retries_to_attested` and
`test_worker_does_not_treat_pending_sidecar_as_finalized`.

**T-055 is good work.** Outcome-only append semantics are the right choice of the two the order offered,
and the commit message defended it on the correct ground: the signed payload already carries durable
pending state, so a diagnostic relation would have bought a diagnostic at the price of a thing the
assurance derivation could mistake for evidence. CODEX also routed the non-`attested` branch into the SLO
breaker, which §T-055.4 asked for only implicitly.

### V-17 · An append the store refuses is counted as a completion — **blocks CP-C**

`record_anchor_attestation` (`evidence.py:613-628`) is `INSERT ... ON CONFLICT DO NOTHING` and returns
`None`. The worker cannot tell an append from a silent refusal, and increments `completed` either way.
T-055's correctness now rests on the `(anchor, authority, type)` slot being empty, and nothing checks
that it is.

CODEX disclosed that a pending row written by pre-fix code cannot be repaired in place. True, and not
the whole cost. T-055 removed the `finalized` skip that used to stop the worker looking at such an
anchor. Case 7 runs three passes over one against an entirely **healthy** TSA:

```
after 3 passes against a healthy TSA the sidecar still reads 'pending';
3 token(s) minted and discarded; the worker reported 3 completion(s)
```

An unbounded external-call loop against a permanently false completion count. This is not an argument
against T-055 — it is the argument that the write path needs to be able to fail. Owner: **T-057**.

Cases 6 and 7 are a pair, as 4 and 6 are: 6 says a failed attempt must stay retryable, 7 says the retry
must be able to land. A fix that greens 7 by restoring the skip reddens 6.

### V-18 · The format is defined only by the program that reads it — **blocks CP-C**

Not a code defect. The anchor core digest — `payload` minus `{attestations, object_key, object_version}`,
JCS-canonicalised, SHA-256 — is the most load-bearing definition in the product. It appears in
`evidence.py`, in `verify_evidence_export.py`, and **nowhere in `SPEC_v1.md` or ADR-004**. Rule 12 keeps
the two copies independent and case 1 proves they agree, but there is no normative statement of what they
are agreeing about.

The consequence is external, not internal. The only implementation of the bundle format is Mizan's own,
so "verify it yourself, offline" currently means "run our program." Apply the second founder test to the
verifier rather than to the evidence and the answer is no. Owner: **T-059**.

### Why neither blocks CP-B

CP-B's question is whether the system asserts external anchoring it does not have. V-17 produces a false
*completion count* and an unbounded retry, not a false assurance — the anchor correctly reads `pending`
throughout. V-18 is a gap in what is written down, not in what is computed. Both are reporting and
delivery defects, so §5's placement of V-12 before CP-C is the right precedent for both. The gate now
prints which checkpoint each open case blocks and still exits non-zero while any case is open.

### T-038 is not a feature on the list

`TM-001` §"NOT COVERED" names two adversaries this design does not defend against: records omitted before
chaining, and an entire final anchor withheld. A party holding the database and the signing key can
present a truncated history that is internally perfect and freshly timestamped — an RFC 3161 token proves
an anchor existed by time T, never that no other anchor exists. A retained inclusion proof is the only
mechanism in the design that lets a third party prove a record **must** be in a chain it does not
control. That makes T-038 the answer to the largest remaining hole in the hostile-party story, and the
work order says so.

**Limitations of this pass.** The 12 live-PostgreSQL tests were again accepted from CODEX's report rather
than re-run. Case 7 models `ON CONFLICT DO NOTHING` by hand from the migration, because the gate must run
without a database; T-057 is therefore required to cover the real rowcount behaviour against a live table.

**Hostile-party answer: still no** — and the reason has moved. The cryptographic boundary holds for
finalized anchors under an independently controlled trust root. What remains is wiring (T-052), custody
disclosure (T-053), and omission (T-038).

Work order: `docs/handoff/CODEX-CP-C-RUN.md` — eleven tasks in four waves, no mandatory stop before CP-C.

## 9. CP-C wave-1 review — 2026-08-26, head `f06cc95`

T-057, T-051, T-052 and T-056 accepted. Reproduced rather than read: 184 passed / 13 skipped, ruff
clean, `make check` five drift gates proven, seven cases green at `f06cc95`. Rule 8 sampled directly
— `1e7b00e`'s `attestation.py` and `evidence.py` were restored into the tree and both of T-057's new
unit tests failed with `assert 1 == 0`; the worktree restored clean afterwards.

T-056 deserves specific credit. Tokens from two authorities nobody here controls, verifying offline
against roots nobody here issued, is the difference between implementing RFC 3161 and interoperating
with it, and it is the first evidence in this repository that the format claim survives contact with
a party outside the building.

### B-14 was half our error

CODEX parked T-059 on a contract mismatch and was right to. One half of it was a defect in the work
order: `CODEX-CP-C-RUN.md` line 189 asks for four attestation `type` values where ratified ADR-004
G.2 defines three. The ratified ADR wins. Refusing to reconcile a ratified artifact with an
unratified one by guessing is exactly the behaviour the escalation rule exists to produce.

The other half is not a conflict at all but a grammar written flat where the system is layered. An
attestation entry is persisted in exactly two places. The signed anchor payload is written *before*
any TSA is contacted and is immutable inside the signature, so it can only ever read `pending` — or
`unattested`, and only with `none_development`. The append-only sidecar stores outcomes rather than
attempts under G.12, so it can only ever read `attested`. There is no third location, and therefore
no write path that emits `failed`. `failed` describes a transient in-flight attempt that G.12 already
decided, deliberately, never to persist.

So `failed` is reserved vocabulary, the verifier's refusal is correct, and G.15 records the narrowing
descriptively — it forbids nothing the implementation has ever emitted.

What the disposition surfaced is smaller and more interesting than the blocker. A bundle carrying
`failed` is currently reported as `anchor N has no verified external attestation`, which sends an
auditor to chase the operations team when the truth is that someone edited the file. That is V-12's
mistake in a new place: `cannot check` is not `check failed`, and `malformed` is not `unattested`.
Bundle 1.0 therefore needs a third verdict class, and the reason is not tidiness:

> The discrepancy is harmless today only because there is exactly one implementation — which is the
> precise condition T-059 exists to end. An independent implementer reading G.2's flat enum would
> legitimately accept `failed` and report it as an assurance level. Two conformant verifiers would
> then return different verdicts on the same bundle, and the format would have failed at the only
> job it has.

### V-19 — the tamper alarm fires on ordinary concurrency

Found the same way V-16, V-17 and V-18 were found: by following the accepted fix one call site
further than the gate case that proved it. T-057 is correct and case 7 is genuinely green. But
`record_anchor_attestation` classifies a refused append by comparing the stored document to the new
one with `existing[0] == attestation`, and ADR-004 G.13 calls an identical document "a benign
idempotent race".

That branch is unreachable for `rfc3161`. An RFC 3161 token carries its own `genTime`, a TSA-chosen
serial number and an optional nonce; two tokens over the same imprint from the same authority are
never byte-identical, because non-determinism is a property of the protocol rather than an accident.
The only classification a concurrent double-pass can reach is `conflict`, which opens
`anchor_attestation_integrity`.

Three facts compose into the severity. There is no lease on the anchor — no `FOR UPDATE SKIP LOCKED`
anywhere on the pending-anchor read. The window between reading the sidecars and appending spans a
full TSA network round-trip. And T-052 has just made the worker run continuously, so that window
opens on every pass. T-057 defined the integrity signal; T-052 built the thing that trips it;
neither is wrong alone.

Case 8, with two healthy TSAs and two valid tokens:

```
RED    CASE 8  V-19  two healthy workers attest the same anchor concurrently
       two healthy workers, two valid tokens, one slot; the stored token is unchanged
       and the alarms raised were ['anchor_attestation_integrity']
```

The consequence is that the one alarm meaning *someone reached into the immutable evidence store* is
fired by ordinary concurrency. An alarm that cries wolf is worse than no alarm: operators learn to
clear it, and the real event arrives looking exactly like the noise. The secondary cost is a real
token minted, requested across the trust boundary and discarded on every losing pass.

T-061 must classify semantically — a stored row that validates against the operator's trust roots
and commits to this anchor's core digest is a second honest witness to the same fact, which is the
opposite of tampering — and must take a lease before spending a token. The breaker survives; it just
has to mean something.

### Why V-19 does not reopen CP-B

CP-B asks whether the system asserts external anchoring it does not have. V-19 produces a false
*alarm*, never a false assurance: the winning token is valid, the anchor is correctly `attested`, and
no stream is described as externally anchored when it is not. It is an operations and
signal-integrity defect, so it sits with cases 5 and 7 before CP-C, following §5's own precedent.

### Limitations

The 12 live-PostgreSQL tests are again taken from CODEX's report rather than re-run here. Case 8
models the JSONB round-trip by hand, and the round-trip is exactly the part a hand model cannot
reproduce — T-061 is required to carry live-PostgreSQL coverage for it.

### Hostile-party answer: still no

Unchanged and unchanged for the same reason. T-038 and T-039 are the tasks that move it, and T-064
is the pass that tests whether they did.
