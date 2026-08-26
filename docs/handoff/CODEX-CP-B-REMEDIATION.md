# CODEX — CP-B Remediation Work Order: Stop Claiming External Anchoring You Do Not Have

**Issued:** 2026-08-26 · **Issuer:** CLAUDE lane (R-007) · **Head reviewed:** `94bb25ec4debbab25d97d826b3b811d32f4b0cc5`
**Scope:** five tasks, T-049..T-053, one order, one commit each · **Authority:** `WORK_LOG.md` remains the
protocol; `docs/handoff/CODEX-STAGE-3.md` §2 non-negotiables (1–9) apply unchanged and are not repeated here.

---

## 0. Where you stand

**T-036 is held in REVIEW. CP-B did not pass.** Read that as narrowly as it is meant.

The cryptography is accepted, and it was accepted on evidence rather than on your say-so. R-007 stood up a
local standards-compliant TSA, minted a real RFC 3161 token over the digest **the verifier itself
reconstructs**, and ran `verify_evidence_export.py` as a subprocess over a real bundle with nothing
monkeypatched on either side. It passed: `ANCHOR 0 ATTESTATION: RFC3161`, the hostile-party limitation line
correctly withdrawn. An unrelated CA was rejected cleanly. That is the first execution in this repository's
history of *both* halves of the digest agreement — every test you shipped stubs one side — and it is the
first evidence that the second founder test can ever be answered yes.

The append-only sidecar is right, and enforcing it twice — trigger *and* grant, under forced RLS — is the
property that makes asynchronous attestation safe at all. And you carried V-8/V-9 forward unfixed and said
so, at a checkpoint whose whole subject is key custody. That is why the rest of the report was read in good
faith rather than re-derived from scratch.

What failed is not the crypto. It is that **three separate surfaces will tell an auditor a stream is
externally anchored when it is not.** That is the exact defect class CP-B exists to stop, so the checkpoint
holds until T-049 and T-050 land.

## 1. The gate — run this first, before you read anything else

```
uv run python docs/reviews/reproductions/R-007-cpb-attestation.py
```

Five cases. Two are green and must stay green; three are red and are your acceptance criteria. Today:

```
GREEN  CASE 1  real token, real bundle, operator trust root
GREEN  CASE 2  same bundle, unrelated certificate authority
RED    CASE 3  V-11  authority A attested, authority B still pending in the signed payload
RED    CASE 4  V-14  TSA returns twenty-one bytes of garbage
RED    CASE 5  V-12  OpenSSL absent from PATH
```

This is R-007's evidence, executable. It is not a substitute for the tests you owe under non-negotiable 3 —
it lives outside `tests/` and CI does not run it — but it is the objective statement of done for three of the
five tasks, and it is what the CP-B re-run will use. **Case 1 is the load-bearing regression guard:** if it
ever goes red, the signer and the verifier have stopped agreeing on what they hash, and nothing in `tests/`
will tell you.

Case 4 is worth watching run. It stands up a local HTTP server that answers a timestamp query with
`b"not-a-timestamp-token"`, and the control plane records `status: "attested"` on it.

---

## T-049 · The signed payload is the authoritative roster of authorities — **blocks CP-B**

**Finding:** R-007 V-11. **Gate:** case 3 turns green; case 1 stays green.

### There are two defects here, not one. Fixing the first alone leaves case 3 red.

**Defect A — the `or` discards signed evidence of incompleteness.**

```python
attestations = row.get("attestations") or payload.get("attestations")   # verify_evidence_export.py:184
```

```python
row.get("attestations") or row.get("payload", {}).get("attestations", [])   # evidence_export.py:106
```

The moment **any** sidecar row exists, every pending marker inside the Mizan-signed payload is thrown away.
The evidence of incompleteness is not missing — it is present, signed by Mizan, and discarded by an `or`.

**Defect B — within one anchor, `verified_external` outranks `pending`.**

```python
state = (
    "unattested" if explicitly_unattested
    else "rfc3161" if verified_external
    else "pending" if pending          # verify_evidence_export.py:224-230
    else "unattested"
)
```

Union the two lists and this anchor now carries `[attested_A, pending_B]`, so `verified_external` and
`pending` are *both* true — and `rfc3161` still wins. The precedence must invert. One verified token does
not cover an anchor whose signed payload demanded two.

`evidence_export.py:109-117` has the same shape and needs the same inversion: `any(... == "rfc3161")`
currently outranks `any(... == "pending")` inside a single anchor.

### What to build

1. **Union, keyed by `(type, authority)`,** with the signed payload as the roster and the sidecar as the
   completion record. `AnchorAttestationWorker.process` already keys finalization exactly this way
   (`attestation.py:120-128`) — the worker is correct, the two readers are not. Reuse its key.
2. **Any authority declared in the signed payload with no verified sidecar token is `pending`.** Not
   missing, not ignorable — pending, with the authority named in the output so an auditor can see which one.
3. **Invert the precedence** at the anchor level in both files, matching the rule the stream already applies
   across anchors: the weakest state wins.
4. **A sidecar row for an authority the signed payload never declared is a verification failure**, not a
   bonus. Otherwise anyone with database write access can add coverage after the fact — which is the entire
   threat this layer exists to address.
5. **Fixture:** mixed-**authority**, alongside the existing mixed-anchor one. The existing test
   monkeypatches `verify_rfc3161` to a no-op with `anchor_digest: "placeholder"`; the new one must not.

### The lesson that outlives the fix

The V-3 claimed-vs-derived cross-check could not catch this, because the exporter and the verifier contained
the *identical expression*. Claimed and derived agreed because both were wrong in the same way. That is now
standing rule 12. When you fix these two lines, **do not fix them by extracting a shared helper both sides
import** — that makes the gate permanently blind. The verifier is a stranger's tool; it must reconstruct the
answer independently, and the duplication is the point. Note this explicitly in your WORK_LOG line so the
next agent does not "clean it up."

**Out of scope:** the worker, the runner, key custody, CI.

---

## T-050 · Validate before recording `attested` — **blocks CP-B**

**Finding:** R-007 V-14. **Gate:** case 4 turns green.

`attestation.py:40-63`. `obtain()` POSTs the query, reads the response, and returns
`pending | {"status": "attested", "evidence": <whatever came back>}`. It never checks the message imprint,
never checks the TSA signature, never sees a trust root. Your own
`test_tsa_egress_contains_digest_and_no_anchor_payload` turns `b"tsa-response"` into an attestation.

`evidence_export.py:109-117` then derives the manifest's assurance from that **status field**. So the
manifest — and any API or dashboard built on the same rows — asserts external anchoring on unvalidated bytes.
Only the offline verifier catches it, and only if the auditor happens to supply a root.

This is V-3 recurring one level in. V-3 is genuinely closed **at the verifier** — the pre-fix `2e4e81e`
rejection proved it — and re-opens **inside the trust boundary**, which is the harder half, because the party
making the claim is the party who skipped the check.

### What to build

1. **Recompute the imprint and verify the token before writing `attested`.** Same operation the verifier
   performs. Trust roots come from operator configuration; register the key in SPEC in the same change-set.
2. **A token that does not validate stays `pending` with a named reason** recorded on the sidecar row —
   never `attested`, and never silently dropped. A TSA that answers with garbage must be visible as a TSA
   that answers with garbage, not as an anchor that never got around to it.
3. **Refuse non-TLS TSA endpoints when `environment == "production"`,** at startup, the way G.1 refuses
   development custody. `urllib.request` currently accepts any scheme, so a network position is enough to
   induce this.
4. **If no trust root is configured in production, refuse to start.** An attestation the operator cannot
   validate is not an attestation; do not let it degrade into one silently.

**Do not** put validation on the authorization hot path. B-12 is explicit and unchanged: attestation is
asynchronous. This is worker-side work.

**Out of scope:** the runner (T-052), the verifier's reporting (T-049/T-051).

---

## T-051 · `cannot check` is not `check failed`

**Finding:** R-007 V-12. **Depends on:** T-049. **Gate:** case 5 turns green.

Run the attested bundle with `PATH=/nonexistent` and the tool whose entire premise is *"a stranger can check
this"* hands the stranger a Python stack trace. `subprocess.run` raises `FileNotFoundError`; `main()` catches
only `VerificationFailure` (`verify_evidence_export.py:307-316`).

Worse than the traceback: **four distinct causes print one message.** A forged token, the wrong trust root, a
missing binary, and an expired TSA certificate all yield `RFC 3161 token verification failed`. An auditor
cannot separate *"Mizan's evidence is bad"* from *"my laptop is missing a tool"* — and the damaging reading
is the one they will take. Stage 4's proposal already states the principle: a false accusation is worse than
no check.

### What to build

1. **Catch `FileNotFoundError` and `OSError` into a distinct failure type** with its own exit code. `FAIL:`
   means the evidence is bad. Something else — `CANNOT CHECK:` — means the environment is incomplete.
2. **Separate the four causes** in the text. `openssl` exit codes and stderr distinguish an untrusted issuer
   from an imprint mismatch from an expired certificate; pass that through instead of flattening it.
3. **Probe `openssl ts` support up front**, before any verification, and say so plainly if it is absent.
   Note for the probe: macOS system LibreSSL 3.3.6 *does* support `ts -query`/`-reply`/`-verify` — R-007
   checked, because the opposite would have made every attested bundle unverifiable on a stock auditor
   laptop. Do not assume a vendor; test the capability.
4. **Add an attested bundle to the `offline-evidence-verifier` CI job.** It currently installs
   `rfc8785==0.1.4` and `cryptography==50.0.0` and runs only the **unattested** golden bundle, so the RFC
   3161 branch is never executed in the declared minimal environment — precisely the environment where this
   traceback appears. Declare the OpenSSL dependency in that job.

The OpenSSL 3 CLI dependency *is* declared in the ADR-004 G.6 delta, so H-3 was satisfied. But it is declared
in a document the auditor never reads, and it is absent from the bundle, from the verifier's own output, and
from the CI environment that exists to prove the dependency list is honest. Put it in all three.

---

## T-052 · The breaker contract needs an enforcement point

**Findings:** R-007 V-13 and V-15. **Gate:** the runner exists and the breaker opens in a test that says it does.

`AnchorAttestationWorker`, `pending_attestation_breaker_open`, `Settings.anchor_attestation_max_pending_seconds`
and `Settings.anchor_tsa_endpoints` have **no callers** outside `attestation.py` and its unit test. In a real
deployment: anchors are written `pending`, nothing completes them, the breaker never opens, and every export
reads `pending` forever. B-12's ratified clause — *breaching
`MIZAN_ANCHOR_ATTESTATION_MAX_PENDING_SECONDS` opens the evidence breaker* — has no enforcement point in the
tree.

Stated fairly: this fails **safe**. Absent a runner the system under-claims. And `OutboxPublisher` has the
same gap, tracked as T-026 — "no runner" is this repo's existing operational shape, not a new sin. The
difference is that the drain has a task and the attestation worker does not, and that a ratified breaker
contract is *unenforced* rather than merely unscheduled.

### What to build

1. **A console-script runner**, in the shape of `mizan-export-evidence`. The owner may merge this into T-026
   instead; if you take that route, say so in the WORK_LOG and do it there, not in both.
2. **Evaluate the SLO outside the `except` branch.** `attestation.py:129-136` opens the breaker only when
   `obtain()` raises. The likelier outage — worker crashed, scheduler off, deploy gap — never raises, so it
   never opens the breaker. Check pending age on every pass, unconditionally.
3. **Narrow `except Exception: continue`.** It makes a programming error indistinguishable from a TSA
   outage, and it will hide the validation failures T-050 introduces.
4. **Make the test assert its own name.** `test_worker_opens_breaker_after_tsa_outage_exceeds_slo`
   (`test_attestation.py:221-239`) collects `opened` and then asserts only `process(...) == 0`. It never
   checks that `opened` is non-empty. The guarantee in the name is untested, and combined with V-13 the
   breaker is verified neither in a unit test nor in a running system.

That last point is now **standing rule 11: a test's name is a claim.** This is the second checkpoint to find
a test that names more than it checks. Before you close this task, grep your own test names for guarantees
and confirm the bodies assert them.

---

## T-053 · Custody honesty — not CP-B-blocking, but it gates delivery

**Findings:** R-007 V-8 and V-9, carried from CP-A and confirmed unchanged in the current tree.

**These were filed as H-7 and are not.** Amendment G.1 already ratified that custody, not naming, is the
rule, and V-9's fix is disclosure rather than policy. Both are engineering tasks. **Nothing in this work
order waits on a human** — do not stop for a ratification that already happened.

- **V-8** — `keys.py:62` refuses production by URI prefix: `any(item.key_id.startswith("local://"))`. A
  development key named anything else passes. Refuse on **custody**, not on the string.
- **V-9** — `keys.py:75` derives development private keys as
  `Ed25519PrivateKey.from_private_bytes(sha256(key_id))`, and the `key_id` ships inside `keys.json` in every
  bundle. Anyone who reads a development bundle can reconstruct its signing key and forge a replacement.

### What to build

1. `LocalKeyProvider` refuses `environment == "production"` **regardless of URI scheme**.
2. Add `custody` — `development-derived` / `kms` / `hsm` — to the published keyset and to
   `required_key_fields`, so a bundle that omits it fails verification rather than defaulting to trusted.
3. The verifier prints, for any `development-derived` key:
   `KEY CUSTODY: publicly derivable development key — this bundle is forgeable by anyone who reads it.`

Blunt on purpose. Until this ships, any staging bundle handed to a design partner is forgeable by its
recipient and the bundle does not say so. **Do not send a bundle to anyone outside the building before
T-053 lands.**

---

## Sequence and stopping points

```
T-049 → T-050 → STOP, re-run CP-B → T-051 → T-052 → T-053 → T-038 → T-039 (CP-C)
```

T-049 and T-050 first because both produce a false claim of external anchoring, and neither depends on the
other. **Stop after T-050 and report.** Do not start T-038 — Merkle inclusion builds a caller-retained proof
on top of the anchor's attestation state, and building it on a state the tree currently misreports would put
the defect inside artifacts held by third parties.

T-051 and T-052 are before CP-C. T-053 is not CP-B-blocking and gates delivery instead.

## What the CP-B re-run will do

Assume all of it will be re-run; R-007 re-ran rather than read, and found what reading would not have.

1. `docs/reviews/reproductions/R-007-cpb-attestation.py` — all five cases green.
2. `make check`, the full unit/property suite, and the live-PostgreSQL gates.
3. Your named pre-fix SHAs, reverted to and re-run, per non-negotiable 3 — sampled again. All four were
   honest at CP-A and the `2e4e81e` claim was honest at CP-B. Keep that record.
4. A fresh independent path for anything the reproduction script does not cover, because a gate the
   implementer optimises against stops being an independent check. Expect at least one case you have not
   seen.
5. The second founder test, recorded in `docs/product/FALSIFICATION_TESTS.md` whatever the answer is. Today
   it is *"no — but for a different reason than yesterday,"* and the reason is wiring and reporting rather
   than cryptography. That is a much better no than CP-A's. **Do not round it up.**

## Report format

One WORK_LOG line per task, as before: what you did, the pre-fix SHA and the test that fails on it, the gates
that pass, **what did not work**, and the hostile-party answer. Standing rule 10 is why this report was
believed; standing rules 11 and 12 were added by this checkpoint and apply from now on.

If any task cannot be closed as specified, park it and say why. Parking is cheap. A silent widening or a
quiet narrowing costs a review cycle, and this checkpoint has already cost one.
