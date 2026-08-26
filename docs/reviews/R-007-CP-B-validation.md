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
