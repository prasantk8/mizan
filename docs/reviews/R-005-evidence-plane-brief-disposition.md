# R-005 — "Evidence Plane First" Brief: Critical Evaluation & Stage-3 Work Order

**Date:** 2026-08-25
**Reviewer:** CLAUDE lane (independent)
**Subject:** Handoff brief *"Evidence Plane First"* (Memtara/AIHOOTS engine → Mizan), dated 25 Aug 2026,
written against **Mizan PRD v1.0** and `memtara-zkp @ evidence-v1`.
**Reviewed against:** the working tree at SPEC v1.3.1, ADR-001..009, and the T-001..T-022 implementation.

---

## 0. Standing before this review

The brief is written against `mizan-prd-v1.md` (PRD v1.0, 119 sections). The repository is two
document generations past that: SPEC v1.3.1, nine ADRs with amendments, twenty-two implemented tasks,
and four review dispositions. **Roughly a third of the brief's engineering argument describes gaps
that closed between PRD v1.0 and SPEC v1.3.** That is not the brief's fault — it is a handoff
artifact, and it says which baseline it used. It does mean its findings cannot be actioned as
written, and the parts that survive re-grounding are a different, smaller, sharper set than the parts
that read as most urgent.

Every claim the brief makes *about Mizan* was checked against the tree. Every claim it makes about
the source repository (`20,700` lines of Rust, `179` Rust tests, `461` Python test functions,
`13` migrations, `12` attacks, `11` enforcement actions) is **unverified** — that repository is not
available here. Under this project's own R-004 rule 6, those are terminal-only numbers. They are
recorded below as claims, never as facts, and must not be re-quoted in any Mizan artifact until the
repository is in hand and re-measured.

**Finding numbering** continues the single project-wide namespace. F-1..F-10 are R-004. F-11 and F-12
are the R-004 §6 independent validation (recorded in §1 below). R-005 opens at **F-13**.

---

## 1. Carried forward — the R-004 §6 validation result

The independent re-run of R-004 §6 against commits `53d1035`..`73c7de9` is complete. Five of CODEX's
claims reproduced exactly (125 unit/property, 11 live PostgreSQL, 50.92% execution coverage,
39 contract-coverage rows, clean worktree). Commit isolation and H-3 ADR deltas hold across all seven.
Three of seven pre-fix failure claims were sampled and reproduced by reverting the implementation
modules to the named SHA — T-016 (`3 failed, 3 passed`, failing on exactly CONSTRAIN/REDACT/ESCALATE),
T-017 (all four fail-closed tests fail), T-019 (`assert 2 == 1` on ADR count). These are genuine
regression tests.

Two findings survived, and they carry into this work order:

### F-11 · MEDIUM · `constraints` reach the caller on the ALLOW path and vanish on replay
T-016's third acceptance criterion — *"No expression in the codebase reads a `constraints` key from
an ADR_Record"* — is **not met**. [`repository.py:120`](../../control-plane/mizan_control_plane/repository.py#L120)
reads `doc.get("constraints")` out of a persisted ADR_Record. CODEX removed the two reads the review
*cited* (`execution.py:153`, `:509` — confirmed gone); this third one predates them and was missed.

The `Policy` schema's prose says constraints are *"Required iff decision ∈ {CONSTRAIN, REDACT}"* but
the machine-checkable `allOf` (SPEC_v1.md:356-370) encodes only the forward implication. An `ALLOW`
policy carrying `constraints` validates. Reproduced end to end:

```
SCHEMA: ALLOW + constraints IS VALID -> the path is reachable
RESPONSE decision = ALLOW | response.constraints = {'max_value': {...}, 'rate_limit_per_hour': 5}
ADR_Record constraints = None
```

The `ADR_Record` schema is closed and has no `constraints` property, so `repository.py:120` is
unconditionally `None`. **The first call returns populated constraints; the idempotent replay of the
same `request_id` returns `None`.** That breaches T-019's contract as well, and it re-opens F-1's
original hazard — a field that reads as a control and binds nothing — through a different door.

**Disposition:** T-016 returns to `READY`, narrowly scoped. T-019 is *not* re-opened; the same
change-set closes it.

### F-12 · MEDIUM · Rule 6 is unmet across the entire stage
`benchmarks/results/` does not exist. [`chain_verifier.py:132`](../../benchmarks/chain_verifier.py#L132)
prints to stdout and nothing else — no host description, no commit SHA, no file. CODEX's
"100k-record chain verification: 6.7463 seconds" is therefore exactly the terminal-only performance
claim rule 6 was written to prohibit after R-004 §0 could not reproduce the sequencer figure. An
independent run here measured 6.4798 s — consistent, which is the point: neither number is recorded.

**Disposition:** new task T-029. This is a global rule violation, not a task defect, so no Stage-2
row is re-opened for it.

**Stage-2 disposition:** T-017, T-018, T-020, T-021, T-022 → `DONE`. T-016 → `READY` (F-11).
T-019 → held in `REVIEW`, released to `DONE` when T-016 lands.

---

## 2. The strategic argument — what is the human's call, and what is not

The brief's thesis is a market-entry sequencing argument: enter through the evidence plane
(out-of-band, append-only, low procurement bar) rather than the control plane (inline, fail-closed,
highest procurement bar), and use the customer's own coverage data to manufacture demand for the
gateway later.

**The argument is well-constructed and its central observation is correct and important:**

> Evidence produced by the control plane, stored in the control plane's database, verifiable only by
> logging into the control plane, is testimony from a party to the dispute.

That sentence is the most valuable thing in the document, and §7 of this review is downstream of it.

**Three things about the argument are the human owner's decision, not CODEX's, and not mine:**

1. **Buyer and sequencing.** Whether to lead with the evidence plane, to whom, and on what timeline
   is a founder decision with no technical answer. It is filed as a note, not a blocker, because
   nothing in the engineering work order below depends on how it resolves.
2. **The brief's own kill-metric.** §03 reports that of eleven incidents scored, evidence would have
   changed the outcome in **1 of 11**, and changed only the speed and cost of proving what happened
   in 8 of 11. The brief is to be commended for leading with that rather than burying it. It is also
   a material qualifier on the whole thesis, and it belongs in front of the owner before any
   sequencing decision — not after.
3. **The four falsification tests in §08** (nobody runs the verifier; the record is never asked for;
   the security review passes without it; the only excited room is internal audit) are well-posed and
   cheap to accept now. Recommend adopting them verbatim as written commitments.

**One part of the strategic argument is rejected outright — see R-5 in §3.** The brief's "explicitly
not in these ninety days" list (policy engine, authorization gateway, sidecar, permission graph,
blast-radius scoring, multi-agent governance) is written for a team that has not built them. Mizan
has built them, tested them, and just carried them through a seven-commit remediation under an
independent validation regime. Applied literally, that advice discards verified working assets.

The correct inversion is stronger than the brief's own case: **because the control plane is already
built, the evidence plane is now the short remaining path to a defensible artifact, not an
alternative to it.** Six tasks, none of them large, stand between this repository and an evidence
record that survives a hostile party holding the database.

---

## 3. What the brief gets wrong about Mizan — rejected, with evidence

These are recorded so they are not re-litigated in a later session.

**R-1 · The "Verbatim" transfer column is a costing error.** Seven of fifteen rows in §03's inventory
are marked *"Verbatim"* or *"Verbatim + one state"*. The source is Rust; Mizan is Python
(`uv`, `ruff`, `pytest`, `psycopg`). There is no verbatim. Every line count in that table is a
**reimplementation** estimate, not a transfer credit, and the headline "roughly 9,500 lines of the
evidence plane already exist" does not shorten Mizan's path by 9,500 lines. The *designs* transfer;
the code does not. Discount the entire table accordingly.

**R-2 · Porting `evidence/canonical.rs` would be a downgrade.** Mizan already canonicalises with
`rfc8785` — RFC 8785 JSON Canonicalization Scheme, a published IETF standard with off-the-shelf
implementations in every language an auditor might use. The brief's stated requirement is *"a digest
a third party recomputes by hand must land on the same bytes in their language, not yours."* A
published standard satisfies that strictly better than 268 lines of hand-rolled canonicaliser.
**Reject; keep `rfc8785`.**

**R-3 · The payload boundary is already closed, and more tightly than the brief proposes.** §05's
"keep exactly one thing from the ZK work" — ingest hashes and policy-relevant fields only, never
payloads — is described as *"a week-one architecture decision… not retrofittable."* It was ratified
at T-001 as **ADR-006**, implemented at T-013, and is enforced by I-17, I-25, and SPEC_v1.md:1173
(*"Raw arguments are excluded from persisted context/evidence and policy evaluation"*), with a
scalars-only, allowlisted, versioned projection capped at 64 fields. **Already done. No action.**

**R-4 · The OpenAPI drift test is superseded.** T-021 delivered four blocking drift gates
(Draft 2020-12 meta-schema, I-16 typed IDs, SPEC-string reachability, closed-schema producibility),
each with a committed negative fixture proven to fail, plus `validate_contract_coverage.py`. The
brief's single route-set derivation test is a subset. **Reject the port.**

**R-5 · The sequencing advice is moot and, taken literally, destructive.** See §2.

**R-6 · Volume tiering (04.1) rests on a premise not established for Mizan.** The brief argues you
cannot sign and anchor every record synchronously and proposes tiering by risk band. But Mizan's
anchoring is *already* asynchronous and batched over checkpoints, not rows — the brief notes this
itself — so the only hot-path cost is the chain append. B-6 measured that at **2,725 transactional
allocations/second across four shards at p99 2.0087 ms** on the M3 Max development host, which
already clears the SPEC §7 target of 500–1,000 decisions/sec. The brief's own closing advice is the
right one and Mizan is already positioned to follow it: *"Measure it under a real lock; do not
assume it."*

**Disposition: do not weaken the record on an unmeasured assumption.** T-023 reruns on
deployment-class Linux and writes artifacts. If that run shows the chain append missing the p95
budget, tiering becomes a live design question and gets its own task with its own ADR. Not before.
Recorded as a deferred option, not a gap.

**R-7 · Source-repository metrics are unverified.** See §0. Do not cite.

---

## 4. What the brief gets right — findings

Everything below was confirmed against the working tree.

### F-13 · HIGH · Layer-4 external anchoring is ratified doctrine and does not exist

This is the finding. The brief's four-layer model (signed record → hash chain → signed checkpoint →
external anchor) maps onto Mizan as **three of four built and the fourth absent**, and the fourth is
the one the brief correctly identifies as *"the layer that makes the record stop being testimony."*

Mizan already has layers one through three, and they are real: Ed25519 signatures over RFC 8785
canonical bytes, a per-tenant hash chain with in-transaction sequence allocation under a chain-head
row lock (`reserve_evidence_sequence`), database triggers rejecting mutation
(`reject_evidence_mutation`), no runtime UPDATE/DELETE grants, checkpointed parallel range
verification (`verify_checkpointed_chain`), and create-only WORM-analogue object storage.

The anchor, however, is signed by Mizan's own key, generated in Mizan's own process:

```python
# evidence.py:74-75
@classmethod
def generate(cls, key_id: str = "local://evidence/dev-1") -> Ed25519EvidenceSigner:
    return cls(key_id=key_id, private_key=Ed25519PrivateKey.generate())
```

```python
# evidence.py:739-741  (OutboxPublisher.anchor)
anchor = unsigned | {"object_key": key, "object_version": object_version}
signature = self.signer.sign(anchor)
self.repository.record_anchor(tenant_id, anchor, signature)
```

Nothing outside the Mizan trust boundary attests to anything. **This contradicts two ratified
positions in the repository's own documents:**

- **I-11** (SPEC_v1.md:1526) asserts integrity *"does not rest on [append-only grants] alone —
  externally signed anchors bound the rewrite window **outside the DB administrative boundary**."*
  With an in-process ephemeral key, there is no outside. The second clause of I-11 is currently false.
- **ADR-004, Amendment B** (line 82) states it plainly and was ratified at T-001:
  > *"External anchoring moves from 'nice to have' to mandatory: without it, I-11 is only an
  > assertion about grants."*
  ADR-004:33 further specifies *"signature via KMS/HSM key."* ADR-004:36 defers RFC 3161 to
  *"consider… for enterprise tier"*, and ADR-004:58 is still an open checkbox.

**Consequence.** An insider holding database write access and the signing process rewrites history
from genesis, re-signs every record, re-signs every anchor, and every verifier in the system —
`verify_chain`, `verify_checkpointed_chain`, `ObjectEvidenceVerifier`, `/v1/audit/verify` — returns
`valid`. Both histories verify. This is precisely the residual the brief's layer-three row names, and
Mizan sits on it.

Note this is **strictly larger than B-11**. B-11 is *"keys are ephemeral, so receipts do not survive
restart"* — an availability and operability defect. F-13 is *"the attestation never left the
building"* — an evidentiary defect. Durable KMS custody fixes B-11 and does **not** fix F-13: a
durable key that Mizan controls still produces testimony from a party to the dispute.

**Split for execution.** The structural seam (T-033) requires no trust decision and proceeds now.
The choice of external attesting party is **B-12**, HUMAN-gated under H-7, and gates T-036 only.

### F-14 · HIGH · Anchors do not chain, count, or order

Independent of F-13 and fixable with no trust decision at all. The anchor payload is:

```python
# evidence.py:726-735
unsigned = {
    "anchor_id":    str(uuid4()),
    "tenant_id":    tenant_id,
    "stream_id":    stream_id,
    "from_sequence": from_sequence,
    "to_sequence":  last["sequence_number"],
    "head_hash":    last["record_hash"],
    "key_id":       self.signer.key_id,
    "anchored_at":  ...,
}
```

Three omissions, each admitting a distinct attack:

| Missing field | Attack it admits |
|---|---|
| `prev_anchor_hash` | Delete an anchor from the middle of a stream's anchor set. Nothing commits to the anchor sequence, so the gap is undetectable and the range it covered becomes unattested. |
| `anchor_number` (monotonic, per stream) | Replay a stale anchor as the current one. `anchored_at` is self-asserted by the signer and is not ordering. |
| `covered_record_count` | `from_sequence`/`to_sequence` describe an interval but nothing asserts the interval is *densely populated*. A verifier reading a short range cannot distinguish "this is all there was" from truncation. |

The brief's layer-three row names all three (`covered_row_count` kills truncation, `checkpoint_no`
kills replay, `prev_checkpoint_hash` kills mid-run removal). It is right on each.

**This is the highest-leverage task in the work order** — it is small, needs no ratification, and
every subsequent evidence claim depends on it.

### F-15 · MEDIUM-HIGH · Absence is unsigned and untyped

There is no provenance tri-state anywhere in the evidence path. A repository-wide grep for
`provenance`, `Unpopulated`, `NotApplicable`, `not_applicable`, `observed`, `declared` returns
nothing in the evidence modules — the only `not_applicable` in the tree is a redaction *scan status*
enum (`security/mizan_security/redaction.py:29`).

Consequently, in a sealed ADR_Record, **"no human approval recorded" is byte-identical across three
materially different situations**:

1. Policy did not require an approval — the correct, compliant case.
2. Policy required one and it did not happen — the finding.
3. Mizan was not in the path and cannot say — the coverage gap.

The brief's observation that this becomes *more* load-bearing for Mizan than for the source system is
correct and worth restating: Mizan will always have agents outside its path (SDK-integrated,
gateway-routed, not integrated at all), so `Unpopulated` is the common case, not the edge case. A
record that renders a coverage gap identically to an answer will be attacked on exactly that point,
and it is the cheapest possible attack.

Two constraints inherited from the brief, both sound and both to be enforced in code:

- **`NotApplicable` is never inferred.** Only a policy that explicitly declares a field out of scope
  may set it. Inferred `NotApplicable` is, in the brief's phrase, *"a lie with a signature on it."*
- **`Observed` and `Declared` must not collapse.** "The gateway saw this model id on the wire" and
  "the tenant told us this agent uses that model" are different evidence and an examiner treats them
  differently. Mizan's gateway position makes `Observed` available, which is strictly stronger than
  the source system could produce — and worth nothing if the record cannot distinguish the two.

### F-16 · MEDIUM · There is no offline verifier

`ObjectEvidenceVerifier` (evidence.py:859) requires a repository handle and a live connection pool.
`/v1/audit/verify` requires an authenticated Mizan session. `scripts/` contains four validators, all
of them CI gates against the repository — none is an auditor's tool.

There is therefore **no artifact a bank's auditor can run without a Mizan account**, which means the
system's entire evidentiary claim currently terminates in "log into our console and we will show
you." That is the objection the brief opens with, unaddressed.

A second reason to build it first, which the brief does not make and which is the stronger one:
**the offline verifier is the only forcing function that proves the export format is complete.** If
the verifier needs a field the export does not carry, the export is not evidence — and there is no
other way to discover that. Build the verifier and the export bundle together, and let the verifier
fail until the bundle is sufficient.

### F-17 · MEDIUM · Evidence-binding coverage is asserted per-policy but never enumerated

The brief's 04.3 argues the chain hashes *that a declaration was made*, not *what it said*, so a
post-hoc `UPDATE` on a mutable row changes what a sealed record means while leaving the chain
byte-identical.

**Mizan is partly ahead of this.** I-8 already pins every cited policy as
`(policy_id, version, content_hash)` with a ratified semantic hash (B-9), and I-9/I-10 bind execution
to `context_hash` and a complete binding tuple. The brief's assumption that policy versions are
unbound does not hold here.

**What has not been done is the enumeration.** No artifact in the repository states, exhaustively,
*every field an ADR_Record cites* and *which hash commits to it*. Until that list exists and is
gate-enforced, "the chain commits to what the record says" is a belief, not a property. Candidates
the brief names that warrant checking here: the tool registry's `risk_tier` and
`executor_spiffe_ids`, the agent manifest's tool list, and the approval record's approver identity
and timestamp.

One sub-point is imported verbatim because the first reviewer will propose the wrong fix: **storing a
digest in a column beside the data is not evidence**, since whoever can write `risk_tier` can write
`risk_tier_digest` in the same statement. A digest is evidence only where it lives somewhere the
writer of the data cannot reach — which, in Mizan, means inside the chain or inside an anchor.

### F-18 · LOW-MEDIUM · CI has drift gates but no anti-rot gates

Mizan's CI is strong on drift (four gates with committed negative fixtures, contract-coverage
validation, a claim-ledger gate, a coverage floor). It is missing the two properties the brief names,
both of which protect the T-021 investment rather than adding new surface:

- **"Fail if the suite got quieter."** No gate asserts the drift-gate count and adversarial-case
  count are monotonic. A gate silently deleted in a future refactor is a green build. The negative
  fixtures make this cheap: the fixture count is already a countable, committed artifact.
- **"A skipped test is green."** No gate distinguishes *ran and passed* from *skipped*. The live
  PostgreSQL suite is exactly the kind of job that silently skips when a service is unavailable, and
  `postgres-contract` is a separate CI job whose skip would not fail the build.

The brief's framing is worth keeping as a convention: **a BLOCKED row is not a pass** — it means the
capability under attack does not exist yet, and an untested surface must not read as an untouched one.

---

## 5. Contract decision requiring HUMAN ratification

### B-12 — The external attesting party (H-7: crypto / key management)

**B-11 and B-12 are one decision family and should be ratified together.** B-11 asks *where Mizan's
signing key lives*; B-12 asks *whose signature makes the record not-testimony*. Answering B-11 alone
produces a durable key that Mizan still controls, which fixes operability and leaves F-13 open.

| Option | What attests | Assessment |
|---|---|---|
| **A · RFC 3161 TSA** (DigiCert / Sectigo / GlobalSign) | A commercial timestamp authority countersigns each anchor's hash. | Standard, examiner-legible, no per-tenant integration, off the hot path (anchors batch over checkpoints, not records). Proves *when*, by a party with no stake. Already contemplated at ADR-004:36/:58. **Recommended as the floor.** |
| **B · Customer-held countersignature** | The tenant's own KMS countersigns each anchor. | The direct answer to "testimony from a party to the dispute" — the bank itself attests. Strongest evidentiary position available. Costs a per-tenant integration and a key-availability dependency. **Recommended as the enterprise tier, additive to A.** |
| **C · Public transparency log** | An append-only public log (CT-style) holds the anchor hashes. | Strong non-repudiation, no vendor. Publishes the existence and cadence of tenant activity — likely disqualifying for banking tenants without careful blinding. |
| **D · Blockchain** | — | **Already rejected** at ADR-004 option 4 (cost/latency/optics). Not reopened. |

**Recommendation: A now, B as an additive enterprise tier.** A and B together answer the brief's
opening objection completely — the TSA proves the record existed at a time Mizan could not backdate,
and the customer countersignature proves the customer saw it. Under this recommendation B-11 is
largely forced: the anchor key must be durable and externally held (KMS/HSM), which is what ADR-004:33
already specifies.

**Until B-12 ratifies:** T-033 builds the provider seam and ships a development provider. T-036 —
the real integration — stays `BLOCKED(B-12)`. No other task in this work order depends on it.

**One correction to make regardless of how B-12 resolves.** I-11's second clause currently asserts a
property the implementation does not have. Either the property is delivered or the invariant is
amended with a dated waiver naming the task that closes it. An invariant that is false in the tree is
worse than an invariant that is absent, because the drift gates will keep reporting it satisfied.
This is scoped into **T-033** as a mandatory ADR/SPEC delta under H-3.

---

## 6. Task specifications

Standing rules from R-004 §"rules" apply unchanged and in full — one commit per task, H-3 absolute,
no scope widening, every fix ships with the test that fails on the pre-fix commit, honest reporting,
and **rule 6, which F-12 shows was not honoured last stage: every performance claim writes a JSON
artifact under `benchmarks/results/` with measurement, host description, and commit SHA.**

**Recommended order: T-016 → T-029 → T-030 → T-032 → T-031 → T-033 → T-034 → T-035.**
T-030 first among the new work because everything downstream depends on the anchor being sound;
T-032 immediately after because it is the only thing that proves the export is complete.

---

### T-016 (re-opened) · Close the ALLOW-path constraints leak — `READY`
**Lane rigor:** CLAUDE · **Depends on:** — · **Priority:** HIGH — do first, it is small

**Objective.** Satisfy T-016's third acceptance criterion literally, and close the replay divergence
it causes.

**Required change.**
1. Remove the `constraints` read at `repository.py:120`. `AuthorizationResponse.constraints` is
   reconstructed from an ADR_Record that structurally cannot carry it.
2. In `service.py::_combine`, do not return `winner.constraints` for a winner whose decision is not
   `CONSTRAIN`/`REDACT`. Under ratified B-10 Option A those decisions raise `NOT_IMPLEMENTED`, so the
   returned value is `None` on every reachable path — make that structural rather than incidental.
3. **H-3 delta:** tighten the `Policy` schema's `allOf` (SPEC_v1.md:356-370) to encode the *"iff"*
   the prose already claims — add the reverse implication so `constraints` present with a decision
   outside `{CONSTRAIN, REDACT}` is a validation error. Amend ADR-002 (or the ADR that owns policy
   shape) with the delta in the same change-set.
4. Add a T-021 gate asserting that where a SPEC description says "iff", the schema encodes both
   implications. The producibility gate should have caught this class and did not; that is the
   generalisable defect.

**Do not touch** `policy_engine.py:166` — that read is legitimate. It reads `constraints` from a
**policy** document while building a `PolicyMatch`, not from an ADR_Record. Confirm you understand
this distinction before editing; conflating them is how this finding was missed the first time.

**Acceptance criteria.**
- `grep -rn "constraints" --include="*.py" control-plane/` shows no expression reading `constraints`
  from an ADR_Record document. Cite the surviving reads and say why each is legitimate.
- A test proves an ALLOW policy carrying `constraints` is now rejected at schema validation.
- A test proves first-call and idempotent-replay responses for one `request_id` are byte-identical.
- Both fail on `73c7de9` and pass on the change.

**Out of scope.** Constrained execution semantics (T-028, v1.4). Do not extend `ADR_Record`.

---

### T-029 · Benchmark artifact discipline — `READY`
**Lane rigor:** TEST · **Depends on:** — · **Priority:** HIGH — trivial, unblocks honest reporting

**Objective.** Make R-004 rule 6 mechanically true rather than aspirational.

**Required change.** Every module under `benchmarks/` writes
`benchmarks/results/<benchmark>-<commit_sha>.json` containing at minimum: the measurement(s), a host
description (CPU, core count, OS, Python version), the commit SHA, the UTC timestamp, and the
parameters the run used. Keep the existing stdout output. Add a CI step that fails if a benchmark
job produces no artifact.

**Acceptance criteria.**
- `python -m benchmarks.chain_verifier` writes a JSON artifact; `benchmarks/results/` is committed
  with at least one real run.
- CI fails when the artifact is absent — demonstrate it, in the manner of T-021's negative fixtures.
- The WORK_LOG entry cites the artifact path, not a terminal number.

**Out of scope.** Changing what the benchmarks measure, or re-running on deployment-class hardware
(that is T-023).

---

### T-030 · Anchor chaining, ordering, and density — `READY`
**Lane rigor:** CLAUDE · **Depends on:** — · **Priority:** HIGHEST of the new work

**Objective.** Close F-14 so that the anchor *set* is as tamper-evident as the record chain already is.

**Required change.** Extend the signed anchor payload with `prev_anchor_hash`, `anchor_number`
(monotonic per `(tenant_id, stream_id)`, allocated in-transaction under a lock exactly as
`reserve_evidence_sequence` allocates record sequences), and `covered_record_count`. Genesis uses the
same `"0"*64` convention as the record chain. Extend `verify_checkpointed_chain` and
`ObjectEvidenceVerifier` to verify anchor continuity, ordering, and density — not merely that each
anchor's signature is well-formed.

**H-3 delta required:** the anchor payload is a contract. Amend ADR-004 and the SPEC anchor shape in
the same change-set. Migration must be additive.

**Acceptance criteria.** Three negative fixtures, each committed and each proven to fail before the
fix and to be rejected after it:
1. An anchor removed from the middle of a stream's anchor set → verification fails, naming the gap.
2. A stale anchor presented as current → rejected on `anchor_number`.
3. A record removed from inside an anchored range → rejected on `covered_record_count`.

**Out of scope.** Who signs the anchor (F-13/B-12). This task changes *what is signed*, not *by whom*.

---

### T-031 · Provenance tri-state and the Observed/Declared qualifier — `READY`
**Lane rigor:** CLAUDE · **Depends on:** T-030 · **Priority:** HIGH

**Objective.** Close F-15 — make absence signed, typed, and non-inferable.

**Required change.** Introduce a provenance type over evidence-bearing ADR_Record fields with
exactly three states — `Recorded` / `NotApplicable` / `Unpopulated` — plus, on `Recorded`, a
mandatory `Observed | Declared` qualifier. Enforce in code that `NotApplicable` is settable **only**
from an explicit policy declaration that the field is out of scope, never by inference from a null.
Provenance is inside the signed payload, not alongside it.

**H-3 delta required:** this extends the `ADR_Record` schema — the one thing B-10 forbade for T-016.
It is permitted here because it is the task's deliberate subject, and it needs a **new ADR-010** with
Product/Architecture and Compliance framing, not merely an amendment. Draft the ADR first; if the
tri-state cannot be expressed under the closed-schema rule without widening something else, park the
task and say so rather than widening.

**Acceptance criteria.**
- A property test over generated contexts asserts every evidence-bearing field carries exactly one
  provenance state and that I-13 (representability) still holds.
- A test proves the three "no approval recorded" situations in F-15 produce three *distinguishable*
  records.
- A test proves no code path can set `NotApplicable` without a policy declaration — assert on the
  absence of an inference path, not merely on one example.
- Contract-coverage index updated; drift gates green.

**Out of scope.** Coverage *reporting* built on top of provenance (a later task). Produce the
substrate, not the dashboard.

---

### T-032 · Standalone offline verifier and evidence export bundle — `READY`
**Lane rigor:** CLAUDE · **Depends on:** T-030 · **Priority:** HIGH — highest external value

**Objective.** Close F-16. Produce the artifact that makes the evidentiary claim checkable by someone
who does not trust Mizan.

**Required change.** Two halves, built together:
1. **Export bundle** — a self-contained directory or archive for a `(tenant, stream, range)`:
   records, receipts, anchors, checkpoints, the public key(s), and a manifest. No database handle, no
   Mizan credential, no network dependency beyond (later) the external attestation's certificate chain.
2. **`scripts/verify_evidence_export.py`** — a standalone verifier over that bundle. It must import
   nothing from `mizan_control_plane`. Dependencies limited to the standard library plus `rfc8785`
   and `cryptography`, both pinned and named in a one-line install instruction at the top of the file.
   Output must be legible to a non-engineer: what verified, what did not, and what the bundle did not
   cover.

**Design constraint that determines the order of work.** Write the verifier against the *desired*
guarantees and let it fail; then extend the export until it passes. Do not derive the verifier from
whatever the export happens to contain — that produces a verifier that certifies its own input.

**Acceptance criteria.**
- The verifier runs in a clean virtualenv containing only its two declared dependencies, against a
  bundle on disk, with no network and no database. Demonstrate this in CI as a distinct job.
- Tampering fixtures: mutate one record byte, drop one receipt, remove one anchor, swap two records
  — each rejected with a specific, human-readable reason.
- The verifier reports what it **cannot** attest — currently, that the anchor signature is Mizan's own
  (F-13). It must say so in its output, in plain language, until T-036 lands. A verifier that implies
  more assurance than exists is worse than none.

**Out of scope.** A UI. External attestation verification (T-036 extends this script).

---

### T-033 · `AnchorProvider` seam and the I-11 correction — `READY`
**Lane rigor:** CLAUDE · **Depends on:** T-030 · **Priority:** MEDIUM-HIGH

**Objective.** Build everything about F-13 that does **not** require B-12, and stop the repository
asserting an invariant it does not satisfy.

**Required change.**
1. Introduce an `AnchorProvider` Protocol — `attest(anchor_payload) -> ExternalAttestation` — with
   the provider selected by config key. Ship exactly one implementation now: a development provider
   that returns a clearly-labelled `unattested` result. It must **not** be silently substitutable for
   a real one; an unattested anchor is marked as such in its own payload and surfaced by the T-032
   verifier.
2. **H-3 delta — mandatory.** Amend I-11 and ADR-004 so the tree stops asserting external anchoring
   as an achieved property. Either restate the invariant as conditional on a configured provider, or
   attach a dated waiver naming T-036. Do not delete it. Add the config key to SPEC §8.

**Acceptance criteria.**
- A test proves the development provider cannot be mistaken for an attesting one: an anchor it
  produces is reported as unattested by the T-032 verifier.
- The reachability drift gate (T-021) passes against the amended I-11 text — that gate is the reason
  this correction cannot be skipped.
- No behavioural change to anchor content beyond the attestation field.

**Out of scope.** Any real provider integration (T-036). Key custody (B-11).

---

### T-034 · Evidence-binding coverage enumeration — `READY`
**Lane rigor:** CLAUDE · **Depends on:** T-031 · **Priority:** MEDIUM

**Objective.** Close F-17 by converting a belief into a gate.

**Required change.** Produce `docs/contracts/EVIDENCE_BINDING_INDEX.md`: for **every field an
ADR_Record cites**, the hash that commits to it and where that hash lives. Then close whatever the
enumeration finds unbound. Check at minimum the tool registry's `risk_tier` and
`executor_spiffe_ids`, the agent manifest's tool list, and the approval record's approver identity
and timestamp — but the enumeration is the deliverable, not that list.

**Report the enumeration before fixing.** If it finds more than two unbound fields, park and report
rather than fixing them all in one change-set; each unbound field is its own contract question.

**Design constraint.** A digest stored in a column beside the data it commits to is **not** evidence —
whoever can write the data can write the digest in the same statement. Bind inside the chain or
inside an anchor.

**Acceptance criteria.**
- The index exists, is complete against the ADR_Record schema, and is validated by a gate in the
  manner of `validate_contract_coverage.py` — a field added to the schema without an index row fails CI.
- For each field closed: a test that mutates the underlying row post-decision and proves verification
  now fails where it previously passed.

**Out of scope.** Fields the enumeration shows are already bound (I-8 policies, I-9/I-10 execution).

---

### T-035 · CI anti-rot gates — `READY`
**Lane rigor:** TEST · **Depends on:** — · **Priority:** MEDIUM — may be done at any point

**Objective.** Close F-18. Protect the T-021 and T-024 investments from silent erosion.

**Required change.**
1. **Monotonic gate count.** A committed manifest records the expected count of drift gates and
   committed negative fixtures. CI fails when the actual count is lower. Raising it is a normal
   change-set; lowering it requires an explicit, reviewed manifest edit.
2. **Skipped is not passed.** CI fails when a declared integration gate skips rather than runs —
   specifically the `postgres-contract` job and the T-032 clean-virtualenv verifier job. Assert on
   pytest's skip count, not on the exit code.

**Acceptance criteria.** Both gates demonstrated failing on a deliberately broken fixture, in the
manner of T-021, with the fixtures committed.

**Out of scope.** Adding new adversarial cases (that is T-024).

---

### T-036 · External attestation integration — `BLOCKED(B-12)`
**Lane rigor:** CLAUDE · **Depends on:** T-033, B-12

Implements the ratified B-12 provider behind the T-033 seam, extends the T-032 verifier to validate
the external attestation offline against a pinned certificate chain, and lifts the T-033 waiver on
I-11. Specified now so the seam is built to the right shape; not startable until B-12 ratifies.

---

## 7. How this work will be validated

Identical regime to R-004 §6. Assume every claim is re-run, because the claims in the last stage
were — and two of them did not hold.

1. `make check`, lint, the full unit/property suite, and `make test-postgres`, re-run from a clean tree.
2. Every finding's cited `file:line` evidence re-checked against the commit.
3. **Each new test confirmed to fail on the named pre-fix SHA.** This was the check omitted from the
   last completion report; it will be sampled again, and the WORK_LOG must name the pre-fix SHA per task.
4. Every negative fixture in T-030, T-032, T-033 and T-035 observed failing. A gate never observed
   failing is not a gate.
5. **`benchmarks/results/` artifacts checked for host and commit SHA** — F-12 means this one is not
   a formality this time.
6. The T-032 verifier run by the reviewer, in a clean virtualenv, with the network off. If it cannot
   be run that way, T-032 is not done regardless of what its tests report.
7. Claim Ledger and WORK_LOG discipline audited across every commit; one commit per task.

---

## 8. Ratification

Requires the human owner:

- **B-12** — the external attesting party. Recommended: **Option A (RFC 3161 TSA) as the floor,
  Option B (customer countersignature) as an additive enterprise tier.** Ratifying B-12 largely
  forces **B-11** (durable KMS/HSM custody), which ADR-004:33 already specifies; ratify them together.
- **The strategic sequencing question in §2** — a founder decision, taken with the brief's own
  1-of-11 metric in view. No engineering task below depends on it.
- **The four falsification tests in §08 of the brief** — recommended for adoption verbatim, now,
  while they are cheap to accept.

Nothing else in this work order needs ratification. T-016, T-029, T-030, T-031, T-032, T-033, T-034
and T-035 are `READY` and may proceed in the recommended order.

---

## 9. Ratification recorded — 2026-08-25

The human owner ratified §8 in full. Recorded here because the work order below depends on it.

- **B-11 + B-12 ratified together**, as recommended. Custody is KMS/HSM with a published verification
  keyset and additive, never-retroactive rotation; the attesting party is **RFC 3161 timestamping as the
  mandatory floor on every production anchor**, with **customer countersignature as an additive enterprise
  tier**. Blockchain anchoring stays rejected. Full contract: **ADR-004 Amendment G**.
- **The four falsification tests adopted**, verbatim in substance, with owners and decision dates:
  `docs/product/FALSIFICATION_TESTS.md`. The brief's second founder test — *would this survive a hostile
  party who holds the database and the signing key?* — is adopted as a standing gate on the evidence plane,
  and its first honest answer is recorded there as **no**.
- **T-025 and T-036 unblock.** No task in this repository now waits on a human decision.

The strategic sequencing question in §2 remains the owner's, is unchanged by this ratification, and gates
no engineering task.

---

## 10. Stage 3 work order — additional tasks

§6 specified T-016 and T-029..T-036. Ratification activates two of those and adds four more. The four are
not scope inflation: three of them are the *evolution path ADR-004 already pre-authorised* (Options
Considered #2, "anchors become tree heads; record shape doesn't change"), and the fourth is the artifact
that makes the whole plane legible to the person it exists for.

**Full order for Stage 3:**

> **T-016 → T-029 → T-030 → T-032 → T-033 → T-025 → T-036 → T-038 → T-039 → T-031 → T-034 → T-035 →
> T-024 → T-040 → T-037 → T-026 → T-023**

The shape of that order: *make the anchor sound* (T-030), *make it checkable by a stranger* (T-032), *make
someone outside the boundary sign it* (T-033/T-025/T-036), *make a single record provable without shipping
the corpus* (T-038/T-039), then provenance, coverage, hardening, and last the artifact an auditor actually
holds (T-037). Nothing later in the list weakens anything earlier; every step is additive to the record shape.

---

### T-025 (activated) · Signing-key custody, keyset, and rotation — `READY`
**Lane rigor:** CLAUDE · **Depends on:** T-033 · **Priority:** HIGH — gates T-036

**Objective.** Implement ADR-004 **Amendment G.1** exactly. Four separately-held key roles
(`evidence-receipt`, `evidence-anchor`, `execution-token`, `degraded-grant`), a KMS/HSM-backed provider
interface, a published verification keyset, and additive rotation.

**Required change.**
1. A `KeyProvider` seam with two implementations: a KMS/HSM adapter (sign-in-place where the backend
   supports it) and a `local://` development adapter. Replace every `Ed25519PrivateKey.generate()` call
   site; `evidence.py:75` is the one R-005 named, but **enumerate them all and cite the list** — a survivor
   reintroduces the whole defect.
2. **Startup assertion:** `MIZAN_ENV=production` together with any `local://` key reference **refuses to
   start**. Not a warning, not a metric. Test it.
3. `GET /v1/audit/keys` publishes the keyset (`key_id`, algorithm, public key, `not_before`, `not_after`,
   `revoked_at`), and the same keyset is copied into every T-032 export bundle.
4. Rotation: new `key_id` for new records; **history is never re-signed**. Add a test that asserts no code
   path re-signs an existing record or anchor — assert on the absence of the capability, not on one example.

**H-3 delta:** config keys (`MIZAN_KEY_CUSTODY_MODE`, `MIZAN_ENV`, per-role key refs) into SPEC §8, plus the
`/v1/audit/keys` contract. ADR-004 Amendment G is already ratified — cite it; do not re-decide it.

**Acceptance criteria.**
- A record signed under a rotated-out key still verifies from the bundle, with the current key absent.
- A revoked key's signature verifies as *"valid signature, key revoked at T"* — not as a flat failure and
  not as a flat pass. Both flat answers are wrong and the distinction is the point.
- Production + `local://` fails startup, demonstrated by a test.

**Out of scope.** Choosing a specific cloud KMS vendor: the adapter interface plus one working
implementation and the dev adapter. Vendor selection is a deployment decision.

---

### T-036 (activated) · RFC 3161 attestation and customer countersignature — `READY`
**Lane rigor:** CLAUDE · **Depends on:** T-033, T-025 · **Priority:** HIGHEST external value

**Objective.** Implement ADR-004 **Amendment G.2**. This is the task that makes the record stop being
testimony.

**Required change.**
1. An `Rfc3161AnchorProvider` behind the T-033 seam. Request carries the SHA-256 of the canonical anchor
   payload **and nothing else** — add a test that asserts the outbound request contains no record content,
   no tenant identifier, and no payload bytes. This is a data-egress boundary; treat it like one.
2. `attestations[]` on the anchor payload per G.2 — ordered array, `{type, status, authority, obtained_at,
   evidence}`. `MIZAN_ANCHOR_TSA_ENDPOINTS` accepts multiple independent authorities.
3. Asynchronous acquisition off the hot path. A TSA outage marks `pending` and **never** blocks
   authorization. Exceeding `MIZAN_ANCHOR_ATTESTATION_MAX_PENDING_SECONDS` (900) **opens the evidence
   breaker** — the same escalation class as unpublished-evidence age, not a log line.
4. A `CustomerCountersignatureProvider` recording a customer-KMS signature over the anchor digest as an
   additional attestation entry. Additive; it never substitutes for the TSA floor.
5. Extend the T-032 verifier: validate the TSA token and its chain **offline**, against a trust root
   supplied by `--tsa-trust-anchor` or the system store. **Mizan must not ship the trust root inside its own
   bundle** — that returns the auditor to trusting Mizan. Print which root was used.
6. Lift the T-033 waiver on I-11 and restore the invariant to an unconditional claim, now true.

**Acceptance criteria.**
- A forged attestation (valid structure, wrong chain) is rejected offline, naming the reason.
- An anchor whose stream contains any `pending` attestation is **not** reported as externally anchored by
  any API, report, or verifier output. Test the negative.
- The evidence breaker opens on a simulated TSA outage exceeding the SLO; authorization stays available
  throughout. Both halves are the requirement.
- The verifier passes with the network **off**, using only bundle contents plus an operator-supplied root.

**Out of scope.** Air-gapped in-perimeter TSA deployment guidance beyond a documented prerequisite in
`docs/deployment/`. Blockchain anchoring (rejected).

---

### T-038 · Merkle inclusion proofs — caller-retained evidence — `READY`
**Lane rigor:** CLAUDE · **Depends on:** T-030, T-036 · **Priority:** HIGH — this is the differentiator

**Objective.** Take the ADR-004 Option-2 evolution path. Today, proving one decision means shipping the
range that contains it. After this task, a counterparty holds a few hundred bytes that prove their decision
was in Mizan's anchored history at a timestamped moment — **verifiable after Mizan no longer exists.**

That is the sentence the product is for. It is also the strongest possible answer to ADR-004's admitted
completeness gap: evidence that has left the building cannot be retracted by whoever holds the building.

**Required change.**
1. Each anchor gains `merkle_root` over the record hashes in its covered range, with **RFC 6962 domain
   separation** — `leaf = H(0x00 ‖ record_hash)`, `node = H(0x01 ‖ left ‖ right)`. Domain separation is not
   optional: without it a leaf and an internal node are confusable and the proof is worthless. Record the
   `merkle_algorithm` identifier in the payload.
2. `covered_record_count` (T-030) must equal the tree's leaf count, checked at construction. This is what
   makes T-030's count *cryptographic* rather than declared.
3. `GET /v1/audit/inclusion/{decision_id}` returns a self-contained proof: record hash, leaf index, audit
   path, `anchor_number`, `merkle_root`, the anchor signature, and the anchor's `attestations[]`. Designed to
   be retained by the caller, in their storage, indefinitely.
4. `verify_evidence_export.py --inclusion proof.json` verifies a proof **standalone** — no bundle, no
   database, no Mizan, no network beyond the operator's trust root.

**Design constraint.** The proof must be verifiable with the record the *caller already holds*, not one
Mizan re-serves at verification time. If the verifier has to ask Mizan for the record, Mizan can choose what
to answer and the proof proves nothing.

**H-3 delta:** anchor payload and a new endpoint. Amend ADR-004 (Amendment H) and SPEC §3/§10 in the same
change-set. Migration additive: existing anchors keep `head_hash`; new anchors carry both.

**Acceptance criteria.**
- A proof issued before an attempted rewrite still verifies against the original root, and the rewritten
  corpus fails to produce a matching root. Demonstrate both halves with a committed fixture.
- Proof size is logged in the benchmark artifact (T-029 discipline applies) and is O(log n) — assert the
  bound, do not just report the number.
- A tampered audit path, a wrong leaf index, and a proof from a different tenant are each rejected with a
  distinct, human-readable reason.

**Out of scope.** Consistency proofs between anchors (T-039). A UI.

---

### T-039 · Merkle consistency proofs — append-only across the anchor set — `READY`
**Lane rigor:** CLAUDE · **Depends on:** T-038 · **Priority:** MEDIUM-HIGH

**Objective.** T-030 makes the anchor *set* continuous by number and count. T-039 makes it continuous
*cryptographically*: prove anchor N+1's tree is an append-only extension of anchor N's, so history cannot be
rewritten between anchors even by a party that can produce both.

**Required change.** RFC 6962 consistency proofs between successive anchors of a stream, exposed on the
anchor listing and verified by `verify_evidence_export.py` across the whole anchor set of a bundle.

**Acceptance criteria.**
- A bundle in which one anchored range was rebuilt with a record altered fails consistency, naming the
  anchor pair where continuity broke.
- Verification cost stays O(log n) per anchor pair; benchmark artifact required.

**Out of scope.** Migrating existing anchors — the property begins at the first anchor carrying a root.
Say so in the verifier output rather than implying retroactive coverage.

---

### T-040 · The adversary drill — `make attack` — `READY`
**Lane rigor:** TEST · **Depends on:** T-036, T-039, T-024 · **Priority:** MEDIUM

**Objective.** One command that takes a real export bundle, runs a documented corpus of tamper classes
against it, and prints which layer caught each — **and which are not caught at all.**

This is simultaneously the most persuasive demo the product can have and its most honest document. Both
properties come from the same source: it must include the attacks that succeed.

**Required change.** `make attack` runs at minimum: rewrite-from-genesis with full re-signing; single-record
byte mutation; two records swapped; a record removed mid-range; an anchor removed mid-set; a stale anchor
replayed; a forged TSA token; a valid token over a different digest; a record dropped **before** chaining
(the known-uncaught case); an entire anchor withheld (caught only by numbering). Output is a table: attack,
layer that caught it, how, and for the uncaught ones, what would be needed.

**Acceptance criteria.**
- Every attack in the corpus is executed against a real bundle, not asserted in prose.
- The uncaught cases are present, labelled uncaught, and cross-referenced to ADR-004 G.3. **A drill that
  reports 100% caught is a broken drill** and will be rejected on review.
- Output is deterministic and committed as a fixture so a regression in coverage fails CI (composes with
  T-035's monotonic manifest).

**Out of scope.** New adversarial *unit* cases — that is T-024. This orchestrates and reports.

---

### T-037 · The auditor's artifact — verification report — `READY`
**Lane rigor:** CLAUDE · **Depends on:** T-036, T-038 · **Priority:** MEDIUM — do it last, and do it well

**Objective.** The verifier from T-032 proves things to an engineer. T-037 makes it legible to the person
who actually decides: a risk officer, an examiner, external counsel. ADR-004 asked whether a customer-side
verification CLI demos brilliantly. It does — but only if its output reads like a finding, not a stack trace.

**Required change.** `verify_evidence_export.py --report report.html` emits a single self-contained file —
no network, no external assets, no fonts fetched, plain-language throughout:

1. **The verdict**, first and in one sentence, in ordinary English.
2. **What was checked**: record count, range, anchors, timestamp authorities and their times, keys used and
   their validity windows at signing time.
3. **What this proves** — stated in the language of a dispute, not of cryptography.
4. **What this does not prove** — completeness against pre-chain drops, withheld anchors, and the classes in
   ADR-004 G.3, in the same typeface and the same prominence as the verdict. Not a footnote.
5. **How to check this yourself without Mizan** — the exact commands, the two pinned dependencies, and where
   the trust root came from.

**Design constraint.** Section 4 is the product. Every competitor's report has sections 1–3. A report that
tells an examiner exactly where its own guarantees stop is the one an examiner believes about sections 1–3.

**Acceptance criteria.**
- The report renders from a bundle with the network off and contains no external references — assert on the
  file, do not eyeball it.
- A failed verification produces a report that names what failed and where, and does **not** produce a
  document that could be mistaken for a passing one at a glance.
- A committed golden-output test over a fixed fixture, so wording changes are reviewed rather than drifting.

**Out of scope.** PDF generation, branding, an interactive UI, anything served by the control plane.
