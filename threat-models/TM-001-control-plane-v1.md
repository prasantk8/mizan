# TM-001 — Mizan Control Plane, Threat Model v1

**Status:** DRAFT — CLAUDE lane, awaiting HUMAN ratification (T-027) · **Date:** 2026-08-26
**Scope:** the authorization path, the evidence plane, and the boundary between them, at `724f7a8`
**Companion documents:** `SPEC_v1.md` §6 (invariants), `docs/adr/` ADR-001..ADR-009,
`docs/product/FALSIFICATION_TESTS.md`, `docs/reviews/R-006` and `R-007`

---

## 0. What this document is, and what it is not

Most threat models are inventories of what a system defends against. Read alone they are unfalsifiable: every
control is listed, every control is present, the conclusion is that the system is secure.

This one is organised the other way round. §3 is the control map and it is deliberately terse, because SPEC
§6 already states the invariants and CP-A and CP-B already re-ran them. **§4 is the document** — the residual
register: what a competent adversary still achieves after every control in this tree works exactly as
designed. A reader who has ten minutes should read §4 and skip the rest.

Two consequences of writing it this way.

First, it produces work. §4 R-2 is a defect this document found while being written, not one carried in from
a review, and it is queued as T-054.

Second, it will be wrong in places, and the correction path matters more than the initial accuracy. Every row
in §4 carries an owner and a disposition. A residual that is argued away without being recorded as argued
away is the failure mode this file exists to prevent — the same rule that governs
`docs/product/FALSIFICATION_TESTS.md`.

**Not in scope for v1:** the operator console (ADR-009) beyond its read-model boundary, the SDKs, the UI, the
deployment substrate (Kubernetes, network policy, secrets injection), and supply-chain integrity of Mizan's
own build. Each deserves its own model. Naming them here is the point: their absence is a choice, recorded,
rather than an oversight.

---

## 1. Adversaries

Capability is stated as what the adversary *holds*, not as a persona. A model that reasons about "a
sophisticated attacker" cannot be checked; one that reasons about "holds the runtime database credential"
can.

| ID | Adversary | Holds | Wants |
|---|---|---|---|
| **A-1** | Compromised agent | Valid agent credentials, its own registered tool set | To act beyond its authorization, or to act with no ADR at all |
| **A-2** | Compromised tool / MCP server | The response channel back into evaluation | To influence a decision by what it returns (OWASP Agentic AI #8, confused deputy) |
| **A-3** | Malicious principal | Legitimate human identity, delegation authority | To use an agent as laundering for an action they may not take directly |
| **A-4** | Cross-tenant attacker | A valid tenant of the same deployment | Any object belonging to another tenant |
| **A-5** | Network position | Traffic interception between Mizan and its dependencies | To alter a decision, a token, or an attestation in flight |
| **A-6** | **Hostile Mizan operator or insider** | **The runtime database, the object store, and the signing keys** | **To rewrite history after the fact, and have it verify** |
| **A-7** | Compromised timestamp authority | The TSA's signing key | To backdate or forward-date an anchor, or to deny service to the evidence plane |
| **A-8** | Compelled Mizan | Legal process, full production access, and a motive to comply | Selective disclosure: to hand an examiner a bundle that is complete-looking and incomplete |

**A-6 is the adversary this product exists for**, and it is why the evidence plane is held to the second
founder test — *would this survive a hostile party who holds the database and the signing key?* — rather than
to the ordinary standard applied to registries, dashboards, and caches, which are allowed to be trusted.

**A-8 is the adversary the tree currently addresses least well.** See §4 R-1.

---

## 2. Trust boundaries

```
      A-3 principal                    A-1 agent            A-2 tool / MCP server
           │                              │                          │
           ▼                              ▼                          ▼
   ┌───────────────────────── B-1 authentication (ADR-001) ─────────────────────────┐
   │  federated JWT, ≤5 min TTL, local JWKS; mTLS/SPIFFE for workload identity      │
   └───────────────────┬───────────────────────────────────┬───────────────────────┘
                       ▼                                   ▼
              B-2 evaluation input                 B-6 foreign payload (ADR-006)
              EvaluationContext + §3.1             allowlisted versioned projection;
              enrichment; policies pinned          raw envelope never an input
              (policy_id, version, content_hash)
                       │                                   │
                       └──────────────┬────────────────────┘
                                      ▼
                         ┌─────── B-3 decision ───────┐
                         │  ADR_Record, hash-chained  │      ← A-6 is INSIDE this line
                         │  sequence allocated in-txn │
                         └─────────────┬──────────────┘
                                       ▼
              B-4 execution (ADR-008)          B-5 evidence plane (ADR-004 Amd. G)
              single-use token → lease;        receipts → object store → anchors →
              bound tuple; executor pinned     RFC 3161 attestation → export bundle
                                                             │
                                                             ▼
                                              ═══ B-7 the only boundary A-6 cannot cross ═══
                                              the standalone verifier, an operator-supplied
                                              trust root, and a third party's own machine
```

Everything above B-7 is testimony. B-7 is the only line in the architecture where the party producing the
evidence stops being the party attesting to it, which is why CP-B was a checkpoint at all and why it is
currently held (R-007).

---

## 3. Control map

Terse by design. Each row: the threat, the control that addresses it, and **whether this document watched it
work** — not whether SPEC says it should.

| Boundary | Threat | Control | Invariant | Independently exercised? |
|---|---|---|---|---|
| B-1 | A-1 replays a stolen token | ≤5 min TTL, DPoP/mTLS binding, local JWKS | ADR-001 | Not by this document |
| B-1 | A-4 asserts another tenant in the payload | Tenant comes from the token, never the body; RLS forced | I-3 | Not by this document; RLS forced on the attestation sidecar was confirmed at CP-B |
| B-2 | A-1 acts with no decision | No ADR → no action | I-1 | Not by this document |
| B-2 | Policy substituted after the fact | Every cited policy pinned `(id, version, content_hash)`, ACTIVE at evaluation | I-8 | Not by this document |
| B-2 | A-3 self-approves | `APPROVED` requires non-null `approver ≠ author`, schema-enforced | §5.4, I-6 | Not by this document |
| B-2 | Control-plane outage used to force an ALLOW | MEDIUM+ fails closed; degraded-allow only LOW under a verified grant | I-7, I-21 | Not by this document |
| B-6 | A-2 injects `"approved": true` into a namespace a policy reads | Raw envelope is never a condition input; only allowlisted versioned projections | I-17, ADR-006 | Not by this document |
| B-3 | A-6 deletes a record | Append-only grants; contiguous chain; sequence allocated in the committing transaction, so a gap is tampering rather than a rollback artefact | I-2, I-11, I-20 | Chain continuity re-verified at CP-A |
| B-4 | Parameter substitution after authorization | Token bound to the full tuple; `parameters_hash` over declared bound pointers only | I-10, I-14 | Not by this document |
| B-4 | Capability used by a different workload | Redemption requires the mTLS/SPIFFE identity to equal the registered `authorized_executor` | I-23 | Not by this document |
| B-5 | A-6 rebuilds and re-signs history from genesis | RFC 3161 attestation from outside the boundary; assurance derived per anchor from validated tokens | I-11 | **Yes — R-007 case 1.** A real token over the digest the verifier independently reconstructs, verified offline. This is the control that answers A-6, and CP-B is the first time it has been shown working |
| B-5 | A-6 forges an attestation | Token verified against a root the *verifier's operator* supplies, never shipped in the bundle | I-11, ADR-004 G.2 | **Yes — R-007 case 2.** An unrelated CA is rejected |
| B-5 | A-6 omits one anchor and calls the rest complete | Anchor chaining, monotonic numbering, covered-record counts, left-edge pinning | I-11, T-030/T-042 | Chain and edge binding re-verified at CP-A |
| B-7 | A-6 ships a verifier that lies | The verifier imports no Mizan code and needs two pinned dependencies | T-032 | **Yes — re-verified at CP-B** with `mizan_control_plane` asserted unimportable |
| B-5 | PII recovered from an audit commitment by dictionary attack | Pre-redaction commitment is HMAC-SHA256 under a separately held key, never a bare hash | I-12, I-18 | **No — and see §4 R-2** |

Rows marked *not by this document* are asserted by SPEC and by the unit and property suites. They are not
weaker for being unsampled; they are simply not yet independently re-run, and this file should not imply
otherwise. CP-C and CP-D are the scheduled opportunities.

---

## 4. Residual risk register

What a competent adversary still achieves after every control above works exactly as designed.

### R-1 · Selective disclosure — A-8, and the largest residual in the tree

**The attack.** Mizan is compelled, or chooses, to hand an examiner a bundle covering a range that excludes
the decisions in question. Every record in it chains, every receipt verifies, every anchor is timestamped by
an independent authority, and the standalone verifier returns PASS. The bundle is *internally* perfect and
*externally* incomplete, and nothing in it says so.

**Why the current controls do not reach it.** They all establish integrity *within* a presented range. The
verifier says this itself, in its own output, which is to the repository's credit:

```
NOT COVERED: Records omitted before chaining and an entire final anchor withheld
before export leave no proof in this bundle.
```

Two variants, and they are not equally hard:

- **Withheld final anchor** — tractable. An examiner who learns the anchor number and timestamp of the
  *latest* anchor from an independent source (a published head, a counterparty's retained inclusion proof
  under T-038, a periodic head digest lodged elsewhere) can detect a truncated export. The anchor chain is
  already monotonic and counted; the missing ingredient is an out-of-band head that Mizan does not control.
- **Pre-chain omission** — a decision the control plane declines to record at all. Nothing downstream of the
  chain can see it, because it never entered the chain. I-1 says no tool executes without an ADR, but the
  adversary here holds the control plane; the invariant binds the honest implementation, not the compelled
  one. **This is not closable by cryptography inside Mizan.** The only real answers are external: an executor
  that refuses to act without a verifiable capability whose issuance is itself independently anchored, or a
  counterparty-side record, or accepting the residual and saying so.

**Disposition.** Open. Not currently a task. **This is the right question to take to a design partner before
building anything for it** — R-1's business form is *"what would your examiner want that we cannot give
them?"* and the answer determines whether T-038 inclusion proofs are the fix or a partial one. Owner: HUMAN.

### R-2 · The audit commitment key has a contract and no custody — **new, found by this document**

**The gap.** ADR-004 defines `source_commitment` as HMAC-SHA256 over the pre-redaction payload under a
rotated key, *"held under separate authority."* SPEC §8 registers `MIZAN_AUDIT_HMAC_KEY_REF` and
`MIZAN_AUDIT_HMAC_KEY_ROTATION_DAYS`. `security/mizan_security/redaction.py` computes the HMAC correctly.

But Amendment G.1's ratified `KeyProvider` has exactly **four** roles — `evidence-receipt`,
`evidence-anchor`, `execution-token`, `degraded-grant` — and `keys.py:65` enforces that set literally:
`if roles != set(KEY_ROLES): raise RuntimeError(...)`. The audit commitment key is **not one of them**. It
therefore has:

- no `KeyProvider` adapter, so no KMS/HSM path and no sign-in-place guarantee;
- no startup refusal of development custody, which G.1 gives the other four;
- no presence in the published `/v1/audit/keys` keyset, so a verifier cannot tell which key version a
  commitment cites, nor that it was rotated, nor that it was revoked;
- no implemented rotation, despite a registered rotation interval.

**Why it matters.** I-12 exists because low-entropy PII — an account number, a national ID, a name — is
recoverable from a bare hash by dictionary attack in seconds. The HMAC is what stops that, and the HMAC is
only as good as the key's custody. A key with no custody story, held wherever the deployment happens to put
it, is the weakest link in a chain whose other four links were hardened at a checkpoint specifically about
key custody. G.1's own stated rationale applies unchanged: *"a single key serving two roles means one
compromise"* — and a fifth key serving a real role outside the provider means one uncovered compromise.

**Disposition.** Queued as **T-054**, CODEX lane, after the CP-B blockers. Fix: add
`audit-commitment` as a fifth `KeyRole`, route redaction through the provider, publish it in the keyset with
its `custody` field (T-053), and implement the rotation the config already promises. H-3 applies — ADR-004
delta and SPEC registration in the same change-set. Note that the key is **not** a signing key, so
`KeyProvider`'s current shape may need a `mac` capability rather than `sign`; if that turns out to be a
contract change rather than an addition, stop and file a blocker rather than widening.

### R-3 · No deployed Mizan can currently finalise an attested anchor

**The attack.** None — this is a self-inflicted residual. `AnchorAttestationWorker` has no production caller
(R-007 V-13), so anchors are written `pending` and stay `pending`. The B-5 control that answers A-6 is
implemented, proven to work in a harness, and not running anywhere.

**Direction of failure.** Safe. Absent a runner the system under-claims: exports read `pending`, and after
T-049 a pending stream will correctly refuse to describe itself as externally anchored. The risk is not a
false claim; it is that the answer to A-6 stays theoretical.

**Disposition.** T-052.

### R-4 · Development bundles are forgeable by whoever receives them

Development private keys are `Ed25519PrivateKey.from_private_bytes(sha256(key_id))` and the `key_id` ships
inside `keys.json` in every bundle (R-007 V-9). Any recipient of a development or staging bundle can
reconstruct the signing key and produce a convincing forgery — and the bundle does not warn them.

**Operational consequence, effective immediately and not contingent on T-053:** no bundle leaves the building
until T-053 lands. That is a process control, and this document is where it is written down.

**Disposition.** T-053.

### R-5 · The record can be cryptographically perfect and factually wrong

Every control in §3 establishes that the record was not altered *after* it was written. None establishes that
it was *right* when written. A policy bug, a mis-mapped projection, or a corrupted risk input produces an
ADR_Record that chains, verifies, timestamps, and misstates what the system actually decided — and it will
survive every check in this tree, forever, with a signature on it.

This is the premise of the proposed Stage 4 (`docs/product/STAGE-4-DECISION-REPLAY.md`), and F-T-5 is already
written against it, before the work, per the rule at the top of the falsification file. Note the honest
framing there: recomputation may be an engineering aesthetic rather than a buying criterion, in which case
the replay engine is cut and the trusted-input ledger kept.

**Disposition.** T-044 (PROPOSED). Blocked on nothing; T-045 blocked on B-13.

### R-6 · A-7 — the timestamp authority is a trusted third party, and trust was the problem

RFC 3161 moves the trust from Mizan to a TSA. That is a large improvement and not an elimination. A
compromised or colluding authority can issue a token bearing any time it likes, and the verifier — correctly
— will accept it under the root the operator supplied.

Partially mitigated by design: ADR-004 G.2 supports **multiple independent authorities**, and trust roots are
supplied by the verifier's operator rather than shipped by Mizan, so the examiner chooses whom to believe.
The residual is that this is only as strong as the operator's configuration, and V-11 currently means a
mixed-authority stream is reported as fully covered — which is exactly the defence against A-7 collapsing
silently. **T-049 is therefore an A-7 control, not only a reporting fix.**

Also unexercised: no real-authority network interoperability anywhere in the tree. CODEX used a local TSA and
said so; R-007 did the same and said so. A public TSA behaves differently — policy OIDs, accuracy fields,
certificate chains, rate limits, availability. Worth one deliberate test before any customer-facing claim.

**Disposition.** T-049 for the reporting half. Real-TSA interoperability: unqueued; propose folding into
T-051's CI work, where an attested bundle is already being added.

### R-7 · Redis, Kafka, and the object store are named but unmodelled

ADR-005 states that policy caches and Kafka topics are as leak-prone as the database, and namespaces them
per tenant. This document does not model the cache-poisoning path (A-4 or A-6 writing a policy decision into
another tenant's cache namespace) or the object-store path (A-6 with write access to the WORM bucket before
retention locks apply). Both are plausible and neither is analysed here.

**Disposition.** Named as out of scope for v1 so the omission is a decision on the record. Should be TM-002.

---

## 5. What would change these answers

| If this happens | Then |
|---|---|
| T-049 and T-050 land and CP-B passes | R-6's reporting half closes; the second founder test gets its first conditional yes, for finalised anchors under an independently trusted token |
| T-052 lands | R-3 closes and the answer to A-6 stops being theoretical |
| T-053 lands | R-4 closes and the delivery hold lifts |
| T-054 lands | R-2 closes |
| A design partner answers R-1's business form | R-1 becomes a task or a recorded accepted risk — either is progress; leaving it open is not |
| F-T-1 fails (fewer than three of fifteen auditors run the verifier themselves) | B-7 is decoration and this entire model is aimed at a boundary nobody crosses |

## 6. Ratification

This is a CLAUDE-lane draft. T-027 is a HUMAN-lane task and the lane discipline in H-4 is not waived by the
draft existing.

The owner is asked to ratify three things specifically, because each is a judgement rather than an
engineering fact:

1. **The adversary list, particularly A-8.** If compelled selective disclosure is not in scope for v1, say so
   explicitly and R-1 becomes a recorded accepted risk rather than an open question. Either answer is fine.
   Silence is not.
2. **R-1's disposition.** Whether to take its business form to a design partner before building, or to
   commit to inclusion proofs (T-038) as the answer now.
3. **R-7's deferral.** Whether Redis, Kafka, and the object store wait for TM-002 or belong in v1.

Ratify by amending this section with the date and the decisions, the way R-005 §8 was ratified. Do not ratify
by silence, and do not ratify by approving a document nobody disagreed with — a threat model that produced no
argument produced no information.
