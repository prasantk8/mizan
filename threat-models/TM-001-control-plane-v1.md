# TM-001 — Mizan Control Plane, Threat Model v1

**Status:** RATIFIED — founder ruling recorded for T-127 · **Date:** 2026-09-01
**Scope:** the authorization path, the evidence plane, and the boundary between them, at `bc16436`
**Companion documents:** `SPEC_v1.md` §6 (invariants), `docs/adr/` ADR-001..ADR-009,
`docs/spec/EVIDENCE-BUNDLE-FORMAT.md`, `docs/product/FALSIFICATION_TESTS.md`,
`docs/reviews/R-006` and `R-007`, and `threat-models/TM-002-memtara-seam-v1.md`

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
deployment substrate (Kubernetes, network policy, secrets injection) except for the evidence store's
retention boundary, and supply-chain integrity of Mizan's own build. The Mizan↔Memtara proof-token seam is
separately bounded in TM-002. Naming these exclusions is the point: their absence is a choice, recorded,
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
| B-2 | Control-plane outage used to force an ALLOW | MEDIUM+ fails closed; degraded-allow only LOW under a verified grant | I-7, I-21 | **Partly.** T-126 fault-injects the real policy/risk dependency reporter and proves fail-closed evidence is truthfully marked degraded. The signed LOW-risk degraded-ALLOW path is still unwired |
| B-6 | A-2 injects `"approved": true` into a namespace a policy reads | Raw envelope is never a condition input; only allowlisted versioned projections | I-17, ADR-006 | Not by this document |
| B-3 | A-6 deletes a record | Append-only grants; contiguous chain; sequence allocated in the committing transaction, so a gap is tampering rather than a rollback artefact | I-2, I-11, I-20 | Chain continuity re-verified at CP-A |
| B-4 | Parameter substitution after authorization | Token bound to the full tuple; `parameters_hash` over declared bound pointers only | I-10, I-14 | Not by this document |
| B-4 | Capability used by a different workload | Redemption requires the mTLS/SPIFFE identity to equal the registered `authorized_executor` | I-23 | Not by this document |
| B-5 | A-6 rebuilds and re-signs history from genesis | RFC 3161 attestation from outside the boundary; assurance derived per anchor from validated tokens | I-11 | **Yes — R-007 case 1.** A real token over the digest the verifier independently reconstructs, verified offline. This is the control that answers A-6, and CP-B is the first time it has been shown working |
| B-5 | A-6 forges an attestation | Token verified against a root the *verifier's operator* supplies, never shipped in the bundle | I-11, ADR-004 G.2 | **Yes — R-007 case 2.** An unrelated CA is rejected |
| B-5 | A-6 omits one anchor and calls the rest complete | Anchor chaining, monotonic numbering, covered-record counts, left-edge pinning | I-11, T-030/T-042 | Chain and edge binding re-verified at CP-A |
| B-5 | A-6 mutates a bucket object or lets the searchable database diverge from it | Production requires S3 Object Lock in COMPLIANCE mode; writes are create-only; the drain worker reconciles database receipts, object versions and dense stream membership | ADR-004 G.23, T-124 | **Yes.** The S3 gate exercises Object Lock configuration/collision refusal and the PostgreSQL gate exercises database↔bucket reconciliation |
| B-7 | A-6 ships a verifier that lies | Two independent implementations consume the normative bundle format and a differential gate requires agreement | T-032, T-059, T-062 | **Yes.** The original verifier imports no Mizan code; `verifier-two/` was written in JavaScript from the format under an implementation seal; CI compares both over the conformance corpus |
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

**Disposition proposed for ratification.** Keep open and take the question to a design partner before
claiming a cryptographic fix. R-1's business form is *"what would your examiner want that we cannot give
them?"* T-038 inclusion proofs and T-039 consistency proofs remain READY, but even together they can prove
properties of submitted history only; they cannot prove that an event was never withheld before chaining.
Owner: HUMAN.

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

**Current state at `bc16436`.** The gap remains. The redaction module is still unwired, so the repository is
not currently exposing a production audit-commitment key while pretending it has this custody. That is an
absence of the redaction control, not closure of the key contract.

**Disposition.** **T-054 is READY.** Fix: add
`audit-commitment` as a fifth `KeyRole`, route redaction through the provider, publish it in the keyset with
its `custody` field (T-053), and implement the rotation the config already promises. H-3 applies — ADR-004
delta and SPEC registration in the same change-set. Note that the key is **not** a signing key, so
`KeyProvider`'s current shape may need a `mac` capability rather than `sign`; if that turns out to be a
contract change rather than an addition, stop and file a blocker rather than widening.

### R-3 · CLOSED — the attestation worker had no production runner

**The attack.** None — this is a self-inflicted residual. `AnchorAttestationWorker` has no production caller
(R-007 V-13), so anchors are written `pending` and stay `pending`. The B-5 control that answers A-6 is
implemented, proven to work in a harness, and not running anywhere.

**Direction of failure.** Safe. Absent a runner the system under-claims: exports read `pending`, and after
T-049 a pending stream will correctly refuse to describe itself as externally anchored. The risk is not a
false claim; it is that the answer to A-6 stays theoretical.

**Closure.** T-052 added `mizan-attest-anchors` as a production runner and wired the pending-age breaker;
T-055/T-057/T-061 made retry and concurrency safe under append-only sidecar semantics. A deployment can
still misconfigure or omit the worker, but the production manifests and CI now have an enforcement point.
Closed in the model on 2026-09-01; operational availability remains covered by R-6.

### R-4 · CLOSED — development custody is labelled and export-gated

Development private keys remain deliberately derivable from `sha256(key_id)`, so a development bundle is
still forgeable by every recipient. The difference is now enforced rather than implied: key documents carry
`custody`, both verifiers print the exact development-custody warning, production refuses the local
provider, and export refuses development custody unless an operator supplies an explicit named reason that
is logged and carried in the bundle.

**Closure.** T-053 and T-065 close the false-claim path; T-102 supplies the production Vault Transit backend
with non-exportable Ed25519 keys reported as `custody=kms`. An override bundle remains forgeable and says so;
that is an explicit development artifact, not production evidence. Closed in the model on 2026-09-01.

### R-5 · The record can be cryptographically perfect and factually wrong

Every control in §3 establishes that the record was not altered *after* it was written. None establishes that
it was *right* when written. A policy bug, a mis-mapped projection, or a corrupted risk input produces an
ADR_Record that chains, verifies, timestamps, and misstates what the system actually decided — and it will
survive every check in this tree, forever, with a signature on it.

This is the premise of the proposed Stage 4 (`docs/product/STAGE-4-DECISION-REPLAY.md`), and F-T-5 is already
written against it, before the work, per the rule at the top of the falsification file. Note the honest
framing there: recomputation may be an engineering aesthetic rather than a buying criterion, in which case
the replay engine is cut and the trusted-input ledger kept.

**Disposition.** Still open. T-044 remains PROPOSED; T-045 remains blocked on B-13. The shipped UI provides
policy *simulation*, not historical decision replay, and must not be cited as closing this residual.

### R-6 · A-7 — the timestamp authority is a trusted third party, and trust was the problem

RFC 3161 moves the trust from Mizan to a TSA. That is a large improvement and not an elimination. A
compromised or colluding authority can issue a token bearing any time it likes, and the verifier — correctly
— will accept it under the root the operator supplied.

Partially mitigated by design and implementation: ADR-004 G.2 supports **multiple independent authorities**,
trust roots come from the verifier's operator rather than the bundle, T-049 makes the weakest pending
authority control stream assurance, and T-056 committed offline fixtures minted by two organisations Mizan
does not control (FreeTSA and Sectigo). Those fixtures establish interoperability, not availability or
independence forever.

**Disposition.** The reporting and interoperability findings are closed. The residual remains accepted by
architecture: assurance is only as strong as the operator's chosen roots and authorities; a colluding or
compromised TSA can lie about time, and an outage keeps anchors pending and opens the evidence breaker. The
operator should configure independent authorities and monitor the breaker. Owner: Security/Operations.

### R-7 · Infrastructure dependencies are only partly modelled

ADR-005 states that policy caches and Kafka topics are as leak-prone as the database. Neither external
Redis nor Kafka exists in the shipped tree: policy compilation uses an in-process content-addressed cache,
and evidence leaves through the transactional outbox/drain worker without a broker. Those external attack
paths become real only if those dependencies are introduced.

The object-store path now exists and is partly covered here: production starts only against an S3-compatible
bucket with Object Lock enabled, writes are conditional/create-only in COMPLIANCE mode, and T-124 reconciles
database receipts against exact bucket objects before anchoring. This answers silent overwrite and
database↔bucket divergence. It does not model credential theft, read-side tenant isolation, denial of
service, retention-policy administration, or the deployment network around the bucket.

**Disposition proposed for ratification.** Keep the remaining infrastructure threats explicit in TM-001
until a deployment-substrate model is opened. Do **not** put them in TM-002: that identifier now belongs to
the Mizan↔Memtara seam, and mixing an unshipped broker with a cross-product proof protocol would leave both
boundaries harder to review. Owner: Security/Platform.

---

## 5. What would change these answers

| If this happens | Then |
|---|---|
| The operator configures at least two independently trusted TSAs and monitors pending age | R-6 is reduced; compromise of one authority need not collapse the time claim |
| The attestation runner or evidence drain is absent/unhealthy | R-3 stays closed as an implementation gap, but the deployment is not permitted to claim externally anchored evidence |
| An export uses the explicit development-custody override | R-4 stays closed as a false-claim path only because the bundle and both verifiers label it forgeable; it is not production evidence |
| T-054 lands | R-2 closes |
| A design partner answers R-1's business form | R-1 becomes a task or a recorded accepted risk — either is progress; leaving it open is not |
| Redis, Kafka, or another shared delivery/cache substrate is introduced | R-7 requires a dedicated infrastructure/deployment threat model before production use |
| The Mizan↔Memtara seam begins implementation | TM-002's draft threats become release gates for T-133..T-138 |
| F-T-1 fails (fewer than three of fifteen auditors run the verifier themselves) | B-7 is decoration and this entire model is aimed at a boundary nobody crosses |

## 6. Ratification

**Founder ruling — 2026-09-01:** ratified T-127 items 1/2/3 as recommended.

1. **A-8 remains in the v1 adversary set.** Compelled or selective disclosure is in scope.
2. **R-1 remains open.** Take the examiner/business question to a design partner before choosing a build
   response. T-038/T-039 are partial submitted-history controls and are not proof against pre-chain omission.
3. **The shipped object-store boundary and remaining infrastructure residual stay in TM-001.** TM-002 is
   reserved for the Mizan↔Memtara seam; unshipped Redis/Kafka are not mixed into it.

This dated decision ratifies the refreshed model. The open residuals remain explicit engineering or product
work; ratification records their accepted disposition and does not claim that they are closed.
