# The governed private stack — reference architecture

**Owner:** Product, with Security · **Task:** T-145 (`docs/handoff/PRIVATE-STACK-POSITIONING-WORKPLAN.md`, WS-P1)
**Issued:** 2026-09-02 · **Baseline:** `main` @ `cf143e0`
**Companion documents:** `threat-models/TM-003-model-endpoint-boundary-v1.md` (the boundary this note
introduces), `../marketing/CLAIMS-REGISTER.md` (every claim below traces to a row or a CI job),
`MODULE_LEDGER.md` (what is shipped), `../spec/EVIDENCE-BUNDLE-FORMAT.md`.

**The rule of this note.** Every present-tense sentence about what the system does cites either a
claims-register row or a CI job that fails if it stops being true. Sentences about what it *will* do
name their task and are written in the future tense. If you find a present-tense claim here with
neither citation, it is a defect in this file — report it rather than repeating it.

---

## 1. The shape, in one sentence

> The customer's model, running on the customer's hardware, drives an agent whose every consequential
> action is decided before it executes by a control plane the customer also runs — and every one of
> those decisions leaves a record an outsider can verify without asking either of them.

Three parties appear in that sentence and only two of them are software we ship. **The model is not
ours.** That is the architecture, not a limitation of it: see §5.

## 2. The diagram

```text
   ┌─────────────────────────── CUSTOMER PERIMETER ────────────────────────────┐
   │                                                                            │
   │  ┌─── B-1 model boundary ──────────┐                                       │
   │  │  the customer's model endpoint  │   Not ours. No Mizan code runs here,  │
   │  │  (OpenAI-compatible; llama.cpp, │   and no Mizan component opens a      │
   │  │   vLLM, or a hosted account)    │   connection to it — see §5 and TM-003│
   │  └──────────────┬──────────────────┘                                       │
   │                 │ the model proposes a tool call                           │
   │                 ▼                                                          │
   │  ┌─── B-2 agent / MCP boundary ────────────────────────────────────────┐   │
   │  │  the customer's agent + `integrations/mcp/mizan_mcp_gateway`        │   │
   │  │  Untrusted by design: it states what it wants to do, and is not     │   │
   │  │  believed. It carries the Memtara proof header opaquely (UC-2).     │   │
   │  └──────────────┬──────────────────────────────────────────────────────┘   │
   │                 │ POST /v1/authorize — a request, never a permission       │
   │                 ▼                                                          │
   │  ┌─── B-3 control-plane boundary ──────────────────────────────────────┐   │
   │  │  identity (`auth.py`, JWKS + `kid` routing)                         │   │
   │  │  enrichment, fail-closed (`service.py`)                             │   │
   │  │  policy evaluation (`policy_engine.py`, Cedar)                      │   │
   │  │  human authority (`approval.py`, epochs, four-eyes)                 │   │
   │  │  exact-request execution (`execution.py`, one-use tokens, leases)   │   │
   │  │       ↑ UC-2 only: `proofs/memtara.py` verifies a third party's     │   │
   │  │         signed attestation before any of its claims reach policy    │   │
   │  └──────────────┬──────────────────────────────────────────────────────┘   │
   │                 │ ADR_Record — written before the action, not after        │
   │                 ▼                                                          │
   │  ┌─── B-4 evidence boundary ───────────────────────────────────────────┐   │
   │  │  hash-chained records → receipts → signed anchors → export bundle   │   │
   │  │  PostgreSQL, forced RLS, mutation refused at the storage layer      │   │
   │  │  object store with Object Lock (write-once)                         │   │
   │  └──────────────┬──────────────────────────────────────────────────────┘   │
   │                 │                                                          │
   └─────────────────┼──────────────────────────────────────────────────────────┘
                     │
      three outbound connections, each to an endpoint the operator names:
                     │
        ┌────────────┼────────────────┬──────────────────────────┐
        ▼            ▼                ▼                          ▼
   customer's    timestamp      Memtara JWKS URL          (nothing else)
     Vault       authority        — UC-2 only —
   `vault_transit.py`  `attestation.py`   `proofs/memtara.py`
        │            │                │
        └────────────┴────────────────┴──► none of these is operated by Mizan
                                            the company. There is no telemetry
                                            endpoint, and none is planned.

                     ┌──────────── OUTSIDE EVERYONE'S PERIMETER ────────────┐
                     │  the auditor, holding only the exported bundle and   │
                     │  a trust root they obtained themselves               │
                     │    `scripts/verify_evidence_export.py`  (Python)     │
                     │    `verifier-two/`                      (Node)       │
                     │  Two implementations, written independently. Neither │
                     │  contacts Mizan, and neither can be made to pass by  │
                     │  a bundle that chooses its own trust root.           │
                     └──────────────────────────────────────────────────────┘
```

## 3. What each component claims — and the gate that would fail

| Component | The claim | Cited by |
|---|---|---|
| **B-2 gateway** | It forwards; it does not decide. A tool call reaches `/v1/authorize` before it reaches the tool, and the gateway performs exactly one operation on a Memtara proof — an `isinstance` string check. It never parses, logs or forwards it upstream | Register §1 row *"Your MCP client and our SDK carry the proof without either of them being able to read it"* · `python-contract` |
| **B-3 identity** | The verification keyset rotates with `kid` routing and a bounded overlap; a token signed by a retired key is refused after the window | T-122 · `python-contract` adversarial tests |
| **B-3 policy** | The decision is deterministic and taken **before** execution, not observed after it. `ALLOW` / `DENY` / `REQUIRE_APPROVAL`, evaluated against a pinned policy version whose semantic hash excludes only lifecycle fields | `python-contract`, `baseline-contract` |
| **B-3 approval** | An approval binds to one exact request. A changed argument invalidates it rather than carrying forward | `python-contract`, the approval-epoch fuzzer |
| **B-3 execution** | Authority to execute is one-use and short-lived, redeemed by compare-and-swap, bound to the executor | `python-contract`, `adversarial-fault-injection` |
| **B-3 Memtara** *(UC-2 only)* | Mizan verifies the third party's signature itself against a **deployment-pinned** issuer and JWKS. A caller cannot choose the trust root, and a self-asserted `mapped.source == "memtara"` projection is stripped before evaluation | Register §1, first three rows · ADR-010 · `python-contract` |
| **B-4 evidence** | Mutation is refused by the storage layer, not by application code: `UPDATE`/`DELETE` on an evidence table raises SQLSTATE 55000, and the object store holds the segment write-once | T-104, T-124 · `postgres-contract`, `evidence-object-lock` |
| **B-4 anchors** | Anchors are externally timestamped under RFC 3161 over a digest the verifier independently reconstructs — the timestamp authority sees that digest and nothing else | ADR-004 G.2 · `offline-evidence-verifier` |
| **The auditor's copy** | Two independently written verifiers agree, or CI fails. The second was written from the specification under a seal (T-062) and is never edited to match the first | `offline-evidence-verifier`, `scripts/compare_verifiers.py` |

**One honest caveat on the whole table.** Verification establishes that the record is intact,
externally timestamped, and consistent with what Mizan recorded. It does not establish that Mizan
recorded everything: a hostile operator can omit a request *before* it enters the chain. That residual
is TM-001 R-1 and TM-002 M-R5, it is open, and adding chain heads does not close it. Anyone presenting
this architecture should be able to say that sentence unprompted.

## 4. Why "private" is precise here

Deployment privacy is architectural, not a configuration setting: there is **no Mizan-operated service
in any path above**, so there is nothing to opt out of. Concretely —

* Mizan the company operates nothing in the diagram. There is no control plane we host, no telemetry
  endpoint, no licence check, no usage beacon.
* The three outbound connections in the diagram are the complete set, each to an endpoint the operator
  configures: Vault (`vault_transit.py`), a timestamp authority (`attestation.py`), and — for UC-2
  only — the Memtara JWKS URL (`proofs/memtara.py`).
* The offline verifiers contact nothing at all. That is deliberate: F-T-1 counts by hand precisely
  because the verifier must never phone home.

**Two things this does not yet mean, and saying either would be an overclaim.**

1. **No gate asserts the absence of an outbound connection.** The three above are what the code shows;
   nothing in CI fails if a fourth appears. That assertion is **T-144's** to add, and until it exists
   the claim rests on reading the code. The claims register §4 says the same in the same words.
2. **"Private" here means deployment, not data.** The DLP redaction path is unwired at *both* ends —
   `security/mizan_security/redaction.py` has no production caller, and neither does
   `EvidenceRepository.append_audit`, the method that enforces the redaction attestation. **T-146**
   decides wire-or-delete. Until it does, do not extend the word to data minimisation.

## 5. What Mizan does not do

Explicit, because the positioning sentence under evaluation contains the word "AI" and that word
invites four wrong assumptions:

| We do not | What that means concretely |
|---|---|
| **Supply, host, tune or resell a model** | There is no model client anywhere in `control-plane/`. Not "not yet" — a founder ruling of 2026-09-02 makes it permanent. The catalogue's *What we do not sell* table carries the customer-facing form |
| **Sit in the inference path** | Mizan never sees a prompt or a completion. It sees a *tool call* — the action the agent wants to take — after the model has already produced it. Latency on inference is unaffected because Mizan is not on that path at all |
| **See training data, or any inference telemetry** | Nothing in the diagram flows from B-1 to B-3. The model endpoint and the control plane never speak |
| **Evaluate whether the model was right** | Mizan decides whether the *action* is permitted, by policy, before it happens. A well-reasoned action that policy forbids is denied; a poorly-reasoned action that policy permits is allowed and recorded. This is a deliberate boundary, not a gap — the alternative is a product whose correctness depends on judging a model's judgement |
| **Prove a fact about the world** | Even in UC-2, Mizan proves that *Memtara attested* suitability and that Mizan verified that attestation under an operator-pinned trust root. It asserts no suitability fact of its own (ADR-010, register §3) |
| **Certify anything** | No regulator has reviewed this. The security pack maps controls; it does not certify them |

The fourth row is the one worth rehearsing, because a prospect will ask it as *"so does it stop the AI
doing something stupid?"* The answer is: it stops the AI doing something **you have not permitted**,
before it happens, and it proves afterwards what was permitted and by whom. Those are different
sentences, and only the second one is a product.

## 6. What is not built yet

Stated here so the note cannot be read as a description of a finished system.

| Gap | Task | What it changes about this note |
|---|---|---|
| No recording of the whole stack running end to end | **T-144** | §1's sentence becomes a nightly CI artifact rather than a description. Adds the egress assertion §4 says is missing |
| Data privacy unresolved | **T-146** | Either §4's second caveat is deleted or the redaction module is |
| Enterprise-grade unproven | **T-129–T-132** | Install by a stranger, restore drill, production end-to-end gate, OIDC. Draft PR #40; conflicting with `main` at the time of writing |
| The Memtara half of UC-2 | **M-01, M-04** | "One record, both chain heads" is half-true today: Mizan's half verifies; Memtara's chain head is recorded but unauthenticated |
| The model boundary has no threat model | **TM-003** | Opened by this task as a skeleton, not a model. It has no ratified residuals yet |
