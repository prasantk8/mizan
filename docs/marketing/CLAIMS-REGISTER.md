# Claims register

**Owner:** Product Marketing · **Engineering signatory:** Tech Lead · **Issued:** 2026-09-02
**Last amended:** 2026-09-02 (T-141 — positioning hypothesis added as §4)

**Scope.** Two parts, and they are not equal.

* **Part A (§1–§3) — the Mizan↔Memtara seam** (workplan T-133–T-138). Cleared for use today.
  Claims about Mizan's control plane, evidence plane and deployment posture live in
  `docs/product/MODULE_LEDGER.md` and are not restated here.
* **Part B (§4) — the private-stack positioning hypothesis** (workplan T-141). **Not cleared for any
  external use.** It is registered before the work so that the words are auditable while they are
  still cheap to withdraw.

The commercial strategy's §11 review must be able to answer *"which product claim was challenged and
what evidence supports it"* by naming a CI job. That is the only purpose of this file. A sentence is
sayable when a gate fails if it stops being true — not when someone believes it.

**How to use it.** Say the sentence in the left column, in that form. If a prospect challenges it,
show the gate. If you want to say something not in this table, it is not cleared; ask the Tech Lead
rather than paraphrasing a neighbouring row.

---

---

# Part A — the seam (cleared)

## 1. Cleared — the seam

| Marketing may say | What actually backs it | Gate |
|---|---|---|
| "Mizan verifies the Memtara proof token itself. It does not take the client's word for it." | Ed25519 JWS verified against Memtara's JWKS; issuer and JWKS URL are deployment-pinned and cannot be chosen by a caller or a token. A token signed by the wrong key, carrying the wrong `kid`, declaring `alg: none` or `HS256`, expired, or from another issuer is refused. | `python-contract` — `tests/unit/test_memtara_proof.py` |
| "A caller cannot claim to hold a proof it does not have." | A request that self-asserts the reserved `mapped.source == "memtara"` projection has it stripped before evaluation, so it cannot satisfy the suitability policy without a verified token. | `python-contract` — `tests/unit/test_app_routes.py` |
| "The recommendation tool cannot run without a suitability proof for that exact product." | The reference policy `policies/reference/require_suitability_proof.json` permits the tool only when the attested `suitable` is `true` **and** the attested `product_isin` equals the tool argument, via the `eq_field` operator. | `python-contract` — `tests/unit/test_policy_engine.py` |
| "A decline is evidenced exactly as completely as an approval." | A verified `suitable=false` token produces a normal `DENY` with reason `suitability_declined` and an ADR record of the same shape as the approval path — not an error, not a dropped request. | `python-contract` — `tests/unit/test_authorization.py` |
| "The bank never holds the client's income figures — only a proof that suitability was assessed." | Only the seven verified claims (`proof_hash`, `circuit`, `predicate`, `product_isin`, `suitable`, `expires_at`, `jti`) reach policy. Memtara's underlying financial inputs never enter Mizan. | `python-contract` — `tests/unit/test_memtara_proof.py` asserts the projection by whole-dict equality, so an added field fails |
| "One evidence bundle carries both the Mizan decision and the Memtara attestation, and an auditor verifies it offline with either of two independent verifiers." | `external_proofs[]` is inside the hashed ADR body, so it is committed by `record_hash`, the receipt and the anchor. Both verifiers check the grammar, and — given Memtara's public keyset as a trust root — the signature and the claim binding. | `offline-evidence-verifier` |
| "The proof token itself is retained, so the signature can be re-checked years later." | The compact JWS is a required member of `external_proofs[]`. A hash alone could never be signature-verified after the fact. | `offline-evidence-verifier`; format rule in `docs/spec/EVIDENCE-BUNDLE-FORMAT.md` §2.1 |
| "Your MCP client and our SDK carry the proof without either of them being able to read it." | The gateway performs exactly one operation on the token — an `isinstance` string check — and never parses, logs, or forwards it upstream. The SDK places it on a header only, never in the JSON context; tests assert that negative. | `python-contract` — `tests/unit/test_sdk.py`, `tests/unit/test_mcp_gateway.py` |
| "The whole journey runs as one command, and we have a deterministic transcript for when the demo gods are unkind." | `make demo-memtara` runs Memtara's own reference prover, then Mizan authorize → approve → execute → export → both verifiers. The committed transcript is a recording of a real journey, re-derived and compared on every CI run. | `python-contract` — `tests/unit/test_demo_memtara_walk.py` |

## 2. Cleared only with the qualifier attached

Say the whole cell, including the second sentence. Dropping the qualifier makes the claim false.

| Marketing may say | Why the qualifier is load-bearing |
|---|---|
| "A proof cannot be replayed. Replay is refused per process today; deployment-wide replay refusal across multiple workers or replicas is not yet claimed." | `JtiReplaySet` is an in-memory set. Under more than one process the same `jti` is claimable once per process. Saying "cannot be replayed" flatly is untrue in any real deployment. |
| "The bundle records which Memtara chain head Mizan relied on. It does not by itself authenticate that head or prove Memtara's history is complete — that needs a Memtara checkpoint alongside it." | Current Memtara tokens do not sign `memtara_chain_head`. Mizan's record hash commits it, which proves what Mizan recorded, not what Memtara's log contains. Closing this is M-04. |
| "An invalid or expired proof cannot authorize the recommendation. An **expired** one is refused at the verifier with a 403 and no decision record, so it is a refusal rather than an evidenced decline." | Expiry is checked inside the proof verifier, before the authorization service. Only a *verified* `suitable=false` produces the evidenced DENY. Saying "every refusal is evidenced" is false on that path. |
| "The reference policy is the suitability gate. Your ordinary read and approval policies still decide who may read a profile and what pauses above a desk limit." | `policies/reference/require_suitability_proof.json` matches only the recommendation tool and has no amount condition. Implying it delivers the whole decision matrix oversells one file. |
| "This is a Technical Preview of the seam. It is not bank-pilot-ready." | Tier B (T-129–T-132: install walkthrough, restore drill, full-journey production gate, OIDC) is not merged, and Memtara's own packaging (M-01–M-06) is not done. |

## 3. Forbidden — do not say these

| Do not say | Why |
|---|---|
| "Zero-knowledge suitability, fully productionised" / "bank-pilot-ready" | Tier B gates are open; Memtara has no multi-arch container and its `evidence-v1` work is not merged (M-01, M-02). |
| "Regulator-approved" / "CBUAE-certified" / "compliant" | No regulator has reviewed anything. The security pack maps controls; it does not certify. |
| "Tamper-proof" | The property is tamper-**evident**: mutation is detected, not prevented. This is exactly the overclaim the AIHOOTS retirement was about — never reintroduce it. |
| "Mizan proves the client is suitable" | Mizan proves *Memtara attested* suitability and that Mizan verified that attestation. Mizan asserts no suitability fact of its own and must never be positioned as doing so (ADR-010). |
| "Memtara keys rotate without downtime" | The keyset is fetched once and not refreshed; a Memtara rotation is an outage until Mizan restarts. |
| "Approve once, run for thirty days" (standing/delegated approval) | No such capability exists; `ExecutionLease` is the opposite. Founder-gated as T-139. |
| Any mention of AIHOOTS as a shipping component | Retired; it is not a product (decision record §1). |

---

# Part B — the positioning hypothesis (not cleared)

## 4. The sentence, per word

> **HYPOTHESIS — 2026-09-02.** *"Enterprise-grade, private, auditable AI for firms that can't afford
> to get it wrong."*

The architecture the sentence describes, with the trust boundaries and the explicit *what Mizan does
not do* list, is `docs/product/GOVERNED-PRIVATE-STACK.md` (T-145). Read it before using any row below
in a conversation — it is where each word's limit is argued rather than merely stated.

**This sentence has no cleared external use.** It is under evaluation by
`docs/handoff/PRIVATE-STACK-POSITIONING-WORKPLAN.md`, tested by **F-T-7**, and ruled on by **T-149**
on **2026-10-31** as Adopt / Adapt / Abandon. Three separate gates stand in front of it, and *all
three* must clear before any part of it is said in public:

1. **T-142 trademark ruling.** No public use of the sentence before counsel rules on the Mizan AI
   (DIFC) collision. Internal codename only until then (risk R-1).
2. **Per-word status below.** A word whose row says *not sayable* is not sayable inside the sentence
   either. Truncating the sentence to its sayable words is permitted; implying the rest is not.
3. **T-149 itself.** Adoption is a founder ruling in writing, not the absence of an objection.

| Word | What it is permitted to mean **today** | Status | Gate that would fail if it stopped being true |
|---|---|---|---|
| **Auditable** | An auditor recomputes the decision record offline, with either of two independently written verifiers, against an externally timestamped anchor and write-once storage. | **Cleared** — this is the only word of the four that is | `offline-evidence-verifier`, `evidence-object-lock`, `adversarial-fault-injection` |
| **Enterprise-grade** | Nothing yet. | **Not sayable** until Tier B (T-129–T-132) merges: clean-machine install performed by a stranger, restore drill, full-journey production gate, OIDC with step-up. Draft PR #40 is open, not merged | Will be `production-e2e` and the walkthrough document; neither exists today |
| **Private** | *Deployment* privacy only: Mizan runs inside the customer's own perimeter, and it reports nothing to Mizan the company. Its only outbound connections are to three endpoints the operator configures — the customer's Vault, the customer's chosen timestamp authority, and the Memtara JWKS URL. None is a Mizan-operated service, and there is no telemetry, no phone-home and no inference path of any kind. | **Cleared for deployment privacy, with the qualifier in §5. Not sayable about data.** | `deployment-manifests`, `production-boot`, `vault-transit`. Nothing today asserts the *absence* of an outbound connection — that assertion is T-144's, and until it exists this row rests on reading the code, not on a gate |
| **AI** | Only as the object of the sentence, never the subject: the customer's own model, governed by Mizan. Mizan supplies no model, hosts none, tunes none, and sees no inference telemetry. | **Not sayable until T-144** makes it a recording rather than an assertion. Even then it is *governed* AI, and the "we are not a model provider" answer travels with it | Will be `private-stack-demo` (nightly); does not exist today |

**The load-bearing sentence for the whole row set:** three of the four words are promises about work
that has not merged. Registering them now is not clearing them. If this table is ever read as
permission, it has failed at its only job.

## 5. What moves each row — and what does not

| Row | The only thing that moves it | What explicitly does not move it |
|---|---|---|
| Enterprise-grade | T-129–T-132 merged and green | A successful demo; a prospect saying it feels enterprise-grade |
| Private (to include data) | **T-146** — `security/mizan_security/redaction.py` wired into evidence export with adversarial tests proving redacted fields are absent while the chain still verifies, or deleted. See the finding below | Deployment privacy being real. They are different claims and the sentence does not distinguish them, which is precisely why the qualifier is mandatory |
| AI | T-144's nightly `private-stack-demo`, transcript reproduced by CI from a clean tree | A model running on a laptop during a call |
| The whole sentence | T-142's ruling **and** T-149's | Time passing without an objection |

> **Finding, recorded 2026-09-02 while registering the "private" row (T-141).** The workplan describes
> `security/mizan_security/redaction.py` as "229 lines, zero production callers". That is true and it
> understates the gap. `EvidenceRepository.append_audit`
> (`control-plane/mizan_control_plane/evidence.py:453`) — the method that *enforces* the DLP
> attestation, the payload-hash commitment and the redaction manifest, failing closed with 503 on each
> — has no production caller either. Its only caller in the tree is
> `tests/integration/test_authorize_postgres.py`. So the redaction path is not merely unwired at the
> producing end; the consuming end is unreached too, and **T-146's wire-or-delete decision is larger
> than one module.** Until it is taken, "private" means deployment and nothing else.

## 6. Maintenance

Every PR that changes a row's backing code must change this file in the same change-set, exactly as
`MODULE_LEDGER.md` requires. A claim whose gate is deleted is withdrawn the same day — the failure
mode this file exists to prevent is a sentence that outlives its evidence.

For Part B there is a second rule, because its rows have no gates yet: **a HYPOTHESIS row is
withdrawn or promoted on its decision date, never renewed by silence.** On 2026-10-31, T-149 either
promotes these rows into Part A with their gates named, rewrites them for the Adapt fallback
(*"auditable AI operations"*), or deletes them. A row still marked HYPOTHESIS after that date is a
defect in this file.
