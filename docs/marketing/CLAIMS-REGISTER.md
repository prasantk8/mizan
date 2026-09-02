# Claims register — the Mizan↔Memtara seam (UC-2)

**Owner:** Product Marketing · **Engineering signatory:** Tech Lead · **Issued:** 2026-09-02
**Scope:** the two-product seam only (workplan T-133–T-138). Claims about Mizan's control plane,
evidence plane and deployment posture live in `docs/product/MODULE_LEDGER.md` and are not restated
here.

The commercial strategy's §11 review must be able to answer *"which product claim was challenged and
what evidence supports it"* by naming a CI job. That is the only purpose of this file. A sentence is
sayable when a gate fails if it stops being true — not when someone believes it.

**How to use it.** Say the sentence in the left column, in that form. If a prospect challenges it,
show the gate. If you want to say something not in this table, it is not cleared; ask the Tech Lead
rather than paraphrasing a neighbouring row.

---

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

## 4. Maintenance

Every PR that changes a row's backing code must change this file in the same change-set, exactly as
`MODULE_LEDGER.md` requires. A claim whose gate is deleted is withdrawn the same day — the failure
mode this file exists to prevent is a sentence that outlives its evidence.
