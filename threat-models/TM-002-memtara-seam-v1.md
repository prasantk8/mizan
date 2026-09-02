# TM-002 — Mizan↔Memtara Proof Seam, Threat Model v1

**Status:** SKELETON — boundary definition for T-127; implementation gates belong to T-133..T-138

> **STALE as of 2026-09-02 — do not cite as current (recorded by T-145).** T-133–T-138 merged in PR #41
> on 2026-09-02. Everything below labelled *planned* has shipped, and §0's "Today Mizan does none of
> those things" is no longer true. §6's questions have answers in ADR-010,
> `docs/spec/EVIDENCE-BUNDLE-FORMAT.md` §2.1 and `docs/product/MODULE_LEDGER.md` — including Q2, whose
> answer is **per process, not across replicas**, which is a stated limit rather than a closed one. A
> v2 revision is owed and is SE-lane work with founder ratification, as TM-001 had. It is deliberately
> not done by editing "planned" to "shipped" in place: re-labelling a control is a claim about the
> control, and each one needs re-verifying against what actually merged.
**Date:** 2026-09-01
**Scope baseline:** Mizan `bc16436`; no Memtara verifier or proof field exists in this tree at this SHA
**Companion documents:** `threat-models/TM-001-control-plane-v1.md`,
`docs/spec/EVIDENCE-BUNDLE-FORMAT.md`, and two-product workplan WS-2 (T-133..T-138)

---

## 0. Purpose and current truth

This model fixes the boundary before the seam is built. Memtara is intended to prove one suitability
predicate on a client device; Mizan is intended to verify that proof token and use the verified result as
policy context for a recommendation tool. Today Mizan does none of those things. There is no
`x-memtara-proof` input, trusted issuer/JWKS configuration, replay set, `external_proofs[]` evidence field,
SDK carriage, or verifier support in this repository.

Accordingly, every control below is labelled **planned**. This skeleton permits design and review; it does
not permit the claim that the products are integrated. The commercial strategy's two-console limitation
remains in force until T-133..T-137 merge and T-138 updates the claims register.

---

## 1. Assets and security objective

The seam must preserve five facts without turning a signed token into unquestioned truth:

1. which Memtara issuer and verification key vouched for the proof;
2. which circuit/predicate and product identifier the proof actually covers;
3. the public verdict (`suitable=true|false`) and expiry that Mizan evaluated;
4. that one proof token cannot authorize two requests through replay or substitution; and
5. that the ADR record and exported evidence bind the same proof Mizan verified.

The objective is narrower than “prove suitability.” A completed seam can establish that Mizan verified a
token under an operator-configured trust root and applied a pinned policy to its public claims. It cannot
prove that Memtara's private inputs were truthful, that its circuit expresses the applicable regulation,
or that a human adviser gave suitable advice overall.

---

## 2. Adversaries

| ID | Capability | Goal |
|---|---|---|
| **M-A1** | Caller holds no Memtara token, or a token for another product/client/request | Obtain a recommendation that policy requires proof for |
| **M-A2** | Caller holds one valid token and can replay or race it | Reuse a favourable proof across requests or products |
| **M-A3** | Caller controls headers, SDK input and tool arguments | Substitute ISIN, predicate, circuit, verdict, issuer, or token after verification |
| **M-A4** | Compromised/hostile Memtara issuer or signing key | Mint cryptographically valid but false suitability claims |
| **M-A5** | Network position between Mizan and Memtara JWKS | Supply a keyset or stale key that makes an attacker-controlled token verify |
| **M-A6** | Cross-tenant Mizan caller | Cause one tenant to trust another tenant's issuer, key, replay slot, proof or evidence |
| **M-A7** | Hostile Mizan operator holding its database/signing key | Rewrite or omit the external-proof account while keeping Mizan evidence internally consistent |
| **M-A8** | Malformed-token sender | Exhaust parser, key lookup, signature verification, or replay storage before authorization |

---

## 3. Trust boundary

```text
 client/private suitability inputs
              │
              ▼
 ┌──── M-1 Memtara proving boundary ────┐
 │ circuit + witness → proof validation │
 │ → signed proof token                │
 └──────────────┬──────────────────────┘
                │ token (untrusted bytes in transit)
                ▼
 ┌──── M-2 Mizan token boundary ──────────────────────────────────────┐
 │ bounded parser → tenant-pinned issuer/JWKS → signature/claims     │
 │ verification → expiry + one-time jti replay claim                 │
 └──────────────┬────────────────────────────────────────────────────┘
                │ VerifiedProof (typed, allowlisted fields only)
                ▼
 ┌──── M-3 policy-input boundary ─────────────────────────────────────┐
 │ proof hash + circuit + predicate + ISIN + suitable + expiry + jti │
 │ bind to tool arguments; no raw token becomes general policy input │
 └──────────────┬────────────────────────────────────────────────────┘
                │ policy outcome and exact verified-proof commitment
                ▼
 ┌──── M-4 Mizan evidence boundary ───────────────────────────────────┐
 │ ADR_Record external_proofs[] + Memtara chain head → receipt       │
 │ → anchor → export bundle                                          │
 └──────────────┬────────────────────────────────────────────────────┘
                ▼
 ═══ M-5 independent verification boundary ═══════════════════════════
 operator-supplied Mizan roots + optional Memtara public key;
 both offline verifiers check the format and proof binding
```

Memtara is outside Mizan's trust boundary. A valid Memtara signature is authenticated input, not an Mizan
authorization. Mizan remains responsible for tenant binding, replay refusal, policy evaluation, approval,
execution capability issuance, and its own evidence.

---

## 4. Planned controls and release evidence

| Boundary | Required control | Owning task | Release evidence |
|---|---|---|---|
| M-2 | The trusted issuer/JWKS binding is operator-controlled and tenant-safe; callers cannot select it; unknown/wrong `kid`, issuer, signature or expiry fails closed | T-133 | Ported unit vectors plus adversarial wrong-key/issuer/expiry/cross-tenant cases |
| M-2 | `jti` is claimed atomically in a tenant-scoped replay set before the proof can affect a decision | T-133 | Sequential and concurrent replay refusal |
| M-2 | Parser and JWKS fetch have explicit size/time/cache bounds; a fetch failure cannot become permission | T-133 | Malformed/oversized and unavailable-JWKS fault tests |
| M-3 | Only a typed `VerifiedProof` projection reaches policy; raw token bytes never enter Cedar context | T-133/T-134 | Namespace and provenance tests |
| M-3 | `product_isin` and predicate/circuit are bound to the exact tool arguments and reference policy | T-134 | Six-row UC-2 matrix including wrong-ISIN and `suitable=false` DENY |
| M-3 | A negative proof produces a normal evidence-bearing DENY, not a parser/service error | T-134 | Approval and decline bundles differ only in decision facts |
| M-4 | ADR evidence binds issuer, proof hash, `jti`, Memtara chain head and the fields that affected policy | T-135 | Previous verifier rejects the new format; both upgraded verifiers accept it; tamper fails both |
| M-5 | Memtara verification material is operator-supplied and cannot be promoted from inside the bundle | T-135 | Offline fixture with independent trust input and missing/wrong-root refusal |
| Transport | SDK and MCP gateway carry opaque proof bytes without treating them as authority or logging them | T-136 | Gateway integration with and without the header |
| End to end | Proof → Mizan decision → approval/execution → one export → two verifier verdicts | T-137 | Clean-machine command and deterministic backup transcript |

Any implementation that changes the bundle format, a closed schema/enum, tenant isolation, or cryptographic
verification contract requires its ADR/SPEC delta and the H-7/H-3 review named by the PR protocol. This
skeleton does not pre-ratify those changes.

---

## 5. Residuals that a green seam will not close

| ID | Residual | Disposition |
|---|---|---|
| **M-R1** | A valid token proves only what the circuit and issuer assert; it does not prove source data truth, legal sufficiency, or overall advice suitability | Product/legal acceptance; state as a limitation in the security pack |
| **M-R2** | Compromise or collusion at Memtara (M-A4) can mint false but valid tokens | Customer controls issuer/key trust; key rotation/revocation and Memtara's own threat model required |
| **M-R3** | JWKS rotation, cache staleness and offline operation create availability-versus-freshness pressure | Fail closed when a policy requires proof; specify bounded overlap and staleness before T-133 ships |
| **M-R4** | A Memtara chain head copied into Mizan evidence proves consistency with that supplied head, not global completeness of Memtara history | Cross-product inclusion/consistency protocol or explicit accepted risk; T-135 must not overclaim it |
| **M-R5** | A hostile Mizan operator can omit an entire request before ADR chaining; a hostile Memtara operator can omit issuance before its chain | Same pre-chain omission class as TM-001 R-1; cannot be closed by adding two self-reported chain heads |
| **M-R6** | Carrying proof tokens in headers/SDKs can leak correlatable claims through logs, traces or support captures | Never log raw tokens; retain only the minimum bound fields/hash and test telemetry redaction |

---

## 6. Questions the implementation PRs must answer

1. What exact token format, signing algorithm, issuer/audience grammar and maximum encoded size are normative?
2. Is `jti` single-use globally, per tenant, per client, or per Mizan request, and how is an atomic claim made
   across replicas?
3. Which public fields are cryptographically inside the Memtara token, and which are independently derived?
4. What exact bytes produce `proof_hash`, and which previous verifier must reject the new bundle fixture?
5. Which Memtara key material may be supplied to an offline auditor without allowing the bundle to choose its
   own trust root?
6. What does Memtara's “chain head at issue time” prove, and what independently retained value pins it?
7. How do key rotation, revocation and compromised-key response affect already-recorded proof evidence?

Answers belong in the relevant ADR/SPEC/task PR, not silently in an implementation constant. Until then,
these are open review gates, not implied design decisions.
