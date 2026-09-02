# Decision record — the two-product pilot (2026-08-31)

**Decided by:** Founder, on the technical due-diligence triage of 2026-08-31
**Scope:** every business, marketing and product document in this repository
**Status:** In force. Supersedes any pitch, deck or plan describing a three-product "Trust Stack" bundle.
**Evidence:** direct code inspection of `mizan @ 837f934`, `memtara-zkp @ c2f4360` (branch `evidence-v1`),
`aihoots-e1-audit-gateway @ 5dae4e6`; triage report revision 2 (artifact link in the engagement transcript).

---

## 1. The decision

> Ship the current **Mizan + Memtara** integration as a **two-product proof-of-concept pilot**. Abandon the
> three-product bundle. Fold AIHOOTS's role into Mizan's evidence export.

Mizan is the product. Memtara is a scoped proof module that makes one regulated use case — advised-sales
suitability — materially better than Mizan alone. AIHOOTS is not sold, not demonstrated and not named in
customer material.

## 2. What the code said

| Repository | Readiness | One-line reason |
|---|---:|---|
| Mizan | **6.5 / 10** | Real, fail-closed, DB-enforced immutability, Vault Transit custody, Object Lock, RFC 3161, two independent offline verifiers, adversarial CI. Unwired to either sibling. |
| Memtara | **4 / 10** | Genuine ZKP with no mock path and an adversarial harness — for **one** circuit (`wealth_suitability`). Toolchain is `curl \| bash` beta binaries, no container, no arm64, vault crate is placeholder, the last 18 commits have never run in CI. |
| AIHOOTS | **1 / 10** | A five-day prototype: SHA-256-linked JSON appended to a plain file. Rewrite, truncate or empty the log and its own verifier reports INTACT. No auth, no signatures, no anchoring. Its function already exists, done properly, in Mizan. |
| "Trust Stack" as pitched | **3 / 10** | Memtara→AIHOOTS and Memtara→PDF seams are real and CI-gated. Mizan→Memtara and Mizan→AIHOOTS do not exist. Three hash chains, zero cross-anchoring. |

## 3. What changes in how we sell

1. **One transaction, two products.** The pitch is Mizan's control loop; Memtara enters only where a
   client-side proof is the policy input (suitability). The proof is verified by Mizan, gates the decision,
   and lands in one cross-anchored evidence bundle. Until that seam ships (workplan WS-2) the two products
   are demonstrated as two consoles and described that way.
2. **No bundle price.** The USD 200k three-product figure is retired. Pricing bands live in
   `MIZAN-COMMERCIAL-STRATEGY.md` §6 and are hypotheses to test, not a rate card.
3. **The moat we can defend is evidence engineering, not cryptographic novelty.** Three senior bank
   engineers reproduce Mizan's happy path in six months and Memtara's circuits in 6–10 weeks. What they do
   not reproduce quickly is the fail-closed discipline, dual verifiers, adversarial CI and a regulator-facing
   evidence apparatus. That is what we price.

## 4. Claims withdrawn — do not use in any channel

- "18-month ZKP head start" (the honest figure is 6–10 weeks to parity).
- "Tamper-evident AIHOOTS", "AIHOOTS audit chain", and any AIHOOTS governance metric ("0% → 12%").
- "Memtara is CBUAE-ready" or any regulatory-readiness claim for either product.
- Any Memtara metric not reproduced in this tree (existing rule, `FALSIFICATION_TESTS.md` note).
- "Delegated leases" / "approve once, run for 30 days". The feature does not exist; the word *lease* in
  Mizan means the opposite (a single-decision, minutes-long execution grant).
- Any suitability claim for Memtara circuits other than `wealth_suitability`; the other four have only
  `should_fail` fixtures.

## 5. Facts that moved since the docs were written (2026-08-30 → 2026-08-31)

| Gate the strategy called open | Status now | Evidence |
|---|---|---|
| Production key custody | **Closed** — Vault Transit backend | `control-plane/mizan_control_plane/vault_transit.py`, CI job `vault-transit` (T-102) |
| Durable evidence store | **Closed** — S3 Object Lock COMPLIANCE | `runtime.py:99-105` `S3ObjectLockStore`, CI job `evidence-object-lock` (T-104) |
| Production mode never boots | **Closed** | CI job `production-boot` (T-101) |
| Storage-layer immutability | **Closed** | `REVOKE UPDATE/DELETE` + `BEFORE UPDATE OR DELETE` triggers, migration 0001 |
| IdP/OIDC login and step-up | Open | console still pastes a bearer JWT |
| Clean-machine install, restore drill, stranger walkthrough | Open | `INSTALL.md`, `CP-F-WALKTHROUGH.md` absent |
| Identity-key rotation | Open (new) | one static PEM, `auth.py:35`; rotation = outage |
| `compose.production.yaml` boots | Open (new) | never sets the S3 store production requires |
| CVE allowlist | **Expires 2026-09-03** | `infra/supply-chain/.trivyignore.yaml`, 13 exceptions |
| UI copy truth | Open | `ui/index.html:10,13,31` still say "Production control plane", "without blind spots", "Independent integrity check" |

## 6. Where the consequences are written down

- Sellable use cases → `docs/business/MIZAN-USE-CASE-CATALOGUE.md`
- Engineering tasks, roles and sequencing → `docs/handoff/TWO-PRODUCT-PILOT-WORKPLAN.md`
- Commercial plan → `docs/business/MIZAN-COMMERCIAL-STRATEGY.md` (revised 2026-08-31)
- Public narrative and content → `docs/product/MIZAN-NARRATIVE-EXPERIENCE-PRD.md`, `docs/marketing/*`
- Claim truth → `docs/product/MODULE_LEDGER.md` (cross-product section added), `FALSIFICATION_TESTS.md` F-T-6

## 7. Two cautions that stay in the record

All three codebases are between five days and two weeks old, single-author, built at AI-agent velocity with
zero production hours. Memtara's most important recent work (`evidence-v1`) has never run in CI. Neither
fact is a reason not to sell a pilot; both are reasons the word "pilot" must stay attached to everything
we say until a design partner has run traffic.
