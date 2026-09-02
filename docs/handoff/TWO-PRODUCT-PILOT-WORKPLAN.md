# Two-product pilot — engineering workplan, roles and tasks

**Read first:** `docs/business/DECISION-2026-08-31-TWO-PRODUCT-PILOT.md`, then `docs/handoff/PR-PROTOCOL.md`.
**Issued:** 2026-08-31 · **Owner:** Tech Lead · **Horizon:** six working weeks from staffing
**Commercial consumer:** `docs/business/MIZAN-USE-CASE-CATALOGUE.md` (every task names the use case it unlocks)
**Repositories:** `mizan` (this tree, task IDs `T-1xx`), `memtara-zkp` (task IDs `M-xx`), `aihoots-e1-audit-gateway` (`A-xx`)

The standing rules do not change: one task, one branch, one PR, CI is the arbiter, the completion report
is the PR body. Nothing here is "done" because a laptop said so.

---

## 0. What this workplan delivers, in one sentence

> A bank's SRE installs Mizan from a written guide; an adviser's copilot cannot recommend a structured
> product without a Memtara suitability proof that Mizan verified; a supervisor approves the exact order
> once; and the bank's internal auditor verifies **one** cross-anchored evidence bundle offline — with
> every step a CI gate.

Two tiers, so the founder can choose where to stop:

| Tier | What it buys | Man-days | Tasks |
|---|---|---:|---|
| **A — Two-product PoC** (the diligence scope) | Everything the triage report priced: Mizan hardening list + the Mizan↔Memtara seam + Memtara pilot-grade toolchain | **≈ 70–90** | WS-0, WS-1a, WS-2, WS-3, WS-4 |
| **B — Bank-pilot-ready** (the commercial strategy's §2 gates on top) | Adds IdP/OIDC login and step-up, written install + stranger walkthrough, restore drill, one full-journey production E2E gate | **≈ 95–125** | Tier A + WS-1b |

Tier A is what a design partner needs to *test*. Tier B is what they need to *run*. Do not call anything
"pilot-ready" before Tier B; do not delay the first design-partner conversation for it.

---

## 1. Roles

Roles, not names. One person can hold two roles; no task may have zero. Suggested staffing: four
engineers plus the tech lead for six weeks.

| Role | Owns | Repos | Default reviewer for |
|---|---|---|---|
| **TL — Tech Lead** | Sequencing, claim sign-off to Product Marketing, merge order, the weekly truth review's engineering line | all | every PR that changes the spec, bundle format or a closed enum |
| **CP — Control-plane engineer** (Python / FastAPI / Cedar / psycopg) | `control-plane/`, policy, auth, SDK, MCP gateway | mizan | CP tasks |
| **EV — Evidence engineer** (hash chains, RFC 3161, Object Lock, both verifiers) | `evidence*.py`, `scripts/verify_evidence_export.py`, `verifier-two/`, `docs/spec/EVIDENCE-BUNDLE-FORMAT.md` | mizan, memtara (bundle side) | anything that touches a bundle field |
| **ZK — ZKP / Rust engineer** (axum, Noir, Barretenberg) | `memtara-zkp` backend, circuits, container, CI | memtara | M tasks |
| **PS — Platform / SRE** (CI, containers, Helm/compose, Vault, MinIO/S3, Postgres) | `.github/workflows`, `infra/`, `deploy/`, install and restore | mizan, memtara | WS-0, packaging, drills |
| **SE — Security engineer** | Threat model, key rotation design, rate limiting, CVE triage, adversarial tests | all | auth, custody, anything fail-closed |
| **FE — Console engineer** | `ui/` truth corrections, approval view, IdP login | mizan | UI tasks |
| **PO — Product owner** | Acceptance against the use-case catalogue; module-ledger and claims-register updates on every merge | docs | claim wording |

RACI shorthand in each task: **R** does the work, **A** signs the PR, **C** must be consulted before the
PR opens.

---

## 2. Workstreams and tasks

Estimates are man-days for one engineer of the named role, excluding review. "Unlocks" names the
catalogue use case or claim that becomes sayable when the task merges.

### WS-0 · Urgent hygiene — this week, before anything else

| ID | Task | R / A / C | Days | Acceptance (CI or artifact) | Unlocks |
|---|---|---|---:|---|---|
| **T-120** | Re-triage the 13 CVE allowlist exceptions in `infra/supply-chain/.trivyignore.yaml` before they expire **2026-09-03**; renew only with a dated justification per entry, upgrade where a fix exists | SE / TL / PS | 1 | `production-image` job green on 2026-09-04 with zero silent expiries | Keeps every other claim's CI green |
| **T-121** | Make `compose.production.yaml` boot: set the S3 evidence store and every other production-required setting; extend `deployment-manifests` validator to launch it | PS / TL / CP | 1–2 | `deployment-manifests` job boots the compose file and hits `/readyz` | "There is a supported production compose path" |

### WS-1a · Mizan hardening — the diligence list

| ID | Task | R / A / C | Days | Acceptance | Unlocks |
|---|---|---|---:|---|---|
| **T-122** | Identity-token key rotation: `/.well-known/jwks.json`-style keyset for the identity verification key, `kid` routing in `auth.py`, overlap window, rotation runbook. Today `auth.py:35` loads one static PEM; rotation is an outage | SE / TL / CP | 6–8 | New adversarial test: token signed with retired `kid` refused after overlap; rotation drill documented and run in CI | Pilot operability; UC-1..UC-6 |
| **T-123** | Wire the nine Postgres integration test files that never run in PR CI into `postgres-contract` | PS / TL / CP | 2–3 | Test count in the job summary rises by the nine files; no `skipped` masking | Honest "tested" claims |
| **T-124** | Close the evidence gaps named in the triage: protect `adr_record_policies` with the same REVOKE + trigger pattern; trigger-fire tests for every protected table; DB↔bucket stream reconciliation check in the drain worker | EV / TL / SE | 4–5 | `postgres-contract` proves UPDATE/DELETE on every evidence table raises SQLSTATE 55000; reconciliation mismatch fails `/readyz` | "Storage-layer immutability" as a stated claim |
| **T-125** | Rate limiting per ADR-003 tiers on `/v1/authorize`, approvals and token issuance | CP / TL / SE | 3 | Adversarial test: burst over tier limit returns 429 with problem URI; limit visible in `/metrics` | Pilot operability |
| **T-126** | Degraded mode: either wire `security/mizan_security/degraded.py` into `service.py:199,276` (which currently write `is_degraded: False` as a literal) or delete it and the ledger row | CP / TL / SE | 2–3 | Fault-injection test: policy backend unavailable → `is_degraded: true` and fail-closed decision, or the module is gone | Truthful degraded-state contract (strategy §8 objection) |
| **T-127** | Ratify `threat-models/TM-001` (status DRAFT), refresh stale residuals, open TM-002 for the Memtara seam | SE / TL / PO | 3 + founder | TM-001 status RATIFIED with date; TM-002 skeleton lists the seam's trust boundary | Security pack (strategy §9) |
| **T-128** | UI truth corrections from strategy §7: runtime-derived environment badge (never "Production" until verified), "Every governed action, decided before execution", rename "Security alerts" to the counted event class, "Control-plane integrity check", policy "simulation" not "replay" | FE / PO / TL | 2–3 | DOM tests assert the strings; `ui/index.html:10,13,31` and `app.js:113,214-268` changed | Any external demo |

### WS-1b · Bank-pilot gates (Tier B)

| ID | Task | R / A / C | Days | Acceptance | Unlocks |
|---|---|---|---:|---|---|
| **T-129** | `INSTALL.md`: clean-machine installation including production credential bootstrap, Vault Transit and S3 Object Lock configuration; then a named person outside the build team performs it and the corrections are recorded as `docs/reviews/CP-F-WALKTHROUGH.md` | PS / TL / PO | 3–4 | Walkthrough document exists with timings and corrections; rerun green after corrections | "A stranger installed it" (strategy §2) |
| **T-130** | Backup / restore drill for Postgres and the evidence object store, ending in a successful offline verification of a restored bundle; runbook committed | PS / EV / SE | 2–3 | Drill script in CI (nightly) restores to a fresh Postgres + bucket and both verifiers PASS | Continuity answer (CBUAE outsourcing objection) |
| **T-131** | One full-journey production-mode CI gate: authorize → approve → execute → attest → export → both verifiers, on top of the existing `production-boot` job | PS / TL / EV | 3–5 | New job `production-e2e` green; the job asserts each hop, not just exit code | "The marketed sequence runs in production mode on every change" |
| **T-132** | Workforce login: OIDC against a customer IdP, mapped roles / control domains, short session, MFA / hardware step-up immediately before a high-risk vote, logout and revocation events. Replaces the pasted-JWT textarea | FE + CP / SE / TL | 8–12 | Browser tests: login, step-up on approval, session expiry, revoked session refused; audit events emitted | Strategy §7 P0 screen; every pilot |

### WS-2 · The seam — Mizan verifies Memtara and both land in one bundle

This is the work the diligence called fiction. It is 20–30 days, not a rewrite, because Memtara already
ships the validation library in Python and Mizan already passes the whole context into Cedar.

| ID | Task | R / A / C | Days | Acceptance | Unlocks |
|---|---|---|---:|---|---|
| **T-133** | Memtara proof-token verification in Mizan: port `integrations/aihoots/memtara_claims.py` (`JwksCache`, `validate_proof_token`, `VerifiedProof`) into `control-plane/mizan_control_plane/proofs/memtara.py`; configuration for trusted issuer and JWKS URL (fail-closed if unset when a policy requires proof); `jti` replay set; token accepted via `x-memtara-proof` on `/v1/authorize` and via the SDK | CP / TL / SE, ZK | 4–5 | Unit tests ported from Memtara's suite; adversarial tests: wrong `kid`, expired, wrong issuer, replayed `jti`, `suitable=None` all refused; `MODULE_LEDGER` row added | UC-2 step "Mizan verifies the token" |
| **T-134** | Bind the verified proof into the decision: land `proof_hash`, `circuit`, `predicate`, `product_isin`, `suitable`, `expires_at`, `jti` in `MappedInput.fields` with `source="memtara"`; ship a reference Cedar policy `require_suitability_proof` that permits the recommendation tool only when `context.mizan.mapped.fields.suitable == true` and ISIN matches the tool argument; a `suitable=false` proof produces DENY with reason `suitability_declined` and the identical evidence shape | CP / TL / EV, PO | 2–3 | Policy simulation tests for all six rows of the UC-2 decision matrix; decline and approval bundles diff only in decision fields | UC-2 decision matrix; "a decline is evidenced identically" |
| **T-135** | One cross-anchored bundle: Mizan `ADR_Record` carries `external_proofs[]` (issuer, `proof_hash`, `jti`, Memtara chain head at issue time); `docs/spec/EVIDENCE-BUNDLE-FORMAT.md` bumped; **both** verifiers parse and check the field (presence, hash format, Memtara JWKS signature when the key is supplied as a trust root); `compare_verifiers.py` gate covers a bundle with proofs | EV / TL / CP, ZK | 3–5 | `offline-evidence-verifier` job verifies a bundle containing a real Memtara token with the Memtara public key as trust root; tampering the `proof_hash` fails both verifiers | UC-2 "one record, both chain heads" |
| **T-136** | SDK and MCP gateway carry the proof: `sdk/python/mizan` client and decorator accept a proof token; `integrations/mcp/mizan_mcp_gateway` forwards `x-memtara-proof` from the MCP client to `/v1/authorize` without reading it | CP / TL / ZK | 2–3 | Gateway integration test: tool call with and without header reaches the expected decision | UC-2 via the customer's MCP client |
| **T-137** | Two-product demo, one command: extend `scripts/demo_walk.py` (or a sibling) to run Memtara's reference client for the proof, call Mizan with it, approve above threshold, execute once, export, verify with both verifiers; deterministic transcript committed for the backup demo | CP / PO / EV, ZK | 3–4 | Runs on a clean machine after `INSTALL.md` + Memtara quickstart; transcript diff-clean in CI | The seven-minute UC-2 demo; retires "two consoles" |
| **T-138** | Claims register and ledger sync for the seam: `MODULE_LEDGER.md` cross-product rows to *shipped*; use-case catalogue UC-2 maturity to Technical Preview; narrative PRD Wow 6 un-gated | PO / TL / — | 0.5 | Docs PR referencing the merged task PRs | Marketing may say it |

### WS-3 · Memtara to pilot-grade (`memtara-zkp` repository)

| ID | Task | R / A / C | Days | Acceptance | Unlocks |
|---|---|---|---:|---|---|
| **M-01** | Merge `evidence-v1` (18 commits, never CI-run) into `main` through a PR; fix whatever CI finds; add `pull_request` runs for every branch | ZK / TL / PS | 1–2 | Green run on `main` at the merged SHA; `vkey` regenerate-and-diff step passes | Any Memtara claim at all |
| **M-02** | Container image with **vendored** `nargo 1.0.0-beta.26` and `bb 5.1.0` (no `curl \| bash` at build or run time), x86_64 and arm64 builds, subprocess timeout and stderr capture on `bb verify`; `quickstart.sh` uses the image | ZK + PS / TL / SE | 5–8 | Multi-arch image published from CI; `test_wealth_suitability_e2e.py` passes inside the image on both arches | Deployable in a customer environment; Apple-silicon demos |
| **M-03** | Close attested re-mint (`issuance/mod.rs:410-440` re-signs from a DB row without re-running crypto): require re-verification or bind the mint to the original verification record; add `cargo audit`, `cargo deny`, `clippy -D warnings` to CI; pin the Nargo compiler version in `Nargo.toml` | ZK / SE / TL | 3–4 | CI fails on a known-vulnerable crate; test: tampered DB row cannot mint a valid token | Security pack for UC-2 |
| **M-04** | `DecisionEvidence` v1 carries the Mizan `decision_id` and Mizan chain head when supplied; Memtara's audit event for a token issue records the relying party (`mizan`) | ZK / EV / CP | 2–3 | Bundle test: round-trip Memtara evidence → Mizan bundle → both verifiers | T-135's other half |
| **M-05** | Add a LICENSE; gate `POST /orgs` behind an allowlist or admin token (self-registration is unauthenticated today); remove the `COB 3.1` string in favour of `COB 3.4` with a migration note for relying parties | ZK / TL / PO | 1–2 | Tests for refused anonymous org creation; README citation defect closed | Customer legal review; UC-2 citation |
| **M-06** | Retire AIHOOTS from the CRO demo: `scripts/demo_cro_workflow.py --aihoots-audit` replaced by `--mizan-evidence`; Case File PDF cites the Mizan evidence export and verifier command; README paragraph claiming a "tamper-evident" AIHOOTS chain removed | ZK / PO / EV | 3–5 | Demo produces a Case File whose cited record verifies with Mizan's offline verifier; `tests/test_bundle.py` updated | UC-2 collateral without AIHOOTS |

### WS-4 · AIHOOTS retirement (`aihoots-e1-audit-gateway`)

| ID | Task | R / A / C | Days | Acceptance | Unlocks |
|---|---|---|---:|---|---|
| **A-01** | Archive the repository (read-only), add a README banner stating it is a 2026-07 prototype superseded by Mizan's evidence plane, correct `SECURITY.md:10,12` ("Defended: Yes" for silent edit) to *No*; remove every AIHOOTS reference from Mizan and Memtara collateral, decks and the `tests/aihoots_reference` submodule once M-06 lands | PO / TL / ZK | 1–2 | `grep -ri aihoots docs/` in Mizan returns only the decision record and this workplan; Memtara `.gitmodules` no longer pins it | No customer ever sees it |

### WS-5 · Founder-gated options — estimate now, build only on a ruling

| ID | Task | R / A / C | Days | Gate | Notes |
|---|---|---|---:|---|---|
| **T-139** | Delegated leases / risk-weighted autonomy: a time-boxed, LOW/MEDIUM-risk standing grant with its own `decision_basis`, event types, bundle fields, verifier support and adversarial tests | CP + EV / SE / TL | 15–25 | A design partner asks for it in writing **and** F-T-3 has not fired | The one existing time-boxed grant (`DegradedModeGrant`) is capped at LOW risk by a human-lane ruling; keep that precedent |
| **T-140** | Rename away from the same-name DIFC competitor: four customer-breaking surfaces (`X-Mizan-Second-Approval`, `https://mizan.ai/problems/*`, `mizan.*` event namespace, two MCP payload keys) plus mechanical operator-facing renames; DB schema name stays | CP / TL / PO | 3–5 | Trademark review outcome (verdict.txt go/no-go list) | 874 test-file occurrences make a botched rename loud; cheap, not urgent |

---

## 3. Sequencing — six weeks, four lanes

Critical path is **T-133 → T-134 → T-135 → T-137**, and T-135 cannot start until **M-01** and **M-04**
exist. Start Memtara's M-01 on day one.

```text
Week   CP lane                 EV lane                 ZK lane                 PS / SE / FE lane
─────  ──────────────────────  ──────────────────────  ──────────────────────  ─────────────────────────
  1    T-125 rate limiting     T-124 evidence gaps     M-01 merge evidence-v1  T-120 CVE (day 1-2)
       T-126 degraded mode                             M-05 licence/org gate   T-121 compose boot
                                                                               T-123 PG tests → CI
  2    T-133 proof verify      T-124 (finish)          M-03 re-mint + audit    T-122 key rotation (SE)
                               spec draft for T-135    M-04 DecisionEvidence   T-128 UI truth (FE)
  3    T-134 proof binding     T-135 bundle + both     M-02 container/arm64    T-122 (finish)
                               verifiers                                       T-127 TM-001 / TM-002
  4    T-136 SDK + MCP         T-135 (finish)          M-02 (finish)           T-129 INSTALL + walkthrough
       T-137 demo (start)      T-130 restore drill     M-06 retire AIHOOTS     T-132 OIDC (FE+CP start)
  5    T-137 demo (finish)     T-131 production-e2e    M-06 (finish)           T-132 (continue)
       T-138 docs sync                                 A-01 archive
  6    buffer / review debt    buffer                  buffer                  T-132 (finish), rerun T-129
```

Tier A closes at the end of week 5 if nothing slips. Tier B closes at the end of week 6 with T-132 as the
long pole; if T-132 slips, the pilot demo runs with the pasted-token console **behind** the presenter and
the strategy's "not bank-pilot-ready" language stays in force.

---

## 4. Definition of done for the programme

1. `production-e2e` (T-131) is green and includes a Memtara proof in its bundle (T-135).
2. A person outside the build team has installed Mizan and run the Memtara quickstart on a clean machine
   and the corrections are committed (T-129).
3. `MODULE_LEDGER.md` cross-product rows read *shipped*; the use-case catalogue's UC-2 row reads
   *Technical Preview*; the claims register lists every sentence marketing may now say (T-138).
4. `grep -ri aihoots` across the three repositories' customer-facing material returns nothing (A-01).
5. The weekly revenue-and-truth review (strategy §11) can answer "which product claim was challenged and
   what evidence supports it" by pointing at a CI job name for every claim in this document.

## 5. Reporting

- Every PR body is the completion report (PR-PROTOCOL H-2) and names the task ID, the use case it unlocks
  and the claim wording it permits.
- The Tech Lead posts a two-line status per lane to the Friday end-to-end review: *merged / blocked on /
  next*. Slips move the sequencing table in this file by PR, not by chat.
- Any task that changes the bundle format, a closed enum, or an ADR requires the EV and SE roles as
  reviewers regardless of lane.
