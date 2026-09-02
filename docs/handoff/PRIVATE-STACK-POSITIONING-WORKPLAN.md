# Private-stack positioning — evaluation workplan, tasks and risk containment

**Read first:** `docs/business/DECISION-2026-08-31-TWO-PRODUCT-PILOT.md`, `docs/business/MIZAN-COMMERCIAL-STRATEGY.md` (§2 gates, §13 stop rules), `docs/handoff/TWO-PRODUCT-PILOT-WORKPLAN.md` (the main programme this plan runs *beside*, never ahead of), `docs/product/FALSIFICATION_TESTS.md`.
**Issued:** 2026-09-02 · **Owner:** Founder (HUMAN lane) with PO · **Horizon:** eight weeks, decision gate **2026-10-31**
**Repositories:** `mizan` (task IDs continue at `T-141`)

The standing rules do not change: one task, one branch, one PR, CI is the arbiter, the completion report
is the PR body.

---

## 0. What this workplan delivers, in one sentence

> By 31 October the founder can point at a recorded, CI-verified demonstration of a customer-owned
> private model driving an agent whose every consequential action Mizan governed and evidenced, plus a
> counted market read on whether the sentence *"Enterprise-grade, private, auditable AI for firms that
> can't afford to get it wrong"* attracts the right buyer — and rules **Adopt / Adapt / Abandon** in a
> decision record, having spent at most **15 engineering man-days**, none of them on the critical path.

### Founder rulings recorded 2026-09-02

1. **Mizan is not and will not be the AI provider.** We govern the customer's model; we never sell,
   host, or fine-tune one. Option C in the feasibility analysis is rejected permanently.
2. **T-120 CVE re-triage is deferred by founder ruling** — we are in building phase and will revisit.
   It stays owned by WS-0 of the main workplan; this plan neither absorbs nor waives it. New images
   introduced *here* must not add to that debt (see R-6).
3. **WS-2 (the Mizan↔Memtara seam) is in progress.** This plan draws only on lanes with slack and
   freezes itself if the seam slips (see R-4).

### What "achieve the positioning" means, per word

| Word | Status today | What this plan does about it |
|---|---|---|
| **Auditable** | Shipped (dual verifiers, hash chain, RFC 3161, Object Lock) | Nothing to build; the register cites it (T-141) |
| **Enterprise-grade** | Gated on Tier B (WS-1b: OIDC, install walkthrough, production E2E) | Nothing to build here; the register marks it *gated*, marketing may not say it before Tier B closes |
| **Private** | Deployment-privacy real; data-privacy unaddressed (`redaction.py` has zero production callers) | T-146 wires or deletes redaction; until then the register limits "private" to deployment |
| **AI** | Not ours to claim as a product | T-144 makes it demonstrable as *governed* AI — the customer's own model, our control plane, one offline-verifiable bundle |

---

## 1. Roles

Same role table as `TWO-PRODUCT-PILOT-WORKPLAN.md` §1. RACI shorthand identical: **R** does the work,
**A** signs the PR, **C** must be consulted before the PR opens.

---

## 2. Workstreams and tasks

Estimates are man-days for one engineer of the named role, excluding review.

### WS-P0 · Words before work — the claim is registered before anything is built

> **Status 2026-09-02 — delivered as one PR, with one task only partly closable.** T-141 and T-143 are
> complete. **T-142 is complete up to the founder's action and cannot be closed by engineering:** the
> brief is written (`docs/business/BRIEF-2026-09-02-TRADEMARK-BRAND-RULING.md`), but its acceptance
> asks for a *ruling recorded as a dated note*, and no ruling exists because counsel has not been
> instructed. The standstill in that brief's §5 is in force from today regardless — no public use of
> the sentence, no branding spend, T-140 stays estimated.
>
> Two things a reader should not have to discover:
>
> * **The per-word table was not copied verbatim, because one row of it was optimistic.** The plan's
>   table calls "private" *deployment-privacy real*. It is — but the register now names the three
>   outbound endpoints that exist (Vault, the timestamp authority, the Memtara JWKS URL, all
>   operator-configured, none Mizan-operated), because "private" and "makes no outbound connection"
>   are different sentences and only the first is true. Nothing today gates the second; that is T-144's
>   assertion to add.
> * **T-146 is bigger than its row says.** `redaction.py` having "zero production callers" is true and
>   incomplete: `EvidenceRepository.append_audit`, the method that *enforces* the redaction
>   attestation, has no production caller either. The wire-or-delete decision spans both ends of the
>   path. Recorded as a finding in the claims register §5.

| Task | Description | R / A / C | Days | Acceptance | Unlocks |
|---|---|---|---:|---|---|
| **T-141** | Claims-register positioning hypothesis: add the sentence to the claims register as **HYPOTHESIS**, one row per word with its permitted meaning today (table above, verbatim); add a "we are not a model provider — we govern yours" row to the use-case catalogue's *What we do not sell* table | PO / TL / founder | 0.5–1 | Docs PR merged; every external use of the sentence traces to a register row | All external copy for this evaluation |
| **T-142** | Trademark / brand ruling package: one-page founder brief compiling the verdict.txt go/no-go list, the Mizan AI (DIFC) collision facts, and T-140's four customer-breaking rename surfaces; sent to counsel; outcome recorded | PO / founder / TL | 0.5 + counsel | Ruling recorded as a dated note in `docs/business/`; **no public use of the sentence before the ruling** | Any public positioning change |
| **T-143** | Adopt **F-T-7** in `docs/product/FALSIFICATION_TESTS.md`, written now, before the work, per that file's own rule: *"The private-stack message attracts the wrong buyer."* Observable: across the twenty problem interviews, if **≥ 5** variant-B conversations produce model-hosting expectations, or the only excited sponsor is internal audit (F-T-4's observable) in **≥ half** of them, the umbrella positioning fails. Instrumented via T-147's log fields | PO / founder / — | 0.5 | F-T-7 committed with owner, observable, decision date 2026-10-31 | An honest kill switch |

### WS-P1 · The demonstrable claim — make the sentence a recording, not a slogan

| Task | Description | R / A / C | Days | Acceptance | Unlocks |
|---|---|---|---:|---|---|
| **T-144** | **Private-model reference demo.** A compose profile (sibling of `compose.test.yaml`) adds one container: an OpenAI-compatible local endpoint (llama.cpp server or vLLM) serving a pinned open-weight model (digest recorded), standing in for *the customer's model*. A scripted agent (sibling of `scripts/demo_walk.py`) plans with that model and attempts consequential tool calls through `integrations/mcp/mizan_mcp_gateway`; Mizan produces one ALLOW, one REQUIRE_APPROVAL → approved → executed once, one DENY; evidence exported; **both** verifiers PASS offline. The compose network is egress-isolated and a test asserts no external connection is attempted — that assertion *is* the "private" claim. Transcript committed **from a real run** with `worktree_clean: true` recorded; nightly CI job re-runs and diffs it | CP + PS / TL / SE, EV | 5–7 | New CI job `private-stack-demo` (nightly) green: boots the profile, runs the walk, diffs the transcript, asserts zero egress; README section "Run it on your own metal" | The sentence as a recording; Phase-3 conversations |
| **T-145** | Reference-architecture note: `docs/product/GOVERNED-PRIVATE-STACK.md` — one diagram, the trust boundaries, what each component claims, and an explicit *what Mizan does not do* list (no model, no hosting, no inference telemetry, no training data access); opens `threat-models/TM-003` skeleton for the model-endpoint↔gateway boundary | PO + SE / TL / CP | 1–2 | Doc merged; TM-003 exists with the boundary and top abuse cases listed; every claim in the note cites a register row or a CI job | Partner and prospect conversations without over-claiming |
| **T-146** | **Data-privacy substance, first brick.** Apply the T-126 rule to `security/mizan_security/redaction.py` (229 lines, zero production callers): either wire it into evidence export — classified fields redacted in the exported bundle, adversarial tests proving redacted fields are absent yet the hash chain still verifies — or delete it and its ledger row. If wired, the register's "private" row gains *data-minimising export*; if deleted, "private" stays deployment-only and we say so | CP + SE / TL / EV | 2–3 | Either: `offline-evidence-verifier` job covers a redacted bundle and both verifiers PASS; or: module gone, ledger row closed | The word "private" beyond deployment — or the honesty of not saying it |

### WS-P2 · The market test — count officers, not enthusiasm

| Task | Description | R / A / C | Days | Acceptance | Unlocks |
|---|---|---|---:|---|---|
| **T-147** | A/B message kit: interview script variant A (current wedge: "control before action, proof after") vs variant B (the sentence), rotated across the twenty already-planned problem interviews — **no new meetings**. Pilot-log fields per conversation: variant shown, sponsor role, model-hosting expectation (y/n), audit-only sponsorship (y/n), asked-for-pilot (y/n) | PO / founder / — | 1 | Kit committed beside the outreach kit; log fields live in the pilot log | F-T-7's instrumentation; Phase-1 read |
| **T-148** | Partner and adjacency probes: two sovereign-cloud / SI partner conversations and one non-banking regulated firm (law or audit), each shown the T-144 recording, logged with the same fields | PO / founder / — | founder time | Three logged conversations referencing the recording | Distribution read (verdict.txt prescription #5) |
| **T-149** | Decision record `docs/business/DECISION-2026-10-31-PRIVATE-STACK-POSITIONING.md`: **Adopt** (sentence becomes umbrella copy, gated on T-142 ruling and Tier B for "enterprise-grade") / **Adapt** (fallback: *"auditable AI operations"*) / **Abandon** (wedge-only). Cites F-T-7 counts, register rows, the trademark ruling, and the demo's CI history | founder / PO / TL | 0.5 | Decision record merged; claims register updated to match | Everything downstream |

**Engineering budget: ≈ 9.5–14 man-days. Hard cap 15.** T-147/T-148 are founder/PO time, not
engineering. If the cap is hit, the remaining scope waits for the decision record rather than growing.

---

## 3. Sequencing — beside the main programme, never ahead of it

Main-programme weeks refer to `TWO-PRODUCT-PILOT-WORKPLAN.md` §3. This plan uses only lanes with slack;
the seam lanes (T-133→T-137) are untouchable.

```
Week (main plan)   This plan
  1                T-141 register rows · T-142 brief to counsel · T-143 F-T-7 adopted
  1–3              T-147 kit, then variants rotate through the problem interviews as they occur
  2–4              T-144 demo build (CP+PS slack lane) · T-145 architecture note
  4–5              T-146 redaction wire-or-delete · T-144 nightly job stabilises
  5–8              T-148 partner probes with the recording
  by 31 Oct        T-149 decision record — Adopt / Adapt / Abandon
```

**Freeze rule.** If the seam's critical path (T-133 → T-134 → T-135 → T-137) slips by a week or more,
WS-P1 pauses immediately and its engineers return to the main plan. WS-P0 and WS-P2 continue — words
and interviews cost the critical path nothing.

---

## 4. Risk register — what could go wrong, and the minimisation for each

| # | Risk | Early signal | Minimisation | Stop / kill rule |
|---|---|---|---|---|
| **R-1** | Brand collision with Mizan AI (DIFC) worsens as the claim broadens | Prospect or counsel confusion; the other firm's copy converges on ours | No public use of the sentence before the T-142 ruling; internal codename only; T-140 rename stays estimated and ready (3–5 days) | Adverse ruling → sentence shelved until post-rename, recorded in T-149 |
| **R-2** | "AI" in the copy creates model-hosting expectations we will never meet | Prospects ask for model SLAs, fine-tuning, GPU pricing | Script disclaimer in T-147 kit ("your model, our governance"); demo visibly runs the model *customer-side*; *What we do not sell* row (T-141) | F-T-7 fires (≥ 5 variant-B conversations) → Adapt or Abandon at T-149 |
| **R-3** | Audit-only sponsor trap — safety language attracts the cost-center buyer (F-T-4) | Only internal audit excited; no operating-lane sponsor appears | Sponsor role logged per conversation (T-147); pilot advance requires an operating-lane sponsor, per the commercial strategy | F-T-4's own trigger stands; F-T-7's second observable counts it for variant B specifically |
| **R-4** | Critical-path theft — this plan delays the seam or Tier B | Seam task slips while WS-P1 is active | Hard cap 15 man-days; slack lanes only; the freeze rule in §3 | Seam slips ≥ 1 week → WS-P1 pauses same day |
| **R-5** | Demo theatre — a transcript that was written, not recorded | Hand-edited transcript; dirty worktree at capture | The `demo_memtara` fixture (a hardcoded constant) is the named anti-pattern; T-144's transcript must come from the CI run itself, `worktree_clean: true` recorded, nightly diff gate | A transcript that cannot be reproduced by CI is deleted, not explained |
| **R-6** | New supply-chain surface — the model-runtime image imports CVE debt while T-120 is deferred | Trivy findings on the demo image | The demo image passes the same `production-image` scan lane; **zero new allowlist entries** without a dated justification — deferral of the old debt is a founder ruling, adding new debt is not | A demo image that needs an undated allowlist entry does not merge |
| **R-7** | Privacy over-claim — copy says "private data" before the substance exists | Draft copy exceeds the register's "private" row | The claims register is the only source of external copy (strategy §12 discipline); PO reviews every outbound doc; T-146 is what moves the row, nothing else does | Any copy beyond the register is withdrawn and logged in the weekly truth review |
| **R-8** | Positioning work dilutes the mandate — 3 paid design partners by 30 Nov is the goal, not applause | Founder calendar fills with positioning meetings that are not pilot-qualified | North star stays *governed consequential actions*; T-147 rides existing interviews; §13 stop rules bind — no pricing changes, no rebrand spend, no new headcount for this | Any §13 stop rule firing halts this plan before it halts the pilot programme |
| **R-9** | The demo model itself misbehaves on camera (hallucinated tool calls, unsafe output) | Flaky transcript diffs; embarrassing plan text in the recording | Deterministic decoding (temperature 0, pinned seed where the runtime allows); the demo's *point* is that Mizan denies the bad call — a wrong model action that gets DENIED is kept in the recording deliberately, as the product argument | Flakiness that survives pinning → scripted stub replaces the live model in CI, live model kept for the on-camera run only, and the register row says which is which |

---

## 5. Definition of done for the evaluation

1. The sentence sits in the claims register with a per-word status, and every external use traces to it (T-141).
2. `private-stack-demo` is green nightly, its transcript reproduced by CI from a clean tree, its egress assertion passing (T-144).
3. F-T-7 has real counts from ≥ 15 conversations, logged by sponsor role (T-143, T-147, T-148).
4. The trademark ruling is recorded, whatever it says (T-142).
5. `redaction.py` is either load-bearing or gone (T-146).
6. `DECISION-2026-10-31-PRIVATE-STACK-POSITIONING.md` exists and the register matches it (T-149).

## 6. Reporting

Same cadence as the main plan: the weekly truth review gains one line — *positioning evaluation:
tasks merged / F-T-7 counts to date / risks fired*. The decision on 2026-10-31 is the founder's,
in writing, and a fired falsification test that is then re-argued is not a test.
