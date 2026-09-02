# Founder brief — trademark and brand-conflict ruling package

**Task:** T-142 (`docs/handoff/PRIVATE-STACK-POSITIONING-WORKPLAN.md`, WS-P0)
**Prepared:** 2026-09-02 · **For:** Founder, to send to counsel · **Decision needed by:** 2026-10-31 (T-149)
**Status: AWAITING COUNSEL.** No ruling has been made. This document is the package, not the outcome.
When counsel rules, record it as `DECISION-<date>-TRADEMARK-BRAND-RULING.md` in this directory and
strike the standstill in §5.

---

## 1. The question put to counsel

We operate as **Mizan**. A separate company presenting itself as **Mizan AI**, incorporated in DIFC
per its public page, occupies a nearly identical category position in the same market. We are about to
evaluate broadening our external claim from a narrow wedge to an umbrella positioning sentence, which
would increase our public surface in that market.

Three questions, in order of what blocks what:

1. **Exposure.** What is our risk from continuing to trade as "Mizan" in the UAE/GCC in this category
   — and does that risk change materially if we broaden the claim?
2. **Registrability.** Can we register in the relevant classes in the UAE and GCC, and is there a
   prior filing by the DIFC entity or anyone else?
3. **Remedy.** If the answer to either is adverse, what is the cheapest sufficient response —
   coexistence, a qualifier, a sub-brand, or a rename?

We are not asking whether to be afraid. We are asking which of those three we should be spending on.

## 2. Why now, and the source of the prompt

The prompt is external, not internal anxiety. The 2026 moat assessment (`verdict.txt`, §"The immediate
go/no-go test") lists eight requirements for the next 90 days. **Its first item, ahead of every
commercial and engineering item, is:**

> *"trademark and brand-conflict review immediately; freeze major spending on 'Mizan AI' branding
> until resolved"*

The remaining seven, for context on where this sits in the queue — they are the same 90-day window
and this one gates the branding half of it:

> 15 UAE regulated-institution interviews involving actual agent tool access · three paid design
> partners, not free demonstrations · two audit/risk teams independently running the verifier · one
> competitive build-versus-buy exercise against Auth0/Entra plus Cedar/OPA and ordinary audit storage ·
> one customer proving that Mizan either shortens security approval materially or enables a previously
> blocked action · measured approval load and time-to-decision · one credible local audit,
> cybersecurity or implementation partner

## 3. The collision, as facts rather than impressions

From the same assessment (§"Why it is not a moat", ¶1). These are that document's reported facts about
the other company's **public self-presentation**; they are not independently verified by us, and
counsel should treat them as the starting point for a search, not as findings:

| Their stated position | Ours |
|---|---|
| Governance and control for AI agents | The same category |
| Built for GCC banks and government | The same buyer |
| Deterministic rule-based decisions | Deterministic authorization before execution |
| Tamper-evident records | Tamper-evident evidence plane (ours is dual-verifier and externally timestamped) |
| Sovereign deployment | Customer-perimeter deployment |
| Arabic/English audit output | Not built |

Public sources cited: their [LinkedIn company page](https://ae.linkedin.com/company/mizan-ai-governance)
and [website](https://mizanai.ai/).

**Two things counsel should know that the table does not show.**

* **Their technical claims are unverified.** Our repository may contain materially deeper engineering.
  That is irrelevant to the naming question and we should not let it comfort us: *buyers see the brand
  and the category before they see the code.*
* **The positioning under evaluation makes the overlap worse, not better.** Our current wedge
  ("control before action, proof after") is narrower than their stated position. The candidate
  sentence — *"Enterprise-grade, private, auditable AI for firms that can't afford to get it wrong"* —
  converges toward it. **This is the specific reason the ruling gates the positioning work** and not
  merely a background risk (R-1 in the positioning workplan).

## 4. What a rename would actually cost — estimated before the ruling, deliberately

So that the ruling is taken against a number rather than a fear. This is task **T-140** in
`TWO-PRODUCT-PILOT-WORKPLAN.md` (WS-5), estimated at **3–5 engineering days**. Counts below were taken
from the tree at `f3aa46e` on 2026-09-02.

**Four customer-breaking surfaces** — these change something a customer has integrated against, so
they need a deprecation path, not a find-and-replace:

| # | Surface | Where | Occurrences | Why it breaks a customer |
|---|---|---|---:|---|
| 1 | HTTP header `X-Mizan-Second-Approval` | request path | 8 (3 files) | A customer's client sends it; renaming without an overlap window silently drops second approvals |
| 2 | Problem-type URIs `https://mizan.ai/problems/*` | error responses | 12 | RFC 9457 `type` URIs are stable identifiers customers switch on; they are also the surface most likely to be *matched* by a customer's alerting |
| 3 | Event namespace `mizan.*` | evidence and audit events (16 distinct types, e.g. `mizan.approval`, `mizan.security.execution_token_replay`) | 16 types | Event types appear inside signed evidence. Records already written keep the old namespace **for ever** — this surface can be renamed going forward but never retroactively, and both offline verifiers must accept both |
| 4 | MCP payload key `mizan` | gateway annotation and policy context (`context.mizan.*`) | 4 | Every customer-authored Cedar policy references `context.mizan.…`. This is the most expensive of the four because the breakage is in *their* policy files, not their code |

Plus mechanical operator-facing renames (env vars, log prefixes, container and package names). The DB
schema name `mizan` stays — it is not customer-visible.

**What makes this cheap-but-not-trivial:** 56 test files reference the name, so a botched rename is
loud rather than silent. That is a good property. The estimate holds only while surface 3's
"old records keep the old namespace for ever" is honoured — the moment anyone proposes rewriting
historical events to the new namespace, the cost is not 3–5 days, it is the evidence plane's entire
credibility, and the answer is no.

## 5. Standstill in force until the ruling

These hold from today until counsel rules, per R-1 of the positioning workplan:

1. **No public use of the positioning sentence** in any channel — site, LinkedIn, deck, or
   conversation. It is registered as a HYPOTHESIS in `../marketing/CLAIMS-REGISTER.md` §4 with no
   cleared use, and it stays there.
2. **No major spend on "Mizan AI" branding** — the assessment's own words. Domains, trademarks in new
   classes, agency work, printed collateral, event branding.
3. **Internal codename only** for the positioning evaluation.
4. **T-140 stays estimated and ready, not started.** A rename executed before the ruling is 3–5 days
   spent on a question nobody has answered.

Note that the standstill costs us almost nothing this quarter: the wedge positioning is unaffected,
every pilot conversation continues, and the engineering programme does not touch the name.

## 6. Outcomes and what each triggers

| Ruling | What we do |
|---|---|
| **Clear** — no material conflict, registrable | Standstill lifts. The positioning sentence still needs its *other* gates (per-word status in the register, T-149's ruling); the trademark gate is simply no longer one of them |
| **Coexistence** — usable with a qualifier or in limited classes | Record the exact permitted form. The claims register gains the qualifier as a mandatory travelling clause, exactly as its §2 rows work |
| **Adverse** — conflict material, or registration refused | The sentence is shelved until after a rename, and T-149 records that as the reason rather than as a market read. **F-T-7 is then unread, not failed** — do not let an adverse trademark ruling be mistaken for evidence that the positioning was wrong. T-140 moves from estimated to scheduled |

## 7. What this brief does not do

It does not choose a name, does not commission a search, and does not assume the answer is a rename —
the assessment's own recommendation is a *review*, and three of the four outcomes above involve no
rename at all. It also takes no position on whether the DIFC entity's claims are true; that is
commercially interesting and legally irrelevant here.

---

**Attachments for counsel:** the moat assessment — the founder's `verdict.txt`, which is deliberately
**not committed to this repository**, so its two load-bearing passages are quoted verbatim in §2 and
§3 above and this brief stands alone without it; the two public URLs in §3; this brief's §4 table as
the cost basis.
