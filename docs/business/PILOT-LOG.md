# Pilot log — one row per substantive conversation

**Owner:** PO, kept by whoever ran the conversation · **Created:** 2026-09-02 (T-147)
**Instruments:** F-T-1, F-T-4, F-T-5, F-T-6, F-T-7 in `../product/FALSIFICATION_TESTS.md`

---

## 0. Why this file exists, and the gap it closes

**Four falsification tests have been citing "the pilot log" since 2026-08-25. It did not exist.** F-T-1
(nobody runs the verifier), F-T-4 (only audit is excited), F-T-5 (nobody replays) and F-T-6 (nobody
values the proof) each name it as their instrument, and each was therefore unmeasurable from the day it
was adopted. Found while adopting F-T-7, which would have been the fifth.

That matters more than a missing file usually would, because these tests exist to be capable of
stopping the company. A kill switch that cannot be read is not a kill switch. The rule at the top of
`FALSIFICATION_TESTS.md` — *a test that fires and is then re-argued is not a test* — has a quieter
sibling: **a test that cannot fire because nobody recorded the observable was never a test either.**

## 1. How to keep it

* **One row per substantive conversation.** Substantive means the product was discussed with someone
  who could sponsor or block it. A referral, an intro call, or a conference chat is not a row.
* **Fill it the same day.** A field remembered a week later is a field invented a week later.
* **Leave a field blank rather than guessing.** Blank is data — it says the question did not come up.
  A guessed `n` is worse than an honest gap, because it counts.
* **Count sponsors, not enthusiasts.** F-T-4's phrasing, and it governs the whole file. Someone who
  loved the demo and controls no budget is not a sponsor. Record who would sign.
* **Never edit a row to match a later outcome.** If a reading changes, add a dated note under the
  table. This file is evidence about our own claims, and it is held to the standard we hold our
  customers' evidence to.
* Nothing here phones home. F-T-1's verifier count is deliberately manual — the offline verifier must
  never report usage, which is the whole point of it.

## 2. Fields

| Field | Values | Which test reads it |
|---|---|---|
| `date` | ISO date | all |
| `org` | organisation name (or a stable pseudonym if the name is sensitive) | all |
| `person_role` | their actual title | F-T-4, F-T-7 |
| `sponsor_function` | `business_line` \| `internal_audit` \| `risk_compliance` \| `security` \| `it_platform` \| `none_identified` | **F-T-4, F-T-7** |
| `would_sign` | `y` \| `n` \| `unknown` — does this person control or directly influence the budget | F-T-4 |
| `use_case` | UC-1 … UC-8 | F-T-6 |
| `variant` | `A` \| `B` \| `none` — which script was used (see `MESSAGE-KIT-AB.md`) | **F-T-7** |
| `model_hosting_expectation` | `y` \| `n` — did they raise model hosting, SLAs, fine-tuning, GPU or inference cost **unprompted**, before we corrected them | **F-T-7** |
| `asked_for_pilot` | `y` \| `n` | F-T-7 |
| `verifier` | `not_shown` \| `shown` \| `offered` \| `ran_it_themselves` | **F-T-1** |
| `replay_run` | `y` \| `n` \| `n/a` — did they run `--replay` on a bundle **we did not hand-pick** | **F-T-5** |
| `proof_changes_control` | `y` \| `n` \| `n/a` — did a compliance or risk officer state that the suitability proof changes a control outcome they are measured on | **F-T-6** |
| `notes` | free text, including anything that would embarrass us | judgement |

**Two definitions that decide the counts, so they are fixed here rather than per-reader.**

* **`model_hosting_expectation` counts on first unprompted mention.** If we say "we don't supply the
  model" and they then ask about GPUs, that is our prompt, not their expectation. This is the field
  most vulnerable to being scored generously by the person who wants the positioning to work.
* **`verifier = ran_it_themselves`** means they executed it. Watching us run it is `shown`. Being sent
  a bundle and not opening it is `offered`. F-T-1 counts only the first.

## 3. The log

| date | org | person_role | sponsor_function | would_sign | use_case | variant | model_hosting_expectation | asked_for_pilot | verifier | replay_run | proof_changes_control | notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| _no conversations logged yet_ | | | | | | | | | | | | |

## 4. Running counts

**Update when a row is added, in the same edit.** A count derived at the decision date from a file
nobody tallied is a count nobody trusts.

| Test | Observable | Threshold | Count today | Reads |
|---|---|---|---:|---|
| **F-T-1** | conversations where they ran the verifier themselves | ≥ 3 of 15 | **0 / 0** | `verifier` |
| **F-T-4** | sponsor is internal audit rather than a business line | — (judgement) | **0 / 0** | `sponsor_function`, `would_sign` |
| **F-T-5** | parties running `--replay` on a bundle we did not pick | ≥ 2 of 10 | **0 / 0** | `replay_run` |
| **F-T-6** | officers stating the proof changes a measured control | ≥ 2 of 6 UC-2 conversations | **0 / 0** | `proof_changes_control` |
| **F-T-7 (a)** | variant-B conversations producing a model-hosting expectation | **≥ 5 fires the test** | **0 / 0** | `variant`, `model_hosting_expectation` |
| **F-T-7 (b)** | variant-B conversations where audit is the only sponsor | **≥ half fires the test** | **0 / 0** | `variant`, `sponsor_function` |

**Read the thresholds in the right direction.** F-T-1, F-T-5 and F-T-6 fire by **falling short** — the
claim fails if too few people do the thing. F-T-7 fires by **reaching** its numbers — the positioning
fails if too many conversations go wrong. Getting this backwards at the decision date would invert a
company-level ruling, which is why it is written on the table rather than left to memory.

**And the count that is not in the table:** F-T-7 needs **≥ 15 conversations** to be readable at all.
Below that it is an unread test, not a pass, and T-149 must record it as unread rather than adopting
the sentence by default.
