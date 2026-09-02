# Mizan use-case catalogue — what sales, marketing and business heads may take to a prospect

**Owner:** Business, with Product sign-off on every maturity label
**Issued:** 2026-08-31
**Governed by:** `DECISION-2026-08-31-TWO-PRODUCT-PILOT.md`, `../product/MODULE_LEDGER.md`,
`../product/FALSIFICATION_TESTS.md`
**Engineering dependencies:** task IDs refer to `../handoff/TWO-PRODUCT-PILOT-WORKPLAN.md`

---

## 0. How to use this catalogue

Each use case is written so that a business head can open a conversation, a marketer can build one
asset, and a seller can qualify a prospect — without inventing a capability. Every use case carries:

- **Maturity today** using the narrative PRD's states: *Shipped · Technical Preview · Roadmap · Research*.
- **Demoable today** — what can be shown on a clean machine this week, and what is narrated.
- **Pilot-ready after** — the workplan tasks that must merge before the word "pilot" is attached.
- **You may say / you may not say** — the claim boundary for this use case specifically.

The rule from the marketing README applies: when a use case and the module ledger disagree, the ledger
wins. When a prospect asks for something in the "may not say" column, answer directly and move on.

### Products in and out of every conversation

| Product | Role in a conversation | Appears in collateral? |
|---|---|---|
| **Mizan** | The product. Action authorization, human authority, exact-request execution, evidence. | Yes — every use case |
| **Memtara** | A scoped proof module: a client's own device proves a predicate; Mizan verifies the proof and gates the action on it. | Only UC-2 (and UC-7/UC-8 as research) |
| **AIHOOTS** | Retired. Its function (a runtime audit chain) is done properly by Mizan's evidence plane. | **No.** Not named, not demonstrated |

### The one-page summary

| ID | Use case | Products | Sponsor to lead with | Maturity | Demoable today | Pilot-ready after |
|---|---|---|---|---|---|---|
| UC-1 | IT-operations agent change control | Mizan | Head of Platform / IT Ops | Technical Preview | Yes, end to end | T-120–T-131 |
| **UC-2** | **Advised-sales suitability: proof-gated recommendation** | **Mizan + Memtara** | **Head of Wealth + CRO / Compliance** | **Technical Preview** | Yes (`scripts/demo_memtara_walk.py`) | M-01–M-06 (Mizan side T-133–T-138 merged) |
| UC-3 | Wealth / relationship-manager copilot rebalance | Mizan | Head of Wealth, Head of AI | Technical Preview | Yes (`scripts/demo_walk.py`) | T-120–T-132 |
| UC-4 | Customer-service agent, bounded service changes | Mizan | Head of Customer Operations | Technical Preview | Yes, with synthetic tools | T-120–T-132 |
| UC-5 | KYC / AML case-work agent | Mizan | Head of Financial Crime | Technical Preview | Policy paths yes; integrations narrated | T-120–T-132 + customer integration |
| UC-6 | Payment / operations exception agent | Mizan | COO / Head of Payments | Technical Preview | Executive demo only | Not a first live deployment |
| UC-7 | "The model never saw more than was granted" | Memtara (+ Mizan) | Head of AI, DPO | **Research** | No | Not offered |
| UC-8 | Income-range proof for credit / affordability agents | Memtara + Mizan | Head of Retail Credit | **Research** | No | Not offered |

Lead with **UC-1 or UC-3** to open an account (fastest to a paid pilot). Bring **UC-2** to any wealth or
private-banking conversation — it is the only use case where a competitor cannot answer with "IAM plus a
policy engine", and it is the reason Memtara is in the portfolio.

---

## UC-1 · IT-operations agent change control

**Buyer and pain.** Head of Platform / IT Operations. An ops copilot can already read dashboards and
runbooks; nobody will let it restart a production workload or touch a firewall rule because change
management requires named authority and an audit trail. The agent is stuck at read-only.

**Agent and tools (3–10).** Service-health read · log search · runbook fetch · secret read · workload
restart · firewall / database change · resource delete.

**Decision matrix.**

```text
Read service health                 → ALLOW
Search logs / fetch runbook         → ALLOW
Read production secrets             → DENY
Restart production workload         → REQUIRE_APPROVAL
Change firewall rule / database     → REQUIRE_APPROVAL + dual control (quorum 2)
Delete resource outside scope       → DENY
```

**What the buyer sees in seven minutes.** Diagnostic reads flow with no human. The restart pauses; the
approver sees the workload, environment, arguments and policy clause — not a decision ID. Approval
executes exactly once; a replayed or altered restart is refused. The evidence bundle exports and a person
on the buyer's side runs the offline verifier.

**Real vs simulated today.** Mizan's decision, approval, execution-token and evidence path is real code
under CI. The downstream tools are synthetic in the demo; in a pilot they are the customer's own MCP tool
server behind the Mizan MCP gateway.

**Proof artifacts to hand over.** A sample evidence bundle; `scripts/verify_evidence_export.py` and the
zero-dependency JavaScript verifier; the fail-closed and adversarial CI job names.

**Pilot scope.** One ops agent, one environment, 3–10 tools, up to five policies, one approval workflow.
Six-week bounded engagement per the strategy §6.

**You may say.** Reads flow, consequential changes pause for the right people, approval binds to the exact
request, evidence verifies offline without a Mizan account.
**You may not say.** "Prevents outages", "production SLA", any latency figure, "delegated approvals" or
standing grants (T-139 does not exist yet).

**Outreach opener.** *"Your ops copilot is read-only because change management needs a named approver and
a record. We put a policy boundary at the tool call: diagnostics flow, a production restart pauses for the
right person, the approved change runs once, and your audit team verifies the record without trusting us.
Could we look at one agent and its ten tools?"*

**Qualifying questions.** Which agent can call infrastructure APIs today? What is the most consequential
action it could attempt? Who signs off a production change now, and what enforces that at the call?

---

## UC-2 · Advised-sales suitability — the proof-gated recommendation *(Mizan + Memtara)*

This is the flagship two-product use case and the only one in which Memtara appears in a sale.

**Buyer and pain.** Head of Wealth / Private Banking, with the CRO or Head of Compliance as validator.
DFSA Conduct of Business requires the firm to satisfy itself that a structured product is suitable before
recommending it (the obligation is COB 3.4; Memtara's tokens emit the string `COB 3.1`, which is the
"Application" section — say COB 3.4 in the room and let the token string be a known citation defect).
Today that means collecting income, liquidity, risk-tolerance and concentration documents and storing them
— a permanent, breachable copy of the client's finances, gathered so that one bit ("suitable") can be
recorded.

**What the two products do together.**

```text
Adviser asks the copilot to recommend the 5-year note to a client
  → the client's own device proves, against the bank's registered product terms,
    that income, liquidity, risk tolerance and concentration were each assessed
    and discloses ONE bit: suitable / not suitable                         (Memtara, real ZKP)
  → the proof token (Ed25519 JWS, 300-second life, published JWKS) reaches Mizan
  → Mizan verifies the token offline, binds proof_hash + product ISIN into the
    decision context, and Cedar policy REQUIRES a valid, unexpired, suitable=true
    proof before the recommendation / order tool may run                    (Mizan — T-133/T-134)
  → above the desk's authority threshold the order still pauses for a supervisor
  → the approved order executes once
  → ONE evidence bundle carries the Mizan decision, the Memtara proof hash and both
    chain heads, RFC 3161-anchored; a regulator re-verifies years later from a
    published key                                                           (T-135, M-04)
```

**Decision matrix.**

```text
Read client profile / product terms              → ALLOW
Recommend product with valid suitable=true proof → ALLOW (below threshold) / REQUIRE_APPROVAL (above)
Recommend product with no proof                  → DENY   (policy: proof required for this tool)
Recommend product with suitable=false proof      → DENY   — and the decline is evidenced identically
Recommend product with a wrong-ISIN proof        → DENY
Recommend product with an EXPIRED proof          → refused at the verifier: HTTP 403, no decision
Export client financial documents                → DENY   (the bank holds none)
```

Two rows in this matrix are **not** what a shipped artefact does today, and both are pinned by tests
that say so rather than by tests that pretend otherwise:

- **The expired-proof row is a refusal, not a decision.** An expired token is rejected inside the
  proof verifier before the authorization service is entered, so the caller gets HTTP 403
  `invalid_memtara_proof` and **no ADR record is written**. That is defensible — an expired
  credential is malformed rather than a verdict — but it means there is no bundle for a supervisor
  to open on that path. Do not tell a prospect an expired proof produces an evidenced decline.
  (`tests/unit/test_app_routes.py::test_an_expired_proof_is_refused_at_the_verifier_and_produces_no_decision`)
- **The ALLOW row and the above-threshold pause need the customer's own policies.**
  `policies/reference/require_suitability_proof.json` is only the gate: it matches the
  recommendation tool and nothing else, so it neither permits the profile read nor expresses a desk
  authority threshold. A deployment composes those from its ordinary read and approval policies.
  (`tests/unit/test_authorization.py::test_the_reference_policy_alone_cannot_express_the_above_threshold_pause`)

**What the buyer sees.** The adviser types one sentence. Two seconds later the recommendation either
proceeds or is refused, and the refusal record is as complete as the approval. The compliance officer
opens the bundle and sees that the bank never held an income figure — only a proof that it was assessed.

**Real vs simulated today — be exact about this.**

| Piece | Status 2026-09-02 |
|---|---|
| Client-side proof generation and `bb verify` for `wealth_suitability` | Real; `tests/test_wealth_suitability_e2e.py` in Memtara, nothing stood in for |
| Memtara's own refusal to approve on exit code alone (reads the verdict public input) | Real (`/api/v1/issue-proof`) |
| Ed25519 proof token + JWKS + offline validation library (`memtara_claims.py`) | Real; ported into Mizan's fail-closed proof verifier by T-133 |
| One-command CRO demo producing a sealed Case File PDF | Real (`scripts/demo_cro_workflow.py`) — but it cites the AIHOOTS log; M-06 repoints it to the Mizan export |
| Mizan verifying the token and gating the tool on it | Technical Preview — T-133/T-134 merged; verification, ISIN binding and the evidenced decline are CI-gated |
| One cross-anchored bundle | Technical Preview — T-135 merged; both offline verifiers check the proof against an operator-supplied Memtara keyset. Memtara-side DecisionEvidence enrichment remains M-04, so the chain head is recorded but not independently authenticated |
| Memtara container image, arm64, CI on the current branch | **Absent** — M-01, M-02 |

The Technical Preview runs as one transaction through `scripts/demo_memtara_walk.py`: Memtara issues the
proof, Mizan verifies and binds it to the decision, and the resulting cross-anchor is exported for both
offline verifiers. The pilot-grade Memtara packaging and reciprocal DecisionEvidence work remain tracked
under M-01–M-06.

**Proof artifacts.** Memtara's published vkey and README; the Case File PDF with detached seal; the Mizan
evidence bundle carrying both chain heads; and both offline verifiers.

**Pilot scope.** One advised-sales desk, one registered instrument family, one supervisor quorum, the
client device stood in by the reference client until the customer's app integrates. Non-production order
endpoint first — always.

**You may say.** The bank holds none of the figures; a decline is evidenced exactly like an approval;
the proof is re-verifiable from a published key; the recommendation tool cannot run without it.
**You may not say.** "CBUAE-ready", "DFSA-compliant", "18-month ZKP head start", "tamper-evident
AIHOOTS", any Memtara metric, any circuit other than suitability, that the proof is revocable inside its
300-second lifetime (it is not), that the sealed PDF shows a green tick in a viewer (detached seal, not
PAdES).

**Outreach opener (Head of Wealth).** *"Your suitability file is a breach waiting to happen, kept so that
one bit can be recorded. We let the client's own device prove suitability against your registered product
terms and disclose only the verdict; the copilot's recommendation cannot run without that proof, a
supervisor still signs above threshold, and the whole decision exports as one record your compliance team
verifies from a published key. Which desk and which instrument would you test it on?"*

**Outreach opener (CRO / Compliance).** *"A firm that can only evidence approvals fails the suitability
rule it claims to satisfy. Our record is identical for a decline. Would your team be willing to run the
verifier on a sample before we meet?"*

**Qualifying questions.** Which structured products carry a suitability obligation today? Where are the
assessment documents stored and for how long? Who is the supervisor of record above threshold? Does the
client have a bank app that could host a prover?

---

## UC-3 · Wealth / relationship-manager copilot rebalance *(Mizan)*

The strategy's original flagship, unchanged in mechanism; UC-2 is its proof-gated extension.

```text
Read portfolio / risk profile               → ALLOW
Draft recommendation                        → outside Mizan unless it is a tool action
Rebalance portfolio                         → REQUIRE_APPROVAL
Rebalance without current consent           → DENY
Send order beyond amount / risk limit       → REQUIRE_APPROVAL or DENY
```

Demoable end to end today with `scripts/demo_walk.py`. Pilot with a non-production execution endpoint
first. **You may not say:** any figure for approval time or straight-through rate until measured.

**Opener (Head of AI).** *"Your RM copilot is allowed to read and forbidden to act. We make the rebalance
pause for the supervisor with the exact changed fields on screen, execute it once, and export the
decision. The reads keep flowing."*

---

## UC-4 · Customer-service agent with bounded service changes *(Mizan)*

```text
Read account / card status                  → ALLOW with verified customer context
Create a low-risk service ticket            → ALLOW
Change address or contact details           → REQUIRE_APPROVAL / step-up
Expose full customer profile                → DENY by policy boundary
Send data to an unapproved tool             → DENY
```

The control is tool, resource, destination and context authorization. **You may not say:** content DLP,
PII detection, prompt-injection detection — none is shipped (module ledger). The tested property is
narrower and worth stating precisely: text inside a tool request cannot grant itself policy authority.

---

## UC-5 · KYC / AML case-work agent *(Mizan)*

```text
Read assigned case                          → ALLOW
Request approved data source                → ALLOW
Change risk classification                  → REQUIRE_APPROVAL
Close or escalate a case                    → REQUIRE_APPROVAL
Access another jurisdiction / tenant        → DENY
```

Strong on separation of duties and evidence; heavier on integration and data residency. Qualify for a
second pilot, not a first.

---

## UC-6 · Payment / operations exception agent *(Mizan)*

```text
Read payment state                          → ALLOW
Prepare an exception packet                 → ALLOW
Release / reroute / reverse payment         → REQUIRE_APPROVAL + dual control
Execute above threshold                     → DENY or enhanced approval
```

Highest value, highest risk. Executive demo and expansion story. Not a first live customer action unless
the customer already has a contained sandbox and a named operational authority.

---

## UC-7 · "The model never saw more than was granted" — *Research, not offered*

Memtara's `ai_session` circuit proves every record disclosed to a model is in the user's vault and under
a consented category. It has `should_fail` fixtures only, no end-to-end proof, and its Merkle limb is not
pinned to the user's committed vault root. If a Head of AI or DPO raises consent-scoped context, say: *"We
have a research circuit for exactly that; it is not something we would put in front of your auditors
yet."* Do not demo it.

## UC-8 · Income-range proof for credit / affordability agents — *Research, not offered*

Memtara's `tax_session` circuit proves an income lies in a range without disclosing it. Same status as
UC-7. Worth one discovery question in retail-credit conversations; not a pilot.

---

## What we do not sell

| Ask | Answer |
|---|---|
| **A model — hosted, supplied, fine-tuned, or resold** | **We are not a model provider. We govern yours.** Mizan supplies no model, hosts none, tunes none, and never sees inference telemetry or training data. Your model runs where you choose, on your metal or your cloud account; Mizan sits at the action boundary and decides, before execution, whether what it asked for may happen — and evidences that. There is no GPU line on our price list and never will be: a founder ruling of 2026-09-02, recorded in `../handoff/PRIVATE-STACK-POSITIONING-WORKPLAN.md`, makes this permanent rather than a stage we are at. If a prospect wants a model, the honest answer is a referral, not a roadmap. |
| "The three-product Trust Stack bundle" | Retired 2026-08-31. Mizan, with Memtara for UC-2. |
| A runtime prompt-injection / PII proxy (the AIHOOTS shape) | Not our product. Keep the customer's AI firewall; its signal can become Mizan policy context later. |
| "Approve once, let it run for 30 days" | Not built (T-139, 15–25 days, only if pilots demand it). What exists is the opposite: minutes-long, single-decision execution grants. |
| ZKP for anything except suitability | Research. |
| Certification, compliance or regulator-endorsement language | Never. Cite the rule; show the control. |

---

## Outreach kit by persona

| Persona | Lead use case | The sentence that earns the meeting | Proof to attach |
|---|---|---|---|
| Head of AI / Platform | UC-1, UC-3 | "Move one agent from read-only to governed action without changing the model." | Architecture note; three-path walkthrough |
| Head of Wealth | UC-2 | "The bank never holds the figures; the recommendation cannot run without the proof." | Case File sample; the one-command `make demo-memtara` walkthrough and its committed transcript (the two-console recording is retired — T-137 replaced it with a single journey) |
| CRO / Compliance | UC-2, UC-3 | "Our decline record is identical to our approval record." | Sample bundle + verifier command |
| CISO / AppSec | UC-1 | "Fail-closed, exact-request approval, one-use execution — and the adversarial CI that proves it." | CI job list; threat-boundary note |
| Internal Audit | any | "Run the verifier yourself before we talk." | Verifier challenge kit |
| Head of Customer Ops | UC-4 | "Bounded service changes with step-up, no profile exposure." | Decision matrix |

Every meeting ends with the same ask: **one agent, 3–10 tools, one consequential action, one named risk
owner, one decision date.** Record whether the verifier was offered, run, or refused (F-T-1).

**Where to record it: [`PILOT-LOG.md`](PILOT-LOG.md), one row per substantive conversation, the same
day.** It instruments five falsification tests and it is the only place the counts live. During the
positioning evaluation, the opening comes from [`MESSAGE-KIT-AB.md`](MESSAGE-KIT-AB.md) — variant A
until the T-142 trademark ruling is recorded, and variant B not at all before then. The openings differ;
everything after the qualifying question, including every answer in that kit's §4, is identical in both,
or the test measures our delivery rather than the two sentences.
