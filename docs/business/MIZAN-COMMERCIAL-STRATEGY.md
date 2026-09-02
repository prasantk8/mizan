# Mizan commercial strategy — control before action, proof after

**Owner:** Business & Marketing

**Issued:** 2026-08-30

**Horizon:** September 2026–February 2027

**Status:** Founder operating plan; commercial hypotheses remain subject to design-partner evidence

**Revised:** 2026-08-31 — the two-product decision applied throughout. Read
`DECISION-2026-08-31-TWO-PRODUCT-PILOT.md` first; sellable use cases live in `MIZAN-USE-CASE-CATALOGUE.md`;
the engineering work this plan depends on is `../handoff/TWO-PRODUCT-PILOT-WORKPLAN.md`.

---

## 1. Executive decision

Mizan should enter the market as an **action-authorization and evidence gateway for enterprise AI
agents**, initially for regulated financial institutions in the UAE and GCC.

The product we sell is not “all of AI governance.” It is one enforceable control loop:

> **Put Mizan between an AI agent and its tools. Mizan evaluates every consequential tool call,
> pauses actions that require human authority, issues execution rights only for the approved request,
> and produces independently verifiable evidence of the decision and outcome.**

The commercial line is:

> **Control before action. Proof after.**

The seven-minute proof is:

```text
Agent proposes a tool call
  → Mizan identifies agent, principal, intent, tool, resource and risk
  → low-risk read is allowed
  → prohibited action is denied
  → consequential write pauses for the right human authority
  → the exact approved action executes with short-lived, one-use authority
  → the decision and outcome become a portable evidence bundle
  → a third party verifies that bundle offline, without a Mizan account
```

This is specific, valuable, demonstrable, and consistent with the implementation. The Design Plane,
PII/DLP engine, prompt-security engine, behavioral analytics, broad governance suite, SIEM connectors,
and Architecture Copilot remain roadmap. They must not appear in “available now” material.

### The product line, after the 2026-08-31 diligence

| Product | Commercial role | Status |
|---|---|---|
| **Mizan** | The product. Every use case, every conversation. | Technical preview; pilot gates in §2 |
| **Memtara** | A scoped proof module sold only inside the advised-sales suitability use case (catalogue UC-2): the client's device proves suitability, Mizan verifies the proof and gates the recommendation on it. | Real ZKP for one circuit; Mizan does not yet verify its tokens (workplan WS-2) |
| **AIHOOTS** | **Not sold, not shown, not named.** A five-day prototype whose function Mizan's evidence plane already performs properly. | Retired |

There is **no three-product bundle and no bundle price**. The pitch is one control transaction; Memtara
enters it as a policy input where a privacy-preserving proof is the thing the regulator wants evidenced.
Until the Mizan↔Memtara seam ships, the two are demonstrated as two consoles and described as such.

### The operating objective

By **30 November 2026**, earn three paid design-partner engagements and have at least one partner run
Mizan on one real agent with 3–10 tools. By **28 February 2027**, convert two partners to annual
platform contracts or produce written evidence that the wedge or buyer is wrong.

The goal is not maximum leads. It is rapid proof that a business owner will sponsor an agent-control
deployment and that an external risk or audit party will independently inspect the evidence.

---

## 2. What the repository says is true

There is no `CLAUDE.md` in this repository. The available Claude context is the Claude-authored work
log and handoff material. Product intent comes from `mizan-prd-v1.md`; implementation claims come from
`docs/product/MODULE_LEDGER.md`, the current source tree, and runnable acceptance gates.

### Sell in a technical preview today

| Capability | Commercially honest statement |
|---|---|
| Context-aware authorization | Mizan can return `ALLOW`, `DENY`, or `REQUIRE_APPROVAL` before an agent tool call executes. |
| Agent/tool/policy registry | Agents, tools, binding profiles and policies are centrally registered and tenant scoped. |
| Human approval | A consequential action can pause for epoch/quorum approval and continue only after approval. |
| Execution binding | Approval does not become a reusable permission; execution uses request-bound, short-lived authority and a lease/receipt flow. |
| MCP gateway | An installed gateway can govern calls to an upstream MCP tool server without becoming the policy authority itself. |
| Python integration | A Python SDK and wrappers provide an application integration path. |
| Decision evidence | Decisions and execution events are recorded, drained, anchored, and exportable. |
| Production key custody | Anchors and receipts are signed through HashiCorp Vault Transit with non-exportable keys; CI exercises a live Vault (`vault-transit` job, T-102). |
| Durable, immutable evidence store | Evidence objects are written to S3-compatible storage under Object Lock COMPLIANCE mode with a configurable retention (default seven years); CI exercises a live bucket (`evidence-object-lock` job, T-104). Database rows are additionally protected by `REVOKE UPDATE/DELETE` and refusal triggers. |
| Production mode boots | The production readiness branch runs in CI against real Vault and Postgres (`production-boot` job, T-101). |
| External timestamping | RFC 3161 attestation is wired as a managed workload and its limitations are disclosed. |
| Independent checking | Evidence can be checked offline; a second JavaScript verifier and cross-verifier gate exist. |
| Operator experience | An approver inbox, decision stream, audit views, evidence verification, and policy simulation UI exist as a demo surface. |

Before any external demo, the UI copy must be made as honest as the module ledger. Today the header
always shows a green “Production control plane” state, the hero says “without blind spots,” the
dashboard can imply a shipped security-alert engine, the live `/v1/audit/verify` view is described as
independent, and Policy Studio uses “replay” language that can be confused with the unshipped Stage 4
decision replay. These are presentation defects with commercial consequences; they must be corrected
even when the underlying code is behaving properly.

### Gates that closed between 2026-08-29 and 2026-08-31

| Former gap | Closed by | Evidence |
|---|---|---|
| Real production key custody | Vault Transit backend, custody enforced as a boot gate | `vault_transit.py`, `runtime.py:59`; CI `vault-transit` (T-102, T-065) |
| Durable evidence store | S3 Object Lock COMPLIANCE store selected in production | `runtime.py:99-105`; CI `evidence-object-lock` (T-104) |
| Production mode had never booted | Production readiness branch executed in CI | CI `production-boot` (T-101) |

### Do not call it bank-pilot-ready until these gates close

Workplan task IDs in the last column; the workplan is the schedule of record.

| Gap | Why it is a commercial blocker | Required evidence | Task |
|---|---|---|---|
| Workforce login and step-up | The console accepts a pasted bearer token and stores it in `sessionStorage`; there is no IdP/OIDC login or approval-time step-up. | Customer IdP login, mapped roles/control domains, short session, MFA/hardware step-up, logout/revocation, and audit events. | T-132 |
| Full-journey production E2E in CI | `production-boot` proves boot; no single gate proves authorize → approve → execute → attest → export → both verifiers in production mode on every change. | CI job `production-e2e` asserting each hop. | T-131 |
| Customer installation | `INSTALL.md` and the production credential bootstrap are absent. | A clean-machine installation guide and a stranger completing it without internal help. | T-129 |
| Restore and continuity | A retention label is not a restore capability. | Executed backup/restore drill for the database and evidence store, ending in successful offline verification. | T-130 |
| Independent walkthrough | `docs/reviews/CP-F-WALKTHROUGH.md` is absent. | Named external operator, new machine, timed run, and documented corrections. | T-129 |
| Identity-key rotation | One static verification PEM (`auth.py:35`); rotating it is an outage. | Keyset with `kid` routing and an overlap window, rotation drill in CI. | T-122 |
| Production compose path | The shipped `compose.production.yaml` cannot boot — it never sets the S3 store production requires. | Manifest validator launches it and reaches `/readyz`. | T-121 |
| Supply-chain allowlist | All 13 CVE exceptions in `.trivyignore.yaml` expire **2026-09-03**. | Re-triaged with dated justifications; `production-image` stays green. | T-120 |
| Degraded-state contract | `service.py` writes `is_degraded: false` as a literal; the degraded module is unwired. | Fault-injection test shows a truthful degraded, fail-closed decision — or the module is deleted. | T-126 |
| Production service evidence | Performance and availability targets are not customer claims until tested on supported deployment classes. | Repeated HTTP-path p95/throughput/lag measurements, capacity envelope, and explicit support boundary. | after T-131 |

### Memtara — what may be said, and only inside UC-2

| Statement | Basis | Status |
|---|---|---|
| The client's device proves suitability against the bank's registered product terms and discloses one bit. | `wealth_suitability` circuit; `tests/test_wealth_suitability_e2e.py` runs real `nargo execute`, `bb prove`, `bb verify` with nothing stood in for. | Sayable, as technical preview |
| A decline is evidenced identically to an approval. | The verdict is a public output; Memtara's `/api/v1/issue-proof` refuses to approve on exit code alone. | Sayable |
| The proof is re-verifiable from a published key. | Ed25519 JWS, `/.well-known/jwks.json`, committed `vkey` diffed in CI. | Sayable |
| Mizan requires the proof before the recommendation tool may run. | **Not built.** | Not sayable until T-133/T-134 merge |
| One evidence bundle carries both products' chain heads. | **Not built.** | Not sayable until T-135/M-04 merge |
| Any other circuit (income range, identity, emergency, AI-session consent). | `should_fail` fixtures only; no end-to-end proof; vault root not pinned. | Research; not sayable |
| "CBUAE-ready", "18-month ZKP head start", any Memtara metric. | Withdrawn by the decision record. | Prohibited |

Memtara's most recent 18 commits (branch `evidence-v1`) have never run in CI; the toolchain is installed
by `curl | bash` from upstream beta scripts; there is no container image and no arm64 build. These are
engineering facts a bank's SRE will find in an hour. Workplan WS-3 closes them; until then Memtara is
demonstrated by us, on our machine, and described as a technical preview.

### Claims prohibited in sales material

- “Complete agent security platform.”
- “Prompt injection protection” or “DLP/PII protection” as shipped features.
- “Prevents AI incidents.” Mizan controls a defined execution boundary; evidence often changes the
  cost of proving what happened, not whether an incident occurs.
- “Tamper-proof” or “immutable” without naming the trust boundary and disclosed omissions.
- “Regulatory compliance guaranteed,” “CBUAE compliant,” or certification claims.
- 99.9%, 99.99%, sub-50 ms, detection-rate, or PII-accuracy promises without current deployment-class
  artifacts and contract definitions.
- Support for Java, TypeScript, SIEM, Kafka, Redis, IAM, DLP, architecture generation, or behavior
  analytics until the module ledger moves from `none`/`unwired` to `shipped`.
- “Unique” or “the only platform.” Identity vendors, security platforms, and new action-control
  entrants now make overlapping claims.
- “Three-product Trust Stack,” “Enterprise Bundle,” or any AIHOOTS reference — retired 2026-08-31.
- “18-month ZKP head start.” The honest figure is 6–10 weeks to parity for a Noir-literate pair.
- “Tamper-evident AIHOOTS chain” or any AIHOOTS governance metric. None survives inspection.
- “Delegated leases,” “approve once and let it run,” or standing grants. Not built (workplan T-139).
- “Memtara is CBUAE-ready / DFSA-compliant.” Cite the rule, show the control, never claim the status.

---

## 3. Market thesis and category

### Why a UAE/GCC beachhead is defensible

The CBUAE now expects licensed financial institutions to maintain documented AI governance,
accountability, ongoing oversight, AI inventories, appropriate human oversight, data provenance and
audit trails. The guidance explicitly connects AI adoption to risk appetite, control functions and
consumer impact. Mizan should turn that obligation into an executable runtime control rather than sell
another policy repository. See the [2026 CBUAE responsible AI guidance](https://rulebook.centralbank.ae/en/rulebook/guidance-note-consumer-protection-and-responsible-adoption-and-use-artificial-intelligence)
and the [CBUAE enabling-technology guidance](https://rulebook.centralbank.ae/en/rulebook/guidelines-financial-institutions-adopting-enabling-technologies).

This is a market catalyst, not a certification shortcut. Our message is:

> “Your governance says high-impact actions need control and human accountability. Mizan is the
> technical boundary that enforces that rule at the tool call and produces the decision record.”

### Category definition

Use **Enterprise AI Agent Control Plane** as the long-term category and **Agent Action Control** as
the buying wedge.

| Adjacent category | What it is good at | Mizan's complementary role |
|---|---|---|
| IAM / agent identity | Authenticating and governing identities and entitlements | Evaluate the exact action, arguments, resource, intent and risk at execution time. |
| API/MCP gateway | Transport, routing, credentials and service access | Add agent-specific policy, human authority, one-use execution binding and decision evidence. |
| AI firewall / guardrail | Inspecting prompts, outputs, content and AI threats | Decide whether a business action may execute; integrate threat signals as policy context later. |
| Observability | Traces, logs and runtime debugging | Enforce before execution and join the decision to approval and outcome evidence. |
| GRC / AI governance | Inventory, assessments, controls and reporting | Turn selected controls into a live authorization decision and generate runtime evidence. |
| Workflow approval | Routing work to people | Bind approval to an exact agent request and its execution capability. |

Microsoft positions Entra Agent ID around agent identities, lifecycle and access governance;
[Microsoft's own documentation](https://learn.microsoft.com/en-us/entra/agent-id/) is the reason to
position Mizan as a consumer and extension of enterprise identity, not its replacement. Palo Alto's
[Prisma AIRS Agent Security](https://www.paloaltonetworks.com/prisma/agent-security) now claims agent
identity, MCP control and runtime action enforcement, while [Google Model Armor](https://cloud.google.com/security/products/model-armor)
focuses on prompts, responses, agent interactions and data/content threats. The safe competitive line
is therefore narrow: Mizan is purpose-built around **contextual business-action authorization,
risk-based human authority, execution binding, and independently checkable evidence for regulated
workflows**.

Direct startups also offer action authorization and portable evidence. We win only if design partners
value the combined banking policy model, deployment control, approval rigor and evidence-verification
experience. That is a hypothesis to prove, not a moat to announce.

---

## 4. Ideal customer and buying committee

### Primary ICP

A UAE or GCC regulated financial institution that:

- has an AI agent or copilot connected to real enterprise tools, not only a chatbot;
- is preparing a pilot or production release within six months;
- has at least one consequential write, customer-data access, or production-system action;
- has a security, model-risk, or architecture review slowing deployment;
- can give one technical owner and one risk/control owner to a design-partner team;
- prefers private cloud, on-premises, or customer-controlled data/evidence paths;
- can start with one agent and 3–10 tools rather than an enterprise-wide platform program.

### Disqualifiers for the first six months

- “We are exploring AI” with no named agent or tool access.
- A content-generation use case with no consequential tool call.
- A procurement-only conversation with no business owner deploying an agent.
- A demand for full DLP, agent discovery, behavioral analytics, multi-cloud HA, or compliance
  certification before testing the action-control loop.
- A free proof of concept with no agreed success criteria, executive readout, or conversion path.

### Buying committee and message

| Role | Problem to lead with | Proof to show | Desired commitment |
|---|---|---|---|
| Head of AI / AI Platform | “We cannot move agents from demos to real actions safely.” | One gateway integration governs existing tools without changing the model. | Own the deployment and platform budget. |
| Business product owner | “The use case is blocked or too restricted to create value.” | Low-risk work proceeds; only consequential actions pause. | Sponsor the use case and define value. |
| CISO / AppSec | “Agent credentials and tool calls create an uncontrolled blast radius.” | Fail-closed policy, exact-request approval, one-use execution and adversarial tests. | Approve the control design. |
| Enterprise architect | “We need a neutral layer that works with our stack.” | MCP gateway, APIs, Python SDK, private deployment and integration boundaries. | Validate reference architecture. |
| AI governance / model risk | “Policy is documented but not enforced at runtime.” | Policy-to-decision linkage and human authority. | Define control mappings and acceptance. |
| Internal audit / compliance | “Logs depend on the operator telling us they are intact.” | Export a real bundle and let them run the verifier. | Independently test evidence. |
| Platform/SRE | “A fail-closed gateway could become an outage.” | Readiness, metrics, degraded-state behavior, SLO envelope and recovery drill. | Accept operations ownership. |

The economic sponsor should be the AI/platform or business owner deploying the agent. Audit and
compliance are essential validators, but an audit-only sponsor risks making Mizan a cost-center tool.

---

## 5. Use-case portfolio

The sellable form of each use case — buyer, decision matrix, real-versus-simulated table, claim
boundary, outreach opener and qualifying questions — is `MIZAN-USE-CASE-CATALOGUE.md`. This section
keeps the priority order and the acceptance contract; the catalogue is what a seller carries.

### Priority 1 — IT operations agent change control

**Why first:** internal IT has real actions, clear approval authority, existing change-management
language, measurable cycle time, and lower consumer-risk exposure than a live financial transaction.
It exercises the same control loop a bank later needs for customer-impacting actions.

```text
Read service health                 → ALLOW
Search logs / fetch runbook         → ALLOW
Read production secrets             → DENY
Restart production workload         → REQUIRE_APPROVAL
Change firewall rule / database     → REQUIRE_APPROVAL + dual control
Delete resource outside scope       → DENY
```

Success means the IT agent can complete safe diagnostic work without human interruption, cannot
cross a defined boundary, and can resume the exact approved production change with full evidence.

### Priority 2 — Wealth or relationship-manager copilot

This remains the flagship banking narrative from the PRD.

```text
Read portfolio                      → ALLOW
Read risk profile                   → ALLOW
Draft recommendation                → ALLOW (outside Mizan unless a tool action)
Rebalance portfolio                 → REQUIRE_APPROVAL
Rebalance without current consent   → DENY
Send order beyond amount/risk limit → REQUIRE_APPROVAL or DENY
```

Pilot with a mock or non-production execution endpoint first. Move to a live order only after IdP,
failure recovery and customer control requirements pass (custody and durable evidence closed 2026-08-30).

### Priority 2a — Advised-sales suitability: the proof-gated recommendation (Mizan + Memtara)

The only use case in which Memtara is sold, and the one a competitor cannot answer with “IAM plus a
policy engine.” Catalogue UC-2 has the full treatment.

```text
Read client profile / product terms               → ALLOW
Recommend product with valid suitable=true proof  → ALLOW below threshold / REQUIRE_APPROVAL above
Recommend product with no proof                   → DENY  (policy requires proof for this tool)
Recommend product with suitable=false proof       → DENY  — evidenced identically to an approval
Recommend with expired / wrong-ISIN proof         → DENY
Export client financial documents                 → DENY  (the bank holds none)
```

Bring it to every wealth and private-banking conversation. Demonstrate it as two consoles until
T-133–T-137 merge, and say so. Do not lead an account with it — lead with Priority 1 or 2 and earn the
right to show it.

### Priority 3 — Customer-service agent with bounded service changes

```text
Read account/card status            → ALLOW with verified customer context
Create a low-risk service ticket    → ALLOW
Change address or contact details   → REQUIRE_APPROVAL / step-up
Expose full customer profile        → DENY by policy boundary
Send data to an unapproved tool     → DENY
```

Do not claim content DLP or prompt-injection detection. The pilot control is tool, resource,
destination and context authorization. Add security-engine signals only after the modules are wired.

### Priority 4 — KYC/AML case-work agent

```text
Read assigned case                  → ALLOW
Request approved data source        → ALLOW
Change risk classification          → REQUIRE_APPROVAL
Close or escalate a case            → REQUIRE_APPROVAL
Access another jurisdiction/tenant  → DENY
```

This is attractive for evidence and separation of duties, but integration and data-residency review
will be heavier than the internal IT wedge.

### Priority 5 — Payment/operations exception agent

This is the highest-value proof and the highest-risk first deployment.

```text
Read payment state                  → ALLOW
Prepare an exception packet         → ALLOW
Release / reroute / reverse payment → REQUIRE_APPROVAL + dual control
Execute above threshold             → DENY or enhanced approval
```

Use this as an executive demo and later expansion. Do not make it the first live customer action unless
the customer already has a contained sandbox and named operational authority.

### Standard IT acceptance contract for every use case

The customer's IT team should be able to handle the use case smoothly only when all twelve conditions
are demonstrated:

1. Agent, human principal, customer/business principal and tool identities are unambiguous.
2. Every tool has an owner, schema, risk tier, bound arguments and permitted executor.
3. `ALLOW`, `DENY`, `REQUIRE_APPROVAL` and control-plane-unavailable paths are tested.
4. A denied or unavailable decision never reaches the upstream tool.
5. Approval shows the exact tool, resource and material arguments the human is authorizing.
6. Self-approval, stale approval, duplicate execution and replay are refused.
7. Approval resumes without making the user repeat the original business request.
8. Outcome and failure are joined to the original decision.
9. Evidence drains, anchors, timestamps, exports and verifies without manual worker intervention.
10. Logs/metrics identify the tenant and decision without exposing raw sensitive payloads.
11. Backup/restore and key/credential rotation do not invalidate retained evidence silently.
12. The customer can disable Mizan safely: consequential actions fail closed, and a documented
    break-glass path belongs to the customer—not to the model or gateway.

---

## 6. The commercial offer

### Offer name

**Mizan Controlled Agent Pilot**

### Promise

> Give us one agent and 3–10 tools. Together we will place an enforceable policy and approval boundary
> around its consequential actions, then hand your security or audit team a decision bundle they can
> verify independently.

### Scope

- One business or IT use case.
- One customer-controlled environment.
- One agent framework or MCP client.
- 3–10 tools with read/write/risk classification.
- Up to five policies covering allow, deny and approval paths.
- One approval workflow with customer-defined roles and quorum.
- Operator dashboard and decision/evidence views.
- Evidence export plus two offline verification paths.
- Architecture, threat-boundary and operational-readiness workshop.
- Final control-effectiveness report and production recommendation.

### The Memtara option — UC-2 only

When the use case is advised-sales suitability, the pilot adds: one registered instrument family in
Memtara's product registry, the reference client standing in for the customer's app, Memtara deployed
from the container image (workplan M-02) in the customer's environment, and the proof-gated Cedar policy
(T-134). It does not add a second sales motion, a second dashboard, or a second price list. The exit test
for the *Prove* phase becomes: the customer's compliance officer verifies **one** bundle containing the
Mizan decision and the Memtara proof.

### Delivery shape

The commercial clock begins after access, identity, deployment and tool-owner prerequisites are met.

| Phase | Target | Deliverable | Exit test |
|---|---:|---|---|
| Qualify | 1 week | Use-case/control canvas and mutual success plan | Named sponsor, agent, tools, impact, owners and decision date. |
| Integrate | 2 weeks | Gateway/SDK path, registry and initial policies | Read action allowed; forbidden action stopped. |
| Govern | 1 week | Approval roles, quorum, execution binding and UI | Consequential action pauses and resumes exactly once. |
| Prove | 1 week | Evidence bundle, verifier exercise and operations pack | Customer risk/audit party runs a verifier themselves. |
| Decide | 1 week | Results, gaps, rollout and commercial proposal | Executive go/no-go with owner and date. |

Customer procurement may make the calendar longer; the technical work should remain a six-week
bounded engagement.

### Commercial hypotheses

These are internal test bands, not public pricing:

- Paid pilot: **USD 50k–100k** depending on deployment and integration burden.
- Initial annual platform contract: **USD 150k–300k**, including one environment and a governed-action
  allowance; private deployment, support, additional environments and custom integrations priced separately.
- No unlimited free proof of concept. A founder-authorized lighthouse exception must buy a concrete
  asset: public reference permission, regulator/auditor access, a strategic integration, or a named
  conversion event.
- **No bundle price.** The USD 200k three-product figure is withdrawn. For UC-2, test a Memtara module
  uplift of **USD 25k–50k** on the pilot and a corresponding line on the annual contract, priced on the
  evidence outcome (a regulator-re-verifiable suitability record), never on “ZKP.” Founder to ratify the
  band after the first three UC-2 conversations.

Pricing must be tested in ten qualified conversations before a public rate card. Charge for controlled
production capability and risk reduction, not registered-agent count alone.

### Pilot success scorecard

| Dimension | Required outcome |
|---|---|
| Coverage | 100% of in-scope tool calls traverse Mizan. |
| Control | All agreed consequential actions pause or deny according to policy. |
| Bypass | No tested direct/bypass path reaches the protected tool. |
| Identity | Agent, principal and approver are attributable; self/weak approval is refused. |
| Execution | Approved action executes once with the reviewed arguments. |
| Evidence | Every governed call has a decision record and outcome state. |
| Independence | At least one customer risk/audit person runs the verifier without Mizan operating it for them. |
| Operability | Customer IT completes install, incident, restore and key/credential procedures from runbooks. |
| Efficiency | Integration time, approval time and security-review time are measured against the customer's baseline. |
| Business | Executive sponsor commits to expansion, annual contract, or a written no-go reason. |

---

## 7. Brand, look and experience direction

### Brand idea

Mizan means balance. The experience should communicate **measured authority**: calm, exact and
institutional—never alarmist “AI cyber” theater.

**Brand freeze.** A separate company, Mizan AI (DIFC), publicly positions itself with nearly identical
language for the same buyers (`verdict.txt`). Until a trademark and brand-conflict review concludes:
no paid promotion of the name, no signage, no domain spend beyond defensive registration, and the
editorial pack's qualifier (“Mizan Agent Control”) is the fallback. Engineering has costed a rename at
3–5 days with four customer-breaking surfaces (workplan T-140); it is cheap, so the decision is purely a
legal and market one, and it must be taken before the first public campaign.

The current graphite/black interface with jade, amber and red accents already communicates a serious
control room. Preserve the restraint and semantic colors. Refine it into a credible financial control
product rather than a developer dashboard.

### Visual system

- **Product palette:** deep ink/charcoal and warm neutral surfaces; jade for permitted/verified,
  amber for review/pending, red only for denied/failed/critical, blue for informational provenance.
- **Typography:** use a highly legible sans-serif for operational data and tabular numerals. Reserve
  an editorial serif for the marketing site or major empty-state statements, not dense approval data.
- **Density:** compact tables for operators; generous hierarchy in approval and evidence detail.
- **Motion:** minimal. Use motion only to show state transition or execution resumption.
- **Language:** plain English first with Arabic layout/readiness designed now; do not retrofit RTL.
- **Accessibility:** WCAG 2.2 AA contrast, visible focus, full keyboard operation, non-color state
  labels, screen-reader announcements and a 200% zoom acceptance test.

### Experience architecture: Before, At, After

1. **Before action — Control design:** agent/tool inventory, risk tier, binding profile, policy status,
   and simulation evidence.
2. **At action — Decision and authority:** decision stream, exact proposed impact, reasons, policy,
   approval quorum and one-use execution state.
3. **After action — Proof:** outcome, receipts, timeline, anchor/attestation, export, independent
   verification and limitations.

This is both the information architecture and the sales narrative.

### Immediate truth-in-interface corrections

| Current presentation | Required correction |
|---|---|
| Static green “Production control plane” | Derive environment, connectivity and readiness from the runtime. Never render `Production` until production configuration is verified. |
| “Decisions, without blind spots” | Use “Every governed action, decided before execution.” Mizan has deliberately disclosed blind spots. |
| “Every action leaves evidence” | Use “Every governed action leaves evidence.” |
| “Security alerts” count | Rename to the exact event class being counted or remove it until a security detection source is shipped. |
| “Independent integrity check” over the live Mizan API | Call it “Control-plane integrity check.” Reserve `independent` for exported bundles run through offline verifiers. |
| Policy “replay” | Call it “Policy impact preview” or “simulation”; state that full historical decision recomputation is not shipped. |
| Raw decision IDs in approval queue | Lead with agent, proposed action, resource/customer, impact, risk, reason and time remaining. |
| Override/escalate beside routine voting | Keep outside the normal sales path; render only with server-confirmed authority, confirmation and justification. |

### Priority screens

| Priority | Screen | It must answer |
|---|---|---|
| P0 | Approver action review | What exactly will happen, to which resource/customer, why, under whose authority, and what changes if I approve? |
| P0 | Live decision detail | Why did Mizan allow/deny/pause; which policy and context mattered; did the upstream tool execute? |
| P0 | Evidence export and verifier result | What checks passed, what assurance is derived, what is not covered, and how can an external party repeat it? |
| P0 | IdP login / approval step-up | Who is acting, what auth strength was used, and when does the session expire? |
| P1 | Use-case control map | Which tools/actions are governed and where are the gaps? |
| P1 | Agent/tool inventory | Who owns it, what can it access, risk, environment and last governed activity. |
| P1 | Policy simulation | What would change before a policy becomes active? |
| P1 | Operational health | Is authorization, drain, attestation and evidence storage healthy; what is the safe response? |

### Approval design requirements

The current approval UI exposes many raw identifiers and governance controls. For a buyer demo and a
pilot, lead with the decision a human must make:

- Human-readable action title: “Rebalance customer portfolio” or “Restart production payments API.”
- Expected impact, amount/environment, destination and irreversible effects.
- Agent, acting principal, customer/resource and business intent.
- Material argument diff with secrets and sensitive values safely represented.
- The policy clause and risk signal that caused approval.
- Required roles/domains, votes received, deadline and consequences of expiry.
- Separate `Approve`, `Reject`, `Abstain`, `Escalate` and `Override` actions with guard explanations.
- Step-up authentication immediately before a high-risk vote.
- Final receipt: approved request hash, executor, outcome and evidence link.
- Visible tenant, user, role/control domain, authentication strength, session expiry and runtime
  environment; none may be inferred in the browser.

Never ask a bank approver to paste a JWT. Never make cryptographic hashes the primary explanation;
make them available as evidence detail.

### Design acceptance gates

- Five target users—AI platform, CISO/AppSec, approver, auditor and SRE—complete their primary task
  without coaching.
- A new approver identifies the agent, action, customer/resource, amount/impact and approval effect in
  under 30 seconds.
- A decision detail distinguishes “denied,” “not executed,” “execution failed,” and “evidence cannot
  be checked” without relying on color.
- A third party downloads a bundle and reaches the correct verifier command from the UI.
- Every roadmap capability is visibly labeled; no empty navigation item implies a shipped module.
- Customer strings render only as data, never as HTML; raw payloads and secrets are not placed in logs
  or analytics.
- Pending, stale epoch, self-approval, duplicate vote, unauthorized override, expiry, disconnected,
  partial-evidence and server-error states have real browser/DOM acceptance tests.

---

## 8. Sales strategy

### Account model

Start with a named-account motion, not broad inbound.

- **Tier 1:** 15 UAE institutions—banks, digital banks, wealth/private banks, payment institutions,
  and regulated fintechs with visible agent programs or direct team access.
- **Tier 2:** 25 GCC institutions with the same triggers, especially Saudi and Qatar after the UAE
  reference motion is repeatable.
- Map five contacts per account: AI/platform owner, business use-case owner, CISO/AppSec, architecture,
  and governance/risk.
- Every target account must have a one-page hypothesis naming the agent, likely tools, consequential
  action, review blocker and relevant control owner.

### Sales stages with hard exit criteria

| Stage | Exit criterion |
|---|---|
| Targeted | Named agent/use case and three likely stakeholders. |
| Problem validated | Buyer confirms a consequential tool call, review/control gap and target date. |
| Technical proof | Buyer sees allow, deny, approval, fail-closed and offline verification. |
| Workshop | Customer maps 3–10 tools, owners, risks, approval authority and deployment constraints. |
| Qualified pilot | Sponsor, budget path, security owner, technical owner, success scorecard and decision date. |
| Pilot live | In-scope traffic governed in customer environment. |
| Expansion | Second agent/use case or production annual contract with a named rollout. |

No opportunity enters forecast from a generic “AI governance” conversation.

### Discovery questions

1. Which agents can call tools or APIs today, and which are expected to within six months?
2. What is the most consequential action one can attempt?
3. Where is approval policy documented, and what enforces it at the exact tool call?
4. Whose identity and authority does the agent carry?
5. What happens if the policy/control service is unavailable?
6. Can you prove the exact arguments a human approved are the ones executed?
7. Which team currently reconstructs agent activity after an incident or review?
8. Would your risk/audit team run an independent verifier, or are normal signed logs sufficient?
9. What deployment, residency, IdP, key-custody and retention controls are mandatory?
10. What decision and date would make a six-week pilot worth funding?

### Objection handling

| Objection | Response |
|---|---|
| “Our IAM already authorizes the agent.” | IAM establishes identity and entitlement. Mizan evaluates the exact action, context and material arguments, and binds human approval to execution. We integrate with IAM. |
| “Our AI firewall blocks prompt injection.” | Keep it. Its threat signal can become Mizan policy context. Mizan's first job is business-action authorization, not replacing content inspection. |
| “Our workflow already approves transactions.” | Mizan can call or complement that workflow; the differentiator is joining the agent request, reviewed arguments, policy, one-use execution and evidence. |
| “We have logs.” | If logs meet the requirement, do not buy evidence for its own sake. Let your audit party run the verifier and decide whether independent portability changes the control outcome. |
| “A fail-closed gateway adds latency/outage risk.” | Correct; it is an inline control. We provide a measured capacity envelope, health/lag signals and a customer-owned continuity design before production. We do not hide the trade-off. |
| “A major security vendor will add this.” | They may. Mizan must win on time-to-control, banking policy/approval depth, deployment neutrality and evidence rigor—not on feature-category novelty. |
| “Is this one product or three?” | One product with one optional proof module. Mizan governs the action; for suitability, the client's device proves the predicate and Mizan verifies it. There is no third product. |
| “Why zero-knowledge at all — we can just store the documents.” | You can, and you then hold a permanent copy of the client's finances so that one bit can be recorded. The proof gives the regulator a re-verifiable record and gives you nothing to breach. If your DPO is comfortable with the file, buy Mizan alone. |
| “Can we approve once and let the agent run for a month?” | Not today, and we will not pretend otherwise. What ships is proportional autonomy by policy tier — reads flow, consequential writes pause. Standing grants are a designed feature we will build against a written pilot requirement (T-139). |

---

## 9. Marketing strategy

### Message hierarchy

1. **Outcome:** Move AI agents from recommendations to controlled actions.
2. **Mechanism:** Evaluate identity, intent, context, tool, resource and risk before execution.
3. **Authority:** Pause consequential actions for the right human decision.
4. **Proof:** Bind decision, approval, execution and outcome into portable evidence.
5. **Fit:** Neutral control layer for regulated, customer-controlled environments.

### Homepage draft

**Headline:** Control every consequential AI-agent action.

**Subhead:** Mizan sits between enterprise agents and their tools, enforcing policy and human authority
before execution and producing evidence your risk team can verify independently.

**Primary CTA:** Run the controlled-action demo.

**Secondary CTA:** Verify a sample evidence bundle.

### Required launch assets

| Asset | Owner | Acceptance |
|---|---|---|
| Seven-minute controlled-action demo | Product Marketing + Engineering | Runs from a clean environment; shows allow, deny, approval, execution and both verifiers. |
| 90-second narrative video | Product Marketing + Design | No roadmap screens or unverified claims; captions and Arabic-ready composition. |
| Controlled Agent Pilot brief | Business + Sales | Scope, prerequisites, scorecard, exclusions and conversion decision. |
| Three use-case briefs | Product Marketing | IT operations, wealth/RM, customer service; exact action matrix in each — derived from `MIZAN-USE-CASE-CATALOGUE.md`. |
| Proof-gated suitability brief (UC-2) | Product Marketing + ZKP Engineering | Two-console version now; single-transaction version only after T-133–T-137 merge. Real-versus-simulated table reproduced verbatim from the catalogue. |
| “Can your auditor verify it?” kit | Marketing + Evidence Engineering | Sample bundle, two commands, trust-root explanation, expected verdict and limitations. |
| Security and architecture pack | Security + Product | Threat boundary, data flows, deployment, identity, custody, retention, failure modes and open gaps. |
| CBUAE control mapping | Governance + Counsel | Maps guidance themes to evidence without claiming certification or legal advice. |
| Competitive battlecard | Product Marketing | IAM, AI firewall, gateway, observability, GRC and closest action-control alternatives; updated monthly. |
| Claims register | Product Marketing + Engineering | Every external claim points to shipped code/test/evidence or is labeled roadmap. |

### Content pillars

- **From policy to enforcement:** why “human oversight required” is incomplete unless a tool call
  actually pauses.
- **Agent authority:** identity is necessary; action context and exact-request authority are the next
  control.
- **MCP in regulated enterprises:** govern tools without trusting the model to police itself.
- **Evidence, honestly:** what offline verification proves and what it does not.
- **Regulated use-case patterns:** safe reads, controlled writes, dual control and fail-closed behavior.

Use demonstrations and technical artifacts as content. Avoid fear-heavy “rogue agent” marketing.

### Campaigns

1. **The Governed Tool Call:** a live monthly session where a guest CISO/architect chooses the policy
   and the audience tries allow, deny and approval paths.
2. **Verifier Challenge:** give risk and audit professionals a sample bundle before a sales call and
   ask them to alter it, verify it and report what the result means.
3. **UAE Agent Control Roundtable:** 8–10 invite-only AI, security and governance leaders; no product
   pitch for the first half; publish anonymized control requirements afterward.
4. **One Agent, Ten Tools:** account-based workshop that turns a live use case into a control matrix
   and a paid-pilot proposal within five business days.

---

## 10. Ambitious cross-functional mandate

### By 30 September 2026 — become commercially demonstrable

| Team | Task | Definition of done |
|---|---|---|
| Founder/Business | Name the first 15 UAE accounts and one executive hypothesis per account. | Five warm introductions, ten cold paths, one named owner per account in CRM. |
| Sales | Complete 20 problem interviews; at least 12 with live/planned agent tool access. | Interview evidence captures agent, tools, action, blocker, sponsor and decision date. |
| Product Marketing | Finalize category, homepage, pilot brief, claims register and two battlecards. | Engineering signs every “shipped” claim; no forbidden claims. |
| Design | Prototype P0 approval, decision and evidence journey plus OIDC/step-up. | Five-user test; approval comprehension gate passes. |
| Engineering/IT | Custody and durable evidence closed 2026-08-30. Close WS-0 hygiene, key rotation, production compose, full-journey production E2E and the customer install gate (workplan T-120–T-131). | Clean CI plus supported deployment path; `production-e2e` green. |
| ZKP Engineering | Merge Memtara `evidence-v1` through CI; container image with vendored toolchain on x86_64 and arm64; close attested re-mint (workplan M-01–M-03). | Green `main` at the merged SHA; multi-arch image published from CI. |
| Security/Governance | Produce customer security pack and CBUAE mapping; ratify TM-001, open TM-002 for the Mizan↔Memtara seam. | Every limitation/open control is explicit; counsel reviews regulatory language. |

### By 31 October 2026 — create qualified demand

| Team | Task | Definition of done |
|---|---|---|
| Sales | Deliver 12 tailored demos and six control-mapping workshops. | Four qualified pilots with sponsor, use case, technical owner, success plan and date. |
| Business | Form a six-member design-partner council. | At least two AI/platform leaders, two security/risk leaders and two audit/governance participants. |
| Marketing | Launch verifier challenge and three use-case briefs. | Ten external verifier runs or documented refusals; source and role recorded. |
| Product/Design | Ship the bank-pilot console experience. | IdP login, step-up approval, action impact view, evidence export and operations health pass. |
| Engineering/IT | Complete the independent stranger walkthrough and restore drill. | Published corrections, rerun green after corrections. |
| Engineering (seam) | Ship the Mizan↔Memtara seam: proof verification, proof-gated policy, one cross-anchored bundle, SDK/MCP carriage, one-command demo (workplan T-133–T-138). | Both offline verifiers PASS a bundle containing a real Memtara proof; UC-2 moves to Technical Preview in the catalogue. |

### By 30 November 2026 — turn demand into contracts

| Team | Task | Definition of done |
|---|---|---|
| Sales/Business | Close three paid design partners. | Signed scope, paid fee, named agent/tools, environment, sponsor and executive decision date. |
| Customer Engineering | Bring the first partner's agent through shadow then enforce mode. | 100% in-scope coverage; no bypass; allow/deny/approval/failure paths accepted. |
| Marketing | Publish one customer-approved technical case study or anonymized benchmark. | Includes measured integration/control outcomes, not testimonial-only copy. |
| Product | Rank expansion requests by repeated paid demand. | No roadmap addition based on one unqualified prospect. |

### By 28 February 2027 — prove repeatability

- Two annual platform conversions at the internal target band, or explicit pricing/buyer revision.
- Five total paid pilots started; three complete.
- Two customer teams have run an offline verifier without Mizan operating it for them.
- At least one real security review is accelerated or passed because of runtime control evidence.
- A second agent/use case is added by one customer, proving land-and-expand.
- Median time from tool inventory to first governed action is below ten working days.
- A written founder review decides whether the next investment is: more integrations, security-signal
  ingestion, governance reporting, or a different wedge. The Architecture Copilot remains parked
  unless customers repeatedly pay for it.

---

## 11. Operating cadence and accountability

### Weekly revenue-and-truth review — 45 minutes

1. Funnel by hard stage and next customer decision date.
2. What buyers actually said; no activity-only reporting.
3. Which product claim was challenged and what evidence supports it.
4. Demo and pilot readiness: custody, durability, identity, E2E, restore and walkthrough.
5. Falsification-test count: offered verifier / ran verifier / asked for record / sponsor function.
6. One stop-doing decision.

### Friday end-to-end review — 30 minutes

One person runs the marketed story from the customer entry point. The reviewer must show:

```text
agent request
→ policy decision
→ human authority
→ bound execution
→ outcome
→ export
→ independent verification
```

Any broken link blocks a “pilot-ready” claim. A screenshot or unit test is not a substitute for the
journey.

### Monthly founder review

- ICP conversion by segment and use case.
- Economic sponsor: business/AI platform versus audit-only.
- Pricing objections and willingness to pay.
- Competitive changes and lost reasons.
- Falsification tests from `docs/product/FALSIFICATION_TESTS.md`.
- Roadmap additions only when supported by repeated, qualified demand.

### Decision rights

| Decision | Accountable |
|---|---|
| Category, ICP, pricing hypothesis and commercial exceptions | Founder / Business Head |
| External product claims | Product Marketing, with Engineering evidence sign-off |
| Use-case acceptance and release gate | Product Head |
| UX system and workflow comprehension | Design Head |
| Production readiness, SLOs and supported deployment | Engineering/IT Head |
| Threat/control assertions | Security Head |
| Memtara proof-module readiness and any circuit claim | ZKP Engineering owner, with Security Head |
| Regulatory interpretation | Customer counsel / qualified legal adviser, never Marketing alone |

---

## 12. Metrics that matter

### North star

**Governed consequential actions:** meaningful tool actions for which Mizan establishes identity and
context, makes an enforceable decision, binds any required human authority, records the outcome and
produces verifiable evidence.

### Commercial leading indicators

- Qualified accounts with a named agent and consequential action.
- Control-mapping workshops completed.
- Paid pilot proposals and conversion rate.
- Days from first meeting to technical workshop and from workshop to paid decision.
- Multi-threading depth across business, AI/platform, security and governance.
- Verifier offered / independently run / refused.

### Product value indicators

- Percentage of in-scope tool calls governed.
- Time from tool inventory to first governed action.
- Safe-read straight-through rate.
- High-risk action approval/denial rate and time to decision.
- Bypass, replay and wrong-executor attempts blocked.
- Evidence publication/attestation lag and export success.
- Time to answer a real review, incident, dispute or audit request.

Do not optimize registered agents, page views, MQL volume or raw decision count until these measures
show that customers are receiving control value.

---

## 13. Stop rules

The plan is ambitious because it has failure conditions.

- If fewer than 10 of 20 qualified interviews identify a consequential action-control gap, revisit
  the wedge before building more modules.
- If fewer than three of 15 audit/risk conversations run the offered verifier, treat independent
  verification as support evidence—not the lead differentiator—per F-T-1.
- If security reviews pass with policies and screenshots alone, evidence is not the deployment
  constraint; reposition around authorization or change the market, per F-T-3.
- If every sponsor is internal audit and no business/AI-platform owner funds a pilot, price and plan
  Mizan as a cost-center product or stop using growth-product assumptions, per F-T-4.
- If six qualified workshops yield no paid pilot, examine offer, trust/readiness and urgency before
  adding features.
- If a major platform wins on “good enough” agent control, narrow to the regulated workflow where
  Mizan can prove superior approval/evidence outcomes—or partner instead of fighting the suite.
- If, across the first six wealth or private-banking conversations, no compliance officer says the
  client-side proof changes a control outcome they are measured on, Memtara is an engineering aesthetic
  in this market: stop the seam work after T-133 and sell Mizan alone, per F-T-6.

---

## 14. Define → Build → Review → Sell protocol

No use case enters collateral, a demo, or a proposal because a feature exists in isolation. Each use
case moves through one shared release packet.

### Define

Business, product, security, design and customer IT create a two-page **Use-Case Control Canvas**:

- business outcome and economic sponsor;
- agent, principal, tools, resources and consequential actions;
- allow/deny/approval matrix and human authority;
- customer impact, data classes, residency and trust boundaries;
- integration, IdP, custody, retention, availability and recovery requirements;
- exact success measures, exclusions and decision date.

**Definition gate:** every tool/action path has an owner and expected decision; every external claim is
in the claims register; no roadmap module is required for the promised outcome.

### Build

Engineering implements or configures only what the accepted canvas needs. Design produces the operator,
approver and auditor journey over real API fields. Marketing writes from the claims register, not from
mock screens.

**Build gate:** the customer path proves allow, deny, approval, unavailable/fail-closed, exact-request
execution and evidence. Production-required custody, identity, durability and operations gates are
green for a pilot claim.

### Review

Four reviewers walk the same scenario independently:

1. Business owner: safe work completes and the high-impact boundary matches the operating policy.
2. Customer IT/SRE: install, observe, fail, recover and restore from the documented path.
3. Security/approver: bypass fails; approval identity, quorum and exact action are clear.
4. Auditor/risk: export the bundle, supply trust roots and run an offline verifier without Mizan doing
   it for them.

Every issue is recorded as **claim defect**, **experience defect**, **control defect**, **operability
defect**, or **new scope**. New scope does not silently enter the release.

**Review gate:** all P0 defects close or appear explicitly as proposal exclusions; the full journey is
rerun after corrections; the reviewer signs the one-page commercial truth card.

### Sell

Sales receives a versioned release packet containing:

- the exact pitch and claims register;
- live demo and deterministic backup transcript;
- supported use cases, deployment model and integration boundary;
- security/architecture and operations packs;
- measured performance/capacity envelope;
- known limitations and roadmap, clearly separated;
- pilot scope, prerequisites, scorecard, price hypothesis and conversion event.

If the packet is incomplete, the team may run discovery but may not call the product pilot-ready.

## 15. The single company task

> **By 30 November 2026, make one regulated institution able to put one real agent with 3–10 tools
> behind Mizan, allow its safe work, stop or pause its consequential work, approve and execute the
> exact request once, and hand the resulting evidence to a person outside the deployment who verifies
> it without trusting Mizan. Then earn the right to expand.**

Everything—sales, marketing, design, engineering, security and business development—should be judged
against that sequence.
