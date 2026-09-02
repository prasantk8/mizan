# TM-003 — Model endpoint ↔ agent/gateway boundary, Threat Model v1

**Status:** SKELETON — boundary definition for T-145; controls belong to T-144
**Date:** 2026-09-02
**Scope baseline:** Mizan `cf143e0`. **No model runtime exists in this tree at this SHA** — there is no
model client in `control-plane/`, no compose profile serving an inference endpoint, and no egress
assertion anywhere in CI.
**Companion documents:** `TM-001-control-plane-v1.md`, `TM-002-memtara-seam-v1.md`,
`../docs/product/GOVERNED-PRIVATE-STACK.md`, positioning workplan WS-P1 (T-144, T-146)

---

## 0. Purpose and current truth

This model fixes a boundary **before** T-144 introduces the component that creates it. The private-stack
positioning rests on a claim about where the customer's model runs and what does not leave the
perimeter; a claim of that shape needs a threat model, not a diagram.

Every control below is **planned**. This skeleton permits design and review. It does not permit the
claim that a private model stack is demonstrated, tested or hardened — the claims register (§4) marks
the word "AI" as *not sayable until T-144*, and nothing here changes that.

**What is genuinely different about this boundary,** and the reason it gets its own model rather than a
TM-001 section: it is the first boundary in this system where **the adversary may be the component we
are protecting the customer's data from and the component the customer chose, at once.** A model
endpoint is attacker-influenced by construction — anything in its context window is untrusted input
that reaches it — and it is also the customer's own infrastructure, which we neither ship nor patch.

---

## 1. Assets and security objective

The boundary must preserve four facts:

1. that the model endpoint receives no Mizan credential, key, token or evidence material;
2. that a model's output is treated as a **proposal** everywhere, and never as an authorization;
3. that data crossing into the model's context is the customer's choice and does not leave their
   perimeter as a side effect of Mizan being present;
4. that the demonstration recording (T-144) shows what actually happened, including when the model
   behaved badly.

**The objective is narrower than "the model is safe."** A completed T-144 can establish that a
consequential action proposed by a model was decided by policy before execution, and that the
containers involved made no connection outside the compose network during the run. It cannot establish
that the model is aligned, that its reasoning was sound, or that a different model would behave the
same way. Mizan's security argument deliberately does not depend on any of those.

---

## 2. Adversaries

| ID | Capability | Goal |
|---|---|---|
| **P-A1** | Prompt-injection content reaching the model's context (a document, a tool result, a web page) | Induce a consequential tool call the user never asked for |
| **P-A2** | The model itself, hallucinating or mis-parameterised | Emit a plausible-looking call with wrong arguments — wrong account, wrong amount, wrong ISIN |
| **P-A3** | A compromised or substituted model image / weights | Emit targeted malicious calls that look ordinary in aggregate |
| **P-A4** | Network position between agent and model endpoint | Read or alter proposals in flight; observe customer data in prompts |
| **P-A5** | A model runtime that phones home — telemetry, licence check, update fetch | Exfiltrate prompt content, defeating the deployment-privacy claim |
| **P-A6** | Whoever authors the demo scenario | Produce a recording that flatters the product: a scripted denial presented as a live one |
| **P-A7** | A model-runtime image importing CVE debt | Widen the supply-chain surface while T-120's re-triage is deferred (risk R-6) |

**P-A1 and P-A2 are not Mizan's to prevent, and this is the whole argument.** The control for both is
that their output is a proposal that policy decides on, before execution, with an evidence record
either way. A model that proposes a forbidden action and is denied is the product working. The threat
this model must actually address is anything that lets such a proposal become an action *without* that
decision — which is P-A3 through P-A5, plus the demo-integrity threat P-A6.

---

## 3. Trust boundary

```text
  untrusted content (documents, tool results, retrieved text)
                        │
                        ▼
 ┌──── P-1 model boundary — NOT OURS, NOT TRUSTED ──────────────────┐
 │  customer's model endpoint, customer's hardware or account       │
 │  Mizan ships no code here and opens no connection to it          │
 │  everything it emits is a proposal                               │
 └──────────────────────┬───────────────────────────────────────────┘
                        │ proposed tool call (untrusted)
                        ▼
 ┌──── P-2 agent / gateway boundary ────────────────────────────────┐
 │  customer's agent + `mizan_mcp_gateway`                          │
 │  holds Mizan credentials; the model must never see them          │
 │  forwards the proposal; decides nothing                          │
 └──────────────────────┬───────────────────────────────────────────┘
                        │ POST /v1/authorize
                        ▼
              [ TM-001 §3 control-plane boundary ]
```

**The credential asymmetry is the load-bearing property of P-2.** The agent holds an agent token and
may hold a Memtara proof; the model holds nothing. Any design in which a model is handed a credential
so it can "call Mizan itself" moves the trust boundary to the wrong side of P-1 and must be refused.

---

## 4. Controls that T-144 must implement, not assume

| ID | Control | Why it is not optional |
|---|---|---|
| **P-C1** | The compose profile is **egress-isolated**, and a test asserts that no external connection is attempted during the run | This assertion *is* the private-stack claim (workplan T-144). Without it the claim rests on reading code — see the architecture note §4 |
| **P-C2** | The model image and weights are **pinned by digest**, and the digest is recorded in the run artifact | Otherwise P-A3 is undetectable and the recording is not reproducible |
| **P-C3** | No Mizan credential, key or evidence material is present in the model container's environment or its context window | P-1 is a trust boundary or it is decoration |
| **P-C4** | The demo image passes the same `production-image` scan lane, with **zero new allowlist entries** without a dated justification | Risk R-6. Deferring the *existing* CVE debt (T-120) is a founder ruling; adding new debt is not |
| **P-C5** | Deterministic decoding (temperature 0, pinned seed where the runtime allows), and the transcript reproduced by CI from a clean tree with `worktree_clean: true` recorded | Risk R-5, and the named anti-pattern is in this repository: the `demo_memtara` transcript was a hardcoded constant no run produced |
| **P-C6** | **A model action that gets DENIED stays in the recording, deliberately** | Risk R-9. Removing it would make the recording an advertisement. The denial is the product argument; a demo in which the model only ever behaves is a demo of nothing |

**P-C6 is a control, not a stylistic preference.** It is the counter to P-A6, and it is the one most
likely to be quietly dropped under demo pressure.

---

## 5. Residuals a green T-144 will not close

| ID | Residual | Disposition |
|---|---|---|
| **P-R1** | Prompt injection (P-A1) is not prevented, only contained by the fact that the resulting proposal is decided on before execution | Accepted and stated. Mizan is not an AI firewall and the catalogue already refuses that product. Containment is the claim; prevention is not |
| **P-R2** | Model correctness (P-A2) is out of scope entirely | Accepted. Stated in the architecture note §5 — "we do not evaluate whether the model was right" |
| **P-R3** | One recorded run on one pinned model is not evidence about other models, other prompts, or adversarial inputs the scenario did not contain | Do not generalise the recording. The claims-register row for "AI" must name the model and the scenario |
| **P-R4** | Egress isolation proven in a compose network is not proven in the customer's deployment, where the network is theirs | The test asserts our reference profile makes no outbound connection; it cannot assert anything about how a customer wires it. Say which one you mean |
| **P-R5** | A customer-hosted model *account* (rather than local weights) reintroduces an external dependency the demo's isolation excludes | Two different deployments with two different privacy stories. The register row must not silently cover both |
| **P-R6** | The model runtime is third-party software we neither patch nor support | Version and digest recorded; patching is the customer's, as with their database |

---

## 6. Questions T-144's PR must answer

1. Which runtime and which pinned model digest, and is the choice defensible on a customer's hardware
   — or does the demo require a machine the buyer does not have?
2. How is "no external connection was attempted" actually asserted — network-namespace denial, a
   recording proxy, or a DNS sinkhole — and what does a **passing** assertion prove versus what does a
   failing one prove?
3. Does the scenario's DENY arise from the model genuinely proposing a forbidden action, or is it
   scripted? If scripted, the recording must say so in the recording, not in a footnote.
4. What exactly is in the model's context window, and is any of it customer-shaped data that would make
   the transcript unpublishable?
5. When the live model is replaced by a scripted stub in CI (risk R-9's fallback), **which is which in
   the register row**, and how does a reader of the nightly artifact tell?
6. What happens to the recording when the pinned model is superseded — is the claim withdrawn, or does
   the artifact carry its own expiry?

Answers belong in T-144's PR body and in the claims register, not in a constant inside the demo script.

---

## 7. What this skeleton deliberately does not do

It does not rank the residuals, because ranking them before the component exists would be guessing. It
does not propose an AI-firewall control for P-A1: that is a product we have said we do not sell, and
adding it here would contradict the catalogue. And it opens no residual against the model's *content* —
Mizan's argument has never depended on the model behaving, and a threat model that quietly starts
depending on it would weaken the product rather than harden it.
