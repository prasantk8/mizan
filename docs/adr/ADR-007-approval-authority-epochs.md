# ADR-007: Approval Authority — Epochs, Dual Control & Rejection Semantics

**Status:** ACCEPTED (R-003 ratified in all required roles)
**Deciders:** Product/Architecture Lead, Cybersecurity Architect, **Compliance/Business sign-off required** (this ADR defines approval semantics — WORK_LOG H-7 escalation)
**Date:** 2026-08-25
**Spec anchors:** SPEC v1.3 §2.2/§2.7 (Policy/Approval/Epoch/Vote), §5.2, Guards G1–G9, Invariants I-6, I-15, I-22, V-2/V-3/V-4/V-5/V-14
**Trigger:** baseline review R-001 — undefined escalation membership and race semantics; role labels counted as authority; universal single-REJECT veto

## Context

v1.0 said escalation "re-enters PENDING with escalation approver pool" and left five questions unanswered: is the original pool replaced or augmented, do earlier approvals still count, may original approvers still vote, does the TTL restart, and who wins when a vote races the escalation transaction. Any combination of answers is *defensible*; leaving them unstated means two conforming implementations can satisfy a quorum from different authority sets, and neither is wrong. In a bank, "which humans actually authorized this payment" is the whole product.

Two adjacent defects surfaced with it:

- **Role labels are not control domains.** G3 already prevents one identity voting twice, so the naive "hold two roles, vote twice" attack does not work. The real weakness is that `approver_role` was recorded as untrusted client text, with no immutable role-assignment snapshot and no rule for which role counts when an identity holds several. G4 counted *labels*, and two labels administered by the same manager are not dual control.
- **Universal veto is wrong as a default for everything.** Any-single-REJECT is exactly right for sanctions screening and fraud holds. Imposed on a 3-of-5 business approval it means one absent or mistaken approver can unilaterally kill a legitimate transaction with no recourse short of an untracked out-of-band override — which is how shadow processes get built.

## Options Considered

1. **Epoch model:** authority versioned as monotonic epochs; votes bind to an epoch; escalation/override close-and-open atomically. Rejection mode and dual-control semantics configured per policy.
2. **Mutable approval with an appended approver list.** Simplest, and the source of the ambiguity — no point at which the authority set is fixed.
3. **Cancel-and-recreate the approval on escalation.** Clean authority boundaries, but loses the audit thread and forces requesters to re-submit; carry-forward becomes impossible even where it is legitimate.
4. **Global rejection policy (always veto).** Simple, but pushes real workflows off-platform.

## Decision (proposed)

Adopt **Option 1**.

**Epochs.** An `Approval` is a sequence of `Epoch`s (max 5). Each epoch fixes, immutably: `quorum`, `rejection_mode`, `expires_at`, and an `eligibility` snapshot (`snapshot_hash`, `snapshot_at`, and a member list binding each `principal_id` to their roles **and exactly one `control_domain`**). Epoch kinds: `initial`, `escalation`, `override`, `review`.

**Votes bind to an epoch.** A vote carries `epoch_number`; a vote citing a non-current epoch gets `409` with the current epoch in the problem body (I-15). Escalation and override close the current epoch (`CLOSED_SUPERSEDED`) and open the next **in a single transaction** (V-14), so a vote racing an escalation is rejected explicitly and never silently re-homed into an authority set its caster never saw.

**The five questions, now answered by configuration rather than by implementation accident:**

| Question | Mechanism | Default |
|---|---|---|
| Replace or augment the pool? | `escalation.pool_mode` | *no default — must be explicit* (V-3) |
| Do earlier approvals count? | `escalation.carry_forward_votes`; carried votes retain their original `epoch_id` and count only while the voter remains in the new snapshot | `false` |
| May original approvers still vote? | Implied by `pool_mode` + new snapshot membership | — |
| Does the TTL restart? | `escalation.reset_expiry` | `true` |
| Vote racing escalation? | `epoch_number` on every vote + atomic close/open | `409` |

Requiring `pool_mode` to be explicit is deliberate: a silent default here is precisely the class of decision that should never be made by whoever wrote the constructor.

**Dual control counts control domains.** `distinct_roles_required` means counted APPROVEs must come from distinct human identities (already G3) **and** distinct `control_domain`s — independently administered authority groups. The eligibility snapshot assigns each member exactly one control domain per epoch, which also resolves the multi-role case deterministically: the recorded `approver_role` comes from the snapshot, never from the client's `role_claim` (which is only a request to vote under a role, validated against the snapshot). V-2 rejects an unsatisfiable quorum at authoring time — a 3-of-N dual-control policy over two control domains fails when the policy is written, not when a payment is stuck.

**Authority source.** The authoritative source is a versioned Mizan tenant role-registry mapping. Tenant IdP groups are synchronized inputs to that mapping, but live token/group claims never assign a control domain at vote time. Each epoch snapshot pins `authority_source=mizan_role_registry` and `authority_mapping_version`; changing the mapping affects only subsequently opened epochs. Mapping publication requires tenant security-administrator approval and emits an audit event.

**Rejection is per policy.** `rejection_mode ∈ {veto, rejection_quorum, review_required}`, defaulting to `veto`:

- `veto` — any single REJECT is terminal. Correct for sanctions, fraud, and compliance gates; unchanged from v1.0 behaviour and still the default.
- `rejection_quorum` — terminal at `rejection_quorum_count` REJECTs. For M-of-N business approvals where one dissent is data, not a decision.
- `review_required` — the first REJECT opens a `review` epoch under an independently controlled pool. For workflows where a rejection should trigger examination rather than termination.

**Override is explicit or impossible.** `approval_requirements.override` is absent by default, and where absent no override endpoint succeeds. Where configured it requires a fresh override epoch (no carried votes), quorum from `eligible_roles`, a non-empty per-voter `justification` (V-5), distinct control domains by default, and high-severity notification to SIEM and compliance (G9, I-22). A silent unilateral override would be at least as dangerous as an over-broad veto; making break-glass a first-class, noisy, evidenced path is what keeps it out of Slack.

## Consequences

- (+) "Who authorized this, under what authority, at what time" is answerable from evidence without reconstructing state.
- (+) Escalation races have one defined outcome; approval-SM fuzzing (WORK_LOG T-007) gets a precise oracle.
- (+) Dual control means what auditors think it means — separated administration, not two strings.
- (−) The approval model is materially more complex: epochs, snapshots, and carry-forward rules are three new concepts for UI, SDK, and workflow integrations to render correctly.
- (−) Control domains require a tenant-side mapping from IdP roles to administrative groups. Tenants without that mapping must supply one before dual control is meaningful; defaulting each role to its own domain would silently restore the weak behaviour, so setup is mandatory instead.
- (−) `pool_mode` having no default means some policies fail validation on first authoring. Intended.
- (~) `rejection_quorum` and `review_required` are new business semantics and need explicit compliance sign-off per tenant before use; `veto` remains the default so the conservative path requires no decision.

## Compliance Mapping

| Framework | Mapping |
|---|---|
| NIST AI RMF | GOVERN 2.1 (roles and accountability), MANAGE 2.2 (human oversight of AI actions) |
| ISO/IEC 42001 | A.9.2 (human oversight), A.6.2.6 (operational controls) |
| OWASP Agentic AI | #5 insufficient human oversight, #10 privilege/authority confusion |
| Banking controls | Maker–checker and four-eyes expectations; segregation of duties evidenced by control domain, not role label |

## Open Questions

- [x] Control domains come from a versioned Mizan-side mapping table populated from IdP data; resolved in SPEC v1.2.
- [ ] Should `carry_forward_votes = true` be permitted at all for HIGH/CRITICAL, or restricted to LOW/MEDIUM?
- [ ] Escalation notification routing — does the escalation role get paged, or is it inbox-only? (Affects `trigger_fraction` tuning.)
- [ ] Is `max_epochs = 2` right for the pilot, or should CRITICAL allow a third escalation tier?

## R-003 Review-Epoch Amendment (ratified 2026-08-25)

`review_required` is fully typed, not a transitional label awaiting an out-of-band workflow. Its
policy configuration names an independent `approver_roles` pool, quorum, expiry, mandatory distinct
control domains, and a terminal review rejection mode (`veto` or `rejection_quorum`). Recursive
`review_required` and carried votes are forbidden.

On the first initial-epoch REJECT, one locked database transaction records the vote, closes the
original epoch with `REVIEW_TRIGGERED`, takes a fresh approved role-authority snapshot, opens the
review epoch, advances `current_epoch_id`, appends decision events, and enqueues the typed
`mizan.approval.review_required` notification. Failure to resolve or validate the reviewer pool
rolls back the rejection as well, preventing an approval from becoming stranded in a state with no
active authority set. Original voters have no inherited vote or eligibility unless independently
present in the configured review snapshot; all later votes must cite the new epoch number.


## Implementation Amendment — the approval opens with the decision *(pending ratification: B-16)*

**Date:** 2026-08-27 · **Trigger:** Stage 5 acceleration review, T-067 · **Spec anchors:** SPEC v1.3 §3 `/v1/approvals`, §4 `mizan.approval.requested`, I-6, I-15

Until now `ApprovalRepository.create` had no caller outside tests. A `REQUIRE_APPROVAL` decision
recorded `approval.status = NOT_REQUIRED` and opened nothing, so the pause half of PRD §37 existed
only as a state machine no running system entered.

A `REQUIRE_APPROVAL` decision now opens its approval **inside the ADR_Record transaction**. The
decision and the approval that lets it resume commit together or not at all: a record that says
"wait" with nothing to wait for is not a state the evidence should be able to hold. The FK from
`mizan.approvals` to `mizan.adr_records` already required this ordering; nothing else enforced it.

Three consequences, all pending ratification under B-16:

1. The controls come from the winning policy's `approval_requirements`. A `REQUIRE_APPROVAL`
   policy that carries none is now a 422 `approval_requirements_missing` and **no record is
   written** — the policy is invalid, not the request.
2. `forbidden_approvers` is seeded with the requesting principal. The accountable owner is not yet
   included because the Agent schema carries it as free text, not a `PrincipalId`; excluding them
   needs a registry change and is left open.
3. `GET /v1/approvals?state=` is the approver queue: tenant-scoped, newest first, carrying each
   approval's current epoch kind, quorum, votes cast, eligible roles and expiry. It is the read
   model the T-072 inbox is built on, and the first way an approver can find out that anything is
   waiting for them.

`mizan.approval.requested` is emitted through the outbox in the same transaction (SPEC §4).
