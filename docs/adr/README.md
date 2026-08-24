# Mizan Architecture Decision Records

**Naming note:** In Mizan, "ADR" is overloaded. Runtime evidence objects are **Action Decision Records** (`ADR_Record`, prefix `adr_`, defined in `SPEC_v1.md` §2.3). The documents in this directory are **Architecture Decision Records** (ADR-001…), covering PRD §70. Code and specs must use `ADR_Record` for the runtime object and `ADR-NNN` for architecture decisions — never bare "ADR" in identifiers.

## Index

| ID | Title | Status | Notes |
|---|---|---|---|
| [ADR-001](ADR-001-identity-authentication.md) | Identity & Authentication Strategy | DRAFT | + v1.2 executor-bound capability clarification |
| [ADR-002](ADR-002-policy-engine.md) | Policy Engine Implementation | ACCEPTED | Cedar 4.8.7 handle benchmark passed; Mizan combines typed outcomes above per-policy Cedar matches |
| [ADR-003](ADR-003-fail-closed-circuit-breakers.md) | Fail-Closed Mechanism & Circuit Breakers | DRAFT | + Amendment A: grants/streams; Amendment B: issuer trust + durable WAL |
| [ADR-004](ADR-004-audit-immutability.md) | Audit Immutability & Hash-Chaining | DRAFT | + Amendment A: evidence pipeline/redaction; Amendment B: DecisionEvents + receipts |
| [ADR-005](ADR-005-multi-tenant-isolation.md) | Multi-Tenant Data Isolation | DRAFT | |
| [ADR-006](ADR-006-external-payload-boundary.md) | External Payload Boundary & Schema Evolution | DRAFT | + Amendment A: parser budgets + raw-payload disposition |
| [ADR-007](ADR-007-approval-authority-epochs.md) | Approval Authority — Epochs, Dual Control & Rejection Semantics | DRAFT | Control-domain source resolved; **needs compliance/business sign-off** (H-7) |
| [ADR-008](ADR-008-execution-token-binding.md) | Execution Token Binding & Long-Running Leases | DRAFT | + Amendment A: executor-bound capabilities |

ADR-006/007/008 and the first amendments were written in response to the SPEC v1.0 baseline review — see [`docs/reviews/R-001-baseline-review-disposition.md`](../reviews/R-001-baseline-review-disposition.md). SPEC v1.2 and the later amendments dispose of re-audit findings in [`docs/reviews/R-002-baseline-review-disposition.md`](../reviews/R-002-baseline-review-disposition.md).

## Lifecycle

`DRAFT → PROPOSED → ACCEPTED → (SUPERSEDED-BY-ADR-NNN | DEPRECATED)`

An ADR moves to ACCEPTED only with sign-off from both the Product/Architecture Lead and the Cybersecurity Architect (PRD §68). Accepted ADRs are change-controlled the same way as `SPEC_v1.md`.
