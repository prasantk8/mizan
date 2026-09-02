# Mizan Architecture Decision Records

**Naming note:** In Mizan, "ADR" is overloaded. Runtime evidence objects are **Action Decision Records** (`ADR_Record`, prefix `adr_`, defined in `SPEC_v1.md` §2.3). The documents in this directory are **Architecture Decision Records** (ADR-001…), covering PRD §70. Code and specs must use `ADR_Record` for the runtime object and `ADR-NNN` for architecture decisions — never bare "ADR" in identifiers.

## Index

| ID | Title | Status | Notes |
|---|---|---|---|
| [ADR-001](ADR-001-identity-authentication.md) | Identity & Authentication Strategy | ACCEPTED | + v1.2 executor-bound capability clarification |
| [ADR-002](ADR-002-policy-engine.md) | Policy Engine Implementation | ACCEPTED | Cedar 4.8.7 handle benchmark passed; Mizan combines typed outcomes above per-policy Cedar matches |
| [ADR-003](ADR-003-fail-closed-circuit-breakers.md) | Fail-Closed Mechanism & Circuit Breakers | ACCEPTED | + Amendment A: grants/streams; Amendment B: issuer trust + durable WAL |
| [ADR-004](ADR-004-audit-immutability.md) | Audit Immutability & Hash-Chaining | ACCEPTED | Canonical segments, append-only receipts, signed anchors; four-shard benchmark passed |
| [ADR-005](ADR-005-multi-tenant-isolation.md) | Multi-Tenant Data Isolation | ACCEPTED | |
| [ADR-006](ADR-006-external-payload-boundary.md) | External Payload Boundary & Schema Evolution | ACCEPTED | + Amendment A: parser budgets + raw-payload disposition |
| [ADR-007](ADR-007-approval-authority-epochs.md) | Approval Authority — Epochs, Dual Control & Rejection Semantics | ACCEPTED | R-003 independently controlled review epoch ratified and implemented |
| [ADR-008](ADR-008-execution-token-binding.md) | Execution Token Binding & Long-Running Leases | ACCEPTED | + R-003 transient arguments and execution revalidation |
| [ADR-009](ADR-009-operator-console-read-model.md) | Operator Console Read Model | DRAFT | Tenant-scoped exact dashboard aggregates and evidence-backed detail views |
| [ADR-010](ADR-010-verified-external-attestation-boundary.md) | Verified External Attestation Boundary (the Memtara seam) | PROPOSED | Why a cryptographically verified third-party attestation may reach policy when ADR-006 says foreign data may not, and the three limits that buys |

ADR-006/007/008 and the first amendments were written in response to the SPEC v1.0 baseline review — see [`docs/reviews/R-001-baseline-review-disposition.md`](../reviews/R-001-baseline-review-disposition.md). SPEC v1.2 and v1.3 amendments dispose of the later findings in [`docs/reviews/R-002-baseline-review-disposition.md`](../reviews/R-002-baseline-review-disposition.md) and [`docs/reviews/R-003-completion-blocker-disposition.md`](../reviews/R-003-completion-blocker-disposition.md).

## Lifecycle

`DRAFT → PROPOSED → ACCEPTED → (SUPERSEDED-BY-ADR-NNN | DEPRECATED)`

An ADR moves to ACCEPTED only with sign-off from both the Product/Architecture Lead and the Cybersecurity Architect (PRD §68). Accepted ADRs are change-controlled the same way as `SPEC_v1.md`.
