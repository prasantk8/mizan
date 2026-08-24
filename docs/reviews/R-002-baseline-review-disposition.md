# R-002 — SPEC v1.1 Re-audit Disposition

**Date:** 2026-08-25  
**Reviewer:** Codex implementation-contract audit  
**Disposition:** All five critical findings incorporated into SPEC v1.2; human ratification remains required.

| Finding | Disposition | Contract changes |
|---|---|---|
| Execution capability did not bind the executor | **Accepted** | ExecutionTokenClaims and ExecutionLease v1.2 bind agent, principal, delegation hash, issuer/audience, and SPIFFE executor; I-23/V-17; ADR-001 and ADR-008 amended. |
| Default-deny could not produce an ADR_Record because `policies.minItems=1` | **Accepted** | ADR_Record v1.2 permits an empty list only under typed `decision_basis`; V-15; ADR-002 resolves no-match as unconditional DENY. |
| Escalation `pool_mode` contradicted V-3 and control-domain authority was unresolved | **Accepted** | `pool_mode` is schema-required with no default; epoch snapshots pin a versioned Mizan role-registry mapping; ADR-007 updated. |
| Approval/execution amendment records had no schema | **Accepted** | Added DecisionEvent v1.2 with dense per-decision ordering, event types, hashes, and idempotency rule V-19; ADR-004 amended. |
| Degraded WAL and signed grants were underspecified | **Accepted** | Grant issuer registry, algorithms, time/nonce validation, encrypted fsync WAL, capacity/replay failure semantics; I-26/V-16; ADR-003 amended. |

## Architecture paradoxes

| Finding | Disposition |
|---|---|
| Financial execution could precede escape of evidence from Postgres | **Accepted:** immutable publication receipts gate `financial_write` redemption (I-25/V-20); bounded asynchronous window remains for non-financial actions. |
| Raw external envelopes conflicted with PII minimization and accepted objects only | **Accepted:** envelope v1.2 accepts any JSON value, enforces server-measured parser budgets, and declares a redacted/discarded/encrypted persistence disposition (V-18). |
| Frozen SPEC depended on DRAFT ADRs | **Acknowledged:** implementation tasks governed by an ADR remain blocked until T-001 ratification; SPEC v1.2 itself remains a candidate baseline until that human gate completes. |

## Ratification required

Product/Architecture and Cybersecurity must accept ADR-001..008 and SPEC v1.2. Compliance/business must additionally accept ADR-007 approval semantics. No production implementation may treat this disposition document as that approval.
