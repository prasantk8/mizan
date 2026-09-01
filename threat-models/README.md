# Threat models

Human-owned threat-model documents and review artefacts.

| ID | Scope | Status |
|---|---|---|
| [TM-001](TM-001-control-plane-v1.md) | Authorization path, evidence plane, and the boundary between them | **DRAFT** — refreshed 2026-09-01, awaiting explicit HUMAN ratification (T-127) |
| [TM-002](TM-002-memtara-seam-v1.md) | Mizan↔Memtara proof-token, policy-input and cross-product evidence seam | **SKELETON** — boundary fixed before T-133..T-138 implementation |

TM-001 R-7 no longer assigns TM-002 to Redis/Kafka/object-storage. The shipped object-store integrity
boundary is now represented in TM-001; unshipped external cache/broker dependencies remain an explicit
infrastructure residual and require a deployment-substrate model if introduced.

**How to read TM-001.** §4, the residual register, is the document; §3 is a terse control map, because
`SPEC_v1.md` §6 already states the invariants. A reader with ten minutes should read §4.

**The rule this directory inherits** from `docs/product/FALSIFICATION_TESTS.md`: a residual that is argued
away without being recorded as argued away is the failure this file exists to prevent. Every row in §4 carries
an owner and a disposition. Amend them in the open, with a date.
