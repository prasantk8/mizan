# Threat models

Human-owned threat-model documents and review artefacts.

| ID | Scope | Status |
|---|---|---|
| [TM-001](TM-001-control-plane-v1.md) | Authorization path, evidence plane, and the boundary between them | **DRAFT** — CLAUDE lane, awaiting HUMAN ratification (T-027) |
| TM-002 | Redis policy cache, Kafka topics, immutable object store | Not started — deferred from TM-001 §4 R-7 as a recorded decision |

**How to read TM-001.** §4, the residual register, is the document; §3 is a terse control map, because
`SPEC_v1.md` §6 already states the invariants. A reader with ten minutes should read §4.

**The rule this directory inherits** from `docs/product/FALSIFICATION_TESTS.md`: a residual that is argued
away without being recorded as argued away is the failure this file exists to prevent. Every row in §4 carries
an owner and a disposition. Amend them in the open, with a date.
