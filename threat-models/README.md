# Threat models

Human-owned threat-model documents and review artefacts.

| ID | Scope | Status |
|---|---|---|
| [TM-001](TM-001-control-plane-v1.md) | Authorization path, evidence plane, and the boundary between them | **RATIFIED** — founder ruling recorded 2026-09-01 (T-127) |
| [TM-002](TM-002-memtara-seam-v1.md) | Mizan↔Memtara proof-token, policy-input and cross-product evidence seam | **SKELETON, now stale** — the seam it calls unbuilt merged in PR #41 on 2026-09-02. A v2 revision is owed before it is cited; see the note below |
| [TM-003](TM-003-model-endpoint-boundary-v1.md) | Model endpoint ↔ agent/gateway boundary — the customer's own model as an untrusted proposer | **SKELETON** — boundary fixed before T-144 builds the component that creates it |

**TM-002 is out of date and must not be cited as current (recorded 2026-09-02, T-145).** It was written
on 2026-09-01 against `bc16436`, where the seam did not exist, and every control in it is labelled
*planned*. T-133–T-138 merged the next day. Its §6 questions now have answers in named artifacts —
`docs/adr/ADR-010-verified-external-attestation-boundary.md`, `docs/spec/EVIDENCE-BUNDLE-FORMAT.md`
§2.1, and the three stated limits in `docs/product/MODULE_LEDGER.md` (per-process `jti` set, unrefreshed
keyset, unauthenticated Memtara chain head, which is M-R3/M-R4 answered as *accepted and disclosed*
rather than closed). Revising it is SE-lane work with a founder ratification step, exactly as TM-001
had; it is **not** done by editing "planned" to "shipped" in place. A security document that describes
a system as unbuilt after it ships is the same failure the WS-2 audit was about — a document outliving
its truth — so it is recorded here rather than left for a reader to notice.

TM-001 R-7 no longer assigns TM-002 to Redis/Kafka/object-storage. The shipped object-store integrity
boundary is now represented in TM-001; unshipped external cache/broker dependencies remain an explicit
infrastructure residual and require a deployment-substrate model if introduced.

**How to read TM-001.** §4, the residual register, is the document; §3 is a terse control map, because
`SPEC_v1.md` §6 already states the invariants. A reader with ten minutes should read §4.

**The rule this directory inherits** from `docs/product/FALSIFICATION_TESTS.md`: a residual that is argued
away without being recorded as argued away is the failure this file exists to prevent. Every row in §4 carries
an owner and a disposition. Amend them in the open, with a date.
