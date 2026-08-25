# ADR-006: External Payload Boundary & Schema Evolution

**Status:** ACCEPTED (T-001 ratified in all required roles)
**Deciders:** Product/Architecture Lead, Cybersecurity Architect
**Date:** 2026-08-25
**Spec anchors:** SPEC v1.2 §0 rule 1, §2.4 (`mapped`), §2.8 (ExternalPayloadEnvelope), §8, Invariants I-17/I-25, V-18
**Trigger:** baseline review R-001 — "closed internal contracts vs. uncontrolled MCP payloads"

## Context

SPEC rule 1 closes every schema (`additionalProperties: false`). That is correct for canonical Mizan records — it is the mechanism that makes drift a build failure rather than a silent divergence. Applied naively at the integration boundary it is a liability: an MCP server, a core-banking adapter, or a CRM webhook that adds one innocuous field would hard-fail validation, and if that validation sits on the authorization path, a third party's routine release becomes a Mizan outage.

The opposite error is worse. Opening the canonical schemas to accommodate foreign payloads would let unvetted, attacker-influenceable fields reach policy evaluation, which is exactly the substrate for OWASP Agentic AI #8 (MCP/server compromise) and confused-deputy attacks: a tool response that injects `"approved": true` or `"risk": "LOW"` into a namespace a policy happens to read.

Forces:

- Third-party schemas evolve on someone else's release cadence, without notice.
- Policy evaluation must be deterministic and explainable; an input space defined by whatever a vendor emits is neither.
- Integration failures must degrade to a *tool* error, not a control-plane fault.
- Provider drift should be *visible* (an operations signal) without being *trusted* (an evaluation input).

## Options Considered

1. **Two-stage boundary:** open, size-limited envelope for capture; strict, versioned, allowlisted projection for evaluation.
2. **Relax canonical schemas to `additionalProperties: true`.** Rejected: destroys the zero-drift property and hands attackers an input channel.
3. **Per-provider strict schemas maintained in-tree.** Every provider release becomes a Mizan release; the failure mode is an outage, and the maintenance burden scales with the integration count.
4. **Validate nothing at the boundary; sanitize downstream.** Rejected: "sanitize later" is how untrusted data reaches evaluators.

## Decision (proposed)

Adopt **Option 1**. The canonical schemas stay closed; exactly one open object exists in the entire spec, and it is inert.

**Stage 1 — capture.** Foreign payloads enter as `ExternalPayloadEnvelope` (SPEC §2.8): `provider`, `schema_uri`, declared version, `received_at`, `raw_hash`, `size_bytes`, and an open `payload`. Bounded by `MIZAN_EXTERNAL_PAYLOAD_MAX_BYTES` (default 256 KiB, hard max 1 MiB) so a hostile or malfunctioning provider cannot exhaust memory. The envelope is stored and hashed. It is never evaluated, never indexed as a policy input, and no `ConditionNode.field` path can reach it — the field-path pattern in SPEC §2.0 admits only the evaluation namespace plus `mapped.*`.

**Stage 2 — projection.** An allowlisted, versioned projection (`prj_*`) maps a named subset into `EvaluationContext.mapped.fields` — **scalars only**, flattened by the projection, at most 64 fields. Unknown keys are dropped and reported as `mizan.integration.schema_drift` with `dropped_fields`, so a provider adding a field shows up on an integration dashboard instead of in a policy decision or a stack trace. `mapped` records `projection_id`, `projection_version`, and `raw_envelope_hash`, so any decision can be replayed against the exact projection that produced its inputs.

**Failure semantics.** Adapter timeout (`MIZAN_EXTERNAL_ADAPTER_TIMEOUT_MS`, default 2000 ms), oversize payload, malformed content, or projection failure all surface as a **controlled tool error** — the tool call fails and the failure is evidence. The authorization service does not fault, and the ADR-003 breaker matrix governs the dependency, exactly as for any other downstream.

## Consequences

- (+) Canonical evidence stays strictly typed while integrations tolerate vendor evolution; a provider's release no longer risks a control-plane outage.
- (+) Foreign data reaches evaluation only through a named, versioned, reviewable projection — the review surface for "what can influence a decision" stays small and enumerable.
- (+) Schema drift becomes an operational signal with a dashboard, rather than an incident.
- (−) Every integration now needs a projection artefact and a version bump discipline; the SDK must make writing one cheap or teams will push to widen `mapped`.
- (−) Scalars-only forces genuinely nested provider data to be flattened deliberately. That is friction on purpose: it makes someone decide which fields are policy-relevant.
- (~) Envelope retention interacts with PII: envelopes can contain unredacted provider data, so they follow the ADR-004 Amendment A redaction pipeline and are not stored in searchable operational tables.

## Compliance Mapping

| Framework | Mapping |
|---|---|
| NIST AI RMF | MAP 4.1 / MANAGE 3.1 (third-party components and their risks) |
| ISO/IEC 42001 | A.7.4 (data provenance and quality), A.10 (third-party relationships) |
| OWASP Agentic AI | #8 MCP/server compromise, #2 tool misuse via poisoned responses |
| ISO 27001 (adjacent) | A.5.19–A.5.21 supplier relationships; input validation controls |

## Open Questions

- [ ] Do projections live in the policy repo (reviewed as policy) or the integration repo (reviewed as code)? Leaning policy repo — they define evaluation inputs.
- [ ] Should high-drift providers auto-open a work item after N `schema_drift` events, or stay a dashboard-only signal?
- [ ] Envelope retention default — is 30 days right, given envelopes may be the only record of what a provider actually said during an incident?

---

## Amendment A — Parser budgets and raw-payload disposition

**Date:** 2026-08-25 · **Trigger:** baseline review R-002 — object-only payloads, caller-asserted sizes, parser bombs, and ambiguous raw-PII persistence · **Spec anchors:** SPEC v1.2 §2.8, §8, V-18

The envelope accepts any valid JSON top-level value, including arrays, scalars, and null. The adapter—not the provider—computes `size_bytes` and `raw_hash`. It streams transport decoding and enforces compressed bytes, decompressed bytes, nesting depth, total keys, and a parse-time budget before constructing an envelope. A declared `Content-Length` is only an early rejection hint and never the authoritative size.

Raw payload capture is transient. Every envelope declares one persistence disposition:

- `discarded_after_projection`: retain only hash, projection provenance, and drift telemetry;
- `redacted_payload`: persist only output that passed the ADR-004 redaction attestation;
- `encrypted_evidence`: retain the original only in the short-retention legal-hold evidence store.

Raw provider data is never written to searchable operational tables. The persistence worker verifies that required attestation/evidence references exist before acknowledging capture; schema prose alone is not treated as a retention control.

---

## Implementation Amendment B — Controlled side effects and parser edge cases

**Date:** 2026-08-25 · **Trigger:** completion audit found unnormalized persistence faults and a
post-persistence deadline check that could report failure after retaining raw evidence · **Spec
anchors:** SPEC v1.2 §2.8, I-17, V-18

The adapter deadline covers bounded transport decode, JSON parse, structure validation, projection,
and mandatory drift recording. It is checked before any irreversible persistence call; evidence
sinks own their separate timeout and acknowledgement contract. Sink and telemetry exceptions are
normalized to controlled integration errors and never escape as service faults.

Malformed RFC 6901 escapes and non-canonical array indexes are rejected when projections are
defined or applied. JSON recursion, integer-conversion, and overflow failures are normalized rather
than surfacing interpreter exceptions. Drift paths are truncated and then deduplicated so the
closed envelope's `uniqueItems` constraint remains valid even when long provider keys collide.
