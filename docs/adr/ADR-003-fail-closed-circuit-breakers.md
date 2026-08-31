# ADR-003: Fail-Closed Mechanism & Circuit Breakers

**Status:** ACCEPTED (T-001 ratified in all required roles)
**Deciders:** Product/Architecture Lead, Cybersecurity Architect
**Date:** 2026-08-25
**Spec anchors:** SPEC_v1 §3 (503 semantics), §5.1 (FAIL_CLOSED state), Invariant I-7; PRD §29

## Context

PRD §29: "A control-plane outage must not silently become unrestricted agent access." Default for high-risk actions is **fail closed**; low-risk actions may be configured to **fail logged/degraded**. The failure surface includes: policy engine crash, Redis policy-cache loss, Postgres unavailability (can't write ADR_Record), risk engine timeout, Kafka backlog, and — critically — **enforcement-point bypass** (an SDK-mode agent that simply doesn't call Mizan).

Key forces:

- Availability target is 99.9%; a naive global fail-closed turns every Mizan blip into a banking outage — the design must degrade *by risk tier*, not binarily.
- Evidence invariant I-1 (no execution without ADR_Record) means audit-store unavailability is itself an authorization-blocking failure for consequential actions.
- Latency budget: breaker checks must cost microseconds.

## Options Considered

1. **Risk-tiered fail behavior with per-dependency circuit breakers and a signed "degraded-mode grant" for LOW-risk paths.**
2. **Global fail-closed.** Maximally safe, operationally brutal; drives customers to disable Mizan — the worst outcome.
3. **Global fail-open with alerting.** Unacceptable for a security control plane (explicitly ruled out by PRD §29).

## Decision (proposed)

Adopt **Option 1**:

- **Dependency breakers:** each downstream (policy engine, risk engine, Postgres, Redis, Kafka) is wrapped in a circuit breaker (closed → open on error-rate/latency threshold → half-open probe). Breaker state changes emit `mizan.authorization.failed_closed`-family events and page on-call.
- **Decision matrix under degradation:**

| Failure | LOW risk context | MEDIUM | HIGH/CRITICAL |
|---|---|---|---|
| Risk engine down | proceed with `risk=MEDIUM` floor | fail closed | fail closed |
| Policy cache (Redis) down | evaluate from Postgres (slow path) | slow path | slow path; if also down → fail closed |
| Postgres (ADR write) down | degraded-allow **only if** tenant opted in: decision buffered to local WAL, flushed later | fail closed | fail closed |
| Policy engine down | fail closed | fail closed | fail closed |
| Kafka down | allow (events via outbox, drained later) | allow (outbox) | allow (outbox) — Kafka is never on the decision path |

- **Degraded-mode grants:** the LOW-risk degraded-allow path requires an explicit, signed, time-boxed tenant configuration (`degraded_mode: {enabled, max_duration, risk_ceiling: LOW}`); every degraded decision is stamped `degraded=true` in its (buffered) ADR_Record.
- **Anti-bypass:** enforcement points send heartbeats; the behavioral layer (Phase 1) alarms when a registered agent's tool-execution telemetry appears without matching authorization calls. In Mode B (gateway) topologies, the tool network path is only reachable via the gateway, making fail-closed structural.
- **Load shedding:** under overload, shed by risk tier ascending (LOW first receives 429), never by arrival order — CRITICAL evaluations are the last to degrade.

## Consequences

- (+) An outage degrades read-only convenience, never financial controls.
- (+) Outbox pattern removes Kafka from the availability equation for decisions.
- (−) The local WAL buffer for degraded LOW decisions is subtle (ordering + hash-chain stitching on flush) — needs a dedicated design note and property tests (chain invariant I-2 must hold after replay).
- (−) Risk-tier classification must be computable *before* full evaluation (cheap static floor from tool `risk_tier` + action type), else the matrix is circular. Tool registry risk tier is therefore the pre-evaluation floor.
- (~) Half-open probes on the policy engine must use synthetic tenants to avoid emitting phantom evidence.

## Compliance Mapping

| Framework | Mapping |
|---|---|
| NIST AI RMF | MANAGE 2.3 / 2.4 (response to AI system failures; safe-state design) |
| ISO/IEC 42001 | A.6.2.6 (operation & monitoring), A.10 (incident handling) |
| OWASP Agentic AI | Mitigates #12 cascading agent failures, #13 abnormal autonomous behavior under partial outage |
| Banking ops | Aligns with operational-resilience expectations (controlled degradation, documented failure modes) |

## Open Questions

- [ ] Breaker thresholds per dependency (error %, window, cool-down) — set after load testing.
- [ ] Should MEDIUM ever be tenant-configurable to degraded-allow? (Current stance: no.)

---

## Amendment A — Degraded mode is a signed, named, defaulted-off capability

**Date:** 2026-08-25 · **Trigger:** baseline review R-001 (missing configuration; WAL/chain-stitching hazard) · **Spec anchors:** SPEC v1.1 §2.9, §8, Invariant I-21

The original decision described degraded-allow in prose ("only if tenant opted in") without naming the artefact that carries the opt-in, the switch that disables it globally, or what happens to the hash chain. Three corrections:

**1. The opt-in is an object, not a config comment.** `DegradedModeGrant` (SPEC §2.9) is signed, time-boxed, names the components it covers, and pins `risk_ceiling: LOW` as a schema constant. `Policy.fail_open_allowed` defaults `false` and is honoured only when the deployment master switch `MIZAN_LOW_RISK_DEGRADED_ALLOW` (default `false`) is on **and** an unexpired grant covers the failed component (I-21). Three independent conditions, all defaulted closed, and the policy engine is never an eligible component — its absence is always fail-closed.

**2. Degraded records get their own chain, not a stitched one.** Buffering a decision locally and later inserting it into the main chain is impossible under ADR-004 Amendment A.3, where sequence numbers are allocated inside the committing transaction against a locked chain head — there is no middle to insert into. Degraded decisions therefore write to a **separate per-node degraded stream** (`{tenant}:adr:degraded-{node}`), which is a first-class chain in its own right: independently sequenced, independently anchored on flush, and cross-referenced from the main stream by `decision_id`. Replay stops being an ordering puzzle and becomes an ordinary append to a different stream. This retires the open question about vector clocks for multi-node buffers — nodes never share a degraded chain.

**3. Every degraded decision is visible as such.** `ADR_Record.degraded` is a required object (`is_degraded`, `reason`, `grant_ref`, `buffered_at`), and exercising the path emits `mizan.authorization.degraded_allow` to SIEM and compliance. A degraded ALLOW is never indistinguishable from a normal ALLOW in evidence.

Named configuration for all of the above lives in SPEC §8 — per rule 9, no thresholds or TTLs may exist only as constants in code.

---

## Amendment B — Degraded grants and the local WAL are security boundaries

**Date:** 2026-08-25 · **Trigger:** baseline review R-002 — caller-selected grant keys and an undefined local WAL made degraded ALLOW evidence erasable · **Spec anchors:** SPEC v1.2 §2.9, §8, I-21, I-26, V-16

### B.1 Grant verification

A grant is trusted only when all of the following hold:

1. `issued_by`, `key_ref`, and `signature_algorithm` match an entry in the tenant's independently administered degraded-grant issuer registry.
2. The signature verifies over RFC 8785 canonical grant claims excluding `signature`; allowed algorithms are EdDSA and ES256 only.
3. `not_before ≤ now < expires_at ≤ issued_at + max_duration_seconds` and duration is within the deployment ceiling.
4. The grant nonce is not revoked; a stale revocation cache disables degraded-allow rather than guessing.
5. Tenant, risk ceiling, failed component, policy opt-in, and deployment master switch all match.

A token-carried `key_ref` is descriptive, not authoritative. This prevents an attacker from signing a grant with their own key and asking Mizan to trust the accompanying reference.

### B.2 WAL durability contract

The per-node degraded stream lives on a dedicated encrypted volume. Before an ALLOW response is returned, the node writes the canonical ADR_Record plus stream metadata, fsyncs it under `MIZAN_DEGRADED_WAL_FSYNC_MODE=always`, and returns a locally signed receipt. WAL capacity is bounded; full disk, fsync error, missing/expired encryption key, corrupt tail, or inability to produce the receipt all fail closed (I-26).

Records use monotonically increasing per-node sequence numbers and authenticated encryption. Recovery verifies every receipt and record hash before idempotent publication to the degraded object-store stream. Publication must finish within `MIZAN_DEGRADED_WAL_REPLAY_DEADLINE_SECONDS` after the record store recovers; breach pages security/compliance and disables further degraded grants on that node. Operators may quarantine corrupt records but may never skip them and continue the same stream.

## Amendment C — fail-closed decisions remain evidence-bearing

**Date:** 2026-08-25 · **Trigger:** R-004 F-2 · **Spec anchors:** SPEC v1.3.1 §5.1, I-8, V-15

A risk-engine or policy-engine failure is an authorization decision, not an absent response. Mizan
persists a DENY ADR_Record with `decision_basis=system_fail_closed`, no cited policies, the static
tool risk floor when live risk is unavailable, and the evaluator build/configuration hash. Once that
record commits, the API returns HTTP 403 `authorization_failed_closed`: access was deliberately
refused, while 503 is reserved for the materially different state in which required evidence could
not be committed.

If the fail-closed evidence write itself fails, the service returns 503
`fail_closed_evidence_write_failed`, increments the dedicated
`system_fail_closed_evidence_write_failed` counter, and emits a critical structured log event. This
is the sole honest no-record terminal case. Expected evidence-store errors are translated; unrelated
exception types are not swallowed by a blanket handler and retain their diagnostic identity.

## Amendment D — the audit sink may not decide the answer it is auditing (T-073)

**Date:** 2026-08-27 · **Trigger:** T-073 · **Spec anchors:** SPEC §4, ADR-008 Amendment A

Security events (`mizan.security.*`) are written on a dedicated bounded connection pool so that
recording one cannot take the connection the decision itself needs. That much was already true.
What was not true is that recording one cannot *change* the decision.

`ExecutionService._record_security_event` runs inside the token-redemption transaction. It caught
`PoolTimeout` and nothing else, so any other fault of the sink — a dropped connection, a
serialization failure, a revoked grant — escaped the handler, rolled the redemption back, and
turned a detected replay of an execution capability into HTTP 500. That inverts the control being
exercised: the caller is told the request failed and may be retried, by the mechanism whose whole
purpose was to refuse it, and the refusal that was correctly reached is discarded on the way out.

Normative for every security-event sink in the control plane:

**No failure of an audit sink may alter the outcome it observes.** Every exception raised while
recording a security event is absorbed at the point of recording. The decision stands as reached.
This is the one place where a deliberately broad `except Exception` is correct, and it is correct
precisely because the alternative is a fail-open path dressed as an error.

**A dropped event is lost, not deferred, and must say so.** There is no queue behind this sink. The
event that could not be written is therefore emitted in full as a structured ERROR log record —
carrying the same identifiers and hashes the outbox row would have carried, so the pipeline that
ships logs to the SIEM remains a path to recovering it — and counted under
`mizan_security_events_dropped_total{event_type,cause}`, where an alert can reach it. Silence about
a lost audit record is the failure; the loss itself is survivable and the silence is not.

**Breaker state is a sample, not an edge.** A breaker that writes its state only on the transition
reads as closed to anything that connected afterwards — every scraper restart, every rollout, every
new alert rule. `mizan_breaker_open{tenant_id,reason}` is therefore re-asserted while the breaker is
open, while the human-facing log line still fires once on the way open and once on the way closed.

## Amendment E — tiered admission control has explicit quotas (T-125)

**Date:** 2026-09-01 · **Trigger:** two-product pilot WS-1a · **Spec anchors:** SPEC §3.2, §8, V-26

The original load-shedding decision gave an ordering (LOW sheds first, CRITICAL last) but no
executable quota. A system can agree with that sentence while admitting every request. The pilot
therefore uses one token bucket per `(process, tenant, route class, risk tier)` for the three
control paths whose saturation either creates decisions or resumes consequential work:
`authorize`, approval mutations, and execution-token issuance.

The default per-minute capacities are:

| Risk tier | LOW | MEDIUM | HIGH | CRITICAL |
|---|---:|---:|---:|---:|
| Requests per protected route class | 60 | 120 | 240 | 480 |

All four values are configured together by `MIZAN_RATE_LIMITS_PER_MINUTE` in that closed order.
They must be positive and strictly increasing; startup refuses missing, extra, equal or inverted
values. A token bucket starts full and refills continuously, so the value is both its maximum burst
and its sustained requests-per-minute rate. Each route class has a separate bucket: an authorize
burst cannot consume the capacity reserved for an approval or token request.

The tenant always comes from the verified identity. `/v1/authorize` uses the stored tool's static
risk floor, which is available before evaluation and is conservative when live risk later rises.
Approval mutations and execution-token issuance use the immutable risk level in the originating
ADR_Record. A header, request body or URL parameter never selects either label.

Exhaustion returns 429 `rate_limit_exceeded` as `application/problem+json` before the protected
mutation/evaluation runs. It does not turn an authorization into DENY, change approval state, mint a
capability, or write false decision evidence. Operators see both
`mizan_rate_limit_configured_requests_per_minute{route_class,risk_tier}` and
`mizan_rate_limit_rejections_total{tenant_id,route_class,risk_tier}` on the private metrics listener.

These are explicitly **per-replica** quotas. The v1 control plane has no shared low-latency quota
store, and putting PostgreSQL on this admission path would contradict the breaker's microsecond
budget. A deployment with multiple replicas therefore has the sum of their capacities and must
divide a desired cluster budget among replicas. This amendment does not claim a global billing or
abuse-prevention quota.
