# ADR-009: Operator Console Read Model

**Status:** DRAFT
**Deciders:** Product/Architecture Lead, Cybersecurity Architect
**Date:** 2026-08-25
**Spec anchors:** PRD §44; SPEC v1.2 I-3, I-11

## Context

The operator console needs exact tenant totals, recent decisions, agent registry details, security
alerts, and independent evidence verification. Deriving headline counts from the first paginated
page is incorrect and loading whole registries into a browser is both slow and an unnecessary data
exposure. A separate analytics system would be premature for the MVP and could lag the enforcement
database during an incident.

## Decision

Add a same-origin, read-only `GET /v1/dashboard/summary` read model. Tenant identity is derived from
the verified operator token and PostgreSQL RLS is set before every aggregate query. The response
contains registry totals plus UTC-day action, denial, approval-request, high-risk-action, and
security-alert counts. It contains no payload bodies or cross-tenant dimensions.

The console uses this endpoint for the main dashboard, paginated APIs for decision/audit streams,
and the tenant-scoped agent registry for agent cards and details. All provider-controlled strings
are rendered through text nodes before insertion. Action details remain the immutable ADR_Record
plus its ordered DecisionEvents; the UI does not synthesize an alternative decision history.

## Consequences

- Operators receive exact headline counts without downloading evidence collections.
- The MVP remains strongly consistent with enforcement state and inherits existing RLS controls.
- Aggregate queries need indexes and latency monitoring as tenant volume grows; a replicated read
  model may later replace them without changing the response contract.
- Calendar-day semantics are UTC for v0.1 and must be made tenant-configurable before localized
  regulatory reporting.
