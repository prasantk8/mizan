# Observability — what the control plane says about itself

Three surfaces, three different strengths of claim. Reading them as though they were
interchangeable is the mistake this document exists to prevent.

| Surface | Strength | Read it for |
|---|---|---|
| `trace_id` / `span_id` in the ADR_Record | **Fact under signature** — chained, anchored, part of the evidence | Joining a decision to the request that caused it, years later |
| Structured logs | **Best effort** — unsigned, rotated, droppable | Reconstructing what a process did, including what it could not write |
| Prometheus metrics | **Sample** — in-process, resettable, lossy by design | Noticing a problem in seconds |

Nothing on this page is ever read back into a decision. A metric is not evidence and cannot become
evidence; when the question is *did this happen*, the answer is the chain.

---

## 1. Traces

Every request continues the caller's W3C `traceparent`, or begins a trace if there is none. The id
is recorded in the ADR_Record and returned on the response, so a caller can join both ways.

```
$ curl -si -H 'traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01' … /v1/authorize
traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-9c1f0aab2d4e5f60-01
x-request-id: 5c1f0a72…
```

The `trace_id` on the response and on the ADR_Record share the caller's trace; the `span_id` names
where the authorization happened inside it. See ADR-004 G.20 for why this is normative rather than
convenient, and for what the field contained before T-073.

Span **export** is optional and additive:

```
pip install 'mizan-control-plane[otel]'
MIZAN_OTEL_EXPORTER_OTLP_ENDPOINT=http://collector:4318/v1/traces
```

Setting the endpoint without installing the extra **refuses to start**. That is deliberate: a
process that answers every request, reports itself ready, and sends nothing to the collector you
are watching has removed your observability while looking healthy.

## 2. Logs

`MIZAN_LOG_FORMAT=json` (the default) emits one object per event. Every line carries whatever the
ambient scope knows — `request_id`, `tenant_id`, `trace_id`, `span_id`, `decision_id` — so
`trace_id=` selects a whole request across the API, and on the worker it selects one tenant's whole
tick.

```json
{"timestamp":"2026-08-27T09:14:02.881Z","level":"ERROR","logger":"mizan.execution",
 "message":"security event dropped and lost","tenant_id":"tnt_bank-a",
 "trace_id":"4bf92f3577b34da6a3ce929d0e0e4736","event_type":"mizan.security.execution_token_replay",
 "cause":"OperationalError","dropped_event":"{\"decision_id\":\"adr_…\"}"}
```

The API emits **one** access line per request, from Mizan, not from uvicorn: uvicorn's own log
config is disabled at startup. Its line carries the request *path* rather than the route template
and knows nothing of the trace, tenant or decision, so keeping both would mean two formats in one
stream and two lines per request, of which the less useful one is the duplicate.

Two guarantees worth knowing:

- **Secrets and payloads never appear.** `arguments`, `token`, `authorization`, `secret`,
  `private_key` and their siblings are replaced with `[redacted:<field>]` however they are passed,
  and every value is length-bounded. `arguments` in particular is the payload the ADR-006 boundary
  exists to keep out of the decision path; a log statement is not a way back in.
- **Ambient context cannot outlive its scope.** A tenant id is bound by whoever owns the unit of
  work and released with it, so one tenant's identifier can never appear on another's line.

## 3. Metrics

Served on a **private listener**, never on the API — the API authenticates a tenant and these
numbers are cross-tenant.

```
MIZAN_METRICS_PORT=9464          # 0 (default) = no listener
MIZAN_METRICS_HOST=127.0.0.1     # off-loopback is allowed and logs a warning saying what it exposes
$ mizan-drain-outbox --tenant-id tnt_bank-a --metrics-port 9464
```

### What to alert on

| Alert | Expression | Why it is the one that matters |
|---|---|---|
| **Evidence is not being published** | `mizan_evidence_publication_lag_seconds > 5` for 2m | This is the SPEC §7 drain-lag SLO. It is also the *cause* of the symptom operators actually see: a financial write refusing on `immutable_receipt_missing` (I-25), which happens far from here and says nothing about this. |
| **The drain worker is gone** | `time() - mizan_drain_worker_last_tick_timestamp_seconds > 60` | A dead worker and a quiet tenant read identically in every other series — zero published, zero relayed, zero pending. This is the only one that separates them. |
| **A row will never publish** | `mizan_outbox_quarantined_rows > 0` | Quarantined rows are excluded from the lag on purpose, so they are invisible to the alert above. Nothing is deleted; each one needs a human. |
| **Any breaker is open** | `mizan_breaker_open == 1` | Includes `outbox_poisoned`, `anchor_refused`, `drain_tick_failed`, `evidence_publication_lag`. |
| **A security event was lost** | `increase(mizan_security_events_dropped_total[5m]) > 0` | There is no queue behind that sink. The full row is in the ERROR log line; this is what tells you to go looking. |
| **Authorizations are failing closed** | `increase(mizan_authorization_fail_closed_total[5m]) > 0` | A risk or policy engine is down. Decisions are still being made and recorded — as DENY. |
| **Latency SLO** | `histogram_quantile(0.95, …_duration_seconds_bucket)` | Every SPEC §7 target (20 ms, 50 ms, 150 ms, 250 ms, 500 ms) is a bucket edge, so p95 is read off an edge rather than interpolated. |

### Cardinality

Label values are bounded: `tenant_id`, `route` (the **template**, never the request path),
`decision`, `decision_basis`, `cause`, `reason`, `error_type`. An identifier reaching a label would
be one time series per decision — a memory leak in the scraper rather than a metric, and one that
arrives quietly, since the dashboards keep working until cardinality crosses the heap. A route that
did not match is reported as `__unmatched__` rather than at its path.

---

## What a clean dashboard does not prove

At equal prominence, because this is the part that gets skipped:

- **Green lag does not mean the evidence is complete.** Lag is measured over the tenants the
  drainer was *configured* with. A tenant missing from `MIZAN_DRAIN_TENANTS` has no series at all,
  and an absent series is not a breach of any threshold above. This is blocker **B-19**: tenants
  cannot be discovered without crossing the ADR-005 isolation boundary. Until it is closed, adding
  a tenant to the drainer's configuration is a manual step whose omission is silent here.
- **Metrics reset on restart; the chain does not.** A counter that reads zero after a crash and a
  workload that genuinely did nothing are the same number.
- **A published record is not a verified one.** These series say a receipt was written. Whether the
  chain verifies is what `verify_evidence_export.py` answers, offline, against *your* trust roots.
- **A trace id proves correlation, not correctness.** It says which request produced a decision. It
  says nothing about whether the decision was right — that is what the replay work (Stage 4) is
  for, and it does not exist yet.
