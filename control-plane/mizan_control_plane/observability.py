"""What this system says about itself while it is running.

Three separate claims live here, and they are not equally strong. Keeping them distinct is the
point of the module:

  **The trace id is a fact.** SPEC §2 declares `ADR_Record.trace_id` to be *"W3C traceparent
  trace-id (OpenTelemetry)"*, and every signed ADR_Record in this tree carried
  `sha256(request_id)[:32]` instead — a value that is the right shape, is stable, and has never
  been part of any trace. An investigator holding an ADR_Record could not find the request that
  produced it in any tracing backend, and nothing said so, because the field was populated and
  well-formed. Trace context is now taken from the caller's `traceparent` header and recorded as
  received. That correction needs no dependency and is not optional.

  **The span export is an integration.** Whether those ids also arrive in a collector depends on
  the `otel` extra and on configuration. It may be absent. What may *not* happen is an operator
  configuring an endpoint and getting a process that quietly exports nothing, so a configured
  endpoint with no exporter installed refuses at startup.

  **The metrics are a sample.** A counter is not evidence: it is unsigned, in-process, resettable
  and lossy by design, and every number here can be wrong without any invariant noticing. Metrics
  exist so an operator sees a problem in seconds instead of at the next audit. They are never the
  answer to "did this happen" — the chain is. Nothing in this module is ever read back into a
  decision.

Metrics are served on their own listener, not on the API. The API authenticates a *tenant*, and
process metrics are cross-tenant by nature; putting them behind a tenant credential would either
leak one tenant's volumes to another or invent a new authority class to avoid it. A private
listener binding to loopback by default is the smaller thing.
"""

from __future__ import annotations

import json
import logging
import os
import re
import secrets
import threading
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol
from wsgiref.simple_server import WSGIRequestHandler, make_server

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, make_wsgi_app

LOGGER = logging.getLogger("mizan.observability")

# ---------------------------------------------------------------------------------------------
# W3C Trace Context (https://www.w3.org/TR/trace-context/)
# ---------------------------------------------------------------------------------------------

# Version 00 is exactly four fields. A *later* version may append fields, and the standard requires
# a version-00 parser to accept the prefix rather than reject the header — refusing it would make
# this service the thing that breaks a caller's trace when the caller upgrades first.
_TRACEPARENT = re.compile(
    r"^(?P<version>[0-9a-f]{2})-(?P<trace>[0-9a-f]{32})-(?P<span>[0-9a-f]{16})-(?P<flags>[0-9a-f]{2})(?:-.*)?$"
)
_INVALID_TRACE_ID = "0" * 32
_INVALID_SPAN_ID = "0" * 16
_SAMPLED = 0x01


@dataclass(frozen=True, slots=True)
class TraceContext:
    """One position in a distributed trace, in the encoding the ADR_Record stores."""

    trace_id: str
    span_id: str
    sampled: bool = True
    remote: bool = False

    @classmethod
    def parse(cls, header: str | None) -> TraceContext | None:
        """A caller's `traceparent`, or None when there is nothing valid to continue."""
        if not header:
            return None
        match = _TRACEPARENT.match(header.strip())
        if match is None:
            return None
        if match["version"] == "ff":  # reserved: never a valid version
            return None
        if match["trace"] == _INVALID_TRACE_ID or match["span"] == _INVALID_SPAN_ID:
            return None
        return cls(
            trace_id=match["trace"],
            span_id=match["span"],
            sampled=bool(int(match["flags"], 16) & _SAMPLED),
            remote=True,
        )

    @classmethod
    def begin(cls) -> TraceContext:
        return cls(trace_id=secrets.token_hex(16), span_id=secrets.token_hex(8), sampled=True)

    @classmethod
    def start(cls, header: str | None) -> TraceContext:
        """Continue the caller's trace, or start one. Never fabricated from a request id."""
        parent = cls.parse(header)
        return parent.child() if parent is not None else cls.begin()

    def child(self) -> TraceContext:
        """A new local span under the same trace."""
        return TraceContext(
            trace_id=self.trace_id,
            span_id=secrets.token_hex(8),
            sampled=self.sampled,
            remote=False,
        )

    def traceparent(self) -> str:
        return f"00-{self.trace_id}-{self.span_id}-{'01' if self.sampled else '00'}"


# ---------------------------------------------------------------------------------------------
# Ambient context — what every log line and every ADR_Record written on this task should carry
# ---------------------------------------------------------------------------------------------

CONTEXT_FIELDS = ("request_id", "tenant_id", "trace_id", "span_id", "decision_id")

_CONTEXT: ContextVar[dict[str, str] | None] = ContextVar("mizan_context", default=None)


def _ambient() -> dict[str, str]:
    return _CONTEXT.get() or {}


def bind(**fields: str | None) -> Any:
    """Add fields to the ambient context; returns a token for `release`."""
    merged = dict(_ambient())
    merged.update({key: value for key, value in fields.items() if value is not None})
    return _CONTEXT.set(merged)


def release(token: Any) -> None:
    _CONTEXT.reset(token)


def current() -> Mapping[str, str]:
    return _ambient()


def current_trace() -> TraceContext | None:
    """The trace this task is running under, if a request bound one."""
    context = _ambient()
    trace_id, span_id = context.get("trace_id"), context.get("span_id")
    if not trace_id or not span_id:
        return None
    return TraceContext(trace_id=trace_id, span_id=span_id)


@contextmanager
def context(**fields: str | None) -> Iterator[None]:
    token = bind(**fields)
    try:
        yield
    finally:
        release(token)


# ---------------------------------------------------------------------------------------------
# JSON logs
# ---------------------------------------------------------------------------------------------

# Reserved LogRecord attributes: anything else on the record came from a caller's `extra`. Derived
# from a real record rather than a hand-kept list, which would rot into leaking internals as fields.
_RESERVED = frozenset(vars(logging.LogRecord("", 0, "", 0, "", (), None))) | {
    "asctime",
    "message",
    "taskName",
}
# Fields a log line must never carry, whatever a caller passes. Tool arguments are the payload
# ADR-006 spends a whole boundary keeping out of the decision path; a log statement is not the
# place they re-enter it.
FORBIDDEN_FIELDS = frozenset(
    {
        "arguments",
        "authorization",
        "credential",
        "execution_token",
        "jwt",
        "password",
        "private_key",
        "secret",
        "token",
    }
)
_MAX_VALUE_CHARS = 512


def _scalar(value: Any) -> Any:
    if isinstance(value, str):
        return value if len(value) <= _MAX_VALUE_CHARS else value[:_MAX_VALUE_CHARS] + "…"
    if isinstance(value, bool | int | float) or value is None:
        return value
    rendered = str(value)
    return rendered if len(rendered) <= _MAX_VALUE_CHARS else rendered[:_MAX_VALUE_CHARS] + "…"


class ContextFilter(logging.Filter):
    """Stamp the ambient request/trace fields onto every record this handler sees.

    A filter and *not* a `logging.setLogRecordFactory` hook, which is where this started and is a
    trap: `Logger.makeRecord` raises `KeyError("Attempt to overwrite ...")` when `extra` names a
    key the factory has already set. Ambient `tenant_id` plus a perfectly ordinary
    `extra={"tenant_id": ...}` therefore raised *inside the logging call* — and the call sites that
    pass a tenant explicitly are the breaker and the dropped-security-event handler, so the crash
    landed on exactly the lines that exist to report that something is wrong. A filter runs after
    `extra` has been merged, so it cannot collide, and an explicit value wins over the ambient one
    because `hasattr` is already true.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        for key, value in _ambient().items():
            if not hasattr(record, key):
                setattr(record, key, value)
        return True


class JsonFormatter(logging.Formatter):
    """One line, one event, stable key order — because logs are read by machines under pressure."""

    def format(self, record: logging.LogRecord) -> str:
        document: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        ambient = _ambient()
        for field in CONTEXT_FIELDS:
            if field in ambient:
                document[field] = ambient[field]
        for key, value in record.__dict__.items():
            if key in _RESERVED or key.startswith("_") or key in document:
                continue
            document[key] = f"[redacted:{key}]" if key in FORBIDDEN_FIELDS else _scalar(value)
        if record.exc_info:
            exception = record.exc_info[1]
            document["error_type"] = type(exception).__name__ if exception else "unknown"
            document["error"] = _scalar(str(exception) if exception else "")
            document["stack"] = _scalar(self.formatException(record.exc_info))
        return json.dumps(document, default=str, separators=(",", ":"))


# Libraries that log one INFO line per operation. `httpx` is the one that matters: every Vault
# Transit signature is an HTTP request, so at INFO a drain worker publishing a thousand receipts
# emits a thousand lines reading `HTTP Request: POST https://vault.../v1/transit/sign/... 200 OK`.
# That is not observability -- it buries the lines that mean something, and it puts the key name
# being used to sign evidence into the log on every write. Raised to WARNING, where a failing
# Vault still says so.
NOISY_LIBRARIES = ("httpx", "httpcore", "urllib3")


def configure_logging(level: str = "INFO", *, json_output: bool = True, stream: Any = None) -> None:
    """Install one handler on the root logger. Idempotent: re-running replaces, never stacks."""
    handler = logging.StreamHandler(stream)
    handler.addFilter(ContextFilter())
    handler.setFormatter(
        JsonFormatter()
        if json_output
        else logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    )
    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(level.upper())
    # WARNING by default; DEBUG passes straight through, because the first thing anyone debugging
    # a Vault or database problem wants is exactly the request log this suppresses. Above WARNING
    # the root level wins, so raising this floor can never make a library *noisier* than asked.
    library_level = root.level if root.level == logging.DEBUG else max(logging.WARNING, root.level)
    for library in NOISY_LIBRARIES:
        logging.getLogger(library).setLevel(library_level)


# ---------------------------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------------------------

# Every boundary is an SPEC §7 target, so the SLO is read off a bucket edge instead of interpolated
# between two: token redemption 20 ms, simple authorize 50 ms, complex authorize 150 ms, registry
# write 250 ms, decision search 500 ms.
LATENCY_BUCKETS = (0.005, 0.01, 0.02, 0.05, 0.1, 0.15, 0.25, 0.5, 1.0, 2.5, 5.0, float("inf"))

# A metric label is a dimension of a time series, so an id in a label is an unbounded series and a
# memory leak in the scraper. Route templates and tenant ids are bounded; decision ids are not.
_ID_LIKE = re.compile(r"(adr_|apr_|lse_|epo_)[0-9a-f]{6,}")


class Metrics:
    """The process's own counters, over a registry it owns.

    Deliberately *not* the `prometheus_client` default registry: `create_app()` is called many
    times in one test process, and a module-global registry turns the second call into a
    duplicate-timeseries error — which is the kind of coupling that makes a test suite pass in one
    order and fail in another.
    """

    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        self.registry = registry or CollectorRegistry()
        kwargs = {"registry": self.registry}

        self.http_requests = Counter(
            "mizan_http_requests_total",
            "HTTP requests served, by matched route template.",
            ("method", "route", "status"),
            **kwargs,
        )
        self.http_latency = Histogram(
            "mizan_http_request_duration_seconds",
            "Wall-clock time to serve a request, bucketed on the SPEC section 7 targets.",
            ("method", "route"),
            buckets=LATENCY_BUCKETS,
            **kwargs,
        )
        self.decisions = Counter(
            "mizan_authorization_decisions_total",
            "Authorization decisions recorded, by outcome and by what decided it.",
            ("tenant_id", "decision", "decision_basis"),
            **kwargs,
        )
        self.fail_closed = Counter(
            "mizan_authorization_fail_closed_total",
            "Authorizations that failed closed, by reason.",
            ("tenant_id", "reason"),
            **kwargs,
        )
        self.security_events_dropped = Counter(
            "mizan_security_events_dropped_total",
            "Security events that could not be written and are lost, by event type and cause.",
            ("tenant_id", "event_type", "cause"),
            **kwargs,
        )
        self.evidence_published = Counter(
            "mizan_evidence_records_published_total",
            "Evidence records turned into immutable receipts by the drain worker.",
            ("tenant_id",),
            **kwargs,
        )
        self.events_relayed = Counter(
            "mizan_outbox_events_relayed_total",
            "SPEC section 4 events delivered to the event sink.",
            ("tenant_id",),
            **kwargs,
        )
        self.outbox_quarantined = Counter(
            "mizan_outbox_rows_quarantined_total",
            "Outbox rows that exceeded max attempts or are malformed and will not be retried.",
            ("tenant_id",),
            **kwargs,
        )
        self.outbox_pending = Gauge(
            "mizan_outbox_pending_rows",
            "Outbox rows still awaiting publication, excluding quarantined rows.",
            ("tenant_id",),
            **kwargs,
        )
        self.outbox_quarantined_rows = Gauge(
            "mizan_outbox_quarantined_rows",
            "Outbox rows parked past max attempts, which no retry will clear.",
            ("tenant_id",),
            **kwargs,
        )
        self.publication_lag = Gauge(
            "mizan_evidence_publication_lag_seconds",
            "Age of the oldest unpublished outbox row. The SPEC section 7 drain-lag SLO reads here.",
            ("tenant_id",),
            **kwargs,
        )
        self.anchors_written = Counter(
            "mizan_evidence_anchors_written_total",
            "Signed anchors written, by stream.",
            ("tenant_id", "stream_id"),
            **kwargs,
        )
        self.approvals_expired = Counter(
            "mizan_approvals_expired_total",
            "Approvals reached EXPIRED at rest by the sweeper.",
            ("tenant_id",),
            **kwargs,
        )
        self.leases_expired = Counter(
            "mizan_execution_leases_expired_total",
            "Leases reached LEASE_EXPIRED at rest by the sweeper.",
            ("tenant_id",),
            **kwargs,
        )
        self.breaker = Gauge(
            "mizan_breaker_open",
            "1 while a named breaker is open for a tenant, 0 once it clears.",
            ("tenant_id", "reason"),
            **kwargs,
        )
        self.rate_limit_configured = Gauge(
            "mizan_rate_limit_configured_requests_per_minute",
            "Configured per-replica request capacity, by protected route class and risk tier.",
            ("route_class", "risk_tier"),
            **kwargs,
        )
        self.rate_limit_rejections = Counter(
            "mizan_rate_limit_rejections_total",
            "Requests refused by tenant-scoped admission control.",
            ("tenant_id", "route_class", "risk_tier"),
            **kwargs,
        )
        self.worker_ticks = Counter(
            "mizan_drain_worker_ticks_total",
            "Completed drain-worker ticks, by tenant.",
            ("tenant_id",),
            **kwargs,
        )
        self.worker_tick_failures = Counter(
            "mizan_drain_worker_tick_failures_total",
            "Drain-worker ticks that raised, by tenant and exception type.",
            ("tenant_id", "error_type"),
            **kwargs,
        )
        # A worker that has stopped ticking looks exactly like a quiet tenant in every counter
        # above; this is the one series that distinguishes them.
        self.worker_heartbeat = Gauge(
            "mizan_drain_worker_last_tick_timestamp_seconds",
            "Unix time of the last completed tick. Staleness here means the worker is gone.",
            ("tenant_id",),
            **kwargs,
        )

    def exposition(self) -> bytes:
        from prometheus_client import generate_latest

        return generate_latest(self.registry)


def safe_route(path: str | None) -> str:
    """A route *template*, never a request path — see `_ID_LIKE`."""
    if not path:
        return "__unmatched__"
    return "__unmatched__" if _ID_LIKE.search(path) else path


class MetricsServer:
    """A private listener that serves `/metrics` and nothing else."""

    def __init__(self, metrics: Metrics, host: str, port: int) -> None:
        self.metrics = metrics
        application = make_wsgi_app(metrics.registry)

        class _Quiet(WSGIRequestHandler):
            def log_message(self, *_arguments: Any) -> None:  # scrapes are not events
                return

        self._server = make_server(host, port, application, handler_class=_Quiet)
        self.port = self._server.server_port
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="mizan-metrics", daemon=True
        )

    def start(self) -> MetricsServer:
        self._thread.start()
        LOGGER.info(
            "metrics listener started",
            extra={"port": self.port, "endpoint": "/metrics"},
        )
        return self

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


# ---------------------------------------------------------------------------------------------
# Tracing
# ---------------------------------------------------------------------------------------------


class Tracer(Protocol):
    def span(
        self, name: str, parent: TraceContext | None, attributes: Mapping[str, Any] | None = None
    ) -> Any: ...


class LocalTracer:
    """Propagates trace context and exports nothing.

    This is not a degraded tracer, it is the default one. The guarantee that matters — an
    ADR_Record naming the trace its request belonged to — is met here; a collector adds the ability
    to *open* that trace, which is an operator's choice and an operator's dependency.
    """

    @contextmanager
    def span(
        self, name: str, parent: TraceContext | None, attributes: Mapping[str, Any] | None = None
    ) -> Iterator[TraceContext]:
        yield parent.child() if parent is not None else TraceContext.begin()


class OtelTracer:
    """Real spans, so the id in the evidence resolves in the operator's tracing backend."""

    def __init__(self, provider: Any) -> None:
        self._provider = provider
        self._tracer = provider.get_tracer("mizan.control-plane")

    @contextmanager
    def span(
        self, name: str, parent: TraceContext | None, attributes: Mapping[str, Any] | None = None
    ) -> Iterator[TraceContext]:
        from opentelemetry.trace import (
            NonRecordingSpan,
            SpanContext,
            TraceFlags,
            set_span_in_context,
        )

        parent_context = None
        if parent is not None:
            parent_context = set_span_in_context(
                NonRecordingSpan(
                    SpanContext(
                        trace_id=int(parent.trace_id, 16),
                        span_id=int(parent.span_id, 16),
                        is_remote=True,
                        trace_flags=TraceFlags(_SAMPLED if parent.sampled else 0x00),
                    )
                )
            )
        with self._tracer.start_as_current_span(
            name, context=parent_context, attributes=dict(attributes or {})
        ) as span:
            recorded = span.get_span_context()
            yield TraceContext(
                trace_id=f"{recorded.trace_id:032x}",
                span_id=f"{recorded.span_id:016x}",
                sampled=bool(recorded.trace_flags & _SAMPLED),
            )

    def shutdown(self) -> None:
        self._provider.shutdown()


class TracingRefused(RuntimeError):
    """Configuration that would run, but not with the tracing it was configured for."""


def build_tracer(
    endpoint: str, service_name: str = "mizan-control-plane", environment: str = "development"
) -> Tracer:
    """`LocalTracer` when no endpoint is configured; a real exporter when one is.

    A configured endpoint whose exporter is not installed is refused. The alternative — logging a
    warning and continuing — produces a process that answers every request, reports itself healthy,
    and sends nothing to the collector an operator is watching, which is the failure that gets
    found during the incident rather than before it.
    """
    if not endpoint:
        return LocalTracer()
    try:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError as missing:  # pragma: no cover - exercised by test with a blocked import
        raise TracingRefused(
            f"MIZAN_OTEL_EXPORTER_OTLP_ENDPOINT is set to {endpoint!r} but the OpenTelemetry "
            "exporter is not installed. Install this distribution with the 'otel' extra, or clear "
            "the endpoint and run with propagation only."
        ) from missing
    provider = TracerProvider(
        resource=Resource.create(
            {"service.name": service_name, "deployment.environment": environment}
        )
    )
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
    return OtelTracer(provider)


def service_instance_id() -> str:
    """Stable within a process, distinct across them — for labelling a metrics scrape."""
    return f"{os.getpid()}-{int(time.time())}"


def annotate(**fields: str | None) -> None:
    """Add fields to the *already open* context, for code that learns them late.

    `bind`/`context` open a nested scope and restore it; `annotate` writes into the scope that is
    already open. The distinction matters at exactly one place and it is the important one: a
    request's tenant and decision id are not known when the middleware starts the request, and the
    access log line is written after the route returns. Without an in-place write the one log line
    an operator greps for would be the one line missing the tenant.

    With no scope open it does nothing, deliberately. An `annotate` that opened its own scope
    would have no owner to close it, so the tenant it wrote would stay ambient in that thread and
    reappear on the *next* unit of work — one tenant's identifier stamped on another tenant's log
    line. In a system whose entire premise is that tenants do not leak into each other, a
    convenience that cannot be released is not a convenience. Whoever owns a unit of work opens
    the scope: the HTTP middleware per request, the drain worker per tenant per tick.
    """
    ambient = _CONTEXT.get()
    if ambient is None:
        return
    ambient.update({key: value for key, value in fields.items() if value is not None})


_REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def _request_id(header: str | None) -> str:
    """A caller's correlation id, or one of ours. Never echoed unvalidated into a log line."""
    if header and _REQUEST_ID.match(header):
        return header
    return secrets.token_hex(16)


class RequestObservabilityMiddleware:
    """Trace context in, metrics and one structured access line out.

    Raw ASGI rather than `BaseHTTPMiddleware` for one reason that is not performance: this
    middleware needs the *matched route template* — which the router writes into the same scope
    dict on its way past — and it needs to see it after the response, without the request body
    being buffered to get there.
    """

    def __init__(self, app: Any, metrics: Metrics, tracer: Tracer | None = None) -> None:
        self.app = app
        self.metrics = metrics
        self.tracer = tracer or LocalTracer()

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        headers = {key.decode("latin-1").lower(): value.decode("latin-1") for key, value in scope.get("headers", [])}
        incoming = TraceContext.parse(headers.get("traceparent"))
        request_id = _request_id(headers.get("x-request-id"))
        method, path = scope.get("method", "GET"), scope.get("path", "")
        started = time.perf_counter()
        status_holder = {"status": 500}

        with self.tracer.span(
            f"{method} {path}", incoming, {"http.request.method": method, "url.path": path}
        ) as span:
            scope["mizan_trace"] = span
            token = bind(
                request_id=request_id, trace_id=span.trace_id, span_id=span.span_id
            )

            async def observed_send(message: dict[str, Any]) -> None:
                if message["type"] == "http.response.start":
                    status_holder["status"] = message["status"]
                    message.setdefault("headers", [])
                    message["headers"] = [
                        *message["headers"],
                        (b"traceparent", span.traceparent().encode("latin-1")),
                        (b"x-request-id", request_id.encode("latin-1")),
                    ]
                await send(message)

            try:
                await self.app(scope, receive, observed_send)
            except Exception:
                # The metric and the access line must exist for a request that crashed; that is
                # the request an operator is looking for.
                self._record(scope, method, status_holder["status"], started, failed=True)
                release(token)
                raise
            self._record(scope, method, status_holder["status"], started, failed=False)
            release(token)

    def _record(
        self, scope: dict[str, Any], method: str, status: int, started: float, *, failed: bool
    ) -> None:
        route = getattr(scope.get("route"), "path", None)
        template = safe_route(route)
        elapsed = time.perf_counter() - started
        self.metrics.http_requests.labels(method, template, str(status)).inc()
        self.metrics.http_latency.labels(method, template).observe(elapsed)
        LOGGER.log(
            logging.DEBUG if template.startswith("/health") else logging.INFO,
            "http request",
            extra={
                "http_method": method,
                "http_route": template,
                "http_status": status,
                "duration_ms": round(elapsed * 1000, 3),
                "unhandled_error": failed,
            },
        )
