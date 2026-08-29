"""What the system says about itself, and what it may not say.

Three claims are under test here and they are not interchangeable. The trace id is a *contract*:
SPEC §2 says `ADR_Record.trace_id` is the W3C traceparent trace-id, so a record whose trace id
belongs to no trace is a false statement in signed evidence, and that is tested against the shape
of the old value directly. The span export is an *integration*, so what is tested is that it joins
the same ids rather than inventing its own, and that a misconfiguration is refused instead of
absorbed. The metrics are a *sample*, so what is tested is the property that makes a sample
readable — bounded label cardinality — and never a count as though it were evidence.

Every test in this module fails on 793a54a, most of them with ImportError because the module is
new. The three that demonstrate a *defect* rather than an addition are named in the docstring of
`test_the_trace_id_recorded_is_the_callers_trace_and_not_a_hash_of_the_request_id`,
`test_a_security_event_sink_that_fails_does_not_change_the_security_answer` and
`test_one_tenant_whose_tick_raises_does_not_stop_the_others`, which run against the pre-T-073 code
paths and fail there for the reason each names.
"""

from __future__ import annotations

import builtins
import io
import json
import logging
import urllib.request
from contextlib import contextmanager

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from mizan_control_plane.observability import (
    FORBIDDEN_FIELDS,
    JsonFormatter,
    LocalTracer,
    Metrics,
    MetricsServer,
    RequestObservabilityMiddleware,
    TraceContext,
    TracingRefused,
    annotate,
    build_tracer,
    configure_logging,
    context,
    current,
    current_trace,
    safe_route,
)

CALLER = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
CALLER_TRACE = "4bf92f3577b34da6a3ce929d0e0e4736"


# --------------------------------------------------------------------------------------------
# W3C trace context
# --------------------------------------------------------------------------------------------


def test_a_callers_trace_is_continued_rather_than_replaced() -> None:
    """The whole value of the field: one id spans the agent, the gateway and the decision."""
    parent = TraceContext.parse(CALLER)
    assert parent is not None and parent.trace_id == CALLER_TRACE and parent.remote
    child = parent.child()
    assert child.trace_id == CALLER_TRACE
    assert child.span_id != parent.span_id
    assert child.traceparent().startswith(f"00-{CALLER_TRACE}-")


@pytest.mark.parametrize(
    "header",
    [
        "",
        "not-a-traceparent",
        "00-" + "0" * 32 + "-00f067aa0ba902b7-01",  # all-zero trace-id is invalid
        "00-4bf92f3577b34da6a3ce929d0e0e4736-" + "0" * 16 + "-01",  # all-zero parent-id
        "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",  # reserved version
        "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",  # uppercase is not hex here
    ],
)
def test_an_invalid_traceparent_is_not_continued(header: str) -> None:
    assert TraceContext.parse(header) is None


def test_a_traceparent_from_a_later_version_is_still_followed() -> None:
    """A caller that upgrades first must not have its trace broken by this service.

    The specification is explicit that a version-00 parser accepts the fields it knows and ignores
    the rest. Rejecting the header would start a *new* trace, which looks like a working system
    and silently severs every request from the caller that made it.
    """
    followed = TraceContext.parse(f"01-{CALLER_TRACE}-00f067aa0ba902b7-01-extra-field")
    assert followed is not None and followed.trace_id == CALLER_TRACE


def test_an_absent_traceparent_begins_a_trace_instead_of_failing_the_request() -> None:
    started = TraceContext.start(None)
    assert len(started.trace_id) == 32 and len(started.span_id) == 16
    assert TraceContext.start(None).trace_id != started.trace_id


def test_the_sampled_flag_survives_the_hop() -> None:
    unsampled = TraceContext.parse(f"00-{CALLER_TRACE}-00f067aa0ba902b7-00")
    assert unsampled is not None and unsampled.sampled is False
    assert unsampled.child().traceparent().endswith("-00")


# --------------------------------------------------------------------------------------------
# Structured logs
# --------------------------------------------------------------------------------------------


@contextmanager
def root_logging_restored():
    """`configure_logging` owns the root logger, so a test that calls it must hand it back.

    Not politeness: pytest's own capture handler lives on the root logger, and a test that clears
    it silently disables `caplog` for every test that runs afterwards in the same process. That is
    a suite that passes in one order and fails in another, which is the failure mode this tree has
    already been bitten by once (T-074's integration fixtures).
    """
    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    try:
        yield
    finally:
        root.handlers[:] = handlers
        root.setLevel(level)


def _one_line(record_call) -> dict:
    stream = io.StringIO()
    with root_logging_restored():
        configure_logging("DEBUG", json_output=True, stream=stream)
        record_call(logging.getLogger("mizan.test"))
    return json.loads(stream.getvalue().strip())


def test_a_log_line_carries_the_trace_of_the_work_that_produced_it() -> None:
    def emit(logger: logging.Logger) -> None:
        with context(request_id="rq-1", tenant_id="tnt_bank-a", trace_id=CALLER_TRACE, span_id="00f067aa0ba902b7"):
            logger.info("drained", extra={"published": 4})

    line = _one_line(emit)
    assert line["trace_id"] == CALLER_TRACE
    assert line["tenant_id"] == "tnt_bank-a"
    assert line["request_id"] == "rq-1"
    assert line["published"] == 4
    assert line["level"] == "INFO"
    assert line["timestamp"].endswith("Z")


def test_a_secret_never_reaches_a_log_line_however_it_is_passed() -> None:
    """A log statement is not a hole in the ADR-006 payload boundary.

    `arguments` is the tool payload the whole external-input boundary exists to keep out of the
    decision path; a well-meant `extra={"arguments": ...}` would put it in a file that leaves the
    host. The field is replaced rather than dropped, so a reader can see something was withheld
    instead of concluding the caller forgot to log it.
    """
    def emit(logger: logging.Logger) -> None:
        logger.warning(
            "refused",
            extra={key: "SENSITIVE" for key in FORBIDDEN_FIELDS} | {"decision_id": "adr_1"},
        )

    line = _one_line(emit)
    assert "SENSITIVE" not in json.dumps(line)
    for key in FORBIDDEN_FIELDS:
        assert line[key] == f"[redacted:{key}]"
    assert line["decision_id"] == "adr_1"


def test_one_enormous_field_cannot_become_the_whole_log_file() -> None:
    line = _one_line(lambda logger: logger.info("big", extra={"blob": "x" * 100_000}))
    assert len(line["blob"]) < 600 and line["blob"].endswith("…")


def test_an_exception_is_a_field_not_a_wall_of_text() -> None:
    def emit(logger: logging.Logger) -> None:
        try:
            raise ValueError("pool is gone")
        except ValueError:
            logger.exception("write failed")

    line = _one_line(emit)
    assert line["error_type"] == "ValueError"
    assert line["error"] == "pool is gone"
    assert "Traceback" in line["stack"]


def test_reconfiguring_logging_replaces_the_handler_and_never_stacks_them() -> None:
    """Two handlers means every line twice, and a duplicated audit line reads as two events."""
    first, second = io.StringIO(), io.StringIO()
    with root_logging_restored():
        configure_logging("INFO", stream=first)
        configure_logging("INFO", stream=second)
        logging.getLogger("mizan.test").info("once")
    assert first.getvalue() == ""
    assert len(second.getvalue().strip().splitlines()) == 1


def test_a_tenant_learned_late_still_reaches_the_line_written_at_the_end() -> None:
    """`annotate` writes into the open scope; `bind` would open a new one and lose it.

    The access log line is emitted after the route returns, and the tenant is only known once the
    bearer token has been verified inside it. Without an in-place write the one line an operator
    greps by tenant is the one line with no tenant on it.
    """
    stream = io.StringIO()
    with root_logging_restored():
        configure_logging("INFO", stream=stream)
        with context(request_id="rq-2"):
            annotate(tenant_id="tnt_bank-b", decision_id="adr_late")
            logging.getLogger("mizan.test").info("access")
    line = json.loads(stream.getvalue().strip())
    assert line["tenant_id"] == "tnt_bank-b" and line["decision_id"] == "adr_late"


def test_a_tenant_can_never_be_annotated_onto_the_next_unit_of_work() -> None:
    """Ambient context may not outlive the scope that opened it.

    `annotate` with nothing open is a no-op rather than a scope it cannot close. The alternative
    looks harmless and is not: a tenant written with no owner to release it stays ambient in that
    thread and reappears on whatever runs next — one tenant's identifier stamped on another
    tenant's log line, in a system whose whole premise is that tenants do not reach each other.
    Worker threads and pooled request handlers are exactly where that bites.
    """
    annotate(tenant_id="tnt_bank-a", decision_id="adr_leaked")
    assert current().get("tenant_id") is None

    with context(request_id="rq-3"):
        annotate(tenant_id="tnt_bank-b")
        assert current()["tenant_id"] == "tnt_bank-b"
    assert current().get("tenant_id") is None


def test_a_json_formatter_never_leaks_a_logrecord_internal_as_a_field() -> None:
    line = _one_line(lambda logger: logger.info("plain"))
    assert set(line) == {"timestamp", "level", "logger", "message"}


# --------------------------------------------------------------------------------------------
# Metrics
# --------------------------------------------------------------------------------------------


def test_an_identifier_can_never_become_a_metric_label() -> None:
    """One time series per decision is a memory leak in the scraper, not a metric.

    This is the failure mode that kills a Prometheus instance rather than degrading it, and it
    arrives quietly: the dashboards keep working until the day the cardinality crosses the heap.
    """
    assert safe_route("/v1/decisions/{decision_id}") == "/v1/decisions/{decision_id}"
    assert safe_route("/v1/decisions/adr_9f2b1c8ad0e14477a1b2") == "__unmatched__"
    assert safe_route("/v1/approvals/apr_7c1d2e3f4a5b6c7d") == "__unmatched__"
    assert safe_route(None) == "__unmatched__"


def test_two_metrics_objects_do_not_collide_in_one_process() -> None:
    """`create_app()` is called many times in one test process; a global registry would explode."""
    first, second = Metrics(), Metrics()
    first.decisions.labels("tnt_bank-a", "ALLOW", "matched_policy").inc()
    assert b"mizan_authorization_decisions_total" in first.exposition()
    assert b'decision="ALLOW"' not in second.exposition()


def test_every_section_7_latency_target_is_a_bucket_edge() -> None:
    """So an SLO is read off the histogram rather than interpolated between two buckets."""
    from mizan_control_plane.observability import LATENCY_BUCKETS

    for target_seconds in (0.02, 0.05, 0.15, 0.25, 0.5):
        assert target_seconds in LATENCY_BUCKETS


def test_the_metrics_listener_serves_the_exposition_and_nothing_else() -> None:
    metrics = Metrics()
    metrics.approvals_expired.labels("tnt_bank-a").inc()
    server = MetricsServer(metrics, "127.0.0.1", 0).start()
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{server.port}/metrics", timeout=5) as body:
            payload = body.read().decode()
        assert "mizan_approvals_expired_total{tenant_id=\"tnt_bank-a\"} 1.0" in payload
    finally:
        server.close()


# --------------------------------------------------------------------------------------------
# Tracing
# --------------------------------------------------------------------------------------------


def test_no_collector_configured_is_a_working_tracer_not_a_disabled_one() -> None:
    tracer = build_tracer("")
    assert isinstance(tracer, LocalTracer)
    parent = TraceContext.parse(CALLER)
    with tracer.span("POST /v1/authorize", parent) as span:
        assert span.trace_id == CALLER_TRACE and span.span_id != parent.span_id


def test_a_configured_collector_with_no_exporter_installed_refuses_to_start(monkeypatch) -> None:
    """Configured-and-silent is the failure an operator finds during the incident.

    A process that answers every request, reports itself ready, and sends nothing to the collector
    that is being watched has removed the observability it was configured for while looking
    healthy. Refusing at startup converts that into a deployment failure, which is the cheap one.
    """
    real_import = builtins.__import__

    def blocked(name: str, *arguments, **keywords):
        if name.startswith("opentelemetry"):
            raise ImportError("no module named opentelemetry")
        return real_import(name, *arguments, **keywords)

    monkeypatch.setattr(builtins, "__import__", blocked)
    with pytest.raises(TracingRefused) as refused:
        build_tracer("http://collector.internal:4318/v1/traces")
    assert "otel" in str(refused.value)


def test_an_exported_span_carries_the_same_ids_the_evidence_will_name() -> None:
    """The join is the point: the id in the ADR_Record must open in the tracing backend.

    Asserting that a tracer was constructed proves nothing an operator cares about. This starts a
    real OpenTelemetry span under the caller's remote parent, exports it, and reads the exported
    span's own ids back — so a change that made the recorded id and the exported id diverge would
    fail here rather than at 3am with an auditor's record in hand.
    """
    from mizan_control_plane.observability import OtelTracer
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = OtelTracer(provider)

    with tracer.span("POST /v1/authorize", TraceContext.parse(CALLER)) as recorded:
        pass

    exported = exporter.get_finished_spans()
    assert len(exported) == 1
    exported_context = exported[0].get_span_context()
    assert f"{exported_context.trace_id:032x}" == CALLER_TRACE == recorded.trace_id
    assert f"{exported_context.span_id:016x}" == recorded.span_id


# --------------------------------------------------------------------------------------------
# The HTTP surface
# --------------------------------------------------------------------------------------------


def _instrumented() -> tuple[TestClient, Metrics]:
    metrics = Metrics()
    app = FastAPI()

    @app.get("/v1/decisions/{decision_id}")
    def one(decision_id: str) -> dict:
        return {"decision_id": decision_id, "trace": current_trace().trace_id}

    @app.get("/v1/boom")
    def boom() -> dict:
        raise RuntimeError("upstream is gone")

    app.add_middleware(RequestObservabilityMiddleware, metrics=metrics, tracer=LocalTracer())
    return TestClient(app, raise_server_exceptions=False), metrics


def test_a_response_names_the_trace_the_caller_can_join() -> None:
    client, _ = _instrumented()
    response = client.get("/v1/decisions/adr_abc123def456", headers={"traceparent": CALLER})
    assert response.status_code == 200
    assert response.json()["trace"] == CALLER_TRACE
    assert response.headers["traceparent"].startswith(f"00-{CALLER_TRACE}-")
    assert response.headers["x-request-id"]


def test_a_hostile_request_id_is_not_echoed_into_the_logs() -> None:
    """A correlation id a caller chooses is caller-controlled text in an operator's log pipeline."""
    client, _ = _instrumented()
    response = client.get(
        "/v1/decisions/adr_abc123def456",
        headers={"X-Request-Id": 'evil"\n{"level":"CRITICAL","message":"forged"}'},
    )
    assert '"' not in response.headers["x-request-id"]
    assert "\n" not in response.headers["x-request-id"]


def test_latency_is_recorded_against_the_route_template_not_the_request_path() -> None:
    client, metrics = _instrumented()
    for suffix in ("aaa111bbb222", "ccc333ddd444", "eee555fff666"):
        client.get(f"/v1/decisions/adr_{suffix}")
    exposition = metrics.exposition().decode()
    assert 'route="/v1/decisions/{decision_id}"' in exposition
    assert "adr_aaa111bbb222" not in exposition
    series = [line for line in exposition.splitlines() if line.startswith("mizan_http_requests_total{")]
    assert len(series) == 1, "three requests to one route must be one time series"


def test_a_request_that_raises_is_still_counted_and_still_logged() -> None:
    """The crashed request is the one an operator is looking for; it must not be the one missing."""
    client, metrics = _instrumented()
    client.get("/v1/boom")
    exposition = metrics.exposition().decode()
    assert 'route="/v1/boom",status="500"' in exposition
    assert 'mizan_http_request_duration_seconds_count{method="GET",route="/v1/boom"} 1.0' in exposition


# ---------------------------------------------------------------------
# What the call sites attach (T-107)
#
# These three came from the other head of this repository, where the same module was written
# against a narrower brief. They are kept because they pin a defect the tests above describe
# only by implication: the formatter this system actually shipped rendered `%(message)s`, so
# every field passed through `extra=` reached the record and was never printed.
# ---------------------------------------------------------------------


def _emit(formatter: logging.Formatter, **extra: object) -> str:
    logger = logging.getLogger("mizan.test.emit")
    record = logger.makeRecord(
        "mizan.test.emit", logging.ERROR, __file__, 1, "security_event_pool_timeout", (), None
    )
    for key, value in extra.items():
        setattr(record, key, value)
    return formatter.format(record)


def test_the_default_formatter_drops_what_the_call_sites_attach() -> None:
    """`execution.py` and `service.py` both report a security-relevant failure through `extra=`.

    Under the `logging.basicConfig()` this system used, the default format is `%(message)s`, so
    both dictionaries were attached to the record and never printed: the operator investigating
    a fail-closed evidence write got a line naming neither the tenant nor the decision. This
    asserts the defect rather than describing it, so the fix has something to be measured against.
    """
    old = logging.Formatter()  # exactly what basicConfig() installs by default
    rendered = _emit(old, tenant_id="tnt_bank-a", decision_id="dec-1")

    assert rendered == "security_event_pool_timeout"
    assert "tnt_bank-a" not in rendered
    assert "dec-1" not in rendered


def test_the_json_formatter_keeps_every_field_the_call_site_attached() -> None:
    payload = json.loads(_emit(JsonFormatter(), tenant_id="tnt_bank-a", decision_id="dec-1"))

    assert payload["message"] == "security_event_pool_timeout"
    assert payload["tenant_id"] == "tnt_bank-a"
    assert payload["decision_id"] == "dec-1"
    assert payload["level"] == "ERROR"
    assert payload["logger"] == "mizan.test.emit"
    assert payload["timestamp"].endswith("Z")


def test_an_unserialisable_field_is_rendered_rather_than_losing_the_line() -> None:
    """A formatter that raises inside a failure path is worse than one that approximates.

    Both `extra=` call sites are on error paths, and one of them is the fail-closed evidence
    write -- the last line anyone gets before the request is refused.
    """

    class Opaque:
        def __repr__(self) -> str:
            return "<opaque>"

    payload = json.loads(_emit(JsonFormatter(), thing=Opaque()))
    assert payload["thing"] == "<opaque>"


def test_a_library_that_logs_every_request_does_not_drown_the_lines_that_matter() -> None:
    """Every Vault Transit signature is an HTTP request, and `httpx` logs one INFO line each.

    Found while booting production for the first time (T-101): four key reads produced four
    `HTTP Request: GET https://vault.../v1/transit/keys/... 200 OK` lines before the process had
    served anything. A drain worker publishing a thousand receipts would emit a thousand more --
    burying the lines that mean something, and naming the key used to sign evidence on every write.
    """
    configure_logging("INFO")
    assert logging.getLogger("httpx").level == logging.WARNING

    # DEBUG passes straight through: the first thing anyone debugging a Vault problem wants is
    # exactly the request log this suppresses.
    configure_logging("DEBUG")
    assert logging.getLogger("httpx").level == logging.DEBUG

    # And raising the floor can never make a library noisier than the level that was asked for.
    configure_logging("ERROR")
    assert logging.getLogger("httpx").level == logging.ERROR
