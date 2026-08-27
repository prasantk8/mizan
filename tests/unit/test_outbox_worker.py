"""The worker that makes `EXPIRED` and `published` reachable without a request.

What is proven here is the scheduling: backpressure, anchor cadence, poison isolation, and the
publication-lag breaker. The repository is a stub at that boundary — deliberately, because the SQL
it stands in for (the attempts filter, the clock-side lag measurement, row-level security) cannot
be proven by a second Python copy of itself. That half is proven against a live database in
`tests/integration/test_outbox_worker_postgres.py`, and neither file is sufficient alone.

Every test in this module fails on 330a2d5: the module under test does not exist there.
"""

from __future__ import annotations

import io
import json
import logging
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from mizan_control_plane.approval import create_approval, expire
from mizan_control_plane.evidence import (
    Ed25519EvidenceSigner,
    LocalImmutableObjectStore,
    OutboxPublisher,
)
from mizan_control_plane.observability import Metrics, configure_logging, context
from mizan_control_plane.outbox_worker import DrainPolicy, EvidenceBreaker, OutboxWorker
from mizan_control_plane.problems import Problem

TENANT = "tnt_bank-a"
EVIDENCE_AGGREGATES = {"decision", "decision_event", "audit"}


def approval(expiry_seconds: int = 900) -> dict[str, Any]:
    return create_approval(
        TENANT,
        "018f47a6-7b42-7c00-8000-0000000000aa",
        "a" * 64,
        {"quorum": 1, "expiry_seconds": expiry_seconds, "approver_roles": ["risk.officer"]},
        {
            "snapshot_at": "2026-08-27T00:00:00Z",
            "authority_source": "mizan_role_registry",
            "authority_mapping_version": 1,
            "roles": ["risk.officer"],
            "members": [
                {
                    "principal_id": "prn_officer",
                    "roles": ["risk.officer"],
                    "control_domain": "risk",
                }
            ],
        },
        datetime(2026, 8, 27, tzinfo=UTC),
    )


class StubRepository:
    """Just enough outbox to schedule against; the SQL itself is proven against Postgres."""

    def __init__(self, rows: list[dict[str, Any]] | None = None) -> None:
        self.rows = rows or []
        self.stream_ids: list[str] = []
        self.published_receipts: list[int] = []
        self.anchor_age: float | None = None

    def add(
        self,
        outbox_id: int,
        aggregate_type: str,
        payload: dict[str, Any],
        event_type: str = "mizan.decision.allow",
        age_seconds: float = 0.0,
        attempts: int = 0,
    ) -> None:
        self.rows.append(
            {
                "outbox_id": outbox_id,
                "event_type": event_type,
                "payload": payload,
                "created_at": datetime.now(UTC) - timedelta(seconds=age_seconds),
                "attempts": attempts,
                "aggregate_type": aggregate_type,
                "published": False,
                "age_seconds": age_seconds,
            }
        )

    def unpublished(
        self,
        tenant_id: str,
        limit: int = 100,
        evidence_only: bool = False,
        max_attempts: int | None = None,
        relay_only: bool = False,
    ) -> list[dict[str, Any]]:
        selected = [row for row in self.rows if not row["published"]]
        if evidence_only:
            selected = [row for row in selected if row["aggregate_type"] in EVIDENCE_AGGREGATES]
        if relay_only:
            selected = [row for row in selected if row["aggregate_type"] not in EVIDENCE_AGGREGATES]
        if max_attempts is not None:
            selected = [row for row in selected if row["attempts"] < max_attempts]
        return selected[:limit]

    def _row(self, outbox_id: int) -> dict[str, Any]:
        return next(row for row in self.rows if row["outbox_id"] == outbox_id)

    def record_publication(
        self, tenant_id: str, outbox_id: int, receipt: dict[str, Any], signature: str
    ) -> None:
        row = self._row(outbox_id)
        row["published"] = True
        row["attempts"] += 1
        self.published_receipts.append(outbox_id)

    def record_delivery(self, tenant_id: str, outbox_id: int) -> bool:
        row = self._row(outbox_id)
        if row["published"]:
            return False
        row["published"] = True
        row["attempts"] += 1
        return True

    def record_delivery_failure(self, tenant_id: str, outbox_id: int) -> int:
        row = self._row(outbox_id)
        row["attempts"] += 1
        return row["attempts"]

    def backlog(self, tenant_id: str, max_attempts: int) -> dict[str, Any]:
        live = [
            row for row in self.rows if not row["published"] and row["attempts"] < max_attempts
        ]
        quarantined = [
            row for row in self.rows if not row["published"] and row["attempts"] >= max_attempts
        ]
        return {
            "pending": len(live),
            "quarantined": len(quarantined),
            "oldest_age_seconds": max((row["age_seconds"] for row in live), default=0.0),
        }

    def streams(self, tenant_id: str) -> list[str]:
        return list(self.stream_ids)

    def seconds_since_last_anchor(self, tenant_id: str, stream_id: str) -> float | None:
        return self.anchor_age


class RecordingSink:
    def __init__(self, fail_on: set[str] | None = None) -> None:
        self.published: list[tuple[str, str, dict[str, Any]]] = []
        self.fail_on = fail_on or set()

    def publish(self, event_type: str, key: str, payload: dict[str, Any]) -> None:
        if event_type in self.fail_on:
            raise RuntimeError("subscriber is down")
        self.published.append((event_type, key, payload))


def evidence_payload(stream: str, sequence: int) -> dict[str, Any]:
    return {"stream_id": stream, "sequence_number": sequence, "record_hash": f"{sequence:064d}"}


def publisher_for(repository: StubRepository, tmp_path, sink: RecordingSink | None = None):
    return OutboxPublisher(
        repository,
        LocalImmutableObjectStore(tmp_path),
        Ed25519EvidenceSigner.development("evidence-receipt"),
        Ed25519EvidenceSigner.development("evidence-anchor"),
        delivery=sink or RecordingSink(),
    )


def worker_for(repository, publisher, **policy: Any) -> OutboxWorker:
    ticks = iter(range(0, 100_000))
    return OutboxWorker(
        publisher,
        repository,
        None,
        (TENANT,),
        DrainPolicy(**policy),
        clock=lambda: float(next(ticks)),
        metrics=Metrics(),
    )


def series(metrics: Metrics, name: str) -> dict[str, float]:
    """One metric family, read back out of the exposition a scraper would actually get.

    Deliberately parsed from the rendered text rather than from the objects that produced it —
    rule 12. A gauge that is set correctly and rendered wrongly is invisible to an operator, and
    reading the counter attribute back would compare the producer against itself.
    """
    found: dict[str, float] = {}
    for line in metrics.exposition().decode().splitlines():
        if line.startswith(f"{name}{{") or line == name:
            labels, _, value = line.rpartition(" ")
            found[labels.removeprefix(name)] = float(value)
    return found


def test_expire_closes_an_elapsed_open_epoch_as_terminal() -> None:
    opened = approval(expiry_seconds=60)
    expired = expire(opened, datetime(2026, 8, 27, 0, 1, 1, tzinfo=UTC))
    assert expired["state"] == "EXPIRED"
    assert expired["epochs"][0]["state"] == "CLOSED_TERMINAL"
    assert expired["epochs"][0]["outcome"] == "EXPIRED"
    assert expired["epochs"][0]["closed_at"] == "2026-08-27T00:01:01Z"


def test_expire_refuses_an_epoch_that_still_has_time_left() -> None:
    opened = approval(expiry_seconds=900)
    with pytest.raises(Problem) as raised:
        expire(opened, datetime(2026, 8, 27, 0, 1, tzinfo=UTC))
    assert raised.value.code == "approval_epoch_live"


def test_expire_refuses_an_approval_that_already_resolved() -> None:
    resolved = approval(expiry_seconds=60)
    resolved["state"] = "APPROVED"
    with pytest.raises(Problem) as raised:
        expire(resolved, datetime(2026, 8, 27, 1, tzinfo=UTC))
    assert raised.value.code == "approval_terminal"


def test_a_malformed_evidence_row_is_quarantined_instead_of_stopping_the_batch(tmp_path) -> None:
    repository = StubRepository()
    repository.add(1, "decision", {"not": "an evidence record"})
    repository.add(2, "decision", evidence_payload("tnt_bank-a:adr:0", 0))
    report = publisher_for(repository, tmp_path).drain_batch(TENANT, limit=10, max_attempts=5)
    assert report.published == 1
    assert report.quarantined == (1,)
    assert repository._row(1)["published"] is False
    assert repository._row(2)["published"] is True


def test_one_unpublishable_stream_does_not_block_the_others(tmp_path) -> None:
    repository = StubRepository()
    repository.add(1, "decision", evidence_payload("tnt_bank-a:adr:0", 0))
    repository.add(2, "decision", evidence_payload("tnt_bank-a:adr:1", 0))
    publisher = publisher_for(repository, tmp_path)
    original = publisher.store.put_once

    def refuse_one_stream(key: str, canonical: bytes) -> str:
        if "adr_0" in key:
            raise OSError("object store rejected the segment")
        return original(key, canonical)

    publisher.store.put_once = refuse_one_stream
    report = publisher.drain_batch(TENANT, limit=10, max_attempts=5)
    assert report.published == 1
    assert repository._row(2)["published"] is True
    # Nothing is dropped: the failed segment is retried, with its attempt counted.
    assert repository._row(1)["published"] is False
    assert repository._row(1)["attempts"] == 1


def test_a_saturated_batch_is_drained_again_before_the_worker_sleeps(tmp_path) -> None:
    repository = StubRepository()
    for index in range(5):
        repository.add(index, "decision", evidence_payload("tnt_bank-a:adr:0", index))
    worker = worker_for(repository, publisher_for(repository, tmp_path), batch_limit=2)
    assert worker.tick_tenant(TENANT).published == 5
    assert all(row["published"] for row in repository.rows)


def test_one_busy_tenant_cannot_hold_the_drain_loop(tmp_path) -> None:
    repository = StubRepository()
    for index in range(10):
        repository.add(index, "decision", evidence_payload("tnt_bank-a:adr:0", index))
    worker = worker_for(
        repository,
        publisher_for(repository, tmp_path),
        batch_limit=1,
        max_batches_per_tenant=3,
    )
    tick = worker.tick_tenant(TENANT)
    assert tick.published == 3
    assert tick.pending == 7


def test_publication_lag_beyond_the_slo_opens_the_breaker_and_recovery_closes_it(tmp_path) -> None:
    repository = StubRepository()
    repository.add(1, "decision", {"not": "publishable"}, age_seconds=30.0)
    worker = worker_for(
        repository,
        publisher_for(repository, tmp_path),
        max_unpublished_seconds=5.0,
        max_attempts=99,
    )
    assert worker.tick_tenant(TENANT).lag_breached is True
    assert ("evidence_publication_lag", TENANT) in worker.breaker.open
    repository.rows[0]["published"] = True
    assert worker.tick_tenant(TENANT).lag_breached is False
    assert ("evidence_publication_lag", TENANT) not in worker.breaker.open


def test_quarantined_rows_are_excluded_from_the_lag_but_open_their_own_breaker(tmp_path) -> None:
    repository = StubRepository()
    repository.add(1, "decision", {"not": "publishable"}, age_seconds=600.0, attempts=5)
    worker = worker_for(
        repository,
        publisher_for(repository, tmp_path),
        max_unpublished_seconds=5.0,
        max_attempts=5,
    )
    tick = worker.tick_tenant(TENANT)
    assert tick.lag_breached is False
    assert tick.oldest_age_seconds == 0.0
    assert ("outbox_poisoned", TENANT) in worker.breaker.open
    assert ("evidence_publication_lag", TENANT) not in worker.breaker.open


def test_events_with_no_receipt_are_relayed_and_marked_published(tmp_path) -> None:
    repository = StubRepository()
    repository.add(1, "approval", {"approval_id": "apr_x"}, event_type="mizan.approval.expired")
    repository.add(2, "agent", {"agent_id": "agt_x"}, event_type="mizan.agent.updated")
    sink = RecordingSink()
    worker = worker_for(repository, publisher_for(repository, tmp_path, sink))
    assert worker.tick_tenant(TENANT).relayed == 2
    assert [event for event, _key, _payload in sink.published] == [
        "mizan.approval.expired",
        "mizan.agent.updated",
    ]
    assert all(row["published"] for row in repository.rows)


def test_a_delivery_failure_counts_an_attempt_and_leaves_the_row_unpublished(tmp_path) -> None:
    repository = StubRepository()
    repository.add(1, "approval", {"approval_id": "apr_x"}, event_type="mizan.approval.expired")
    sink = RecordingSink(fail_on={"mizan.approval.expired"})
    worker = worker_for(repository, publisher_for(repository, tmp_path, sink))
    assert worker.tick_tenant(TENANT).relayed == 0
    assert repository._row(1)["published"] is False
    assert repository._row(1)["attempts"] == 1


def test_a_stream_that_has_never_been_anchored_is_due_immediately(tmp_path) -> None:
    repository = StubRepository()
    repository.stream_ids = ["tnt_bank-a:adr:0"]
    repository.anchor_age = None
    publisher = publisher_for(repository, tmp_path)
    anchored: list[str] = []
    publisher.anchor = lambda tenant, stream: anchored.append(stream)
    worker = worker_for(repository, publisher, anchor_interval_seconds=300.0)
    assert worker.tick_tenant(TENANT).anchored == ("tnt_bank-a:adr:0",)
    assert anchored == ["tnt_bank-a:adr:0"]


def test_anchor_cadence_is_measured_from_the_stream_not_from_process_start(tmp_path) -> None:
    repository = StubRepository()
    repository.stream_ids = ["tnt_bank-a:adr:0"]
    repository.anchor_age = 100.0
    publisher = publisher_for(repository, tmp_path)
    anchored: list[str] = []
    publisher.anchor = lambda tenant, stream: anchored.append(stream)
    worker = worker_for(repository, publisher, anchor_interval_seconds=300.0)
    # A worker that restarts more often than the cadence would never reach this point if the
    # baseline were its own start time; the stream's last anchor is what decides.
    for _ in range(5):
        assert worker.tick_tenant(TENANT).anchored == ()
    repository.anchor_age = 301.0
    assert worker.tick_tenant(TENANT).anchored == ("tnt_bank-a:adr:0",)
    assert anchored == ["tnt_bank-a:adr:0"]


def test_enough_published_records_anchor_a_stream_before_its_time_is_up(tmp_path) -> None:
    repository = StubRepository()
    repository.stream_ids = ["tnt_bank-a:adr:0"]
    repository.anchor_age = 10.0
    for index in range(4):
        repository.add(index, "decision", evidence_payload("tnt_bank-a:adr:0", index))
    publisher = publisher_for(repository, tmp_path)
    reached: list[str] = []
    publisher.anchor = lambda tenant, stream: reached.append(stream)
    worker = worker_for(
        repository, publisher, anchor_interval_seconds=86_400.0, anchor_interval_records=4
    )
    assert worker.tick_tenant(TENANT).anchored == ("tnt_bank-a:adr:0",)
    assert reached == ["tnt_bank-a:adr:0"]


def test_an_empty_anchor_range_is_not_a_worker_failure(tmp_path) -> None:
    repository = StubRepository()
    repository.stream_ids = ["tnt_bank-a:adr:0"]
    repository.anchor_age = None
    publisher = publisher_for(repository, tmp_path)

    def nothing_to_anchor(tenant: str, stream: str) -> dict[str, Any]:
        raise Problem(404, "evidence_range_empty", "No published records are available to anchor")

    publisher.anchor = nothing_to_anchor
    worker = worker_for(repository, publisher, anchor_interval_seconds=0.0)
    assert worker.tick_tenant(TENANT).anchored == ()


def test_an_anchor_failure_is_loud_but_does_not_stop_the_worker(tmp_path) -> None:
    repository = StubRepository()
    repository.stream_ids = ["tnt_bank-a:adr:0", "tnt_bank-a:adr:1"]
    repository.anchor_age = None
    publisher = publisher_for(repository, tmp_path)
    anchored: list[str] = []

    def broken(tenant: str, stream: str) -> dict[str, Any]:
        if stream.endswith(":0"):
            raise Problem(409, "anchor_range_not_dense", "Anchor range must be dense")
        anchored.append(stream)
        return {}

    publisher.anchor = broken
    worker = worker_for(repository, publisher, anchor_interval_seconds=0.0)
    # The process publishes for everyone; killing the tick would stop every other tenant too.
    assert worker.tick_tenant(TENANT).anchored == ("tnt_bank-a:adr:1",)
    assert anchored == ["tnt_bank-a:adr:1"]
    assert ("anchor_refused", TENANT) in worker.breaker.open


def test_a_stream_is_not_anchored_while_anything_is_still_unpublished(tmp_path) -> None:
    repository = StubRepository()
    repository.stream_ids = ["tnt_bank-a:adr:0"]
    repository.anchor_age = None
    # A quarantined row leaves a permanent gap: an anchor over it would swear to a range the
    # stream does not have, which the database refuses outright.
    repository.add(1, "decision", {"not": "publishable"}, attempts=9)
    publisher = publisher_for(repository, tmp_path)
    publisher.anchor = lambda tenant, stream: pytest.fail("anchored over an unpublished gap")
    worker = worker_for(repository, publisher, anchor_interval_seconds=0.0, max_attempts=99)
    assert worker.tick_tenant(TENANT).anchored == ()


def test_a_worker_with_no_tenants_is_refused(tmp_path) -> None:
    repository = StubRepository()
    with pytest.raises(ValueError, match="no tenants"):
        OutboxWorker(publisher_for(repository, tmp_path), repository, None, ())


def test_the_breaker_reports_open_until_it_is_cleared() -> None:
    breaker = EvidenceBreaker()
    assert breaker.is_open is False
    breaker.trip("evidence_publication_lag", TENANT, "12.0s")
    breaker.trip("evidence_publication_lag", TENANT, "13.0s")
    assert breaker.is_open is True
    assert len(breaker.history) == 1, "an open breaker must not re-fire every tick"
    breaker.clear("evidence_publication_lag", TENANT)
    assert breaker.is_open is False


# ---------------------------------------------------------------------------------------------
# T-073: the worker's voice. Before this, the only way to learn any of the below was to read the
# process's stderr, and the breaker was a set inside it that no operator could reach at all.
# ---------------------------------------------------------------------------------------------


class ExplodingRepository(StubRepository):
    """A repository that fails for exactly one tenant, the way a per-tenant fault actually does."""

    def __init__(self, doomed: str) -> None:
        super().__init__()
        self.doomed = doomed

    def backlog(self, tenant_id: str, max_attempts: int) -> dict[str, Any]:
        if tenant_id == self.doomed:
            raise RuntimeError("relation mizan.outbox does not exist for this tenant")
        return super().backlog(tenant_id, max_attempts)


def test_one_tenant_whose_tick_raises_does_not_stop_the_others(tmp_path) -> None:
    """The same isolation T-074 gave a stream, one level up — and for a larger reason.

    This process is the only thing publishing evidence for *every* tenant, so a fault scoped to
    one tenant that takes the loop down converts a local outage into a total one: every other
    tenant's financial writes then block on receipts nothing is writing. Fails on 793a54a, where
    `tick` is a list comprehension and the first exception ends the pass.
    """
    repository = ExplodingRepository("tnt_broken")
    metrics = Metrics()
    worker = OutboxWorker(
        publisher_for(repository, tmp_path),
        repository,
        None,
        ("tnt_broken", TENANT),
        DrainPolicy(),
        metrics=metrics,
    )
    ticks = worker.tick()
    assert [tick.tenant_id for tick in ticks] == [TENANT]
    assert series(metrics, "mizan_drain_worker_tick_failures_total") == {
        '{error_type="RuntimeError",tenant_id="tnt_broken"}': 1.0
    }
    assert worker.breaker.open == {("drain_tick_failed", "tnt_broken")}


def test_a_tick_publishes_the_backlog_it_found_as_gauges_a_scraper_can_read(tmp_path) -> None:
    repository = StubRepository()
    repository.add(1, "decision", evidence_payload("tnt_bank-a:adr:0", 1))
    repository.add(2, "approval", {"approval_id": "apr_1"}, event_type="mizan.approval.requested")
    metrics = Metrics()
    worker = OutboxWorker(
        publisher_for(repository, tmp_path),
        repository,
        None,
        (TENANT,),
        DrainPolicy(anchor_interval_seconds=0.0),
        metrics=metrics,
    )
    tick = worker.tick_tenant(TENANT)
    label = f'{{tenant_id="{TENANT}"}}'
    assert series(metrics, "mizan_evidence_records_published_total")[label] == 1.0
    assert series(metrics, "mizan_outbox_events_relayed_total")[label] == 1.0
    assert series(metrics, "mizan_outbox_pending_rows")[label] == 0.0
    assert series(metrics, "mizan_drain_worker_ticks_total")[label] == 1.0
    assert series(metrics, "mizan_drain_worker_last_tick_timestamp_seconds")[label] > 0
    assert tick.published == 1 and tick.relayed == 1


def test_a_worker_that_stopped_ticking_is_distinguishable_from_a_quiet_tenant(tmp_path) -> None:
    """Every counter above reads identically for both, and they call for opposite responses.

    A tenant with nothing to publish and a worker that died three hours ago both show zero
    published, zero relayed, zero pending. The heartbeat gauge is the only series that separates
    them, which is why it exists and why it is a timestamp rather than a count.
    """
    repository = StubRepository()
    metrics = Metrics()
    worker = OutboxWorker(
        publisher_for(repository, tmp_path), repository, None, (TENANT,), DrainPolicy(),
        metrics=metrics,
    )
    worker.tick_tenant(TENANT)
    first = series(metrics, "mizan_drain_worker_last_tick_timestamp_seconds")[f'{{tenant_id="{TENANT}"}}']
    time.sleep(0.01)
    worker.tick_tenant(TENANT)
    second = series(metrics, "mizan_drain_worker_last_tick_timestamp_seconds")[f'{{tenant_id="{TENANT}"}}']
    assert second > first


def test_the_lag_gauge_is_read_from_the_database_not_accumulated_in_the_process(tmp_path) -> None:
    """So a restarted worker reports the real backlog on its first tick instead of zero.

    A process-local accumulator resets on restart, and a backlog metric that reads zero after a
    crash is indistinguishable from a backlog that cleared. Those two states call for opposite
    responses, and the crash is the one where being wrong costs the most.
    """
    repository = StubRepository()
    # Undrainable rather than malformed: a malformed row is quarantined on the first pass and
    # leaves the lag, which is T-074's behaviour and not what is under test here.
    repository.add(1, "approval", {"approval_id": "apr_1"}, event_type="mizan.approval.requested", age_seconds=42.0)
    metrics = Metrics()
    fresh = OutboxWorker(
        publisher_for(repository, tmp_path, RecordingSink(fail_on={"mizan.approval.requested"})),
        repository,
        None,
        (TENANT,),
        DrainPolicy(),
        metrics=metrics,
    )
    fresh.tick_tenant(TENANT)
    label = f'{{tenant_id="{TENANT}"}}'
    assert series(metrics, "mizan_evidence_publication_lag_seconds")[label] >= 42.0
    assert series(metrics, "mizan_outbox_pending_rows")[label] == 1.0


def test_the_breaker_gauge_keeps_asserting_while_it_is_open() -> None:
    """A scraper that starts after the edge must still learn the breaker is open.

    The log line fires once because a human reads it. The gauge cannot: Prometheus samples, so a
    series that is written only on the transition is a series that reads zero to anything that
    connected afterwards — which is every scraper restart, every rollout, every new alert rule.
    """
    metrics = Metrics()
    breaker = EvidenceBreaker(metrics)
    breaker.trip("evidence_publication_lag", TENANT, "12.0s old")
    breaker.trip("evidence_publication_lag", TENANT, "12.5s old")
    assert len(breaker.history) == 1, "the human-facing log fires once"
    assert series(metrics, "mizan_breaker_open")[
        f'{{reason="evidence_publication_lag",tenant_id="{TENANT}"}}'
    ] == 1.0
    breaker.clear("evidence_publication_lag", TENANT)
    assert series(metrics, "mizan_breaker_open")[
        f'{{reason="evidence_publication_lag",tenant_id="{TENANT}"}}'
    ] == 0.0


def test_every_tick_of_one_tenant_shares_one_trace(tmp_path) -> None:
    """The worker has no caller, so each tick starts its own trace.

    Without one, a tick's log lines are unrelated records that happen to share a timestamp; with
    one, `trace_id=` selects everything one tenant's pass did and nothing else's. Read out of the
    rendered JSON rather than off the `LogRecord`, because what an operator greps is the line that
    was written, not the object that produced it.
    """
    repository = StubRepository()
    repository.add(1, "decision", {"malformed": True})
    worker = worker_for(repository, publisher_for(repository, tmp_path))
    stream = io.StringIO()
    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    try:
        configure_logging("WARNING", json_output=True, stream=stream)
        worker.tick_tenant(TENANT)
    finally:
        root.handlers[:] = handlers
        root.setLevel(level)
    lines = [json.loads(line) for line in stream.getvalue().splitlines() if line.strip()]
    assert lines, "a quarantined row must say so"
    traces = {line["trace_id"] for line in lines}
    assert len(traces) == 1
    assert {line["tenant_id"] for line in lines} == {TENANT}


def test_a_log_line_that_names_its_own_tenant_does_not_crash_the_worker(tmp_path) -> None:
    """The ambient tenant and an explicit `extra={"tenant_id": ...}` must coexist.

    They did not, briefly: stamping ambient fields via `logging.setLogRecordFactory` made
    `makeRecord` raise `KeyError` whenever a caller passed the same key — and the two call sites
    that pass a tenant explicitly are the breaker and the dropped-security-event handler. An
    observability change that crashes on the log line reporting a fault is worse than no line.
    """
    stream = io.StringIO()
    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    try:
        configure_logging("WARNING", json_output=True, stream=stream)
        with context(tenant_id=TENANT, trace_id="a" * 32, span_id="b" * 16):
            EvidenceBreaker(Metrics()).trip("evidence_publication_lag", TENANT, "12.0s")
    finally:
        root.handlers[:] = handlers
        root.setLevel(level)
    line = json.loads(stream.getvalue().strip())
    assert line["tenant_id"] == TENANT and line["trace_id"] == "a" * 32
    assert line["breaker"] == "evidence_publication_lag"
