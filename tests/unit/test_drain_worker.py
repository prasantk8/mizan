"""The drain worker's four behaviours, each exercised against the real `OutboxPublisher`.

Only the repository is faked, and it is faked at the SQL boundary rather than at the publisher's
-- so `drain`, its grouping, its receipt signing and its error path all run for real. A worker
tested against a faked publisher would prove only that the worker calls the methods it calls.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from mizan_control_plane.drain_worker import (
    DrainReport,
    StopSignal,
    resolve_tenants,
    run_once,
)
from mizan_control_plane.evidence import (
    Ed25519EvidenceSigner,
    LocalImmutableObjectStore,
    OutboxPublisher,
)
from mizan_control_plane.problems import Problem

TENANT = "tnt_bank-a"
STREAM = f"{TENANT}:adr:0"


class FakeDrainRepository:
    """The three tables the worker touches, with the semantics that actually matter.

    `unpublished` hides published and quarantined rows and honours the limit, because the
    worker's backpressure loop reads saturation off exactly that; `record_publication_failure`
    reproduces the migration's quarantine-at-budget arithmetic; `oldest_unpublished_age_seconds`
    is driven by an injected age so the SLO test does not sleep.
    """

    def __init__(self, rows: list[dict[str, Any]], lag: float | None = None) -> None:
        self.rows = rows
        self.lag = lag
        self.receipts: list[dict[str, Any]] = []
        self.anchor_data: list[dict[str, Any]] = []
        self.stream_ids = [STREAM]
        self.published_ids: set[int] = set()
        self.quarantined_ids: set[int] = set()

    def unpublished(self, tenant_id, limit=100, evidence_only=False):
        pending = [
            row
            for row in self.rows
            if row["outbox_id"] not in self.published_ids
            and row["outbox_id"] not in self.quarantined_ids
        ]
        return pending[:limit]

    def record_publication(self, tenant_id, outbox_id, receipt, signature):
        self.published_ids.add(outbox_id)
        self.receipts.append({"payload": receipt, "signature": signature})

    def record_publication_failure(self, tenant_id, outbox_id, error, quarantine_at_attempts):
        row = next(item for item in self.rows if item["outbox_id"] == outbox_id)
        row["attempts"] += 1
        row["last_error"] = error
        if row["attempts"] >= quarantine_at_attempts:
            self.quarantined_ids.add(outbox_id)
            return True
        return False

    def streams(self, tenant_id):
        return self.stream_ids

    def oldest_unpublished_age_seconds(self, tenant_id):
        pending = [
            row
            for row in self.rows
            if row["outbox_id"] not in self.published_ids
            and row["outbox_id"] not in self.quarantined_ids
        ]
        return self.lag if pending else None

    # Anchoring, reused from the shapes `OutboxPublisher.anchor` reads.
    def receipt_rows(self, tenant_id, stream_id, start=None, end=None):
        return [
            item
            for item in self.receipts
            if start is None or item["payload"]["sequence_number"] >= start
        ]

    def anchors(self, tenant_id, stream_id):
        return self.anchor_data

    def record_anchor(self, tenant_id, anchor, signature):
        self.anchor_data.append({"payload": anchor, "signature": signature})


def outbox_row(outbox_id: int, sequence: int, *, payload: dict[str, Any] | None = None):
    return {
        "outbox_id": outbox_id,
        "event_type": "mizan.decision.recorded",
        "attempts": 0,
        "created_at": None,
        "payload": payload
        if payload is not None
        else {
            "stream_id": STREAM,
            "sequence_number": sequence,
            "record_hash": f"{sequence:064x}",
        },
    }


def publisher_for(repository: FakeDrainRepository, tmp_path: Path) -> OutboxPublisher:
    return OutboxPublisher(
        repository,
        LocalImmutableObjectStore(tmp_path),
        Ed25519EvidenceSigner.development("evidence-receipt"),
        Ed25519EvidenceSigner.development("evidence-anchor"),
    )


def test_a_cycle_publishes_every_row_and_anchors_what_it_published(tmp_path: Path) -> None:
    repository = FakeDrainRepository([outbox_row(index, index) for index in range(3)])
    report = run_once(publisher_for(repository, tmp_path), repository, [TENANT], 100, 5)

    assert report.published == 3
    assert report.anchored == 1
    assert report.quarantined == 0
    # The receipt is what `execution.py::_require_receipts` looks for, so assert its binding
    # rather than only the count.
    assert {item["payload"]["sequence_number"] for item in repository.receipts} == {0, 1, 2}
    assert repository.anchor_data[0]["payload"]["covered_record_count"] == 3


def test_a_full_batch_is_followed_immediately_rather_than_after_the_poll_interval(
    tmp_path: Path,
) -> None:
    """Backpressure. Five rows through a batch of two must all publish in one cycle.

    Without the saturation loop this publishes two per cycle, so a backlog drains at
    batch-size per `MIZAN_OUTBOX_DRAIN_INTERVAL_MS` and the queue that gates every financial
    write falls further behind the busier the system gets.
    """
    repository = FakeDrainRepository([outbox_row(index, index) for index in range(5)])
    report = run_once(publisher_for(repository, tmp_path), repository, [TENANT], 2, 5)

    assert report.published == 5
    assert repository.published_ids == {0, 1, 2, 3, 4}


def test_one_hot_tenant_cannot_consume_the_whole_cycle(tmp_path: Path) -> None:
    repository = FakeDrainRepository([outbox_row(index, index) for index in range(50)])
    report = run_once(
        publisher_for(repository, tmp_path), repository, [TENANT], 2, 5, max_batches=3
    )

    # Three batches of two, and then the cycle moves on rather than draining all fifty.
    assert report.published == 6


def test_a_row_that_can_never_publish_is_quarantined_and_stops_blocking_the_queue(
    tmp_path: Path,
) -> None:
    """Poison handling.

    A payload with no `stream_id` cannot be grouped, so it can never publish. Before the retry
    budget existed it was re-read on every cycle forever. It must now be set aside with its
    reason, and -- the part that matters -- the healthy rows behind it must still publish.
    """
    poison = outbox_row(0, 0, payload={"no_stream_id": True})
    repository = FakeDrainRepository([poison, outbox_row(1, 1), outbox_row(2, 2)])
    publisher = publisher_for(repository, tmp_path)

    for _ in range(2):
        run_once(publisher, repository, [TENANT], 100, 5, quarantine_at_attempts=2)

    assert repository.quarantined_ids == {0}
    assert poison["attempts"] == 2
    assert "KeyError" in poison["last_error"]
    # The healthy rows are not held up behind it.
    assert repository.published_ids == {1, 2}


def test_a_poisoned_row_is_retried_until_its_budget_is_spent_not_before(tmp_path: Path) -> None:
    poison = outbox_row(0, 0, payload={"no_stream_id": True})
    repository = FakeDrainRepository([poison])
    publisher = publisher_for(repository, tmp_path)

    report = run_once(publisher, repository, [TENANT], 100, 5, quarantine_at_attempts=3)
    assert report.quarantined == 0 and report.failed == 1 and not repository.quarantined_ids

    run_once(publisher, repository, [TENANT], 100, 5, quarantine_at_attempts=3)
    final = run_once(publisher, repository, [TENANT], 100, 5, quarantine_at_attempts=3)
    assert final.quarantined == 1 and repository.quarantined_ids == {0}


def test_breaching_the_publication_slo_opens_the_evidence_breaker(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """ADR-004: breaching the SLO opens the breaker and is not merely a warning.

    The lag is measured after draining, so this models the case that matters -- rows the worker
    could not publish this cycle -- rather than rows it was about to publish.
    """
    poison = outbox_row(0, 0, payload={"no_stream_id": True})
    repository = FakeDrainRepository([poison], lag=42.0)

    report = run_once(publisher_for(repository, tmp_path), repository, [TENANT], 100, 5)

    assert report.lag_breaches == [(TENANT, 42.0)]
    assert "EVIDENCE BREAKER OPEN: unpublished_evidence_slo_breached" in capsys.readouterr().err


def test_a_drained_queue_reports_no_lag_at_all(tmp_path: Path) -> None:
    repository = FakeDrainRepository([outbox_row(0, 0)], lag=9_000.0)
    report = run_once(publisher_for(repository, tmp_path), repository, [TENANT], 100, 5)
    # The row published, so there is no unpublished age to breach -- an empty queue must never
    # open the breaker on a stale reading.
    assert report.lag_breaches == []


def test_a_stream_with_nothing_new_is_not_an_anchoring_error(tmp_path: Path) -> None:
    repository = FakeDrainRepository([])
    report = run_once(publisher_for(repository, tmp_path), repository, [TENANT], 100, 5)

    # `evidence_range_empty` is the ordinary answer for an idle stream. Counting it as a failure
    # would make an idle deployment look broken every cycle.
    assert report.anchored == 0 and report.failed == 0


def test_a_stop_signal_ends_the_cycle_between_tenants(tmp_path: Path) -> None:
    repository = FakeDrainRepository([outbox_row(0, 0)])
    stop = StopSignal(requested=True)

    report = run_once(publisher_for(repository, tmp_path), repository, [TENANT], 100, 5, stop=stop)

    assert report.published == 0


def test_anchoring_refusals_other_than_an_empty_range_are_counted_not_swallowed(
    tmp_path: Path,
) -> None:
    repository = FakeDrainRepository([outbox_row(0, 0)])
    publisher = publisher_for(repository, tmp_path)

    def refuse(tenant_id, stream_id, from_sequence=None):
        raise Problem(409, "anchor_range_not_dense", "Anchor range must continue the prior anchor")

    publisher.anchor = refuse  # type: ignore[method-assign]
    report = run_once(publisher, repository, [TENANT], 100, 5)

    assert report.anchored == 0 and report.failed == 1


def test_tenants_come_from_the_flag_then_the_environment_and_keep_their_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MIZAN_DRAIN_TENANTS", "tnt_from-env, tnt_other ")
    assert resolve_tenants(["tnt_explicit"]) == ["tnt_explicit"]
    assert resolve_tenants(None) == ["tnt_from-env", "tnt_other"]
    assert resolve_tenants([]) == ["tnt_from-env", "tnt_other"]
    # Duplicates would drain the same tenant twice per cycle for no benefit.
    assert resolve_tenants(["tnt_a", "tnt_b", "tnt_a"]) == ["tnt_a", "tnt_b"]

    monkeypatch.delenv("MIZAN_DRAIN_TENANTS")
    assert resolve_tenants(None) == []


def test_a_drainer_that_serves_no_tenant_refuses_to_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """It would otherwise run, log nothing, stay healthy, and publish no evidence at all --
    which presents as every financial write being refused, with no failing component."""
    from mizan_control_plane import drain_worker

    monkeypatch.delenv("MIZAN_DRAIN_TENANTS", raising=False)
    with pytest.raises(SystemExit) as exit_info:
        drain_worker.main([])
    assert exit_info.value.code == 2


def test_a_report_knows_whether_it_did_anything() -> None:
    assert not DrainReport().did_work
    assert not DrainReport(failed=3).did_work
    assert DrainReport(published=1).did_work
    assert DrainReport(anchored=1).did_work
    assert DrainReport(quarantined=1).did_work


def test_one_unanchorable_stream_does_not_kill_the_worker(tmp_path: Path) -> None:
    """Found by running `make demo`, not by any test that existed.

    `anchor_tenant` caught `Problem` and nothing else, so a `RuntimeError` from
    `LocalImmutableObjectStore.put_once` -- `immutable object collision`, raised when the store
    holds an object the database no longer knows about -- escaped `run_once` and terminated the
    process. The drain worker is what every `financial_write` depends on, so one unanchorable
    stream stopped every tenant's publication indefinitely.
    """
    repository = FakeDrainRepository([outbox_row(0, 0)])
    repository.stream_ids = [STREAM, f"{TENANT}:adr:1"]
    publisher = publisher_for(repository, tmp_path)
    real_anchor = publisher.anchor
    calls: list[str] = []

    def anchor(tenant_id, stream_id, from_sequence=None):
        calls.append(stream_id)
        if stream_id == STREAM:
            raise RuntimeError("immutable object collision")
        return real_anchor(tenant_id, stream_id, from_sequence)

    publisher.anchor = anchor  # type: ignore[method-assign]
    report = run_once(publisher, repository, [TENANT], 100, 5)

    # The failure is counted and named, and the *next* stream was still attempted.
    assert report.failed == 1
    assert calls == [STREAM, f"{TENANT}:adr:1"]
    # And the rows still published: draining is not held hostage by an anchoring fault.
    assert report.published == 1


class FakeExecutionService:
    """Just the sweep surface the worker uses, so the cycle's wiring is what is under test."""

    def __init__(self, expired: list[str] | None = None, raises: Exception | None = None) -> None:
        self.expired = expired or []
        self.raises = raises
        self.swept: list[str] = []

    def sweep_expired_leases(self, tenant_id, limit=100, now=None):
        self.swept.append(tenant_id)
        if self.raises is not None:
            raise self.raises
        return list(self.expired)


def test_the_cycle_expires_leases_before_it_drains(tmp_path: Path) -> None:
    """Order matters, and it is not arbitrary.

    The sweep writes its DecisionEvents and their outbox rows in one transaction, so sweeping
    first means the expiries it records are published by the *same* cycle. Sweeping after the
    drain would leave every expiry sitting unpublished until the next pass.
    """
    repository = FakeDrainRepository([outbox_row(0, 0)])
    execution = FakeExecutionService(expired=["lse_abandoned"])

    report = run_once(
        publisher_for(repository, tmp_path), repository, [TENANT], 100, 5, execution=execution
    )

    assert report.expired == 1
    assert execution.swept == [TENANT]
    # Published in the same cycle, not the next one.
    assert report.published == 1


def test_a_sweep_that_fails_does_not_stop_the_drain(tmp_path: Path) -> None:
    """The drainer is what every financial write depends on. A sweep fault must not stop it."""
    repository = FakeDrainRepository([outbox_row(0, 0)])
    execution = FakeExecutionService(raises=RuntimeError("lease table unavailable"))

    report = run_once(
        publisher_for(repository, tmp_path), repository, [TENANT], 100, 5, execution=execution
    )

    assert report.failed == 1 and report.expired == 0
    assert report.published == 1


def test_a_worker_with_no_execution_service_simply_does_not_sweep(tmp_path: Path) -> None:
    repository = FakeDrainRepository([outbox_row(0, 0)])
    report = run_once(publisher_for(repository, tmp_path), repository, [TENANT], 100, 5)
    assert report.expired == 0 and report.failed == 0 and report.published == 1


def test_every_served_tenant_is_swept(tmp_path: Path) -> None:
    repository = FakeDrainRepository([])
    execution = FakeExecutionService()
    run_once(
        publisher_for(repository, tmp_path),
        repository,
        [TENANT, "tnt_bank-b"],
        100,
        5,
        execution=execution,
    )
    assert execution.swept == [TENANT, "tnt_bank-b"]


def test_an_expiry_counts_as_work_even_when_nothing_published(tmp_path: Path) -> None:
    """`did_work` drives the cycle's log line. An expiry nobody logged is most of the way to
    an expiry nobody noticed."""
    repository = FakeDrainRepository([])
    execution = FakeExecutionService(expired=["lse_abandoned"])
    report = run_once(
        publisher_for(repository, tmp_path), repository, [TENANT], 100, 5, execution=execution
    )
    assert report.did_work and report.published == 0
