"""The part of Mizan that runs when nobody is calling it.

Three things in this tree only ever happened because a request happened to arrive:

  * evidence was published when a test stood up its own publisher thread,
  * an approval epoch's TTL was noticed when the next voter was told "too late",
  * a lease became `LEASE_EXPIRED` when its executor came back to a lease it had already lost.

None of those are states the system *reaches*. They are states it *reports* when asked, which is a
different and much weaker claim: an approval nobody ever voted on again stayed `PENDING` forever,
and a deployed MCP gateway's financial write waited on a receipt that nothing at rest was writing.
This module is the process that closes that gap — it drains the outbox, anchors on a cadence, and
sweeps expiries — so that "expired" and "published" are things that become true on their own.

It decides nothing. Every transition it performs is one the request path already performs, reached
through the same domain function and the same transaction shape, because two writers with two
opinions about a state machine is how an audit trail learns to contradict itself.
"""

from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from psycopg_pool import ConnectionPool

from .approval import expire
from .approval_repository import SYSTEM_ACTOR, update_approval_tx
from .config import Settings
from .evidence import (
    Ed25519EvidenceSigner,
    EvidenceRepository,
    LocalImmutableObjectStore,
    OutboxPublisher,
    append_decision_event_tx,
)
from .execution import save_lease_tx
from .problems import Problem
from .runtime import build_key_provider

LOGGER = logging.getLogger("mizan.drain")

LIVE_LEASE_STATES = ("LEASED", "EXECUTING")
TERMINAL_APPROVAL_STATES = ("APPROVED", "REJECTED", "EXPIRED", "WITHDRAWN", "OVERRIDDEN")


class Breaker(Protocol):
    def trip(self, reason: str, tenant_id: str, detail: str) -> None: ...

    def clear(self, reason: str, tenant_id: str) -> None: ...


class EvidenceBreaker:
    """The publication alarm SPEC §8 attaches to `MIZAN_EVIDENCE_MAX_UNPUBLISHED_SECONDS`.

    It is an alarm, not a gate. Financial writes are already held closed by the receipt itself
    (I-25), and halting the drainer on breach would only deepen the backlog it is complaining
    about. What it must do is fire once on the way open and once on the way closed: a breaker that
    re-fires every 250ms is a breaker nobody reads, and one that never re-fires hides a recurrence.
    """

    def __init__(self) -> None:
        self.open: set[tuple[str, str]] = set()
        self.history: list[tuple[str, str, str]] = []

    def trip(self, reason: str, tenant_id: str, detail: str) -> None:
        key = (reason, tenant_id)
        if key in self.open:
            return
        self.open.add(key)
        self.history.append((reason, tenant_id, detail))
        LOGGER.error("EVIDENCE BREAKER OPEN: %s tenant=%s %s", reason, tenant_id, detail)

    def clear(self, reason: str, tenant_id: str) -> None:
        if (reason, tenant_id) in self.open:
            self.open.discard((reason, tenant_id))
            LOGGER.warning("evidence breaker closed: %s tenant=%s", reason, tenant_id)

    @property
    def is_open(self) -> bool:
        return bool(self.open)


@dataclass(frozen=True, slots=True)
class DrainPolicy:
    """Cadence and limits, all of them named in SPEC §8."""

    batch_limit: int = 100
    interval_seconds: float = 0.25
    max_attempts: int = 5
    max_unpublished_seconds: float = 5.0
    anchor_interval_seconds: float = 300.0
    anchor_interval_records: int = 10000
    sweep_interval_seconds: float = 30.0
    max_batches_per_tenant: int = 20

    @classmethod
    def from_settings(cls, settings: Settings) -> DrainPolicy:
        return cls(
            batch_limit=settings.outbox_batch_limit,
            interval_seconds=settings.outbox_drain_interval_ms / 1000,
            max_attempts=settings.outbox_max_attempts,
            max_unpublished_seconds=settings.evidence_max_unpublished_seconds,
            anchor_interval_seconds=float(settings.audit_anchor_interval_seconds),
            anchor_interval_records=settings.audit_anchor_interval_records,
            sweep_interval_seconds=settings.expiry_sweep_interval_seconds,
        )


@dataclass(frozen=True, slots=True)
class SweepReport:
    approvals: tuple[str, ...] = ()
    leases: tuple[str, ...] = ()

    def __bool__(self) -> bool:
        return bool(self.approvals or self.leases)


@dataclass(frozen=True, slots=True)
class TenantTick:
    tenant_id: str
    published: int = 0
    relayed: int = 0
    quarantined: int = 0
    anchored: tuple[str, ...] = ()
    swept: SweepReport = field(default_factory=SweepReport)
    pending: int = 0
    oldest_age_seconds: float = 0.0
    lag_breached: bool = False


class ExpirySweeper:
    """Reaches `EXPIRED` and `LEASE_EXPIRED` at rest, transactionally with their §4 events.

    Every candidate is re-checked under a row lock after being selected, because the scan and the
    write are not the same transaction: between them an approver may have voted, or an executor may
    have completed. The scan is a hint about where to look, never a decision.
    """

    def __init__(
        self, database_url: str, pool: ConnectionPool | None = None, batch_limit: int = 100
    ) -> None:
        self.pool = pool or ConnectionPool(database_url, min_size=1, max_size=4, open=True)
        self.batch_limit = batch_limit

    @staticmethod
    def _scope(connection: Any, tenant_id: str) -> None:
        connection.execute("SELECT set_config('app.tenant_id', %s, true)", (tenant_id,))

    def sweep(self, tenant_id: str, now: datetime | None = None) -> SweepReport:
        now = now or datetime.now(UTC)
        return SweepReport(
            approvals=tuple(self.expire_approvals(tenant_id, now)),
            leases=tuple(self.expire_leases(tenant_id, now)),
        )

    def expire_approvals(self, tenant_id: str, now: datetime) -> list[str]:
        expired: list[str] = []
        for approval_id in self._expired_approval_candidates(tenant_id, now):
            if self._expire_one_approval(tenant_id, approval_id, now):
                expired.append(approval_id)
        return expired

    def _expired_approval_candidates(self, tenant_id: str, now: datetime) -> list[str]:
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            rows = connection.execute(
                "SELECT e.approval_id FROM mizan.approval_epochs e "
                "JOIN mizan.approvals a ON a.tenant_id=e.tenant_id "
                "  AND a.approval_id=e.approval_id AND a.active_epoch_id=e.epoch_id "
                "WHERE e.tenant_id=%s AND e.state='OPEN' AND e.expires_at<=%s "
                "  AND a.state <> ALL(%s) "
                "ORDER BY e.expires_at LIMIT %s",
                (tenant_id, now, list(TERMINAL_APPROVAL_STATES), self.batch_limit),
            ).fetchall()
            return [row[0] for row in rows]

    def _expire_one_approval(self, tenant_id: str, approval_id: str, now: datetime) -> bool:
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            row = connection.execute(
                "SELECT document FROM mizan.approvals WHERE tenant_id=%s AND approval_id=%s "
                "FOR UPDATE",
                (tenant_id, approval_id),
            ).fetchone()
            if not row:
                return False
            try:
                updated = expire(row[0], now)
            except Problem as raced:
                # Someone voted, escalated or withdrew between the scan and this lock. That is the
                # ordinary outcome of a sweeper racing a person, and the person wins.
                LOGGER.info("approval %s was not expired: %s", approval_id, raced.code)
                return False
            update_approval_tx(connection, tenant_id, updated)
            epoch = next(
                item for item in updated["epochs"] if item["epoch_id"] == updated["current_epoch_id"]
            )
            append_decision_event_tx(
                connection,
                tenant_id,
                updated["decision_id"],
                "APPROVAL_RESOLVED",
                SYSTEM_ACTOR,
                {
                    "approval_id": approval_id,
                    "epoch_id": epoch["epoch_id"],
                    "approval_state": "EXPIRED",
                },
                now,
            )
            connection.execute(
                "INSERT INTO mizan.outbox(tenant_id,aggregate_type,aggregate_id,event_type,payload) "
                "VALUES (%s,'approval',%s,'mizan.approval.expired',%s)",
                (
                    tenant_id,
                    approval_id,
                    json.dumps(
                        {
                            "approval_id": approval_id,
                            "decision_id": updated["decision_id"],
                            "epoch_id": epoch["epoch_id"],
                            "epoch_number": epoch["epoch_number"],
                            "expires_at": epoch["expires_at"],
                        }
                    ),
                ),
            )
            return True

    def expire_leases(self, tenant_id: str, now: datetime) -> list[str]:
        expired: list[str] = []
        for lease_id in self._expired_lease_candidates(tenant_id, now):
            if self._expire_one_lease(tenant_id, lease_id, now):
                expired.append(lease_id)
        return expired

    def _expired_lease_candidates(self, tenant_id: str, now: datetime) -> list[str]:
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            rows = connection.execute(
                "SELECT lease_id FROM mizan.execution_leases "
                "WHERE tenant_id=%s AND state = ANY(%s) AND expires_at<=%s "
                "ORDER BY expires_at LIMIT %s",
                (tenant_id, list(LIVE_LEASE_STATES), now, self.batch_limit),
            ).fetchall()
            return [row[0] for row in rows]

    def _expire_one_lease(self, tenant_id: str, lease_id: str, now: datetime) -> bool:
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            row = connection.execute(
                "SELECT document,state,expires_at FROM mizan.execution_leases "
                "WHERE tenant_id=%s AND lease_id=%s FOR UPDATE",
                (tenant_id, lease_id),
            ).fetchone()
            if not row or row[1] not in LIVE_LEASE_STATES or row[2] > now:
                return False
            lease = row[0]
            lease["state"] = "LEASE_EXPIRED"
            save_lease_tx(connection, tenant_id, lease)
            append_decision_event_tx(
                connection,
                tenant_id,
                lease["decision_id"],
                "LEASE_EXPIRED",
                {"kind": "system", "id": "mizan-execution-service", "authenticated_workload": None},
                {"lease_id": lease_id},
                now,
            )
            connection.execute(
                "INSERT INTO mizan.outbox(tenant_id,aggregate_type,aggregate_id,event_type,payload) "
                "VALUES (%s,'execution',%s,'mizan.execution.lease_expired',%s)",
                (
                    tenant_id,
                    lease_id,
                    json.dumps({"decision_id": lease["decision_id"], "lease_id": lease_id}),
                ),
            )
            return True

    def close(self) -> None:
        self.pool.close()


class OutboxWorker:
    """One tick drains, relays, anchors and sweeps every configured tenant.

    Tenants are configured rather than discovered, and that is a deliberate refusal rather than an
    omission: `mizan.tenants` carries FORCE ROW LEVEL SECURITY keyed on the current tenant, so a
    process that could enumerate tenants would be a process that had already broken the isolation
    boundary ADR-005 is built on. See blocker B-19 — automatic discovery needs either BYPASSRLS or
    a SECURITY DEFINER enumerator, and widening that boundary to save an operator one config line
    is not a trade this component may make on its own.
    """

    def __init__(
        self,
        publisher: OutboxPublisher,
        repository: EvidenceRepository,
        sweeper: ExpirySweeper | None,
        tenants: tuple[str, ...],
        policy: DrainPolicy | None = None,
        breaker: Breaker | None = None,
        clock: Any = time.monotonic,
    ) -> None:
        if not tenants:
            raise ValueError("a drain worker with no tenants publishes nothing")
        self.publisher = publisher
        self.repository = repository
        self.sweeper = sweeper
        self.tenants = tenants
        self.policy = policy or DrainPolicy()
        self.breaker = breaker or EvidenceBreaker()
        self.clock = clock
        self._records_since_anchor: dict[tuple[str, str], int] = {}
        self._last_sweep: dict[str, float] = {}

    def tick(self) -> list[TenantTick]:
        return [self.tick_tenant(tenant_id) for tenant_id in self.tenants]

    def tick_tenant(self, tenant_id: str) -> TenantTick:
        published, quarantined = self._drain(tenant_id)
        relayed = self._relay(tenant_id)
        swept = self._sweep(tenant_id)
        backlog = self.repository.backlog(tenant_id, self.policy.max_attempts)
        # An anchor asserts that a range is complete. Making that assertion while anything is
        # still unpublished is how a stream acquires a gap it has already sworn does not exist —
        # and the database refuses it (`evidence_anchor_declared_density`), correctly.
        anchored = self._anchor(tenant_id, published) if not backlog["pending"] else ()
        if backlog["pending"] and self.repository.streams(tenant_id):
            LOGGER.debug(
                "anchoring deferred for %s: %s row(s) still unpublished",
                tenant_id,
                backlog["pending"],
            )
        breached = self._check_lag(tenant_id, backlog, quarantined)
        return TenantTick(
            tenant_id=tenant_id,
            published=published,
            relayed=relayed,
            quarantined=quarantined,
            anchored=anchored,
            swept=swept,
            pending=backlog["pending"],
            oldest_age_seconds=backlog["oldest_age_seconds"],
            lag_breached=breached,
        )

    def _drain(self, tenant_id: str) -> tuple[int, int]:
        """Keep draining while batches come back full.

        Backpressure runs the other way from the usual instinct: a saturated batch means the
        backlog is growing faster than one batch per interval, so the worker comes straight back
        instead of sleeping. `max_batches_per_tenant` is the fairness bound — one busy tenant may
        not hold the drain loop and starve every other tenant's publication SLO.
        """
        published = quarantined = 0
        for _ in range(self.policy.max_batches_per_tenant):
            report = self.publisher.drain_batch(
                tenant_id, self.policy.batch_limit, self.policy.max_attempts
            )
            published += report.published
            quarantined += len(report.quarantined)
            if not report.saturated(self.policy.batch_limit):
                break
        else:
            LOGGER.warning(
                "tenant %s still saturated after %s batches; backlog is growing",
                tenant_id,
                self.policy.max_batches_per_tenant,
            )
        return published, quarantined

    def _relay(self, tenant_id: str) -> int:
        """Publish the §4 events that never become receipts.

        `approval`, `policy`, `agent`, `execution` and `security` rows have external subscribers
        and no evidence receipt, so `OutboxPublisher.drain` has always ignored them — which meant
        they were written, counted against the publication lag, and never delivered to anything.
        """
        relayed = 0
        for item in self.repository.unpublished(
            tenant_id,
            self.policy.batch_limit,
            relay_only=True,
            max_attempts=self.policy.max_attempts,
        ):
            try:
                self.publisher.delivery.publish(
                    item["event_type"], item["aggregate_type"], item["payload"]
                )
            except Exception:
                attempts = self.repository.record_delivery_failure(tenant_id, item["outbox_id"])
                LOGGER.exception(
                    "delivery of %s (row %s) failed; attempts=%s",
                    item["event_type"],
                    item["outbox_id"],
                    attempts,
                )
                continue
            if self.repository.record_delivery(tenant_id, item["outbox_id"]):
                relayed += 1
        return relayed

    def _sweep(self, tenant_id: str) -> SweepReport:
        if self.sweeper is None:
            return SweepReport()
        now = self.clock()
        last = self._last_sweep.get(tenant_id)
        if last is not None and now - last < self.policy.sweep_interval_seconds:
            return SweepReport()
        self._last_sweep[tenant_id] = now
        report = self.sweeper.sweep(tenant_id)
        if report:
            LOGGER.info(
                "swept tenant %s: %s approval(s) expired, %s lease(s) expired",
                tenant_id,
                len(report.approvals),
                len(report.leases),
            )
        return report

    def _anchor(self, tenant_id: str, published: int) -> tuple[str, ...]:
        """Anchor a stream when its own last anchor is old enough, or enough records have landed.

        The clock that matters is the stream's, read back from the database. Timing from process
        start would mean a worker restarting more often than the cadence never anchors at all, and
        `--once` from cron never anchors even once.
        """
        anchored: list[str] = []
        for stream_id in self.repository.streams(tenant_id):
            key = (tenant_id, stream_id)
            self._records_since_anchor[key] = self._records_since_anchor.get(key, 0) + published
            age = self.repository.seconds_since_last_anchor(tenant_id, stream_id)
            due_by_time = age is None or age >= self.policy.anchor_interval_seconds
            due_by_count = self._records_since_anchor[key] >= self.policy.anchor_interval_records
            if not (due_by_time or due_by_count):
                continue
            self._records_since_anchor[key] = 0
            try:
                self.publisher.anchor(tenant_id, stream_id)
            except Problem as problem:
                if problem.code == "evidence_range_empty":
                    continue
                self.breaker.trip("anchor_refused", tenant_id, f"{stream_id}: {problem.code}")
                continue
            except Exception as failure:
                # One stream that cannot be anchored must not stop the process from publishing
                # every other tenant's evidence. It is loud, not fatal.
                LOGGER.exception("anchor failed for %s/%s", tenant_id, stream_id)
                self.breaker.trip("anchor_refused", tenant_id, f"{stream_id}: {failure!r}")
                continue
            anchored.append(stream_id)
        return tuple(anchored)

    def _check_lag(self, tenant_id: str, backlog: dict[str, Any], quarantined: int) -> bool:
        if backlog["quarantined"] or quarantined:
            self.breaker.trip(
                "outbox_poisoned",
                tenant_id,
                f"{backlog['quarantined']} row(s) exceeded {self.policy.max_attempts} attempts",
            )
        breached = backlog["oldest_age_seconds"] > self.policy.max_unpublished_seconds
        if breached:
            self.breaker.trip(
                "evidence_publication_lag",
                tenant_id,
                f"oldest unpublished row is {backlog['oldest_age_seconds']:.1f}s old, "
                f"SLO is {self.policy.max_unpublished_seconds}s",
            )
        else:
            self.breaker.clear("evidence_publication_lag", tenant_id)
        return breached

    def run(self, stop: threading.Event, once: bool = False) -> None:
        while not stop.is_set():
            self.tick()
            if once:
                return
            stop.wait(self.policy.interval_seconds)


def build_worker(
    settings: Settings, tenants: tuple[str, ...]
) -> tuple[OutboxWorker, EvidenceRepository, ExpirySweeper]:
    provider = build_key_provider(settings)
    repository = EvidenceRepository(settings.database_url)
    publisher = OutboxPublisher(
        repository,
        LocalImmutableObjectStore(Path(settings.evidence_object_store_root)),
        Ed25519EvidenceSigner(provider.active_key("evidence-receipt")),
        Ed25519EvidenceSigner(provider.active_key("evidence-anchor")),
    )
    sweeper = ExpirySweeper(settings.database_url)
    policy = DrainPolicy.from_settings(settings)
    return OutboxWorker(publisher, repository, sweeper, tenants, policy), repository, sweeper


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Drain the Mizan outbox, anchor evidence, and sweep expiries"
    )
    parser.add_argument(
        "--tenant-id",
        action="append",
        default=[],
        help="tenant to serve; repeatable. Falls back to MIZAN_DRAIN_TENANTS.",
    )
    parser.add_argument("--once", action="store_true", help="run one tick and exit")
    parser.add_argument("--no-sweep", action="store_true", help="drain only; skip expiry sweeping")
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.INFO, stream=sys.stderr, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    settings = Settings.from_environment()
    tenants = tuple(args.tenant_id) or settings.drain_tenants
    if not tenants:
        parser.error(
            "no tenants configured. Pass --tenant-id (repeatable) or set MIZAN_DRAIN_TENANTS. "
            "Tenants are not discovered: mizan.tenants enforces row-level security keyed on the "
            "current tenant, and a drainer able to enumerate them would already have crossed the "
            "isolation boundary it exists to publish evidence for (see blocker B-19)."
        )
    worker, repository, sweeper = build_worker(settings, tenants)
    if args.no_sweep:
        worker.sweeper = None
    stop = threading.Event()
    for received in (signal.SIGTERM, signal.SIGINT):
        signal.signal(received, lambda *_: stop.set())
    LOGGER.info("draining %s tenant(s): %s", len(tenants), ", ".join(tenants))
    try:
        worker.run(stop, once=args.once)
    finally:
        repository.pool.close()
        sweeper.close()
    # A drainer that exits while the breaker is open must not look like a clean shutdown to a
    # supervisor: the backlog it leaves behind is the thing that blocks financial writes.
    return 2 if getattr(worker.breaker, "is_open", False) else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
