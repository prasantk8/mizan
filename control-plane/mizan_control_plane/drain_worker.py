"""`mizan-drain-outbox` -- the worker without which no financial write can ever execute.

Both production manifests have named this entrypoint since T-075 shipped them
(`compose.production.yaml`, `charts/mizan/templates/drainer-deployment.yaml`) and it did not
exist. Trace what follows from that, because it is worse than a missing background job:

  nothing drains  ->  `mizan.evidence_receipts` is never written (its only writer is
  `OutboxPublisher.drain`, and every caller of that was a test or a benchmark)  ->
  `execution.py::_require_receipts` finds no receipt for the ADR_Record  ->  403
  `immutable_receipt_missing` on every `financial_write`.

So Mizan pauses the payment for a human, the human approves it, **and Mizan refuses it anyway,
permanently.** And with no receipts there are no anchors, with no anchors no RFC 3161 timestamps,
and `mizan-export-evidence` raises "cannot export an empty evidence range" -- there is no bundle
for the second verifier to check. A running Mizan could not produce T-062's artifact.

This process is what closes that. Each cycle, for each tenant it was told to serve:

  1. **Drain** unpublished evidence rows into the object store, taking a signed receipt for each.
     Backpressure is a saturation check, not a sleep: a full batch means more is waiting, so the
     tenant is drained again immediately, up to `--max-batches-per-cycle` so one busy tenant
     cannot starve the others.
  2. **Quarantine** a row that has failed its retry budget, with the error and the time, instead
     of retrying it forever (which blocks the queue) or skipping it silently (which is this
     repository's documented failure mode). See migration 0004.
  3. **Anchor** every stream that has receipts beyond its last anchor. `evidence_range_empty` is
     the ordinary answer for a stream with nothing new and is not an error.
  4. **Measure the lag** against `MIZAN_EVIDENCE_MAX_UNPUBLISHED_SECONDS` and open the evidence
     breaker on breach, which ADR-004 requires be more than an observability warning.

It also **expires leases at rest**, before draining, so the expiries it records are published by
the same cycle. `LEASE_EXPIRED` used to be reachable only from an inbound call by the lease's own
holder, so an executor that crashed left its lease `LEASED` for ever and the decision never
reached a terminal state (T-108).

**Tenants are named, never discovered, and that is deliberate.** `mizan.tenants` carries
`FORCE ROW LEVEL SECURITY` with `USING (tenant_id = mizan.current_tenant_id())`, and there is not
one `SECURITY DEFINER` function in the schema, so `mizan_app` cannot enumerate tenants and no
amount of SQL here changes that without changing the isolation model. Widening it is an H-7
decision about tenant isolation, so it is escalated as **B-27** and not taken here. Until it is
ruled on, the served set comes from `--tenant-id` or `MIZAN_DRAIN_TENANTS`, and a deployment that
names none refuses to start rather than idling while it silently drains nothing.
"""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import time
from dataclasses import dataclass, field
from types import FrameType

from .approval_repository import ApprovalRepository
from .config import Settings, resolve_served_tenants
from .evidence import (
    Ed25519EvidenceSigner,
    EvidenceReconciler,
    EvidenceReconciliationMismatch,
    EvidenceRepository,
    ObjectEvidenceVerifier,
    OutboxPublisher,
)
from .execution import ExecutionService
from .observability import configure_logging
from .problems import Problem
from .runtime import (
    build_execution_service,
    build_key_provider,
    build_object_store,
    verification_public_keys,
)

LOGGER = logging.getLogger("mizan.drain")

# A row that has failed this many times is set aside for a human rather than retried again.
DEFAULT_QUARANTINE_ATTEMPTS = 5
# Bounds one tenant's share of a cycle so a large backlog cannot starve the other tenants.
DEFAULT_MAX_BATCHES_PER_CYCLE = 20


@dataclass
class DrainReport:
    published: int = 0
    relayed: int = 0
    anchored: int = 0
    quarantined: int = 0
    expired: int = 0
    approvals_expired: int = 0
    # Elapsed approval epochs found and deliberately not acted on, because this deployment runs
    # `MIZAN_APPROVAL_EPOCH_EXPIRY=advisory`. Counted rather than ignored: the whole difference
    # between "we chose not to expire these" and "expiry is broken" is this number existing.
    approvals_overdue: int = 0
    failed: int = 0
    lag_breaches: list[tuple[str, float]] = field(default_factory=list)
    reconciliation_mismatches: list[EvidenceReconciliationMismatch] = field(default_factory=list)

    @property
    def did_work(self) -> bool:
        return bool(
            self.published
            or self.relayed
            or self.anchored
            or self.quarantined
            or self.expired
            or self.approvals_expired
        )


@dataclass
class StopSignal:
    """Set by SIGTERM/SIGINT. Checked between units of work, never inside one.

    A drainer killed mid-group leaves a segment object written and some of its receipts missing,
    which the next cycle repairs (`put_once` is idempotent, `record_publication` is
    `ON CONFLICT DO NOTHING`) -- but repairing something we could have simply finished is a worse
    default than finishing it, so the flag is only read at boundaries.
    """

    requested: bool = False

    def install(self) -> None:
        for number in (signal.SIGTERM, signal.SIGINT):
            signal.signal(number, self._handle)

    def _handle(self, number: int, frame: FrameType | None) -> None:
        if self.requested:
            LOGGER.warning("second signal %s -- exiting immediately", number)
            raise SystemExit(130)
        LOGGER.info("signal %s received; finishing the current unit of work", number)
        self.requested = True


def build_publisher(
    settings: Settings,
) -> tuple[
    OutboxPublisher,
    EvidenceRepository,
    ExecutionService,
    ApprovalRepository,
    EvidenceReconciler,
]:
    provider = build_key_provider(settings)
    repository = EvidenceRepository(settings.database_url)
    # The same store the API reads through. A drainer writing to its own pod's directory while the
    # API exports from another's is how a bundle comes to reference segments nobody can fetch.
    store = build_object_store(settings)
    publisher = OutboxPublisher(
        repository,
        store,
        Ed25519EvidenceSigner(provider.active_key("evidence-receipt")),
        Ed25519EvidenceSigner(provider.active_key("evidence-anchor")),
    )
    # The lease sweeper lives on the execution service because that is where lease state and its
    # transitions already are; a second implementation of `LEASE_EXPIRED` is how two components
    # come to disagree about what a terminal lease means. `receipt_gate=None` is deliberate --
    # the sweep reads and expires leases and never admits an execution, so it needs no verifier.
    execution = build_execution_service(settings, provider, None)
    # Same reasoning as the lease sweeper: approval state and its transitions already live on
    # `ApprovalRepository`, and `approval.expire` is the one function that decides whether an
    # epoch may close. A second implementation here is how the worker and the request path come
    # to disagree about what a terminal approval means.
    approvals = ApprovalRepository(settings.database_url, settings.approval_epoch_expiry)
    reconciler = EvidenceReconciler(
        ObjectEvidenceVerifier(
            repository,
            store,
            verification_public_keys(provider),
            settings.hash_verify_checkpoint_interval,
        )
    )
    return publisher, repository, execution, approvals, reconciler


def drain_tenant(
    publisher: OutboxPublisher,
    repository: EvidenceRepository,
    tenant_id: str,
    report: DrainReport,
    batch_size: int,
    quarantine_at_attempts: int,
    max_batches: int,
    stop: StopSignal,
) -> None:
    def on_failure(items: list[dict[str, object]], error: Exception) -> None:
        detail = f"{type(error).__name__}: {error}"
        for item in items:
            outbox_id = int(item["outbox_id"])  # type: ignore[arg-type]
            if repository.record_publication_failure(
                tenant_id, outbox_id, detail, quarantine_at_attempts
            ):
                report.quarantined += 1
                LOGGER.error(
                    "quarantined outbox row after %s attempts: tenant=%s outbox_id=%s error=%s",
                    quarantine_at_attempts,
                    tenant_id,
                    outbox_id,
                    detail,
                )
            else:
                report.failed += 1
                LOGGER.warning(
                    "publication failed, will retry: tenant=%s outbox_id=%s error=%s",
                    tenant_id,
                    outbox_id,
                    detail,
                )

    for _ in range(max_batches):
        published = publisher.drain(tenant_id, limit=batch_size, on_failure=on_failure)
        report.published += published
        # A short batch means the queue is drained; a full one means more is waiting and the
        # next batch should start now rather than after the poll interval.
        if published < batch_size or stop.requested:
            break


def relay_tenant(
    publisher: OutboxPublisher,
    repository: EvidenceRepository,
    tenant_id: str,
    report: DrainReport,
    batch_size: int,
    quarantine_at_attempts: int,
) -> None:
    """Deliver the SPEC §4 events that never become receipts.

    `approval`, `policy`, `agent`, `execution` and `security` rows have external subscribers and
    no evidence receipt, so `OutboxPublisher.drain` -- which selects `evidence_only=True` -- has
    always skipped them. They were written, they counted against the publication lag, and they
    were delivered to nothing: a SIEM integration subscribed to `mizan.approval.expired` would
    have received silence while the rows accumulated, and the only visible symptom would have
    been an evidence lag alarm blamed on the drainer.

    Delivery is **at-least-once**: the sink is called before the row is marked published, so a
    subscriber must tolerate a repeat. Marking first would make it at-most-once, and a silently
    dropped security event is worse than a duplicated one.
    """
    for item in repository.unpublished(tenant_id, batch_size, relay_only=True):
        outbox_id = int(item["outbox_id"])
        try:
            publisher.delivery.publish(
                item["event_type"], str(item["aggregate_type"]), item["payload"]
            )
        except Exception as error:
            detail = f"{type(error).__name__}: {error}"
            if repository.record_publication_failure(
                tenant_id, outbox_id, detail, quarantine_at_attempts
            ):
                report.quarantined += 1
                LOGGER.error(
                    "quarantined undeliverable event after %s attempts",
                    quarantine_at_attempts,
                    extra={
                        "tenant_id": tenant_id,
                        "outbox_id": outbox_id,
                        "event_type": item["event_type"],
                        "error": detail,
                    },
                )
            else:
                report.failed += 1
                LOGGER.warning(
                    "event delivery failed, will retry",
                    extra={
                        "tenant_id": tenant_id,
                        "outbox_id": outbox_id,
                        "event_type": item["event_type"],
                        "error": detail,
                    },
                )
            continue
        if repository.record_delivery(tenant_id, outbox_id):
            report.relayed += 1


def sweep_approvals(
    approvals: ApprovalRepository | None,
    tenant_id: str,
    report: DrainReport,
    mode: str,
) -> None:
    """Close elapsed approval epochs, or count them and leave them, per the deployment's mode.

    `MIZAN_APPROVAL_EPOCH_EXPIRY` is a money-movement policy rather than a tuning knob, which is
    why both modes are implemented rather than one being the other with the sweeper switched off:

      * `enforced` -- an unanswered approval is a refusal. The epoch closes as `EXPIRED` at rest
        and `mizan.approval.expired` is emitted, so a payment cannot sit pending indefinitely
        because nobody looked at it.
      * `advisory` -- no clock decides a payment. Nothing is written, elapsed epochs stay `OPEN`
        and a late vote is still accepted; the overdue count is reported every cycle so the
        condition is visible to the people whose decision it now is.

    An institution that wants the second and is given the first has had an approval decision made
    for it by a background process, which is exactly the class of thing H-7 exists to keep out of
    an engineer's hands.
    """
    if approvals is None:
        return
    try:
        if mode == "enforced":
            expired = approvals.sweep_expired_epochs(tenant_id)
            report.approvals_expired += len(expired)
            for approval_id in expired:
                LOGGER.warning(
                    "approval epoch expired at rest",
                    extra={
                        "tenant_id": tenant_id,
                        "approval_id": approval_id,
                        "detected_by": "sweep",
                    },
                )
        else:
            overdue = approvals.overdue_epochs(tenant_id)
            report.approvals_overdue += len(overdue)
            if overdue:
                LOGGER.warning(
                    "approval epochs are past their deadline and this deployment does not "
                    "expire them",
                    extra={
                        "tenant_id": tenant_id,
                        "overdue": len(overdue),
                        "approval_epoch_expiry": mode,
                    },
                )
    except Exception:
        # Same reasoning as the anchor and lease paths: one tenant's sweep must not stop the
        # others or kill the process every financial write depends on.
        LOGGER.exception("approval sweep failed", extra={"tenant_id": tenant_id})
        report.failed += 1


def anchor_tenant(
    publisher: OutboxPublisher,
    repository: EvidenceRepository,
    tenant_id: str,
    report: DrainReport,
    stop: StopSignal,
) -> None:
    for stream_id in repository.streams(tenant_id):
        if stop.requested:
            return
        try:
            anchor = publisher.anchor(tenant_id, stream_id)
        except Problem as problem:
            # A stream with nothing new since its last anchor is the ordinary case, not a fault.
            if problem.code == "evidence_range_empty":
                continue
            LOGGER.error(
                "anchoring refused: tenant=%s stream=%s code=%s", tenant_id, stream_id, problem.code
            )
            report.failed += 1
            continue
        except Exception:
            # Anything else -- `put_once` raising `immutable object collision` when the object
            # store holds a segment the database no longer knows about, a transient database
            # fault, a full disk. This used to escape `run_once` and terminate the process, so a
            # single unanchorable stream stopped the worker that every financial write depends
            # on, in a way no unit test reached: `make demo` found it the first time the worker
            # ran continuously against a real store. One stream's failure is not the fleet's.
            LOGGER.exception("anchoring failed: tenant=%s stream=%s", tenant_id, stream_id)
            report.failed += 1
            continue
        report.anchored += 1
        LOGGER.info(
            "anchored tenant=%s stream=%s anchor_number=%s records=%s",
            tenant_id,
            stream_id,
            anchor["anchor_number"],
            anchor["covered_record_count"],
        )


def sweep_tenant(
    execution: ExecutionService | None,
    tenant_id: str,
    report: DrainReport,
) -> None:
    """Expire leases whose holder never came back.

    Ordered **before** draining in the cycle deliberately: the sweep writes DecisionEvents and
    their outbox rows in the same transaction as the state change, so running it first means the
    expiries it records are published by the very same cycle rather than waiting for the next
    one. An expiry an operator cannot see is most of the way to no expiry at all.
    """
    if execution is None:
        return
    try:
        expired = execution.sweep_expired_leases(tenant_id)
    except Exception:
        # Same reasoning as the anchor path: this worker is what every financial write depends
        # on, and one tenant's sweep failing must not stop the others or kill the process.
        LOGGER.exception("lease sweep failed: tenant=%s", tenant_id)
        report.failed += 1
        return
    report.expired += len(expired)
    for lease_id in expired:
        LOGGER.warning(
            "lease expired at rest: tenant=%s lease_id=%s detected_by=sweep", tenant_id, lease_id
        )


def run_once(
    publisher: OutboxPublisher,
    repository: EvidenceRepository,
    tenants: list[str],
    batch_size: int,
    max_unpublished_seconds: int,
    quarantine_at_attempts: int = DEFAULT_QUARANTINE_ATTEMPTS,
    max_batches: int = DEFAULT_MAX_BATCHES_PER_CYCLE,
    stop: StopSignal | None = None,
    execution: ExecutionService | None = None,
    approvals: ApprovalRepository | None = None,
    approval_epoch_expiry: str = "enforced",
    reconciler: EvidenceReconciler | None = None,
) -> DrainReport:
    stop = stop or StopSignal()
    report = DrainReport()
    for tenant_id in tenants:
        if stop.requested:
            break
        sweep_tenant(execution, tenant_id, report)
        sweep_approvals(approvals, tenant_id, report, approval_epoch_expiry)
        drain_tenant(
            publisher,
            repository,
            tenant_id,
            report,
            batch_size,
            quarantine_at_attempts,
            max_batches,
            stop,
        )
        # After draining, so an expiry recorded by this cycle's sweep is delivered by this cycle
        # rather than waiting for the next one.
        relay_tenant(
            publisher, repository, tenant_id, report, batch_size, quarantine_at_attempts
        )
        anchor_tenant(publisher, repository, tenant_id, report, stop)
        if reconciler is not None:
            reconciliation = reconciler.reconcile([tenant_id])
            report.reconciliation_mismatches.extend(reconciliation.mismatches)
            report.failed += len(reconciliation.mismatches)
            for mismatch in reconciliation.mismatches:
                LOGGER.error(
                    "evidence reconciliation mismatch: tenant=%s stream=%s sequence=%s "
                    "expected=%s actual=%s",
                    mismatch.tenant_id,
                    mismatch.stream_id,
                    mismatch.first_broken_sequence,
                    mismatch.expected,
                    mismatch.actual,
                )
        # Measured after draining: the number that matters is what is still waiting once the
        # worker has done everything it can, not what was waiting when the cycle began.
        lag = repository.oldest_unpublished_age_seconds(tenant_id)
        if lag is not None and lag > max_unpublished_seconds:
            report.lag_breaches.append((tenant_id, lag))
            print(
                f"EVIDENCE BREAKER OPEN: unpublished_evidence_slo_breached tenant={tenant_id} "
                f"lag={lag:.1f}s limit={max_unpublished_seconds}s",
                file=sys.stderr,
                flush=True,
            )
    return report


def resolve_tenants(argument: list[str] | None) -> list[str]:
    """This worker's served set. The reasoning, and B-27, live on the shared helper."""
    return resolve_served_tenants(argument, "MIZAN_DRAIN_TENANTS")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Publish evidence from the outbox, anchor it, and hold the publication SLO"
    )
    parser.add_argument(
        "--tenant-id",
        action="append",
        help="tenant to serve; repeatable. Defaults to MIZAN_DRAIN_TENANTS (comma-separated). "
        "Tenants cannot be discovered: mizan.tenants is under FORCE ROW LEVEL SECURITY and "
        "widening that is an H-7 tenant-isolation decision, escalated as B-27.",
    )
    parser.add_argument("--interval-seconds", type=float, default=None)
    parser.add_argument("--batch-size", type=int, default=100)
    parser.add_argument("--quarantine-after", type=int, default=DEFAULT_QUARANTINE_ATTEMPTS)
    parser.add_argument("--max-batches-per-cycle", type=int, default=DEFAULT_MAX_BATCHES_PER_CYCLE)
    parser.add_argument("--once", action="store_true")
    arguments = parser.parse_args(argv)

    configure_logging()

    tenants = resolve_tenants(arguments.tenant_id)
    if not tenants:
        parser.error(
            "no tenants named. Pass --tenant-id (repeatable) or set MIZAN_DRAIN_TENANTS. "
            "A drainer that serves no tenant publishes no evidence, and every financial write "
            "is then refused with 403 immutable_receipt_missing -- so this refuses to start "
            "rather than run and appear healthy."
        )

    settings = Settings.from_environment()
    interval = (
        arguments.interval_seconds
        if arguments.interval_seconds is not None
        else settings.outbox_drain_interval_ms / 1000.0
    )
    stop = StopSignal()
    stop.install()

    publisher, repository, execution, approvals, reconciler = build_publisher(settings)
    LOGGER.info(
        "draining %s tenant(s) every %.3fs, batch=%s, SLO=%ss, approval-epoch-expiry=%s",
        len(tenants),
        interval,
        arguments.batch_size,
        settings.evidence_max_unpublished_seconds,
        settings.approval_epoch_expiry,
    )
    breached = False
    try:
        while True:
            report = run_once(
                publisher,
                repository,
                tenants,
                arguments.batch_size,
                settings.evidence_max_unpublished_seconds,
                arguments.quarantine_after,
                arguments.max_batches_per_cycle,
                stop,
                execution,
                approvals,
                settings.approval_epoch_expiry,
                reconciler,
            )
            breached = breached or bool(
                report.lag_breaches or report.reconciliation_mismatches
            )
            if report.did_work or report.failed:
                LOGGER.info(
                    "published=%s relayed=%s anchored=%s quarantined=%s leases_expired=%s "
                    "approvals_expired=%s approvals_overdue=%s failed=%s",
                    report.published,
                    report.relayed,
                    report.anchored,
                    report.quarantined,
                    report.expired,
                    report.approvals_expired,
                    report.approvals_overdue,
                    report.failed,
                )
            if arguments.once:
                return 2 if breached else 0
            if stop.requested:
                LOGGER.info("stopping cleanly")
                return 0
            time.sleep(interval)
    finally:
        repository.pool.close()
        approvals.pool.close()


if __name__ == "__main__":
    raise SystemExit(main())
