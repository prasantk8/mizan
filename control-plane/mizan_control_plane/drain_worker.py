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
from pathlib import Path
from types import FrameType

from .config import Settings, resolve_served_tenants
from .evidence import (
    Ed25519EvidenceSigner,
    EvidenceRepository,
    LocalImmutableObjectStore,
    OutboxPublisher,
)
from .observability import configure_logging
from .problems import Problem
from .runtime import build_key_provider

LOGGER = logging.getLogger("mizan.drain")

# A row that has failed this many times is set aside for a human rather than retried again.
DEFAULT_QUARANTINE_ATTEMPTS = 5
# Bounds one tenant's share of a cycle so a large backlog cannot starve the other tenants.
DEFAULT_MAX_BATCHES_PER_CYCLE = 20


@dataclass
class DrainReport:
    published: int = 0
    anchored: int = 0
    quarantined: int = 0
    failed: int = 0
    lag_breaches: list[tuple[str, float]] = field(default_factory=list)

    @property
    def did_work(self) -> bool:
        return bool(self.published or self.anchored or self.quarantined)


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


def build_publisher(settings: Settings) -> tuple[OutboxPublisher, EvidenceRepository]:
    provider = build_key_provider(settings)
    repository = EvidenceRepository(settings.database_url)
    store = LocalImmutableObjectStore(Path(settings.evidence_object_store_root))
    publisher = OutboxPublisher(
        repository,
        store,
        Ed25519EvidenceSigner(provider.active_key("evidence-receipt")),
        Ed25519EvidenceSigner(provider.active_key("evidence-anchor")),
    )
    return publisher, repository


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


def run_once(
    publisher: OutboxPublisher,
    repository: EvidenceRepository,
    tenants: list[str],
    batch_size: int,
    max_unpublished_seconds: int,
    quarantine_at_attempts: int = DEFAULT_QUARANTINE_ATTEMPTS,
    max_batches: int = DEFAULT_MAX_BATCHES_PER_CYCLE,
    stop: StopSignal | None = None,
) -> DrainReport:
    stop = stop or StopSignal()
    report = DrainReport()
    for tenant_id in tenants:
        if stop.requested:
            break
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
        anchor_tenant(publisher, repository, tenant_id, report, stop)
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

    publisher, repository = build_publisher(settings)
    LOGGER.info(
        "draining %s tenant(s) every %.3fs, batch=%s, SLO=%ss",
        len(tenants),
        interval,
        arguments.batch_size,
        settings.evidence_max_unpublished_seconds,
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
            )
            breached = breached or bool(report.lag_breaches)
            if report.did_work or report.failed:
                LOGGER.info(
                    "published=%s anchored=%s quarantined=%s failed=%s",
                    report.published,
                    report.anchored,
                    report.quarantined,
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


if __name__ == "__main__":
    raise SystemExit(main())
