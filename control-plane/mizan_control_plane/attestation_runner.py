from __future__ import annotations

import argparse
import logging
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from .attestation import AnchorAttestationWorker, Rfc3161AnchorProvider
from .config import Settings, resolve_served_tenants
from .drain_worker import StopSignal
from .evidence import EvidenceRepository

LOGGER = logging.getLogger("mizan.attest")


@dataclass
class ReportingEvidenceBreaker:
    opened: list[tuple[str, str, str]] = field(default_factory=list)

    def open(self, reason: str, tenant_id: str, anchor_id: str) -> None:
        event = (reason, tenant_id, anchor_id)
        if event not in self.opened:
            self.opened.append(event)
            print(
                f"EVIDENCE BREAKER OPEN: {reason} tenant={tenant_id} anchor={anchor_id}",
                file=sys.stderr,
            )


def run_once(
    repository: EvidenceRepository,
    provider: Rfc3161AnchorProvider,
    breaker: ReportingEvidenceBreaker,
    tenant_id: str,
    stream_id: str,
    max_pending_seconds: int,
) -> int:
    rows = repository.anchors(tenant_id, stream_id)
    return AnchorAttestationWorker(repository, provider, breaker).process(
        tenant_id, rows, max_pending_seconds
    )


def run_all(
    repository: EvidenceRepository,
    provider: Rfc3161AnchorProvider,
    breaker: ReportingEvidenceBreaker,
    tenants: list[str],
    max_pending_seconds: int,
    only_stream: str | None = None,
    stop: StopSignal | None = None,
) -> int:
    """One pass over every stream of every served tenant. Returns anchors completed.

    The CLI used to require exactly one `--tenant-id` and one `--stream-id`. A tenant's evidence
    is sharded -- four `adr` streams by default, plus `audit` -- so a deployment running this as
    written attested whichever single shard someone named and left every other one `pending`
    forever. B-12 forbids describing a stream carrying a pending attestation as externally
    anchored, so the product ran and never produced the external timestamp that is its central
    claim, on every shard nobody happened to type.

    Streams are enumerated from inside each tenant's own RLS scope and cross no isolation
    boundary. Tenants are named rather than discovered, for the reason B-27 records.
    """
    stop = stop or StopSignal()
    completed = 0
    for tenant_id in tenants:
        if stop.requested:
            break
        streams = [only_stream] if only_stream else repository.streams(tenant_id)
        for stream_id in streams:
            if stop.requested:
                break
            completed += run_once(
                repository, provider, breaker, tenant_id, stream_id, max_pending_seconds
            )
    return completed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Complete pending anchor attestations")
    parser.add_argument(
        "--tenant-id",
        action="append",
        help="tenant to serve; repeatable. Defaults to MIZAN_ATTEST_TENANTS (comma-separated). "
        "Tenants cannot be discovered: mizan.tenants is under FORCE ROW LEVEL SECURITY and "
        "widening that is an H-7 tenant-isolation decision, escalated as B-27.",
    )
    parser.add_argument(
        "--stream-id",
        help="restrict to one stream. Omitted -- the default, and what a managed workload must "
        "do -- every stream of every served tenant is attested, because a tenant's evidence is "
        "sharded and the shards nobody names stay pending forever.",
    )
    parser.add_argument("--interval-seconds", type=float, default=30.0)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    tenants = resolve_served_tenants(args.tenant_id, "MIZAN_ATTEST_TENANTS")
    if not tenants:
        parser.error(
            "no tenants named. Pass --tenant-id (repeatable) or set MIZAN_ATTEST_TENANTS. "
            "An attestation runner serving no tenant leaves every anchor pending, and B-12 "
            "forbids describing such a stream as externally anchored -- so this refuses to "
            "start rather than run and appear healthy."
        )

    settings = Settings.from_environment()
    if settings.anchor_provider != "rfc3161":
        parser.error("mizan-attest-anchors requires MIZAN_ANCHOR_PROVIDER=rfc3161")
    repository = EvidenceRepository(settings.database_url)
    # Endpoint scheme is settled in Settings.from_environment: production refuses non-HTTPS
    # authorities before this process reaches the provider, which takes no environment argument.
    provider = Rfc3161AnchorProvider(
        list(settings.anchor_tsa_endpoints),
        trust_anchors=[Path(item) for item in settings.anchor_tsa_trust_anchors],
    )
    breaker = ReportingEvidenceBreaker()
    stop = StopSignal()
    stop.install()
    LOGGER.info(
        "attesting %s tenant(s) every %.1fs against %s",
        len(tenants),
        args.interval_seconds,
        ", ".join(settings.anchor_tsa_endpoints) or "no configured authority",
    )
    try:
        while True:
            completed = run_all(
                repository,
                provider,
                breaker,
                tenants,
                settings.anchor_attestation_max_pending_seconds,
                args.stream_id,
                stop,
            )
            if completed:
                LOGGER.info("completed %s anchor attestation(s)", completed)
            if args.once:
                return 2 if breaker.opened else 0
            if stop.requested:
                LOGGER.info("stopping cleanly")
                return 0
            time.sleep(args.interval_seconds)
    finally:
        repository.pool.close()
