from __future__ import annotations

import argparse
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from .attestation import AnchorAttestationWorker, Rfc3161AnchorProvider
from .config import Settings
from .evidence import EvidenceRepository


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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Complete pending anchor attestations")
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--stream-id", required=True)
    parser.add_argument("--interval-seconds", type=float, default=30.0)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args(argv)
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
    try:
        while True:
            run_once(
                repository,
                provider,
                breaker,
                args.tenant_id,
                args.stream_id,
                settings.anchor_attestation_max_pending_seconds,
            )
            if args.once:
                return 2 if breaker.opened else 0
            time.sleep(args.interval_seconds)
    finally:
        repository.pool.close()
