from datetime import UTC, datetime
from types import SimpleNamespace

from mizan_control_plane.attestation_runner import ReportingEvidenceBreaker, run_once


def test_runner_loads_pending_anchors_and_executes_worker() -> None:
    pending = {
        "type": "rfc3161", "status": "pending", "authority": "tsa",
        "anchor_digest": "a" * 64, "requested_at": datetime.now(UTC).isoformat(),
    }
    writes = []
    repository = SimpleNamespace(
        anchors=lambda tenant, stream: [{
            "payload": {"anchor_id": "anchor-1", "attestations": [pending]},
            "attestations": [],
        }],
        record_anchor_attestation=lambda *args: writes.append(args) or "appended",
    )
    provider = SimpleNamespace(
        obtain=lambda item: item | {"status": "attested", "evidence": "AA=="}
    )

    assert run_once(
        repository, provider, ReportingEvidenceBreaker(), "tnt_bank-a", "stream-a", 900
    ) == 1
    assert writes[0][1] == "anchor-1"
