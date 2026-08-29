from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from mizan_control_plane.attestation_runner import ReportingEvidenceBreaker, run_all, run_once
from mizan_control_plane.config import resolve_served_tenants
from mizan_control_plane.drain_worker import StopSignal


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


def _repository(streams_by_tenant: dict[str, list[str]], writes: list) -> SimpleNamespace:
    def anchors(tenant, stream):
        # One pending anchor per stream, named for the stream so the test can tell which
        # shards were actually visited rather than only how many.
        return [
            {
                "payload": {
                    "anchor_id": f"anchor-{stream}",
                    "attestations": [
                        {
                            "type": "rfc3161",
                            "status": "pending",
                            "authority": "tsa",
                            "anchor_digest": "a" * 64,
                            "requested_at": datetime.now(UTC).isoformat(),
                        }
                    ],
                },
                "attestations": [],
            }
        ]

    return SimpleNamespace(
        anchors=anchors,
        streams=lambda tenant: streams_by_tenant[tenant],
        record_anchor_attestation=lambda *args: writes.append(args) or "appended",
    )


def test_every_shard_of_every_served_tenant_is_attested() -> None:
    """T-106. The CLI required one `--tenant-id` and one `--stream-id`.

    A tenant's evidence is sharded, so a deployment running the runner as written attested
    whichever single shard someone named and left the rest `pending` forever. B-12 forbids
    calling a stream with a pending attestation externally anchored, so the product ran and
    never produced the external timestamp that is its central claim -- on every shard nobody
    happened to type.
    """
    writes: list = []
    repository = _repository(
        {
            "tnt_bank-a": [f"tnt_bank-a:adr:{shard}" for shard in range(4)]
            + ["tnt_bank-a:audit:0"],
            "tnt_bank-b": ["tnt_bank-b:adr:0"],
        },
        writes,
    )
    provider = SimpleNamespace(
        obtain=lambda item: item | {"status": "attested", "evidence": "AA=="}
    )

    completed = run_all(
        repository,
        provider,
        ReportingEvidenceBreaker(),
        ["tnt_bank-a", "tnt_bank-b"],
        900,
    )

    assert completed == 6
    attested = {call[1] for call in writes}
    # Every shard, not just `adr:0` -- which is the one a hand-written --stream-id would name.
    assert attested == {
        "anchor-tnt_bank-a:adr:0",
        "anchor-tnt_bank-a:adr:1",
        "anchor-tnt_bank-a:adr:2",
        "anchor-tnt_bank-a:adr:3",
        "anchor-tnt_bank-a:audit:0",
        "anchor-tnt_bank-b:adr:0",
    }


def test_one_stream_can_still_be_named_for_an_operator_running_it_by_hand() -> None:
    writes: list = []
    repository = _repository({"tnt_bank-a": ["tnt_bank-a:adr:0", "tnt_bank-a:adr:1"]}, writes)
    provider = SimpleNamespace(
        obtain=lambda item: item | {"status": "attested", "evidence": "AA=="}
    )

    completed = run_all(
        repository,
        provider,
        ReportingEvidenceBreaker(),
        ["tnt_bank-a"],
        900,
        only_stream="tnt_bank-a:adr:1",
    )

    assert completed == 1
    assert {call[1] for call in writes} == {"anchor-tnt_bank-a:adr:1"}


def test_a_stop_signal_ends_the_pass_without_starting_another_tenant() -> None:
    writes: list = []
    repository = _repository({"tnt_bank-a": ["tnt_bank-a:adr:0"]}, writes)
    provider = SimpleNamespace(
        obtain=lambda item: item | {"status": "attested", "evidence": "AA=="}
    )

    completed = run_all(
        repository,
        provider,
        ReportingEvidenceBreaker(),
        ["tnt_bank-a"],
        900,
        stop=StopSignal(requested=True),
    )

    assert completed == 0 and writes == []


def test_a_runner_that_serves_no_tenant_refuses_to_start(monkeypatch) -> None:
    """It would otherwise poll forever, attest nothing, and leave every anchor pending --
    with no failing component to point at."""
    from mizan_control_plane import attestation_runner

    monkeypatch.delenv("MIZAN_ATTEST_TENANTS", raising=False)
    with pytest.raises(SystemExit) as exit_info:
        attestation_runner.main([])
    assert exit_info.value.code == 2


def test_served_tenants_come_from_the_flag_then_the_environment(monkeypatch) -> None:
    monkeypatch.setenv("MIZAN_ATTEST_TENANTS", "tnt_from-env, tnt_other ")
    assert resolve_served_tenants(["tnt_explicit"], "MIZAN_ATTEST_TENANTS") == ["tnt_explicit"]
    assert resolve_served_tenants(None, "MIZAN_ATTEST_TENANTS") == ["tnt_from-env", "tnt_other"]
    # The two workloads read different keys, so a drainer's list cannot silently become the
    # attestation runner's.
    assert resolve_served_tenants(None, "MIZAN_DRAIN_TENANTS") == []
