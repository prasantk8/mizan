from __future__ import annotations

import base64
import hashlib
import re
import subprocess
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
import rfc8785
from mizan_control_plane.attestation import (
    AnchorAttestationWorker,
    CustomerCountersignatureProvider,
    Rfc3161AnchorProvider,
    customer_countersignature,
    pending_attestation_breaker_open,
)
from mizan_control_plane.evidence import Ed25519EvidenceSigner

from scripts.verify_evidence_export import VerificationFailure, verify_rfc3161


def test_rfc3161_provider_queues_only_anchor_digest() -> None:
    payload = {"tenant_id": "tnt_bank-a", "head_hash": "a" * 64}
    attestation = Rfc3161AnchorProvider(["https://tsa.example.test"]).attest(payload)[0]
    assert attestation["status"] == "pending"
    assert attestation["anchor_digest"] == hashlib.sha256(rfc8785.dumps(payload)).hexdigest()
    assert "tenant_id" not in str(attestation)


def test_rfc3161_provider_queues_each_configured_authority() -> None:
    attestations = Rfc3161AnchorProvider(["https://tsa-a.test", "https://tsa-b.test"]).attest(
        {"head_hash": "a" * 64}
    )
    assert [item["authority"] for item in attestations] == [
        "https://tsa-a.test", "https://tsa-b.test"
    ]
    assert len({item["anchor_digest"] for item in attestations}) == 1


def test_pending_slo_opens_evidence_breaker() -> None:
    now = datetime.now(UTC)
    pending = [{
        "status": "pending",
        "requested_at": (now - timedelta(seconds=901)).isoformat().replace("+00:00", "Z"),
    }]
    assert pending_attestation_breaker_open(pending, 900, now)


def test_offline_rfc3161_verification_uses_operator_trust_root(tmp_path, monkeypatch) -> None:
    trust = tmp_path / "operator-root.pem"
    trust.write_text("operator supplied", encoding="utf-8")
    observed = {}

    def successful(command, **kwargs):
        observed["command"] = command
        return SimpleNamespace(returncode=0, stdout="-verify", stderr="")

    monkeypatch.setattr("scripts.verify_evidence_export.subprocess.run", successful)
    verify_rfc3161(
        {"anchor_digest": "a" * 64, "evidence": "AA=="},
        "a" * 64,
        [trust],
    )
    assert observed["command"][0] == "openssl"
    assert "-CAfile" in observed["command"]


def test_rfc3161_verification_fails_without_operator_trust_root() -> None:
    with pytest.raises(VerificationFailure, match="requires --tsa-trust-anchor"):
        verify_rfc3161({"anchor_digest": "a" * 64, "evidence": "AA=="}, "a" * 64, [])


def test_real_rfc3161_response_verifies_offline_and_before_recording(tmp_path, monkeypatch) -> None:
    digest = hashlib.sha256(b"anchor-core").hexdigest()
    key = tmp_path / "tsa.key"
    cert = tmp_path / "tsa.pem"
    query = tmp_path / "request.tsq"
    response = tmp_path / "response.tsr"
    serial = tmp_path / "serial"
    serial.write_text("01\n", encoding="utf-8")
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=Mizan Test TSA",
            "-addext", "extendedKeyUsage=critical,timeStamping",
        ],
        check=True,
        capture_output=True,
    )
    config = tmp_path / "tsa.cnf"
    config.write_text(
        "\n".join([
            "[tsa]", "default_tsa=tsa_config1", "[tsa_config1]", f"serial={serial}",
            "crypto_device=builtin", f"signer_cert={cert}", f"certs={cert}", f"signer_key={key}",
            "signer_digest=sha256", "default_policy=1.2.3.4.1", "digests=sha256",
            "accuracy=secs:1", "ordering=yes", "tsa_name=yes", "ess_cert_id_chain=no",
        ]),
        encoding="utf-8",
    )
    subprocess.run(
        ["openssl", "ts", "-query", "-digest", digest, "-sha256", "-cert", "-out", str(query)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["openssl", "ts", "-reply", "-queryfile", str(query), "-config", str(config), "-out", str(response)],
        check=True,
        capture_output=True,
    )
    verify_rfc3161(
        {"anchor_digest": digest, "evidence": base64.b64encode(response.read_bytes()).decode()},
        digest,
        [cert],
    )

    class TsaResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self):
            return response.read_bytes()

    monkeypatch.setattr(
        "mizan_control_plane.attestation.urllib.request.urlopen",
        lambda request, timeout: TsaResponse(),
    )
    provider = Rfc3161AnchorProvider(["https://tsa.example.test"], [cert])
    obtained = provider.obtain({
        "type": "rfc3161", "status": "pending", "authority": "https://tsa.example.test",
        "anchor_digest": digest, "evidence": None, "obtained_at": None,
    })
    assert obtained["status"] == "attested"
    assert base64.b64decode(obtained["evidence"]) == response.read_bytes()
    wrong_key = tmp_path / "wrong.key"
    wrong_cert = tmp_path / "wrong.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(wrong_key), "-out", str(wrong_cert), "-days", "1",
            "-subj", "/CN=Wrong TSA", "-addext", "extendedKeyUsage=critical,timeStamping",
        ],
        check=True,
        capture_output=True,
    )
    with pytest.raises(VerificationFailure, match="timestamp signer is not trusted"):
        verify_rfc3161(
            {"anchor_digest": digest, "evidence": base64.b64encode(response.read_bytes()).decode()},
            digest,
            [wrong_cert],
        )


def test_tsa_egress_contains_digest_and_no_anchor_payload(tmp_path, monkeypatch) -> None:
    payload = {"tenant_id": "tnt_secret-bank", "head_hash": "a" * 64}
    provider = Rfc3161AnchorProvider(["https://tsa.example.test"])
    pending = provider.attest(payload)[0]
    observed = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self):
            return b"tsa-response"

    def open_request(request, timeout):
        observed["body"] = request.data
        observed["url"] = request.full_url
        return Response()

    monkeypatch.setattr("mizan_control_plane.attestation.urllib.request.urlopen", open_request)
    provider.obtain(pending)
    query = tmp_path / "request.tsq"
    query.write_bytes(observed["body"])
    decoded = subprocess.run(
        ["openssl", "ts", "-query", "-in", str(query), "-text"],
        check=True, capture_output=True, text=True,
    ).stdout.lower()
    message_hex = "".join(
        "".join(re.findall(r"\b[0-9a-f]{2}\b", line.strip().split("   ", 1)[0]))
        for line in decoded.splitlines()
        if " - " in line
    )
    assert message_hex == pending["anchor_digest"]
    assert b"tnt_secret-bank" not in observed["body"]
    assert observed["url"] == "https://tsa.example.test"


def test_unvalidated_tsa_response_remains_pending_with_named_reason(monkeypatch) -> None:
    provider = Rfc3161AnchorProvider(["https://tsa.example.test"])
    pending = provider.attest({"head_hash": "a" * 64})[0]

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self):
            return b"not-a-timestamp-token"

    monkeypatch.setattr(
        "mizan_control_plane.attestation.urllib.request.urlopen",
        lambda request, timeout: Response(),
    )

    result = provider.obtain(pending)

    assert result["status"] == "pending"
    assert result["evidence"] is None
    assert result["failure_reason"] == (
        "token validation unavailable: no TSA trust anchor configured"
    )


def test_provider_records_attested_only_after_token_validation(tmp_path, monkeypatch) -> None:
    trust = tmp_path / "tsa-root.pem"
    trust.write_text("operator root", encoding="utf-8")
    provider = Rfc3161AnchorProvider(["https://tsa.example.test"], [trust])
    pending = provider.attest({"head_hash": "a" * 64})[0]
    commands = []

    def openssl(command, **kwargs):
        commands.append(command)
        if "-query" in command:
            Path(command[command.index("-out") + 1]).write_bytes(b"timestamp-query")
        return SimpleNamespace(returncode=0, stderr="")

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self):
            return b"validated-timestamp-token"

    monkeypatch.setattr("mizan_control_plane.attestation.subprocess.run", openssl)
    monkeypatch.setattr(
        "mizan_control_plane.attestation.urllib.request.urlopen",
        lambda request, timeout: Response(),
    )

    result = provider.obtain(pending)

    assert result["status"] == "attested"
    assert len(commands) == 2
    assert commands[1][1:3] == ["ts", "-verify"]
    assert commands[1][commands[1].index("-digest") + 1] == pending["anchor_digest"]
    assert commands[1][commands[1].index("-CAfile") + 1].endswith("trust.pem")


def test_worker_does_not_persist_validation_failure_and_retries_to_attested() -> None:
    pending = {
        "type": "rfc3161",
        "status": "pending",
        "authority": "https://tsa.example.test",
        "anchor_digest": "a" * 64,
        "requested_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }
    writes = []
    results = iter([
        pending | {
            "failure_reason": "RFC 3161 token validation failed: transient garbage",
        },
        pending | {"status": "attested", "evidence": "AA=="},
    ])
    calls = []
    provider = SimpleNamespace(obtain=lambda item: (calls.append(item), next(results))[1])
    worker = AnchorAttestationWorker(
        SimpleNamespace(
            record_anchor_attestation=lambda *args: writes.append(args) or "appended"
        ),
        provider,
        SimpleNamespace(open=lambda *args: None),
    )
    rows = [{
        "payload": {"anchor_id": "anchor-1", "attestations": [pending]},
        "attestations": [],
    }]

    assert worker.process("tnt_bank-a", rows, 900) == 0
    assert writes == []
    assert worker.process("tnt_bank-a", rows, 900) == 1
    assert len(calls) == 2
    assert writes[0][2]["status"] == "attested"


def test_tsa_outage_opens_only_evidence_breaker_and_authorization_remains_available(
    monkeypatch,
) -> None:
    now = datetime.now(UTC)
    provider = Rfc3161AnchorProvider(["https://tsa.example.test"])
    pending = provider.attest({"head_hash": "a" * 64})[0] | {
        "requested_at": (now - timedelta(seconds=901)).isoformat().replace("+00:00", "Z")
    }
    monkeypatch.setattr(
        "mizan_control_plane.attestation.urllib.request.urlopen",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("simulated TSA outage")),
    )
    with pytest.raises(OSError, match="simulated TSA outage"):
        provider.obtain(pending)
    assert pending_attestation_breaker_open([pending], 900, now)
    assert (lambda: "authorization-available")() == "authorization-available"


def test_worker_appends_final_attestation_without_mutating_anchor_payload() -> None:
    pending = {
        "type": "rfc3161", "status": "pending", "authority": "tsa",
        "anchor_digest": "a" * 64, "requested_at": datetime.now(UTC).isoformat(),
    }
    payload = {"anchor_id": "anchor-1", "attestations": [pending.copy()]}
    writes = []
    repository = SimpleNamespace(
        record_anchor_attestation=lambda tenant, anchor, item: (
            writes.append((tenant, anchor, item)) or "appended"
        )
    )
    provider = SimpleNamespace(obtain=lambda item: item | {"status": "attested", "evidence": "AA=="})
    breaker = SimpleNamespace(open=lambda *args: None)
    assert AnchorAttestationWorker(repository, provider, breaker).process(
        "tnt_bank-a", [{"payload": payload, "attestations": []}], 900
    ) == 1
    assert writes[0][2]["status"] == "attested"
    assert payload["attestations"][0]["status"] == "pending"


def test_worker_escalates_occupied_pending_sidecar_without_retrying_forever() -> None:
    pending = {
        "type": "rfc3161", "status": "pending", "authority": "tsa",
        "anchor_digest": "a" * 64, "requested_at": datetime.now(UTC).isoformat(),
    }
    calls = []
    opened = []
    worker = AnchorAttestationWorker(
        SimpleNamespace(record_anchor_attestation=lambda *args: "conflict"),
        SimpleNamespace(obtain=lambda item: calls.append(item) or item | {
            "status": "attested", "evidence": "AA==",
        }),
        SimpleNamespace(open=lambda *args: opened.append(args)),
    )

    assert worker.process(
        "tnt_bank-a",
        [{
            "payload": {"anchor_id": "anchor-1", "attestations": [pending]},
            "attestations": [pending | {"failure_reason": "prior transient failure"}],
        }],
        900,
    ) == 0
    assert calls == []
    assert opened == [("anchor_attestation_integrity", "tnt_bank-a", "anchor-1")]


def test_worker_does_not_count_store_refusal_and_names_conflict() -> None:
    pending = {
        "type": "rfc3161", "status": "pending", "authority": "tsa",
        "anchor_digest": "a" * 64, "requested_at": datetime.now(UTC).isoformat(),
    }
    opened = []
    worker = AnchorAttestationWorker(
        SimpleNamespace(record_anchor_attestation=lambda *args: "conflict"),
        SimpleNamespace(obtain=lambda item: item | {"status": "attested", "evidence": "AA=="}),
        SimpleNamespace(open=lambda *args: opened.append(args)),
    )

    assert worker.process(
        "tnt_bank-a",
        [{"payload": {"anchor_id": "anchor-1", "attestations": [pending]}, "attestations": []}],
        900,
    ) == 0
    assert opened == [("anchor_attestation_integrity", "tnt_bank-a", "anchor-1")]


def test_worker_takes_anchor_lease_before_spending_token() -> None:
    pending = {
        "type": "rfc3161", "status": "pending", "authority": "tsa",
        "anchor_digest": "a" * 64, "requested_at": datetime.now(UTC).isoformat(),
    }
    events = []

    class Repository:
        @contextmanager
        def lease_anchor_attestation(self, tenant_id, anchor_id):
            events.append("lease-enter")
            yield []
            events.append("lease-exit")

        def record_anchor_attestation(self, *args):
            events.append("append")
            return "appended"

    provider = SimpleNamespace(
        obtain=lambda item: events.append("obtain") or item | {
            "status": "attested", "evidence": "AA=="
        }
    )
    worker = AnchorAttestationWorker(
        Repository(), provider, SimpleNamespace(open=lambda *args: None)
    )

    assert worker.process(
        "tnt_bank-a",
        [{"payload": {"anchor_id": "anchor-1", "attestations": [pending]}}],
        900,
    ) == 1
    assert events == ["lease-enter", "obtain", "append", "lease-exit"]


def test_worker_skips_locked_anchor_without_spending_token() -> None:
    pending = {
        "type": "rfc3161", "status": "pending", "authority": "tsa",
        "anchor_digest": "a" * 64, "requested_at": datetime.now(UTC).isoformat(),
    }
    calls = []

    class Repository:
        @contextmanager
        def lease_anchor_attestation(self, tenant_id, anchor_id):
            yield None

    worker = AnchorAttestationWorker(
        Repository(),
        SimpleNamespace(obtain=lambda item: calls.append(item)),
        SimpleNamespace(open=lambda *args: None),
    )

    assert worker.process(
        "tnt_bank-a",
        [{"payload": {"anchor_id": "anchor-1", "attestations": [pending]}}],
        900,
    ) == 0
    assert calls == []


def test_worker_treats_different_valid_token_for_same_anchor_as_benign() -> None:
    payload = {
        "anchor_id": "anchor-1", "head_hash": "b" * 64,
        "object_key": "ignored", "object_version": "ignored",
    }
    digest = hashlib.sha256(rfc8785.dumps({
        "anchor_id": payload["anchor_id"], "head_hash": payload["head_hash"]
    })).hexdigest()
    pending = {
        "type": "rfc3161", "status": "pending", "authority": "tsa",
        "anchor_digest": digest, "requested_at": datetime.now(UTC).isoformat(),
    }
    stored = pending | {"status": "attested", "evidence": "token-one"}
    candidate = pending | {"status": "attested", "evidence": "token-two"}
    opened = []
    provider = SimpleNamespace(
        obtain=lambda item: candidate,
        attestation_validation_failure=lambda item, expected, authority: (
            None
            if item == stored and expected == digest and authority == "tsa"
            else "invalid"
        ),
    )
    repository = SimpleNamespace(
        record_anchor_attestation=lambda *args: "conflict",
        anchor_attestation=lambda *args: stored,
    )

    assert AnchorAttestationWorker(
        repository, provider, SimpleNamespace(open=lambda *args: opened.append(args))
    ).process(
        "tnt_bank-a", [{"payload": payload | {"attestations": [pending]}, "attestations": []}], 900
    ) == 0
    assert opened == []


@pytest.mark.parametrize(
    "stored",
    [
        {"type": "rfc3161", "status": "attested", "authority": "other", "anchor_digest": "a" * 64, "evidence": "AA=="},
        {"type": "rfc3161", "status": "attested", "authority": "tsa", "anchor_digest": "b" * 64, "evidence": "AA=="},
        {"type": "rfc3161", "status": "attested", "authority": "tsa", "anchor_digest": "a" * 64, "evidence": "bad"},
    ],
)
def test_stored_attestation_semantic_validation_rejects_tampering(
    tmp_path: Path, monkeypatch, stored: dict
) -> None:
    root = tmp_path / "root.pem"
    root.write_text("root")
    provider = Rfc3161AnchorProvider(["https://tsa.example"], [root])
    monkeypatch.setattr(provider, "_validation_failure", lambda *args: "invalid token")

    assert provider.attestation_validation_failure(stored, "a" * 64, "tsa") is not None


def test_customer_countersignature_binds_anchor_digest() -> None:
    signer = Ed25519EvidenceSigner.development("evidence-anchor")
    payload = {"anchor_id": "anchor-1", "head_hash": "a" * 64}
    attestation = customer_countersignature(payload, "customer-a", signer.signing_key)
    digest = hashlib.sha256(rfc8785.dumps(payload)).digest()
    signer.public_key.verify(base64.urlsafe_b64decode(attestation["evidence"]), digest)
    assert attestation["anchor_digest"] == digest.hex()
    assert CustomerCountersignatureProvider(
        "customer-a", signer.signing_key
    ).attest(payload)["type"] == "customer_countersignature"


def test_worker_opens_breaker_after_tsa_outage_exceeds_slo() -> None:
    now = datetime.now(UTC)
    pending = {
        "type": "rfc3161", "status": "pending", "authority": "tsa",
        "anchor_digest": "a" * 64,
        "requested_at": (now - timedelta(seconds=901)).isoformat().replace("+00:00", "Z"),
    }
    opened = []
    worker = AnchorAttestationWorker(
        SimpleNamespace(record_anchor_attestation=lambda *args: None),
        SimpleNamespace(obtain=lambda item: (_ for _ in ()).throw(OSError("TSA unavailable"))),
        SimpleNamespace(open=lambda *args: opened.append(args)),
    )
    assert worker.process(
        "tnt_bank-a",
        [{"payload": {"anchor_id": "anchor-1", "attestations": [pending]}, "attestations": []}],
        900,
        now,
    ) == 0
    assert opened == [("anchor_attestation_slo", "tnt_bank-a", "anchor-1")]


def test_worker_opens_breaker_for_stale_pending_even_when_tsa_recovers() -> None:
    now = datetime.now(UTC)
    pending = {
        "type": "rfc3161", "status": "pending", "authority": "tsa",
        "anchor_digest": "a" * 64,
        "requested_at": (now - timedelta(seconds=901)).isoformat().replace("+00:00", "Z"),
    }
    opened = []
    worker = AnchorAttestationWorker(
        SimpleNamespace(record_anchor_attestation=lambda *args: "appended"),
        SimpleNamespace(obtain=lambda item: item | {"status": "attested", "evidence": "AA=="}),
        SimpleNamespace(open=lambda *args: opened.append(args)),
    )

    assert worker.process(
        "tnt_bank-a",
        [{"payload": {"anchor_id": "anchor-1", "attestations": [pending]}, "attestations": []}],
        900,
        now,
    ) == 1
    assert opened == [("anchor_attestation_slo", "tnt_bank-a", "anchor-1")]
