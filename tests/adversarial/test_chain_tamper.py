"""Targeted evidence mutations are named at the first broken link by the HTTP API."""

from __future__ import annotations

from pathlib import Path

import pytest
import rfc8785
from fastapi.testclient import TestClient
from mizan_control_plane import app as app_module
from mizan_control_plane.canonical import canonical_hash
from mizan_control_plane.config import Settings
from mizan_control_plane.dev_token import ensure_keypair, mint
from mizan_control_plane.evidence import (
    Ed25519EvidenceSigner,
    LocalImmutableObjectStore,
    ObjectEvidenceVerifier,
)

from scripts.check_evidence_mutations import mutations

TENANT = "tnt_bank-a"
STREAM = "tnt_bank-a:adr:0"


class _Pool:
    def close(self) -> None:
        pass


class _UnusedRepository:
    def __init__(self, _database_url: str, *_arguments: object) -> None:
        # `*_arguments` because `ApprovalRepository` also takes the deployment's
        # `MIZAN_APPROVAL_EPOCH_EXPIRY` mode; these doubles model no expiry behaviour.
        self.pool = _Pool()


class _EvidenceRows:
    def __init__(self, receipts: list[dict], anchors: list[dict]) -> None:
        self.receipts = receipts
        self.anchor_rows = anchors

    def receipt_rows(self, _tenant_id, _stream_id, start=None, end=None):
        return [
            row
            for row in self.receipts
            if (start is None or row["payload"]["sequence_number"] >= start)
            and (end is None or row["payload"]["sequence_number"] <= end)
        ]

    def anchors(self, _tenant_id, _stream_id):
        return self.anchor_rows


def _low_bit_mutation(value: str) -> str:
    _offset, _operation, changed = next(mutations(value.encode(), [0]))
    return changed.decode()


def _verifier(root: Path, mutation: str) -> ObjectEvidenceVerifier:
    # No swap-in verifier: this always constructs and returns the real
    # ObjectEvidenceVerifier, unconditionally. R-008 F-3 -- a fault injected
    # into a stub class that only ever accepts proves nothing about the guard
    # this test exists to demonstrate; the real fault lives externally, in
    # scripts/adversarial_fault_injection.py, and reverts the actual hash
    # comparison inside verify_chain (evidence.py).
    signer = Ed25519EvidenceSigner.development("evidence-receipt")
    store = LocalImmutableObjectStore(root)
    records: list[dict] = []
    previous = "0" * 64
    for sequence in range(3):
        item = {
            "tenant_id": TENANT,
            "stream_id": STREAM,
            "sequence_number": sequence,
            "prev_hash": previous,
            "value": f"record-{sequence}",
        }
        item["record_hash"] = canonical_hash(item)
        records.append(item)
        previous = item["record_hash"]
    if mutation == "record_body":
        records[1]["value"] = "tampered"
    elif mutation == "prev_hash":
        records[1]["prev_hash"] = "f" * 64
    elif mutation == "sequence_number":
        records[2]["sequence_number"] = 3

    segment_key = f"segments/{mutation}.json"
    segment_version = store.put_once(segment_key, rfc8785.dumps(records))
    receipts = []
    for item in records:
        payload = {
            "tenant_id": TENANT,
            "stream_id": STREAM,
            "sequence_number": item["sequence_number"],
            "record_hash": item["record_hash"],
            "object_key": segment_key,
            "object_version": segment_version,
            "key_id": signer.key_id,
        }
        receipts.append({"payload": payload, "signature": signer.sign(payload)})
    if mutation == "receipt_signature":
        receipts[1]["signature"] = _low_bit_mutation(receipts[1]["signature"])

    unsigned_anchor = {
        "anchor_id": "018f47a6-7b42-7c00-8000-000000000024",
        "tenant_id": TENANT,
        "stream_id": STREAM,
        "anchor_number": 0,
        "prev_anchor_hash": "0" * 64,
        "from_sequence": 0,
        "to_sequence": 2,
        "covered_record_count": 3,
        "head_hash": records[2]["record_hash"],
        "key_id": signer.key_id,
        "anchored_at": "2026-08-27T00:00:00Z",
    }
    if mutation == "anchor":
        unsigned_anchor["head_hash"] = "e" * 64
    anchor_key = f"anchors/{mutation}.json"
    anchor_version = store.put_once(anchor_key, rfc8785.dumps(unsigned_anchor))
    anchor = unsigned_anchor | {
        "object_key": anchor_key,
        "object_version": anchor_version,
    }
    rows = _EvidenceRows(
        receipts,
        [{"payload": anchor, "signature": signer.sign(anchor)}],
    )
    return ObjectEvidenceVerifier(
        rows,
        store,
        {signer.key_id: signer.public_key},
        checkpoint_interval=2,
        workers=2,
    )


@pytest.mark.parametrize(
    ("mutation", "first_broken_sequence"),
    [
        ("record_body", 1),
        ("prev_hash", 1),
        ("sequence_number", 3),
        ("receipt_signature", 1),
        ("anchor", 2),
    ],
)
def test_audit_verify_names_the_first_broken_link(
    monkeypatch,
    tmp_path: Path,
    mutation: str,
    first_broken_sequence: int,
) -> None:
    for repository_name in (
        "PostgresAuthorizationRepository",
        "RegistryRepository",
        "EvidenceRepository",
        "ApprovalRepository",
    ):
        monkeypatch.setattr(app_module, repository_name, _UnusedRepository)
    private_key, public_key = ensure_keypair(tmp_path / "identity")
    monkeypatch.setenv("MIZAN_DATABASE_URL", "postgresql://unused")
    monkeypatch.setenv("MIZAN_JWT_ISSUER", "urn:mizan:development:dev-token")
    monkeypatch.setenv("MIZAN_JWT_PUBLIC_KEY", public_key)
    monkeypatch.setenv("MIZAN_EVIDENCE_OBJECT_STORE_ROOT", str(tmp_path / "unused"))
    application = app_module.create_app(
        Settings.from_environment(),
        evidence_verifier=_verifier(tmp_path / "objects", mutation),
    )
    token = mint(
        private_key,
        tenant_id=TENANT,
        subject="prn_adversarial",
        agent_id="agt_wealth-01",
        identity_kind="human",
        auth_strength="hardware",
        roles=["auditor"],
        audience="mizan-control-plane",
        ttl_seconds=300,
    )
    with TestClient(application) as client:
        response = client.post(
            "/v1/audit/verify",
            json={"stream_id": STREAM, "verify_anchors": True},
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 409
    assert response.json()["type"].endswith("evidence_chain_broken")
    assert f"Sequence {first_broken_sequence}:" in response.json()["detail"]
