from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import rfc8785
from cryptography.hazmat.primitives import serialization
from mizan_control_plane.canonical import canonical_hash
from mizan_control_plane.evidence import Ed25519EvidenceSigner, LocalImmutableObjectStore
from mizan_control_plane.evidence_export import export_evidence_bundle


class ExportRepository:
    def __init__(self, receipts: list[dict], anchors: list[dict]) -> None:
        self.receipts = receipts
        self.anchor_rows = anchors

    def receipt_rows(self, tenant_id, stream_id, start=None, end=None):
        return [
            row
            for row in self.receipts
            if (start is None or row["payload"]["sequence_number"] >= start)
            and (end is None or row["payload"]["sequence_number"] <= end)
        ]

    def anchors(self, tenant_id, stream_id):
        return self.anchor_rows


def build_bundle(
    root: Path,
    count: int = 4,
    *,
    anchor_interval: int | None = None,
    anchor_head_overrides: dict[int, str] | None = None,
    export_start: int | None = None,
    include_attestations: bool = True,
    revoked_receipt_at: str | None = None,
) -> Path:
    receipt_signer = Ed25519EvidenceSigner.development("evidence-receipt")
    anchor_signer = Ed25519EvidenceSigner.development("evidence-anchor")
    store = LocalImmutableObjectStore(root / "objects")
    records: list[dict] = []
    previous = "0" * 64
    for sequence in range(count):
        record = {
            "tenant_id": "tnt_bank-a",
            "stream_id": "tnt_bank-a:adr:0",
            "sequence_number": sequence,
            "prev_hash": previous,
            "value": f"record-{sequence}",
        }
        record["record_hash"] = canonical_hash(record)
        records.append(record)
        previous = record["record_hash"]
    object_key = "segments/tnt_bank-a/export/0-3.json"
    object_version = store.put_once(object_key, rfc8785.dumps(records))
    receipts = []
    for record in records:
        payload = {
            "tenant_id": "tnt_bank-a",
            "stream_id": "tnt_bank-a:adr:0",
            "sequence_number": record["sequence_number"],
            "record_hash": record["record_hash"],
            "object_key": object_key,
            "object_version": object_version,
            "key_id": receipt_signer.key_id,
        }
        receipts.append({"payload": payload, "signature": receipt_signer.sign(payload)})
    anchor_interval = anchor_interval or count
    anchor_head_overrides = anchor_head_overrides or {}
    anchor_rows = []
    previous_anchor_hash = "0" * 64
    for anchor_number, from_sequence in enumerate(range(0, count, anchor_interval)):
        to_sequence = min(from_sequence + anchor_interval - 1, count - 1)
        anchor_payload = {
            "anchor_id": f"018f47a6-7b42-7c00-8000-{anchor_number:012d}",
            "tenant_id": "tnt_bank-a",
            "stream_id": "tnt_bank-a:adr:0",
            "anchor_number": anchor_number,
            "prev_anchor_hash": previous_anchor_hash,
            "from_sequence": from_sequence,
            "to_sequence": to_sequence,
            "covered_record_count": to_sequence - from_sequence + 1,
            "head_hash": anchor_head_overrides.get(
                anchor_number, records[to_sequence]["record_hash"]
            ),
            "key_id": anchor_signer.key_id,
            "anchored_at": "2026-08-25T00:00:00Z",
            "object_key": f"anchors/tnt_bank-a/export/{to_sequence}.json",
            "object_version": "fixture-version",
        }
        if include_attestations:
            anchor_payload["attestations"] = [{
                "type": "none_development",
                "status": "unattested",
                "authority": "development",
                "obtained_at": None,
                "evidence": None,
            }]
        anchor_rows.append({"payload": anchor_payload, "signature": anchor_signer.sign(anchor_payload)})
        previous_anchor_hash = canonical_hash(anchor_payload)
    repository = ExportRepository(receipts, anchor_rows)
    key_documents = [
        {
            "key_id": item.key_id,
            "role": role,
            "algorithm": "Ed25519",
            "public_key": base64.urlsafe_b64encode(item.public_key.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )).decode(),
            "not_before": "2026-08-24T00:00:00Z",
            "not_after": "2026-08-25T00:00:00Z" if role == "evidence-receipt" and revoked_receipt_at else None,
            "revoked_at": revoked_receipt_at if role == "evidence-receipt" else None,
        }
        for role, item in (
            ("evidence-receipt", receipt_signer),
            ("evidence-anchor", anchor_signer),
        )
    ]
    return export_evidence_bundle(
        repository,
        store,
        {
            receipt_signer.key_id: receipt_signer.public_key,
            anchor_signer.key_id: anchor_signer.public_key,
        },
        "tnt_bank-a",
        "tnt_bank-a:adr:0",
        root / "bundle",
        start=export_start,
        checkpoint_interval=2,
        key_documents=key_documents,
    )


def refresh_manifest(bundle: Path, name: str) -> None:
    manifest = json.loads((bundle / "manifest.json").read_bytes())
    manifest["files"][name] = hashlib.sha256((bundle / name).read_bytes()).hexdigest()
    (bundle / "manifest.json").write_bytes(rfc8785.dumps(manifest))


def run_verifier(bundle: Path) -> subprocess.CompletedProcess[str]:
    verifier = os.getenv("MIZAN_TEST_VERIFIER", "scripts/verify_evidence_export.py")
    return subprocess.run(
        [sys.executable, verifier, str(bundle)],
        check=False,
        capture_output=True,
        text=True,
    )


def test_standalone_export_verifies_and_discloses_self_signed_limit(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    result = run_verifier(bundle)
    assert result.returncode == 0
    assert "PASS:" in result.stdout
    assert "anchor signature is Mizan's own" in result.stdout
    assert "holding Mizan's database and signing key" in result.stdout
    assert "unsigned checkpoints were used only as a parallel-verification performance aid" in result.stdout
    assert "ATTESTATION: UNATTESTED" in result.stdout
    source = Path("scripts/verify_evidence_export.py").read_text(encoding="utf-8")
    assert "mizan_control_plane" not in source
    assert "rfc8785==0.1.4 cryptography==50.0.0" in source


def test_record_byte_mutation_is_rejected_with_specific_reason(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    records = json.loads((bundle / "records.json").read_bytes())
    records[1]["value"] = "tampered"
    (bundle / "records.json").write_bytes(rfc8785.dumps(records))
    refresh_manifest(bundle, "records.json")
    result = run_verifier(bundle)
    assert result.returncode == 1
    assert "record hash mismatch at sequence 1" in result.stderr


def test_dropped_receipt_is_rejected_with_specific_reason(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    receipts = json.loads((bundle / "receipts.json").read_bytes())
    receipts.pop(2)
    (bundle / "receipts.json").write_bytes(rfc8785.dumps(receipts))
    refresh_manifest(bundle, "receipts.json")
    result = run_verifier(bundle)
    assert result.returncode == 1
    assert "receipt coverage missing at sequence 2" in result.stderr


def test_removed_anchor_is_rejected_with_specific_reason(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    (bundle / "anchors.json").write_bytes(rfc8785.dumps([]))
    refresh_manifest(bundle, "anchors.json")
    result = run_verifier(bundle)
    assert result.returncode == 1
    assert "anchor set is empty" in result.stderr


def test_swapped_records_are_rejected_with_specific_reason(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    records = json.loads((bundle / "records.json").read_bytes())
    records[1], records[2] = records[2], records[1]
    (bundle / "records.json").write_bytes(rfc8785.dumps(records))
    refresh_manifest(bundle, "records.json")
    result = run_verifier(bundle)
    assert result.returncode == 1
    assert "record order mismatch: expected sequence 1, got 2" in result.stderr


def test_bundle_is_self_contained_after_source_objects_disappear(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    shutil.rmtree(tmp_path / "objects")
    assert run_verifier(bundle).returncode == 0


def test_validly_signed_intermediate_anchor_must_bind_to_its_record(tmp_path: Path) -> None:
    bundle = build_bundle(
        tmp_path,
        count=6,
        anchor_interval=2,
        anchor_head_overrides={1: "f" * 64},
    )
    result = run_verifier(bundle)
    assert result.returncode == 1
    assert "anchor 1 head does not match record 3" in result.stderr


def test_non_genesis_range_is_pinned_by_preceding_anchor(tmp_path: Path) -> None:
    bundle = build_bundle(
        tmp_path,
        count=4,
        anchor_interval=2,
        anchor_head_overrides={0: "e" * 64},
        export_start=2,
    )
    result = run_verifier(bundle)
    assert result.returncode == 1
    assert "left-edge anchor head does not match record 2 previous hash" in result.stderr


def test_pre_provider_anchor_cannot_be_mistaken_for_attested(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path, include_attestations=False)
    result = run_verifier(bundle)
    assert result.returncode == 1
    assert "anchor 0 attestation status is missing" in result.stderr


def test_rotated_revoked_key_signature_is_valid_but_distinctly_reported(tmp_path: Path) -> None:
    revoked_at = "2026-08-25T01:00:00Z"
    bundle = build_bundle(tmp_path, revoked_receipt_at=revoked_at)
    keys = json.loads((bundle / "keys.json").read_bytes())
    assert all(not item["key_id"].endswith("/v2") for item in keys)  # current key is absent
    result = run_verifier(bundle)
    assert result.returncode == 0
    assert f"valid signature, key local://evidence-receipt/dev-1 revoked at {revoked_at}" in result.stdout
