from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import rfc8785
from mizan_control_plane.canonical import canonical_hash
from mizan_control_plane.evidence import Ed25519EvidenceSigner, LocalImmutableObjectStore
from mizan_control_plane.evidence_export import export_evidence_bundle


class ExportRepository:
    def __init__(self, receipts: list[dict], anchors: list[dict]) -> None:
        self.receipts = receipts
        self.anchor_rows = anchors

    def receipt_rows(self, tenant_id, stream_id, start=None, end=None):
        return self.receipts

    def anchors(self, tenant_id, stream_id):
        return self.anchor_rows


def build_bundle(root: Path, count: int = 4) -> Path:
    signer = Ed25519EvidenceSigner.generate("local://evidence/export-test")
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
            "key_id": signer.key_id,
        }
        receipts.append({"payload": payload, "signature": signer.sign(payload)})
    anchor_payload = {
        "anchor_id": "018f47a6-7b42-7c00-8000-00000000abcd",
        "tenant_id": "tnt_bank-a",
        "stream_id": "tnt_bank-a:adr:0",
        "anchor_number": 0,
        "prev_anchor_hash": "0" * 64,
        "from_sequence": 0,
        "to_sequence": count - 1,
        "covered_record_count": count,
        "head_hash": records[-1]["record_hash"],
        "key_id": signer.key_id,
        "anchored_at": "2026-08-25T00:00:00Z",
        "object_key": "anchors/tnt_bank-a/export/3.json",
        "object_version": "fixture-version",
    }
    repository = ExportRepository(
        receipts,
        [{"payload": anchor_payload, "signature": signer.sign(anchor_payload)}],
    )
    return export_evidence_bundle(
        repository,
        store,
        {signer.key_id: signer.public_key},
        "tnt_bank-a",
        "tnt_bank-a:adr:0",
        root / "bundle",
        checkpoint_interval=2,
    )


def refresh_manifest(bundle: Path, name: str) -> None:
    manifest = json.loads((bundle / "manifest.json").read_bytes())
    manifest["files"][name] = hashlib.sha256((bundle / name).read_bytes()).hexdigest()
    (bundle / "manifest.json").write_bytes(rfc8785.dumps(manifest))


def run_verifier(bundle: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "scripts/verify_evidence_export.py", str(bundle)],
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
