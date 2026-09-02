"""T-135 defects: the exported bundle version, and the presence of `external_proofs`.

Three separate failures, each with its own test here:

1. The exporter hardcoded `bundle_version: "1.0"` while every ADR_Record became schema 1.3 and
   started carrying `external_proofs`. Both offline verifiers refuse a record that carries the
   member unless the bundle declares 1.1, so every bundle Mizan exported was MALFORMED.
2. Both verifiers returned early when `external_proofs` was absent, so a producer that silently
   dropped the array from a schema-1.3 record passed verification. Absence has to be a grammar
   failure or the required member is not required.
3. An unreadable `--memtara-trust-root` is the operator's mistake, not the bundle's. The Python
   CLI routed it through the bundle loader and answered MALFORMED, which accuses the evidence of
   a defect that lives on the command line.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import rfc8785
from cryptography.hazmat.primitives import serialization
from mizan_control_plane.canonical import canonical_hash
from mizan_control_plane.evidence import Ed25519EvidenceSigner, LocalImmutableObjectStore
from mizan_control_plane.evidence_export import export_evidence_bundle

from scripts.verify_evidence_export import MalformedBundle, verify_bundle
from tests.unit.test_evidence_export import ExportRepository

EXTERNAL_PROOF = {
    "issuer": "https://memtara.example/issuer",
    "proof_hash": "a" * 64,
    "jti": "memtara-proof-0001",
    "memtara_chain_head": "b" * 64,
    "token": "eyJhbGciOiJFZERTQSIsImtpZCI6ImsxIn0.eyJ2ZXJpZmllZCI6dHJ1ZX0.c2ln",
}


def export_bundle(root: Path, *, record_extra: dict | None = None, count: int = 2) -> Path:
    """A minimal single-anchor bundle whose records carry whatever `record_extra` says.

    Deliberately not `test_evidence_export.build_bundle`: what is under test here is what the
    exporter writes into the manifest *because of* a record member, so the record member has to
    be a parameter of the fixture rather than a constant inside it.
    """
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
        } | (record_extra or {})
        record["record_hash"] = canonical_hash(record)
        records.append(record)
        previous = record["record_hash"]
    object_key = f"segments/tnt_bank-a/export/0-{count - 1}.json"
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
    anchor_payload = {
        "anchor_id": "018f47a6-7b42-7c00-8000-000000000000",
        "tenant_id": "tnt_bank-a",
        "stream_id": "tnt_bank-a:adr:0",
        "anchor_number": 0,
        "prev_anchor_hash": "0" * 64,
        "from_sequence": 0,
        "to_sequence": count - 1,
        "covered_record_count": count,
        "head_hash": records[-1]["record_hash"],
        "key_id": anchor_signer.key_id,
        "anchored_at": "2026-08-25T00:00:00Z",
        "object_key": f"anchors/tnt_bank-a/export/{count - 1}.json",
        "object_version": "fixture-version",
        "attestations": [{
            "type": "none_development",
            "status": "unattested",
            "authority": "development",
            "obtained_at": None,
            "evidence": None,
        }],
    }
    anchor_rows = [{"payload": anchor_payload, "signature": anchor_signer.sign(anchor_payload)}]
    key_documents = [
        {
            "key_id": item.key_id,
            "role": role,
            "custody": "development-derived",
            "algorithm": "Ed25519",
            "public_key": base64.urlsafe_b64encode(item.public_key.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )).decode(),
            "not_before": "2026-08-24T00:00:00Z",
            "not_after": None,
            "revoked_at": None,
        }
        for role, item in (
            ("evidence-receipt", receipt_signer),
            ("evidence-anchor", anchor_signer),
        )
    ]
    return export_evidence_bundle(
        ExportRepository(receipts, anchor_rows),
        store,
        {
            receipt_signer.key_id: receipt_signer.public_key,
            anchor_signer.key_id: anchor_signer.public_key,
        },
        "tnt_bank-a",
        "tnt_bank-a:adr:0",
        root / "bundle",
        key_documents=key_documents,
        development_custody_reason="unit test fixture",
    )


def manifest_of(bundle: Path) -> dict:
    return json.loads((bundle / "manifest.json").read_bytes())


def test_a_bundle_carrying_external_proofs_declares_the_version_that_permits_them(
    tmp_path: Path,
) -> None:
    """Otherwise Mizan exports a bundle that its own verifiers refuse."""
    bundle = export_bundle(
        tmp_path,
        record_extra={"schema_version": "1.3", "external_proofs": [EXTERNAL_PROOF]},
    )
    assert manifest_of(bundle)["bundle_version"] == "1.1"


def test_a_bundle_without_external_proofs_still_declares_1_0(tmp_path: Path) -> None:
    """The bump is adaptive: a proof-free history stays readable by a 1.0-only verifier."""
    bundle = export_bundle(tmp_path)
    assert manifest_of(bundle)["bundle_version"] == "1.0"


def test_a_schema_1_3_record_without_external_proofs_is_malformed(tmp_path: Path) -> None:
    """The member is required by SPEC for schema 1.3, so dropping it must be caught."""
    bundle = export_bundle(tmp_path, record_extra={"schema_version": "1.3"})
    with pytest.raises(MalformedBundle, match="external_proofs"):
        verify_bundle(bundle)


def test_an_unreadable_memtara_trust_root_is_a_usage_error_not_a_malformed_bundle(
    tmp_path: Path,
) -> None:
    """The operator named a file that is not there. The bundle did nothing wrong."""
    bundle = export_bundle(
        tmp_path,
        record_extra={"schema_version": "1.3", "external_proofs": [EXTERNAL_PROOF]},
    )
    # Pinned rather than assumed, so this test stays about the trust-root path even if the
    # exporter's version rule changes. The manifest's own digest is not one of `files`.
    manifest = manifest_of(bundle)
    manifest["bundle_version"] = "1.1"
    (bundle / "manifest.json").write_bytes(rfc8785.dumps(manifest))
    verifier = os.getenv("MIZAN_TEST_VERIFIER", "scripts/verify_evidence_export.py")
    result = subprocess.run(
        [
            sys.executable, verifier, str(bundle),
            "--memtara-trust-root", str(tmp_path / "absent.jwks.json"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    # argparse's exit status for a bad invocation, which is what this CLI already uses.
    assert result.returncode == 2
    assert "MALFORMED" not in result.stderr
    assert "usage:" in result.stderr
    assert "--memtara-trust-root" in result.stderr
