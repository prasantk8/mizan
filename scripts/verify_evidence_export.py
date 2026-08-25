#!/usr/bin/env python3
# Install: python -m pip install rfc8785==0.1.4 cryptography==50.0.0
"""Standalone Mizan evidence verifier: no control-plane, database, or network dependency."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

FILES = ("records.json", "receipts.json", "anchors.json", "checkpoints.json", "keys.json")
ZERO_HASH = "0" * 64


class VerificationFailure(ValueError):
    pass


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationFailure(f"{path.name} is missing or malformed: {exc}") from exc


def verify_signature(payload: dict[str, Any], signature: str, key: Ed25519PublicKey, label: str) -> None:
    try:
        key.verify(base64.urlsafe_b64decode(signature), rfc8785.dumps(payload))
    except Exception as exc:
        raise VerificationFailure(f"{label} signature is invalid") from exc


def verify_bundle(bundle: Path) -> dict[str, Any]:
    manifest = load_json(bundle / "manifest.json")
    if manifest.get("bundle_version") != "1.0":
        raise VerificationFailure("manifest bundle_version is unsupported")
    if set(manifest.get("files", {})) != set(FILES):
        raise VerificationFailure("manifest file inventory is incomplete or contains unknown files")
    for name in FILES:
        path = bundle / name
        try:
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as exc:
            raise VerificationFailure(f"{name} is missing") from exc
        if actual != manifest["files"][name]:
            raise VerificationFailure(f"{name} checksum mismatch")

    records = load_json(bundle / "records.json")
    receipts = load_json(bundle / "receipts.json")
    anchors = load_json(bundle / "anchors.json")
    checkpoints = load_json(bundle / "checkpoints.json")
    key_documents = load_json(bundle / "keys.json")
    if not records:
        raise VerificationFailure("record set is empty")
    keys: dict[str, Ed25519PublicKey] = {}
    for item in key_documents:
        if item.get("algorithm") != "Ed25519":
            raise VerificationFailure(f"key {item.get('key_id')} uses an unsupported algorithm")
        try:
            keys[item["key_id"]] = Ed25519PublicKey.from_public_bytes(
                base64.urlsafe_b64decode(item["public_key"])
            )
        except Exception as exc:
            raise VerificationFailure(f"key {item.get('key_id')} is malformed") from exc

    range_start = manifest["range"]["from_sequence"]
    range_end = manifest["range"]["to_sequence"]
    previous = ZERO_HASH if range_start == 0 else records[0].get("prev_hash")
    for offset, record in enumerate(records):
        sequence = range_start + offset
        if record.get("sequence_number") != sequence:
            raise VerificationFailure(
                f"record order mismatch: expected sequence {sequence}, got {record.get('sequence_number')}"
            )
        if record.get("prev_hash") != previous:
            raise VerificationFailure(f"record chain previous-hash mismatch at sequence {sequence}")
        actual_hash = canonical_hash({key: value for key, value in record.items() if key != "record_hash"})
        if actual_hash != record.get("record_hash"):
            raise VerificationFailure(f"record hash mismatch at sequence {sequence}")
        previous = record["record_hash"]
    if records[-1]["sequence_number"] != range_end:
        raise VerificationFailure("record range does not reach the manifest terminal sequence")

    receipt_by_sequence: dict[int, dict[str, Any]] = {}
    for receipt in receipts:
        payload = receipt.get("payload", {})
        sequence = payload.get("sequence_number")
        if sequence in receipt_by_sequence:
            raise VerificationFailure(f"duplicate receipt at sequence {sequence}")
        key = keys.get(payload.get("key_id"))
        if key is None:
            raise VerificationFailure(f"receipt key is unavailable at sequence {sequence}")
        verify_signature(payload, receipt.get("signature", ""), key, f"receipt {sequence}")
        receipt_by_sequence[sequence] = payload
    for record in records:
        sequence = record["sequence_number"]
        receipt = receipt_by_sequence.get(sequence)
        if receipt is None:
            raise VerificationFailure(f"receipt coverage missing at sequence {sequence}")
        if (
            receipt.get("tenant_id") != manifest["tenant_id"]
            or receipt.get("stream_id") != manifest["stream_id"]
            or receipt.get("record_hash") != record["record_hash"]
        ):
            raise VerificationFailure(f"receipt binding mismatch at sequence {sequence}")

    expected_anchor_previous = ZERO_HASH
    expected_anchor_from = 0
    if not anchors:
        raise VerificationFailure("anchor set is empty")
    for expected_anchor_number, row in enumerate(anchors):
        payload = row.get("payload", {})
        number = payload.get("anchor_number")
        if number != expected_anchor_number:
            raise VerificationFailure(
                f"anchor number gap: expected {expected_anchor_number}, got {number}"
            )
        if payload.get("prev_anchor_hash") != expected_anchor_previous:
            raise VerificationFailure(f"anchor previous-hash mismatch at anchor {number}")
        if payload.get("from_sequence") != expected_anchor_from:
            raise VerificationFailure(f"anchor range gap at anchor {number}")
        declared = payload.get("covered_record_count")
        if declared != payload.get("to_sequence") - payload.get("from_sequence") + 1:
            raise VerificationFailure(f"anchor covered-record count is inconsistent at anchor {number}")
        key = keys.get(payload.get("key_id"))
        if key is None:
            raise VerificationFailure(f"anchor key is unavailable at anchor {number}")
        verify_signature(payload, row.get("signature", ""), key, f"anchor {number}")
        expected_anchor_from = payload["to_sequence"] + 1
        expected_anchor_previous = canonical_hash(payload)
    if anchors[-1]["payload"]["to_sequence"] != range_end:
        raise VerificationFailure(
            f"stale terminal anchor: ends at {anchors[-1]['payload']['to_sequence']}, records end at {range_end}"
        )
    if anchors[-1]["payload"].get("head_hash") != records[-1]["record_hash"]:
        raise VerificationFailure("terminal anchor head does not match the terminal record")

    expected_checkpoint_from = range_start
    for index, checkpoint in enumerate(checkpoints):
        if checkpoint.get("from_sequence") != expected_checkpoint_from:
            raise VerificationFailure(f"checkpoint range gap at checkpoint {index}")
        selected = [
            record for record in records
            if checkpoint["from_sequence"] <= record["sequence_number"] <= checkpoint["to_sequence"]
        ]
        if not selected or selected[0]["prev_hash"] != checkpoint.get("expected_previous"):
            raise VerificationFailure(f"checkpoint previous-hash mismatch at checkpoint {index}")
        if selected[-1]["record_hash"] != checkpoint.get("head_hash"):
            raise VerificationFailure(f"checkpoint head mismatch at checkpoint {index}")
        expected_checkpoint_from = checkpoint["to_sequence"] + 1
    if expected_checkpoint_from != range_end + 1:
        raise VerificationFailure("checkpoint coverage does not reach the terminal record")

    return {
        "records": len(records),
        "from_sequence": range_start,
        "to_sequence": range_end,
        "anchors": len(anchors),
        "anchor_attestation": manifest["assurance"]["anchor_attestation"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a self-contained Mizan evidence bundle")
    parser.add_argument("bundle", type=Path)
    args = parser.parse_args()
    try:
        result = verify_bundle(args.bundle)
    except VerificationFailure as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(
        "PASS: The exported records, receipts, checkpoints, and complete anchor chain verified "
        f"for sequences {result['from_sequence']} through {result['to_sequence']} "
        f"({result['records']} records, {result['anchors']} anchors)."
    )
    print("WHAT THIS CHECKED: File integrity, record ordering/hash links, signed receipt coverage, and signed anchor continuity.")
    print("LIMITATION: The anchor signature is Mizan's own. No independent timestamp authority is present, so a party holding Mizan's database and signing key could rebuild and re-sign this history.")
    print("NOT COVERED: Records omitted before chaining and an entire final anchor withheld before export leave no proof in this bundle.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
