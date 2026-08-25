from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .evidence import ChainCheckpoint, EvidenceRepository, LocalImmutableObjectStore

BUNDLE_FILES = ("records.json", "receipts.json", "anchors.json", "checkpoints.json", "keys.json")


def load_public_keyset(path: Path) -> tuple[dict[str, Ed25519PublicKey], list[dict[str, Any]]]:
    """Load the public verification-key document published by Mizan."""
    documents = json.loads(path.read_bytes())
    if not isinstance(documents, list) or not documents:
        raise ValueError("verification keyset must be a non-empty JSON array")
    keys: dict[str, Ed25519PublicKey] = {}
    for document in documents:
        if document.get("algorithm") != "Ed25519":
            raise ValueError(f"unsupported key algorithm for {document.get('key_id')}")
        key_id = document.get("key_id")
        if not isinstance(key_id, str) or key_id in keys:
            raise ValueError("verification key IDs must be unique strings")
        keys[key_id] = Ed25519PublicKey.from_public_bytes(
            base64.urlsafe_b64decode(document["public_key"])
        )
    return keys, documents


def _write(path: Path, value: Any) -> str:
    payload = rfc8785.dumps(value)
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def export_evidence_bundle(
    repository: Any,
    store: LocalImmutableObjectStore,
    public_keys: dict[str, Ed25519PublicKey],
    tenant_id: str,
    stream_id: str,
    target: Path,
    start: int | None = None,
    end: int | None = None,
    checkpoint_interval: int = 1000,
    key_documents: list[dict[str, Any]] | None = None,
) -> Path:
    """Export authoritative object evidence; Postgres record documents are not trusted."""
    target.mkdir(parents=True, exist_ok=False)
    receipts = repository.receipt_rows(tenant_id, stream_id, start, end)
    records_by_sequence: dict[int, dict[str, Any]] = {}
    for receipt in receipts:
        payload = receipt["payload"]
        raw = store.get(payload["object_key"])
        stored = json.loads(raw)
        candidates = stored if isinstance(stored, list) else [stored]
        matches = [
            record for record in candidates
            if record["sequence_number"] == payload["sequence_number"]
            and record["record_hash"] == payload["record_hash"]
        ]
        if len(matches) != 1 or payload["sequence_number"] in records_by_sequence:
            raise ValueError(f"receipt/object mismatch at sequence {payload['sequence_number']}")
        records_by_sequence[payload["sequence_number"]] = matches[0]
    records = [records_by_sequence[index] for index in sorted(records_by_sequence)]
    if not records:
        raise ValueError("cannot export an empty evidence range")
    range_start = records[0]["sequence_number"]
    range_end = records[-1]["sequence_number"]
    checkpoints = []
    for offset in range(0, len(records), checkpoint_interval):
        group = records[offset : offset + checkpoint_interval]
        checkpoint = ChainCheckpoint(
            group[0]["sequence_number"],
            group[-1]["sequence_number"],
            group[0]["prev_hash"],
            group[-1]["record_hash"],
        )
        checkpoints.append(
            {
                "from_sequence": checkpoint.from_sequence,
                "to_sequence": checkpoint.to_sequence,
                "expected_previous": checkpoint.expected_previous,
                "head_hash": checkpoint.head_hash,
            }
        )
    keys = key_documents or [
        {
            "key_id": key_id,
            "algorithm": "Ed25519",
            "public_key": base64.urlsafe_b64encode(
                key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            ).decode(),
        }
        for key_id, key in sorted(public_keys.items())
    ]
    documents = {
        "records.json": records,
        "receipts.json": receipts,
        "anchors.json": repository.anchors(tenant_id, stream_id),
        "checkpoints.json": checkpoints,
        "keys.json": keys,
    }
    file_hashes = {name: _write(target / name, value) for name, value in documents.items()}
    manifest = {
        "bundle_version": "1.0",
        "canonicalization": "RFC8785",
        "hash_algorithm": "SHA-256",
        "tenant_id": tenant_id,
        "stream_id": stream_id,
        "range": {"from_sequence": range_start, "to_sequence": range_end},
        "files": file_hashes,
        "assurance": {
            "anchor_attestation": "mizan_self_signed",
            "external_timestamp": False,
        },
    }
    _write(target / "manifest.json", manifest)
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export a self-contained Mizan evidence bundle")
    parser.add_argument("--database-url", required=True, help="PostgreSQL runtime-role DSN")
    parser.add_argument("--object-store", required=True, type=Path, help="Immutable object-store root")
    parser.add_argument("--keyset", required=True, type=Path, help="Published verification keyset JSON")
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--stream-id", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--from-sequence", type=int)
    parser.add_argument("--to-sequence", type=int)
    parser.add_argument("--checkpoint-interval", type=int, default=1000)
    args = parser.parse_args(argv)
    if args.checkpoint_interval < 1:
        parser.error("--checkpoint-interval must be positive")
    repository = EvidenceRepository(args.database_url)
    try:
        public_keys, key_documents = load_public_keyset(args.keyset)
        target = export_evidence_bundle(
            repository,
            LocalImmutableObjectStore(args.object_store),
            public_keys,
            args.tenant_id,
            args.stream_id,
            args.output,
            start=args.from_sequence,
            end=args.to_sequence,
            checkpoint_interval=args.checkpoint_interval,
            key_documents=key_documents,
        )
    finally:
        repository.pool.close()
    print(target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
