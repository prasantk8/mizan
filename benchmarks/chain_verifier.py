from __future__ import annotations

import json
import time
from typing import Any

import rfc8785
from mizan_control_plane.canonical import canonical_hash
from mizan_control_plane.evidence import (
    Ed25519EvidenceSigner,
    ObjectEvidenceVerifier,
    canonical_hash_bytes,
)

RECORDS = 100_000
SEGMENT_SIZE = 1_000
CHECKPOINT_INTERVAL = 1_000
WORKERS = 4
TENANT = "tnt_bank-a"
STREAM = "tnt_bank-a:audit:perf"


class MemoryStore:
    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}

    def put(self, key: str, payload: bytes) -> str:
        self.objects[key] = payload
        return canonical_hash({"key": key, "payload_sha256": canonical_hash_bytes(payload)})

    def get(self, key: str) -> bytes:
        return self.objects[key]


class FixtureRepository:
    def __init__(self, receipts: list[dict[str, Any]], anchors: list[dict[str, Any]]) -> None:
        self.receipts = receipts
        self.anchor_rows = anchors

    def receipt_rows(
        self,
        tenant_id: str,
        stream_id: str,
        start: int | None = None,
        end: int | None = None,
    ) -> list[dict[str, Any]]:
        return [
            row
            for row in self.receipts
            if (start is None or row["payload"]["sequence_number"] >= start)
            and (end is None or row["payload"]["sequence_number"] <= end)
        ]

    def anchors(self, tenant_id: str, stream_id: str) -> list[dict[str, Any]]:
        return self.anchor_rows


def fixture() -> tuple[FixtureRepository, MemoryStore, Ed25519EvidenceSigner]:
    signer = Ed25519EvidenceSigner.generate("local://benchmark/evidence-1")
    store = MemoryStore()
    receipts: list[dict[str, Any]] = []
    previous = "0" * 64
    for start in range(0, RECORDS, SEGMENT_SIZE):
        records: list[dict[str, Any]] = []
        for sequence in range(start, min(start + SEGMENT_SIZE, RECORDS)):
            document = {
                "tenant_id": TENANT,
                "stream_id": STREAM,
                "sequence_number": sequence,
                "prev_hash": previous,
                "event_type": "benchmark",
                "payload": {"fixture": sequence},
            }
            document["record_hash"] = canonical_hash(document)
            records.append(document)
            previous = document["record_hash"]
        key = f"segments/{TENANT}/perf/{start:020d}-{records[-1]['sequence_number']:020d}.json"
        version = store.put(key, rfc8785.dumps(records))
        for document in records:
            payload = {
                "tenant_id": TENANT,
                "stream_id": STREAM,
                "sequence_number": document["sequence_number"],
                "record_hash": document["record_hash"],
                "object_key": key,
                "object_version": version,
                "key_id": signer.key_id,
            }
            receipts.append({"payload": payload, "signature": signer.sign(payload)})
    unsigned_anchor = {
        "anchor_id": "benchmark-anchor",
        "tenant_id": TENANT,
        "stream_id": STREAM,
        "from_sequence": 0,
        "to_sequence": RECORDS - 1,
        "head_hash": previous,
        "key_id": signer.key_id,
        "anchored_at": "2026-08-25T00:00:00Z",
    }
    anchor_key = f"anchors/{TENANT}/perf/{RECORDS - 1:020d}.json"
    anchor_version = store.put(anchor_key, rfc8785.dumps(unsigned_anchor))
    anchor = unsigned_anchor | {"object_key": anchor_key, "object_version": anchor_version}
    repository = FixtureRepository(
        receipts, [{"payload": anchor, "signature": signer.sign(anchor)}]
    )
    return repository, store, signer


def main() -> int:
    repository, store, signer = fixture()
    verifier = ObjectEvidenceVerifier(
        repository,
        store,
        {signer.key_id: signer.public_key},
        checkpoint_interval=CHECKPOINT_INTERVAL,
        workers=WORKERS,
    )
    started = time.perf_counter()
    result = verifier.verify(TENANT, STREAM)
    elapsed = time.perf_counter() - started
    report = {
        "records": RECORDS,
        "segments": RECORDS // SEGMENT_SIZE,
        "checkpoints": RECORDS // CHECKPOINT_INTERVAL,
        "workers": WORKERS,
        "valid": result.valid,
        "checked_records": result.checked_records,
        "verification_seconds": round(elapsed, 4),
        "records_per_second": round(RECORDS / elapsed, 2),
        "target_seconds": 10,
    }
    print(json.dumps(report, sort_keys=True))
    return 0 if result.valid and result.checked_records == RECORDS and elapsed < 10 else 1


if __name__ == "__main__":
    raise SystemExit(main())
