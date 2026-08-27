from __future__ import annotations

import json
import os
import time
from typing import Any

import rfc8785
from mizan_control_plane.canonical import canonical_hash
from mizan_control_plane.evidence import (
    Ed25519EvidenceSigner,
    ObjectEvidenceVerifier,
    canonical_hash_bytes,
)

from benchmarks.artifacts import write_artifact

RECORDS = 100_000
SEGMENT_SIZE = 1_000
CHECKPOINT_INTERVAL = 1_000
WORKERS = 4
TENANT = "tnt_bank-a"
STREAM = "tnt_bank-a:audit:perf"

# R-008 F-9, founder ruling 2026-08-27: "could be any machine." There is no reference
# hardware, so the budget is set from the slowest machine we have measured and not from the
# fastest. The 10 s it used to be was calibrated on a sixteen-core Apple-silicon laptop that
# does 15,637 records/second; the four-core CI runner does 6,630 and took 15.081 s. Those two
# machines differ by 2.36x and the old target sat between them, so the gate was measuring the
# machine.
#
# This number is a regression tripwire, not a performance claim. It is wide enough that the
# slowest machine we support clears it and narrow enough that a change halving throughput
# trips it. The claim is `records_per_second` beside the host that produced it, in the
# artifact. Do not quote the budget as a result.
SLOWEST_MEASURED_SECONDS = 15.081
BUDGET_SECONDS = float(os.environ.get("MIZAN_CHAIN_VERIFIER_BUDGET_SECONDS", "35"))
BUDGET_BASIS = (
    "2x the slowest run measured to date (15.081 s / 6,630 records per second on a four-core "
    "ubuntu-latest GitHub runner, R-008 F-9), rounded up: 35 s. A regression tripwire, not a "
    "performance claim; the claim is records_per_second beside `host` in this artifact."
)


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


def fixture() -> tuple[
    FixtureRepository, MemoryStore, Ed25519EvidenceSigner, Ed25519EvidenceSigner
]:
    receipt_signer = Ed25519EvidenceSigner.development("evidence-receipt")
    anchor_signer = Ed25519EvidenceSigner.development("evidence-anchor")
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
                "key_id": receipt_signer.key_id,
            }
            receipts.append({"payload": payload, "signature": receipt_signer.sign(payload)})
    unsigned_anchor = {
        "anchor_id": "benchmark-anchor",
        "tenant_id": TENANT,
        "stream_id": STREAM,
        "anchor_number": 0,
        "prev_anchor_hash": "0" * 64,
        "from_sequence": 0,
        "to_sequence": RECORDS - 1,
        "covered_record_count": RECORDS,
        "head_hash": previous,
        "key_id": anchor_signer.key_id,
        "anchored_at": "2026-08-25T00:00:00Z",
    }
    anchor_key = f"anchors/{TENANT}/perf/{RECORDS - 1:020d}.json"
    anchor_version = store.put(anchor_key, rfc8785.dumps(unsigned_anchor))
    anchor = unsigned_anchor | {"object_key": anchor_key, "object_version": anchor_version}
    repository = FixtureRepository(
        receipts, [{"payload": anchor, "signature": anchor_signer.sign(anchor)}]
    )
    return repository, store, receipt_signer, anchor_signer


def main() -> int:
    repository, store, receipt_signer, anchor_signer = fixture()
    verifier = ObjectEvidenceVerifier(
        repository,
        store,
        {
            receipt_signer.key_id: receipt_signer.public_key,
            anchor_signer.key_id: anchor_signer.public_key,
        },
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
        "budget_seconds": BUDGET_SECONDS,
        "budget_basis": BUDGET_BASIS,
    }
    print(json.dumps(report, sort_keys=True))
    write_artifact(
        "chain-verifier",
        report,
        {
            "records": RECORDS,
            "segment_size": SEGMENT_SIZE,
            "checkpoint_interval": CHECKPOINT_INTERVAL,
            "workers": WORKERS,
        },
    )
    correct = result.valid and result.checked_records == RECORDS
    return 0 if correct and elapsed < BUDGET_SECONDS else 1


if __name__ == "__main__":
    raise SystemExit(main())
