from __future__ import annotations

import json
import time

from mizan_control_plane.canonical import canonical_hash
from mizan_control_plane.evidence import ChainCheckpoint, verify_checkpointed_chain

RECORDS = 100_000
CHECKPOINT_INTERVAL = 1_000
WORKERS = 4


def fixture() -> tuple[list[dict], list[ChainCheckpoint]]:
    records: list[dict] = []
    checkpoints: list[ChainCheckpoint] = []
    previous = "0" * 64
    for start in range(0, RECORDS, CHECKPOINT_INTERVAL):
        expected_previous = previous
        end = min(start + CHECKPOINT_INTERVAL, RECORDS)
        for sequence in range(start, end):
            document = {
                "tenant_id": "tnt_bank-a",
                "stream_id": "tnt_bank-a:audit:perf",
                "sequence_number": sequence,
                "prev_hash": previous,
                "event_type": "benchmark",
                "payload": {"fixture": sequence},
            }
            document["record_hash"] = canonical_hash(document)
            records.append(document)
            previous = document["record_hash"]
        checkpoints.append(ChainCheckpoint(start, end - 1, expected_previous, previous))
    return records, checkpoints


def main() -> int:
    records, checkpoints = fixture()
    started = time.perf_counter()
    result = verify_checkpointed_chain(records, checkpoints, workers=WORKERS)
    elapsed = time.perf_counter() - started
    report = {
        "records": RECORDS,
        "checkpoints": len(checkpoints),
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
