from __future__ import annotations

import hashlib
import json
import os
import statistics
import time
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import psycopg

from benchmarks.artifacts import write_artifact

TENANT = "tnt_bank-a"
SHARDS = 4
OPERATIONS_PER_SHARD = 500


def run_shard(database_url: str, shard: int, barrier: Barrier) -> list[float]:
    stream = f"{TENANT}:audit:bench{shard}"
    previous = "0" * 64
    samples: list[float] = []
    with psycopg.connect(database_url) as connection:
        with connection.transaction():
            connection.execute("SELECT set_config('app.tenant_id', %s, true)", (TENANT,))
            connection.execute(
                "INSERT INTO mizan.evidence_chain_heads(tenant_id,stream_id) VALUES (%s,%s) "
                "ON CONFLICT DO NOTHING", (TENANT, stream),
            )
        barrier.wait()
        for index in range(OPERATIONS_PER_SHARD):
            new_hash = hashlib.sha256(f"{stream}:{index}".encode()).hexdigest()
            started = time.perf_counter_ns()
            with connection.transaction():
                connection.execute("SELECT set_config('app.tenant_id', %s, true)", (TENANT,))
                allocated = connection.execute(
                    "SELECT mizan.reserve_evidence_sequence(%s,%s,%s,%s)",
                    (TENANT, stream, previous, new_hash),
                ).fetchone()[0]
            if allocated != index:
                raise RuntimeError(f"non-dense allocation on shard {shard}: {allocated} != {index}")
            samples.append((time.perf_counter_ns() - started) / 1_000_000)
            previous = new_hash
    return samples


def main() -> int:
    database_url = os.environ["MIZAN_TEST_DATABASE_URL"]
    barrier = Barrier(SHARDS)
    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=SHARDS) as executor:
        groups = list(executor.map(lambda shard: run_shard(database_url, shard, barrier), range(SHARDS)))
    elapsed = time.perf_counter() - started
    samples = [sample for group in groups for sample in group]
    throughput = len(samples) / elapsed
    result = {
        "shards": SHARDS, "operations": len(samples),
        "operations_per_second": round(throughput, 2),
        "p50_ms": round(statistics.median(samples), 4),
        "p99_ms": round(sorted(samples)[int(len(samples) * 0.99)], 4),
    }
    print(json.dumps(result, sort_keys=True))
    write_artifact(
        "evidence-sequencer",
        result,
        {"shards": SHARDS, "operations_per_shard": OPERATIONS_PER_SHARD},
    )
    return 0 if throughput >= 1_000 else 1


if __name__ == "__main__":
    raise SystemExit(main())
