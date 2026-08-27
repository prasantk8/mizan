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

# R-008 F-15. This gate has already failed the founder's "could be any machine" test twice
# over, and worse than the chain verifier did, because it is not even stable on one machine.
# Two runs of identical code on the same runner class:
#
#   17:33 UTC  1,198.33 ops/s   p99   6.2563 ms   pass
#   18:35 UTC    315.73 ops/s   p99 171.6093 ms   fail
#
# 3.8x on throughput and 27x on p99, against a floor of 1,000 that sat inside the range. That
# is not a measurement, it is a coin flip, and it decided whether `postgres-contract` -- the
# job that proves the *schema contract* -- went green. A gate that fails at random is worse
# than no gate: it teaches everyone to re-run CI until it passes, which is how H-8 ("CI is
# authoritative") dies from the inside.
#
# So the floor is set from the slowest run ever observed, with headroom under it. It catches a
# change that collapses throughput and nothing else. The correctness assertions in run_shard()
# -- dense, gapless allocation under concurrency -- are the real gate here and they are
# unconditional.
SLOWEST_MEASURED_OPS = 315.73
THROUGHPUT_FLOOR = float(os.environ.get("MIZAN_SEQUENCER_THROUGHPUT_FLOOR", "150"))
FLOOR_BASIS = (
    "half the slowest run measured to date (315.73 ops/s on a four-core ubuntu-latest GitHub "
    "runner, which the same runner class beat by 3.8x an hour earlier, R-008 F-15). A "
    "collapse detector, not a performance claim; the claim is operations_per_second beside "
    "`host` in this artifact."
)


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
        "throughput_floor": THROUGHPUT_FLOOR,
        "floor_basis": FLOOR_BASIS,
    }
    print(json.dumps(result, sort_keys=True))
    write_artifact(
        "evidence-sequencer",
        result,
        {"shards": SHARDS, "operations_per_shard": OPERATIONS_PER_SHARD},
    )
    return 0 if throughput >= THROUGHPUT_FLOOR else 1


if __name__ == "__main__":
    raise SystemExit(main())
