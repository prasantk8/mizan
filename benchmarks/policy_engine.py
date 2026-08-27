from __future__ import annotations

import json
import os
import statistics
import time

from mizan_control_plane.policy_engine import compile_policy

from benchmarks.artifacts import write_artifact
from tests.unit.test_authorization import context
from tests.unit.test_policy_engine import policy

# R-008 F-15. `evaluations_per_second >= 1_000 and p99_ms < 5` was written on a laptop and
# **has never executed on any other machine**: no CI job invokes `make benchmark-policy`, so
# unlike F-9 and the sequencer this one has not failed yet, it has merely never been asked.
# A 5 ms p99 ceiling is the most machine-dependent assertion in this repository -- the
# sequencer's p99 moved 27x between two runs on the same runner class -- and the first time
# this runs on a shared runner it will fail for reasons that have nothing to do with the
# evaluator.
#
# Set from the same principle as the others: floors and ceilings that only a collapse trips,
# with the measured numbers published beside their host. Tighten with the environment
# variables when there is a machine to tighten against.
THROUGHPUT_FLOOR = float(os.environ.get("MIZAN_POLICY_THROUGHPUT_FLOOR", "200"))
P99_CEILING_MS = float(os.environ.get("MIZAN_POLICY_P99_CEILING_MS", "25"))
BOUNDS_BASIS = (
    "never measured off a developer laptop -- no CI job runs this benchmark (R-008 F-15) -- "
    "so the bounds are loose enough that only a collapse trips them. A collapse detector, "
    "not a performance claim; the claim is evaluations_per_second and p99_ms beside `host` "
    "in this artifact."
)


def percentile(samples: list[float], fraction: float) -> float:
    return sorted(samples)[min(len(samples) - 1, int(len(samples) * fraction))]


def main() -> int:
    source = policy({"field": "action.type", "op": "eq", "value": "financial_write"})
    compiled = compile_policy(json.dumps(source, sort_keys=True, separators=(",", ":")))
    request = context()
    for _ in range(200):
        compiled.matches(request)
    samples: list[float] = []
    for _ in range(5_000):
        started = time.perf_counter_ns()
        compiled.matches(request)
        samples.append((time.perf_counter_ns() - started) / 1_000_000)
    elapsed_seconds = sum(samples) / 1_000
    result = {
        "iterations": len(samples),
        "evaluations_per_second": round(len(samples) / elapsed_seconds, 2),
        "p50_ms": round(statistics.median(samples), 4),
        "p99_ms": round(percentile(samples, 0.99), 4),
        "throughput_floor": THROUGHPUT_FLOOR,
        "p99_ceiling_ms": P99_CEILING_MS,
        "bounds_basis": BOUNDS_BASIS,
    }
    print(json.dumps(result, sort_keys=True))
    write_artifact(
        "policy-engine",
        result,
        {"iterations": 5_000, "warmup_iterations": 200},
    )
    within_bounds = (
        result["evaluations_per_second"] >= THROUGHPUT_FLOOR
        and result["p99_ms"] < P99_CEILING_MS
    )
    return 0 if within_bounds else 1


if __name__ == "__main__":
    raise SystemExit(main())
