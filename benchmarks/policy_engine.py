from __future__ import annotations

import json
import statistics
import time

from mizan_control_plane.policy_engine import compile_policy

from tests.unit.test_authorization import context
from tests.unit.test_policy_engine import policy


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
    }
    print(json.dumps(result, sort_keys=True))
    return 0 if result["evaluations_per_second"] >= 1_000 and result["p99_ms"] < 5 else 1


if __name__ == "__main__":
    raise SystemExit(main())

