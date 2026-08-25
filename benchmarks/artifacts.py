from __future__ import annotations

import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def commit_sha() -> str:
    override = os.environ.get("MIZAN_BENCHMARK_COMMIT_SHA")
    if override:
        return override
    return subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()


def host_description() -> dict[str, Any]:
    return {
        "cpu": platform.processor() or platform.machine(),
        "logical_cores": os.cpu_count(),
        "os": platform.platform(),
        "python": platform.python_version(),
    }


def write_artifact(
    benchmark: str,
    measurements: dict[str, Any],
    parameters: dict[str, Any],
) -> Path:
    sha = commit_sha()
    result_dir = Path(
        os.environ.get("MIZAN_BENCHMARK_RESULTS_DIR", ROOT / "benchmarks" / "results")
    )
    result_dir.mkdir(parents=True, exist_ok=True)
    path = result_dir / f"{benchmark}-{sha}.json"
    payload = {
        "benchmark": benchmark,
        "commit_sha": sha,
        "host": host_description(),
        "measurements": measurements,
        "parameters": parameters,
        "timestamp_utc": datetime.now(UTC).isoformat(),
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path
