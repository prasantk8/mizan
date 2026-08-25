from __future__ import annotations

import json
from pathlib import Path

from benchmarks.artifacts import write_artifact
from scripts.validate_benchmark_artifacts import validate


def test_benchmark_writer_records_reproducibility_metadata(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("MIZAN_BENCHMARK_RESULTS_DIR", str(tmp_path))
    monkeypatch.setenv("MIZAN_BENCHMARK_COMMIT_SHA", "a" * 40)
    path = write_artifact("fixture", {"seconds": 1.25}, {"records": 10})
    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["measurements"] == {"seconds": 1.25}
    assert document["parameters"] == {"records": 10}
    assert document["commit_sha"] == "a" * 40
    assert {"cpu", "logical_cores", "os", "python"} <= set(document["host"])
    assert validate(tmp_path, {"fixture"}) == []


def test_missing_artifact_negative_fixture_fails_gate() -> None:
    fixture = Path("tests/fixtures/benchmark_artifacts/missing")
    assert validate(fixture, {"chain-verifier"}) == [
        "missing benchmark artifact: chain-verifier"
    ]
