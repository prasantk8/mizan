from __future__ import annotations

import json
from pathlib import Path

import pytest

import benchmarks.artifacts as artifacts
from benchmarks.artifacts import write_artifact
from scripts.validate_benchmark_artifacts import validate


def test_benchmark_writer_records_reproducibility_metadata(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("MIZAN_BENCHMARK_RESULTS_DIR", str(tmp_path))
    monkeypatch.setattr(artifacts, "worktree_clean", lambda: True)
    path = write_artifact("fixture", {"seconds": 1.25}, {"records": 10})
    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["measurements"] == {"seconds": 1.25}
    assert document["parameters"] == {"records": 10}
    assert document["commit_sha"] == artifacts.commit_sha()
    assert document["worktree_clean"] is True
    assert {"cpu", "logical_cores", "os", "python"} <= set(document["host"])
    assert validate(tmp_path, {"fixture"}) == []


def test_missing_artifact_negative_fixture_fails_gate() -> None:
    fixture = Path("tests/fixtures/benchmark_artifacts/missing")
    assert validate(fixture, {"chain-verifier"}) == [
        "missing benchmark artifact: chain-verifier"
    ]


def test_forged_or_dirty_artifacts_fail_provenance_gate(tmp_path: Path) -> None:
    forged = {
        "benchmark": "forged",
        "commit_sha": "a" * 40,
        "host": {"cpu": "fixture", "logical_cores": 1, "os": "fixture", "python": "3.12"},
        "measurements": {},
        "parameters": {},
        "timestamp_utc": "2026-08-25T00:00:00Z",
        "worktree_clean": True,
    }
    (tmp_path / f"forged-{'a' * 40}.json").write_text(json.dumps(forged), encoding="utf-8")
    dirty = forged | {
        "benchmark": "dirty",
        "commit_sha": artifacts.commit_sha(),
        "worktree_clean": False,
    }
    (tmp_path / f"dirty-{dirty['commit_sha']}.json").write_text(
        json.dumps(dirty), encoding="utf-8"
    )
    errors = validate(tmp_path, {"forged", "dirty"})
    assert any("commit_sha does not resolve" in error for error in errors)
    assert any("benchmark ran with a dirty worktree" in error for error in errors)


def test_commit_override_cannot_claim_other_code(monkeypatch) -> None:
    monkeypatch.setenv("MIZAN_BENCHMARK_COMMIT_SHA", "a" * 40)
    with pytest.raises(RuntimeError, match="must equal the checked-out HEAD"):
        artifacts.commit_sha()
