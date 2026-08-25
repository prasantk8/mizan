#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_FIELDS = {
    "benchmark", "commit_sha", "host", "measurements", "parameters", "timestamp_utc",
    "worktree_clean",
}
REQUIRED_HOST_FIELDS = {"cpu", "logical_cores", "os", "python"}


def validate(results_dir: Path, required: set[str]) -> list[str]:
    errors: list[str] = []
    found: set[str] = set()
    for path in sorted(results_dir.glob("*.json")) if results_dir.exists() else []:
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            errors.append(f"{path}: unreadable artifact: {exc}")
            continue
        missing = REQUIRED_FIELDS - set(document)
        if missing:
            errors.append(f"{path}: missing fields {sorted(missing)}")
            continue
        host_missing = REQUIRED_HOST_FIELDS - set(document.get("host", {}))
        if host_missing:
            errors.append(f"{path}: missing host fields {sorted(host_missing)}")
        benchmark = document["benchmark"]
        found.add(benchmark)
        if not path.name.startswith(f"{benchmark}-{document['commit_sha']}"):
            errors.append(f"{path}: filename does not bind benchmark and commit SHA")
        if document["worktree_clean"] is not True:
            errors.append(f"{path}: benchmark ran with a dirty worktree")
        resolved = subprocess.run(
            ["git", "cat-file", "-e", f"{document['commit_sha']}^{{commit}}"],
            cwd=ROOT,
            check=False,
            capture_output=True,
        )
        if resolved.returncode != 0:
            errors.append(f"{path}: commit_sha does not resolve to a repository commit")
    for benchmark in sorted(required - found):
        errors.append(f"missing benchmark artifact: {benchmark}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results-dir", type=Path, default=Path("benchmarks/results"))
    parser.add_argument("--require", action="append", default=[])
    args = parser.parse_args()
    errors = validate(args.results_dir, set(args.require))
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
