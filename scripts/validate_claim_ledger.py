#!/usr/bin/env python3
"""Enforce WORK_LOG claim provenance for every implementation commit."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import PurePosixPath

SCOPED_ROOTS = {
    ".github", "benchmarks", "control-plane", "examples", "infra", "integrations",
    "policies", "scripts", "sdk", "security", "tests", "threat-models", "ui",
}
SCOPED_FILES = {"compose.yaml", "compose.test.yaml", "Makefile", "pyproject.toml", "uv.lock"}
CLAIM_ROW = re.compile(
    r"^\|\s*(T-\d+)\s*\|\s*([^|]+)\|\s*([^|]+)\|\s*(\d+)\s*\|",
    re.MULTILINE,
)
CLOSE_LOG = re.compile(r"^-\s+\d{4}-\d{2}-\d{2}\s+·\s+\w+\s+·\s+(T-\d+)\s+·", re.MULTILINE)
QUEUE_HANDOFF = re.compile(
    r"^\|\s*(T-\d+)\s*\|.*\|\s*(REVIEW|DONE|PARKED(?:\([^)]*\))?)\s*\|$", re.MULTILINE
)


def is_scoped(path: str) -> bool:
    parsed = PurePosixPath(path)
    return path in SCOPED_FILES or (bool(parsed.parts) and parsed.parts[0] in SCOPED_ROOTS)


def validate_snapshot(changed_paths: list[str], worklog_changed: bool, worklog: str) -> list[str]:
    if not any(is_scoped(path) for path in changed_paths):
        return []
    errors: list[str] = []
    if not worklog_changed:
        errors.append("lane-scoped implementation changed without WORK_LOG.md in the same commit")
        return errors
    claims = [match for match in CLAIM_ROW.findall(worklog) if match[0] != "—"]
    if len(claims) > 1:
        errors.append("more than one live claim exists")
    if claims:
        return errors
    close = CLOSE_LOG.search(worklog)
    reviewed = {task for task, _state in QUEUE_HANDOFF.findall(worklog)}
    if not close or close.group(1) not in reviewed:
        errors.append("implementation commit has neither one live claim nor a newest REVIEW/DONE/PARKED handoff")
    return errors


def git(*arguments: str) -> str:
    return subprocess.check_output(["git", *arguments], text=True).strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base")
    parser.add_argument("--head", default="HEAD")
    arguments = parser.parse_args()
    if arguments.base:
        commits = git("rev-list", "--reverse", f"{arguments.base}..{arguments.head}").splitlines()
    else:
        commits = [arguments.head]
    failures: list[str] = []
    for commit in commits:
        parents = git("rev-list", "--parents", "-n", "1", commit).split()
        if len(parents) == 1:
            changed = git("show", "--pretty=format:", "--name-only", commit).splitlines()
        else:
            changed = git("diff-tree", "--no-commit-id", "--name-only", "-r", commit).splitlines()
        changed = [path for path in changed if path]
        if not any(is_scoped(path) for path in changed):
            continue
        try:
            worklog = git("show", f"{commit}:WORK_LOG.md")
        except subprocess.CalledProcessError:
            failures.append(f"{commit[:12]}: WORK_LOG.md missing")
            continue
        errors = validate_snapshot(changed, "WORK_LOG.md" in changed, worklog)
        failures.extend(f"{commit[:12]}: {error}" for error in errors)
    if failures:
        print("Claim-ledger validation failed:", file=sys.stderr)
        print("\n".join(f"- {failure}" for failure in failures), file=sys.stderr)
        return 1
    print(f"Claim-ledger valid for {len(commits)} commit(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
