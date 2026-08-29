#!/usr/bin/env python3
"""Ensure every coverage row resolves to a collected pytest node.

Every row, not only the `I-n`/`V-n` ones. The narrower pattern this used to carry meant a row
naming an ADR amendment or a SPEC section was never checked against pytest at all: it could cite a
test that had been renamed, or deleted, or never written, and the index still reported itself
valid. An unchecked coverage row is worse than a missing one, because it reads as evidence.
"""

from __future__ import annotations

import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COVERAGE = ROOT / "tests/CONTRACT_COVERAGE.md"
ROW = re.compile(r"^\|\s*([^|]+?)\s*\|(.+)\|$", re.MULTILINE)
HEADER = {"Contract"}
REFERENCE = re.compile(r"`((?:unit|integration)/test_[^:`]+\.py::test_[A-Za-z0-9_]+)`")


def check_coverage(document: str, collected: set[str]) -> tuple[list[str], int]:
    """Every row that names a contract must cite a test pytest actually collects."""
    errors: list[str] = []
    checked = 0
    citation_counts: Counter[str] = Counter()
    for contracts, evidence in ROW.findall(document):
        if contracts in HEADER or set(contracts) <= {"-"}:
            continue
        checked += 1
        references = REFERENCE.findall(evidence)
        if not references:
            errors.append(f"{contracts} has no explicit pytest node")
            continue
        for reference in references:
            citation_counts[reference] += 1
            if reference not in collected:
                errors.append(f"{contracts} references uncollected test {reference}")
    for reference, count in citation_counts.items():
        if count > 3:
            errors.append(f"{reference} is primary evidence for {count} contract rows (maximum 3)")
    return errors, checked


def main() -> int:
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        print(result.stdout, file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        return result.returncode
    collected = {
        line.removeprefix("tests/").split("[", 1)[0]
        for line in result.stdout.splitlines()
        if line.startswith("tests/") and "::test_" in line
    }
    errors, checked = check_coverage(COVERAGE.read_text(encoding="utf-8"), collected)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"Contract coverage valid: {checked} rows, {len(collected)} collected tests.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
