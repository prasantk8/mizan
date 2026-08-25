#!/usr/bin/env python3
"""Ensure every invariant coverage reference resolves to a collected pytest node."""

from __future__ import annotations

import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COVERAGE = ROOT / "tests/CONTRACT_COVERAGE.md"
ROW = re.compile(r"^\|\s*(I-\d+(?:,\s*I-\d+)*|V-\d+(?:,\s*V-\d+)*)\s*\|(.+)\|$", re.MULTILINE)
REFERENCE = re.compile(r"`((?:unit|integration)/test_[^:`]+\.py::test_[A-Za-z0-9_]+)`")


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
    errors: list[str] = []
    citation_counts: Counter[str] = Counter()
    rows = ROW.findall(COVERAGE.read_text(encoding="utf-8"))
    for contracts, evidence in rows:
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
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"Contract coverage valid: {len(rows)} rows, {len(collected)} collected tests.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
