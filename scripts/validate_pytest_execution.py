#!/usr/bin/env python3
"""Reject a pytest run that passed by skipping work or executing nothing."""

from __future__ import annotations

import re
import sys

OUTCOME = r"passed|failed|error|errors|skipped|xfailed|xpassed|deselected"
SUMMARY = re.compile(
    rf"(?P<summary>\d+ (?:{OUTCOME})(?:, \d+ (?:{OUTCOME}))*)"
    r"(?: in [0-9:.]+s)?"
)


def validate_pytest_execution(output: str) -> str:
    """Return the final pytest summary, or raise when it proves no real run."""
    matches = list(SUMMARY.finditer(output))
    if not matches:
        raise ValueError("pytest output contains no execution summary")

    summary = matches[-1].group("summary")
    passed = re.search(r"\b(?P<count>\d+) passed\b", summary)
    if not passed or int(passed.group("count")) == 0:
        raise ValueError(f"pytest reported no passed tests: {summary}")
    expected = f"{passed.group('count')} passed"
    if summary != expected:
        raise ValueError(f"pytest reported non-passing outcomes, which is not a pass: {summary}")
    return summary


def main() -> int:
    try:
        summary = validate_pytest_execution(sys.stdin.read())
    except ValueError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"PostgreSQL integration execution confirmed: {summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
