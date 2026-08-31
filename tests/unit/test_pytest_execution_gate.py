"""The PostgreSQL CI gate must distinguish execution from skipped collection."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.validate_pytest_execution import validate_pytest_execution

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "postgres-contract"


def test_the_gate_rejects_the_green_pre_fix_summary_that_masked_23_skips() -> None:
    output = (FIXTURES / "pre-fix-0ea6420-summary.txt").read_text()

    with pytest.raises(ValueError, match="23 skipped"):
        validate_pytest_execution(output)


def test_the_gate_accepts_an_explicit_postgres_run_with_no_skips() -> None:
    summary = validate_pytest_execution("35 passed in 12.34s\n")

    assert summary == "35 passed"


@pytest.mark.parametrize("output", ["", "no tests ran in 0.01s"])
def test_the_gate_rejects_output_without_an_executed_test(output: str) -> None:
    with pytest.raises(ValueError, match="no execution summary"):
        validate_pytest_execution(output)


@pytest.mark.parametrize("outcome", ["xfailed", "xpassed", "deselected"])
def test_the_gate_rejects_any_non_passing_outcome(outcome: str) -> None:
    with pytest.raises(ValueError, match="non-passing outcomes"):
        validate_pytest_execution(f"34 passed, 1 {outcome} in 12.34s\n")
