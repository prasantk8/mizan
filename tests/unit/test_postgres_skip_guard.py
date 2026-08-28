"""The "a skip is not a pass" guard must refuse a real run and permit an inventory.

R-008 F-11: `tests/conftest.py` refuses to let a CI run report the PostgreSQL suite as
skipped, which is right. It also refused `pytest --collect-only`, which is not a run at all --
and that is what `scripts/validate_contract_coverage.py` does to take an inventory of node
IDs. The result was that `python-contract`, a job with no database and no reason to have one,
died over a condition that `postgres-contract` already satisfies.

Rule 11: the name of each test is the claim. The first fails on pre-fix `e8ef4cd` because the
guard fires on an inventory. The second is the half that must keep working and is what stops
the fix from being "delete the guard".
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
GATED = "tests/integration/test_authorize_postgres.py"


def run_pytest(*arguments: str) -> subprocess.CompletedProcess[str]:
    """A build machine: `CI=true`, and no database was ever provisioned."""
    environment = dict(os.environ, CI="true")
    environment.pop("MIZAN_TEST_DATABASE_URL", None)
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", *arguments],
        cwd=REPO,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def test_a_collect_only_inventory_is_not_a_test_run() -> None:
    completed = run_pytest("--collect-only", "-q", GATED)
    assert completed.returncode == 0, (
        "collection executes nothing, so nothing can be falsely reported as skipped. "
        f"stderr:\n{completed.stderr}"
    )


def test_the_guard_still_refuses_a_run_that_would_report_the_postgres_suite_as_skipped() -> None:
    completed = run_pytest("-q", GATED)
    assert completed.returncode != 0, "a skipped PostgreSQL suite in CI is not a pass"
    assert "which is not a pass" in completed.stderr + completed.stdout
