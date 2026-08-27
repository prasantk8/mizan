"""A skipped Postgres suite in CI is a suite that did not run.

`pytest.mark.skipif(not MIZAN_TEST_DATABASE_URL)` is right on a laptop and wrong on a build
machine: it turns "the database was never provisioned" into a green run. Under `CI=true` the
absence of the DSN is a configuration failure, reported before a single test executes.

The guard is about tests that are going to *execute*. A `--collect-only` run takes an
inventory of node IDs and runs nothing, so nothing can be falsely reported as skipped and the
guard's premise does not hold. It fired there anyway, which killed `python-contract` -- a job
with no PostgreSQL service and no reason to have one -- over a condition satisfied by
`postgres-contract`, which does set the DSN and does run the gated suite. R-008 F-11.
"""

from __future__ import annotations

import os

import pytest

POSTGRES_REASON = "Postgres not configured"


def _needs_postgres(item: pytest.Item) -> bool:
    return any(
        marker.name == "skipif" and POSTGRES_REASON in str(marker.kwargs.get("reason", ""))
        for marker in item.iter_markers()
    )


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    if config.option.collectonly:
        return
    if os.environ.get("CI", "").lower() != "true" or os.environ.get("MIZAN_TEST_DATABASE_URL"):
        return
    gated = [item.nodeid for item in items if _needs_postgres(item)]
    if gated:
        raise pytest.UsageError(
            f"CI=true collected {len(gated)} PostgreSQL-gated tests with no "
            f"MIZAN_TEST_DATABASE_URL. They would be reported as skipped, which is not a pass. "
            f"First: {gated[0]}"
        )
