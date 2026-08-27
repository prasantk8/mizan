"""A performance number is a claim about a machine, and it has to say which one.

R-008 F-9, founder ruling 2026-08-27: "could be any machine." The chain-verifier budget was
10 s, calibrated on a sixteen-core laptop doing 15,637 records/second. The four-core CI runner
does 6,630 and took 15.081 s. The chain verified correctly on both -- `valid: true` -- and the
gate failed anyway, because it was measuring the hardware and reporting it as a defect.

Rule 11: the name of each test is the claim. Rule 6 as extended by the ruling: no number
without its artifact, and no artifact without its machine.
"""

from __future__ import annotations

import json
from pathlib import Path

from benchmarks import chain_verifier
from scripts.validate_benchmark_artifacts import REQUIRED_HOST_FIELDS

REPO = Path(__file__).resolve().parents[2]
RESULTS = REPO / "benchmarks" / "results"

# The slowest run measured to date, on the smallest machine this project has ever run on.
# Any budget at or under this is a budget that machine fails.
SLOWEST_MEASURED_SECONDS = 15.081


def test_the_budget_is_set_from_the_slowest_machine_measured_and_not_the_fastest() -> None:
    """A budget between the two machines fails the slow one and tells you nothing about it."""
    assert chain_verifier.BUDGET_SECONDS > SLOWEST_MEASURED_SECONDS, (
        f"the budget is {chain_verifier.BUDGET_SECONDS} s and the slowest machine measured "
        f"took {SLOWEST_MEASURED_SECONDS} s, so this gate fails on hardware we support and "
        f"the failure says nothing about the code that caused it"
    )


def test_the_budget_carries_headroom_over_the_slowest_machine_measured() -> None:
    """One observation of a shared runner is not a bound. A tripwire on the edge is a flake."""
    assert chain_verifier.BUDGET_SECONDS >= 2 * SLOWEST_MEASURED_SECONDS, (
        "a single sample from a noisy shared runner set as the budget converts CI variance "
        "into red builds, and red builds nobody believes are worse than no gate"
    )


def test_the_report_states_what_its_budget_is_based_on() -> None:
    """`target_seconds: 10` said what the number was and never what it meant."""
    assert "records per second" in chain_verifier.BUDGET_BASIS
    assert "not a performance claim" in chain_verifier.BUDGET_BASIS, (
        "the basis has to say the budget is a tripwire, because the first thing anyone does "
        "with a number in an artifact is quote it"
    )


def test_no_committed_benchmark_artifact_states_a_number_without_its_machine() -> None:
    """Green before this change and after it. It is here so the repair cannot be undone."""
    anonymous: list[str] = []
    for path in sorted(RESULTS.glob("*.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        if REQUIRED_HOST_FIELDS - set(document.get("host", {})):
            anonymous.append(path.name)
    assert anonymous == [], (
        f"these artifacts publish a rate with no machine attached, which is the form the "
        f"10 s target took before it was a defect: {anonymous}"
    )
