from __future__ import annotations

import pytest
from mizan_control_plane.config import parse_rate_limits
from mizan_control_plane.observability import Metrics
from mizan_control_plane.problems import Problem
from mizan_control_plane.rate_limits import RateLimiter


class Clock:
    now = 0.0

    def __call__(self) -> float:
        return self.now


def limits() -> dict[str, int]:
    return {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def test_buckets_are_isolated_by_tenant_route_and_risk_tier() -> None:
    limiter = RateLimiter(limits(), Metrics(), Clock())
    limiter.require("tnt_bank-a", "authorize", "LOW")
    with pytest.raises(Problem, match="LOW"):
        limiter.require("tnt_bank-a", "authorize", "LOW")

    limiter.require("tnt_bank-b", "authorize", "LOW")
    limiter.require("tnt_bank-a", "approval", "LOW")
    limiter.require("tnt_bank-a", "authorize", "MEDIUM")


def test_capacity_refills_continuously_without_wall_clock_control() -> None:
    clock = Clock()
    limiter = RateLimiter(limits(), Metrics(), clock)
    limiter.require("tnt_bank-a", "authorize", "LOW")
    with pytest.raises(Problem):
        limiter.require("tnt_bank-a", "authorize", "LOW")

    clock.now = 60.0
    limiter.require("tnt_bank-a", "authorize", "LOW")


@pytest.mark.parametrize(
    "raw",
    ["", "1,2,3", "1,2,3,0", "1,2,2,4", "one,2,3,4"],
)
def test_configuration_refuses_missing_non_positive_or_inverted_tiers(raw: str) -> None:
    with pytest.raises(RuntimeError, match="MIZAN_RATE_LIMITS_PER_MINUTE"):
        parse_rate_limits(raw)


def test_configuration_maps_the_closed_tier_order() -> None:
    assert parse_rate_limits("10, 20, 30, 40") == (10, 20, 30, 40)


def test_runtime_limiter_refuses_non_integer_capacity_even_outside_environment_parser() -> None:
    invalid = {"LOW": 1.5, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    with pytest.raises(ValueError, match="positive integer"):
        RateLimiter(invalid, Metrics())  # type: ignore[arg-type]
