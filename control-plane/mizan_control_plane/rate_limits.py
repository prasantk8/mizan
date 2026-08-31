"""Tenant-scoped, risk-tiered admission control for pilot-critical routes.

The limiter is deliberately an availability control, never an authorization input.  A refusal
does not write an ADR record or alter an approval: it says only that this process has no capacity
for this route class at this instant.  The authoritative tenant comes from the verified bearer
and the authoritative risk tier comes from stored Mizan state; neither is read from a header.

Buckets are per process.  ADR-003 Amendment E records the operational consequence: a deployment
with N replicas has N independently enforced shares, so the configured values are per-replica
limits and the load balancer must not describe them as a cluster-wide quota.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from itertools import pairwise
from threading import Lock

from .observability import Metrics
from .problems import Problem

RISK_TIERS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
ROUTE_CLASSES = ("authorize", "approval", "execution_token")


@dataclass(slots=True)
class _Bucket:
    tokens: float
    updated_at: float


class RateLimiter:
    """A token bucket for each `(tenant, route class, risk tier)` tuple."""

    def __init__(
        self,
        limits_per_minute: Mapping[str, int],
        metrics: Metrics,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if set(limits_per_minute) != set(RISK_TIERS):
            raise ValueError("rate limits must name LOW, MEDIUM, HIGH and CRITICAL exactly")
        if any(
            not isinstance(value, int) or isinstance(value, bool) or value < 1
            for value in limits_per_minute.values()
        ):
            raise ValueError("every rate limit must be a positive integer")
        if any(
            limits_per_minute[left] >= limits_per_minute[right]
            for left, right in pairwise(RISK_TIERS)
        ):
            raise ValueError("rate limits must rise strictly from LOW through CRITICAL")

        self._limits = dict(limits_per_minute)
        self._metrics = metrics
        self._clock = clock
        self._buckets: dict[tuple[str, str, str], _Bucket] = {}
        self._lock = Lock()
        for route_class in ROUTE_CLASSES:
            for risk_tier in RISK_TIERS:
                metrics.rate_limit_configured.labels(route_class, risk_tier).set(
                    self._limits[risk_tier]
                )

    def require(self, tenant_id: str, route_class: str, risk_tier: str) -> None:
        """Consume one admission or raise the public 429 problem."""
        if route_class not in ROUTE_CLASSES:
            raise ValueError(f"unknown rate-limit route class: {route_class}")
        if risk_tier not in RISK_TIERS:
            # Stored risk outside the closed enum is a server contract failure, not a bucket a
            # caller can choose.  It must never fall back to LOW and gain an invented meaning.
            raise ValueError(f"unknown rate-limit risk tier: {risk_tier}")

        capacity = self._limits[risk_tier]
        now = self._clock()
        key = (tenant_id, route_class, risk_tier)
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _Bucket(float(capacity), now)
                self._buckets[key] = bucket
            else:
                elapsed = max(0.0, now - bucket.updated_at)
                bucket.tokens = min(
                    float(capacity), bucket.tokens + elapsed * capacity / 60.0
                )
                bucket.updated_at = now

            if bucket.tokens < 1.0:
                self._metrics.rate_limit_rejections.labels(
                    tenant_id, route_class, risk_tier
                ).inc()
                raise Problem(
                    429,
                    "rate_limit_exceeded",
                    f"{route_class} capacity for the {risk_tier} risk tier is exhausted",
                )
            bucket.tokens -= 1.0
