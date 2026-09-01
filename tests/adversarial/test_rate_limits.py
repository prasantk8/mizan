"""A burst must stop at the admission guard, not merely produce a 429-shaped fixture."""

from fastapi import FastAPI
from fastapi.testclient import TestClient
from mizan_control_plane.observability import Metrics
from mizan_control_plane.problems import Problem, problem_response
from mizan_control_plane.rate_limits import RateLimiter


def test_burst_over_the_low_tier_limit_never_reaches_the_protected_handler() -> None:
    metrics = Metrics()
    limiter = RateLimiter({"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}, metrics)
    calls: list[str] = []
    application = FastAPI()
    application.add_exception_handler(Problem, problem_response)

    @application.post("/protected")
    def protected() -> dict[str, bool]:
        limiter.require("tnt_bank-a", "authorize", "LOW")
        calls.append("called")
        return {"accepted": True}

    client = TestClient(application)
    assert client.post("/protected").status_code == 200
    refused = client.post("/protected")

    assert refused.status_code == 429
    assert refused.json()["type"] == "https://mizan.ai/problems/rate_limit_exceeded"
    assert calls == ["called"]
    exposition = metrics.exposition().decode()
    assert (
        'mizan_rate_limit_configured_requests_per_minute{risk_tier="LOW",route_class="authorize"} '
        "1.0" in exposition
    )
    assert "mizan_rate_limit_rejections_total" in exposition
