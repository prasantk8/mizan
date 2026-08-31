"""The SDK against a real control plane: the shapes it builds must be the shapes the server takes."""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest
from mizan import Denied, MizanClient, Principal, Resource
from mizan.adapters import GovernedTool, GovernedToolRouter
from mizan_control_plane.dev_token import DEVELOPMENT_ISSUER, ensure_keypair, mint, public_jwks

from tests.integration.test_closed_loop_postgres import activate_policy

TENANT = "tnt_bank-a"
AGENT = "agt_wealth-01"
CUSTOMER = "prn_demo-customer"
RESOURCE = Resource("portfolio/42", "portfolio", "core-banking", "financial")

pytestmark = pytest.mark.skipif(
    not os.getenv("MIZAN_TEST_DATABASE_URL"), reason="Postgres not configured"
)


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


@pytest.fixture
def live_control_plane(tmp_path: Path):
    activate_policy(os.environ["MIZAN_TEST_DATABASE_URL"])
    identity_key, _public_pem = ensure_keypair(tmp_path / "identity")
    port = _free_port()
    process = subprocess.Popen(
        [sys.executable, "-m", "mizan_control_plane", "--log-level", "warning"],
        env=os.environ
        | {
            "MIZAN_DATABASE_URL": os.environ["MIZAN_TEST_DATABASE_URL"],
            "MIZAN_JWT_ISSUER": DEVELOPMENT_ISSUER,
            "MIZAN_IDENTITY_JWKS": public_jwks(identity_key),
            "MIZAN_EVIDENCE_OBJECT_STORE_ROOT": str(tmp_path / "evidence"),
            "MIZAN_HTTP_HOST": "127.0.0.1",
            "MIZAN_HTTP_PORT": str(port),
            "PYTHONPATH": "control-plane",
        },
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    base_url = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(f"service exited: {process.communicate()[0]}")
        try:
            if httpx.get(f"{base_url}/health/ready", timeout=2).status_code == 200:
                break
        except httpx.TransportError:
            pass
        time.sleep(0.25)
    else:
        process.terminate()
        raise AssertionError(f"never ready: {process.communicate()[0]}")
    token = mint(
        identity_key,
        tenant_id=TENANT,
        subject=CUSTOMER,
        agent_id=AGENT,
        identity_kind="agent",
        auth_strength="federated",
        roles=[],
        audience="mizan-control-plane",
        ttl_seconds=900,
    )
    try:
        yield base_url, token
    finally:
        process.terminate()
        process.wait(timeout=15)


def sdk(base_url: str, token: str) -> MizanClient:
    return MizanClient(base_url, token, agent_id=AGENT, environment="production")


def test_the_sdk_reads_the_live_binding_profile_and_the_server_accepts_its_hash(
    live_control_plane,
) -> None:
    base_url, token = live_control_plane
    with sdk(base_url, token) as mizan:
        profile = mizan.binding_profile("tool_transfer")
        assert profile["bound_pointers"]
        decision = mizan.decide(
            tool_id="tool_transfer",
            arguments={"amount": 12500, "request_time": "sdk-live"},
            action_type="financial_write",
            intent="rebalance the portfolio",
            principal=Principal(id=CUSTOMER, type="customer"),
            resource=RESOURCE,
            business={"transaction_value": {"amount": 12500, "currency": "AED"}},
            wait_for_approval=False,
        )
    # A parameters_hash the SDK got wrong would have been a 400 before any decision existed.
    assert decision.decision == "REQUIRE_APPROVAL"
    assert decision.approval_id is not None


def test_the_router_round_trips_require_approval_without_performing_the_action(
    live_control_plane,
) -> None:
    base_url, token = live_control_plane
    performed: list[dict] = []
    with sdk(base_url, token) as mizan:
        router = GovernedToolRouter(
            mizan,
            {
                "rebalance": GovernedTool(
                    "tool_transfer",
                    "financial_write",
                    RESOURCE,
                    lambda **kwargs: performed.append(kwargs),
                    intent="rebalance the portfolio",
                )
            },
            principal=Principal(id=CUSTOMER, type="customer"),
            approval_timeout_seconds=0.0,
        )
        outcome = router.invoke(
            "rebalance", "toolu_live", {"amount": 12500, "request_time": "router-live"}
        )
    assert outcome.ok is False
    assert outcome.refusal_class == "approval_pending"
    assert performed == []
    assert "still waiting for an approver" in outcome.content


def test_an_unregistered_tool_is_denied_by_the_server_not_by_the_client(
    live_control_plane,
) -> None:
    base_url, token = live_control_plane
    with sdk(base_url, token) as mizan, pytest.raises(Exception) as raised:
        mizan.decide(
            tool_id="tool_not-registered",
            arguments={"amount": 1},
            action_type="financial_write",
            intent="probe",
            principal=Principal(id=CUSTOMER, type="customer"),
            resource=RESOURCE,
        )
    assert not isinstance(raised.value, Denied)  # a 404 from the registry, not a policy decision
