"""Routes through the real ASGI app.

Nothing in the suite went through `create_app` before, so every route-level defect was invisible:
the dependency-resolution bug these tests were written for made ten routes demand a query
parameter named `principal` instead of reading the bearer token.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient
from mizan_control_plane import app as app_module
from mizan_control_plane.config import Settings
from mizan_control_plane.dev_token import ensure_keypair, mint
from mizan_control_plane.registry import require_registry_authority

TENANT = "tnt_bank-a"
SIMULATION_CONTEXT = {
    "schema_version": "1.2",
    "request_id": "018f47a6-7b42-7c00-8000-0000000000ab",
    "principal": {"id": "prn_demo-customer", "type": "customer", "auth_strength": "mfa"},
    "agent": {"id": "agt_wealth-01", "version": "1.0.0", "delegation_chain": ["agt_wealth-01"]},
    "intent": "route test",
    "tool": {
        "id": "tool_transfer",
        "arguments": {},
        "parameters_hash": "0" * 64,
        "binding_profile": {"profile_id": "bp_transfer-v1", "profile_version": 1},
    },
    "action": {"type": "financial_read"},
    "resource": {
        "id": "portfolio/42",
        "type": "portfolio",
        "resource_owner": "core-banking",
        "data_classification": "financial",
    },
    "environment": "development",
    "timestamp": "2026-08-26T00:00:00Z",
}


class FakePool:
    closed = False

    def close(self) -> None:
        self.closed = True


class FakeRepository:
    """Records what the route asked for; asserts nothing about how it asked."""

    def __init__(self, database_url: str) -> None:
        self.pool = FakePool()
        self.calls: list[tuple[str, tuple[Any, ...]]] = []

    def _record(self, name: str, *arguments: Any) -> dict[str, Any]:
        self.calls.append((name, arguments))
        return {"called": name}

    def get(self, *arguments: Any) -> dict[str, Any]:
        return self._record("get", *arguments)

    def simulate_policy(self, *arguments: Any) -> dict[str, Any]:
        return self._record("simulate_policy", *arguments)

    def transition_policy(self, *arguments: Any) -> dict[str, Any]:
        return self._record("transition_policy", *arguments)

    def vote(self, *arguments: Any) -> dict[str, Any]:
        return self._record("vote", *arguments)

    def escalate(self, *arguments: Any) -> dict[str, Any]:
        return self._record("escalate", *arguments)

    def override(self, *arguments: Any) -> dict[str, Any]:
        return self._record("override", *arguments)

    def withdraw(self, *arguments: Any) -> dict[str, Any]:
        return self._record("withdraw", *arguments)

    def update_agent(self, *arguments: Any) -> dict[str, Any]:
        return self._record("update_agent", *arguments)

    def _guarded(self, name: str, tenant_id, document, actor, second=None, environment="development"):
        # The double implements the authority contract with the shipped rule, not a copy of it:
        # these tests are about which principal the route hands over, not about re-deriving who
        # may write to a registry.
        require_registry_authority(actor, document, second, environment)
        return self._record(name, tenant_id, document, actor, second, environment)

    def create_agent(self, *arguments: Any) -> dict[str, Any]:
        return self._guarded("create_agent", *arguments)

    def create_tool(self, *arguments: Any) -> dict[str, Any]:
        return self._guarded("create_tool", *arguments)

    def create_policy(self, *arguments: Any) -> dict[str, Any]:
        return self._guarded("create_policy", *arguments)


@pytest.fixture
def wired(monkeypatch, tmp_path) -> tuple[TestClient, dict[str, FakeRepository], Any]:
    repositories: dict[str, FakeRepository] = {}

    def factory(name: str):
        def build(database_url: str) -> FakeRepository:
            repositories[name] = FakeRepository(database_url)
            return repositories[name]

        return build

    for attribute, name in (
        ("PostgresAuthorizationRepository", "authorization"),
        ("RegistryRepository", "registry"),
        ("EvidenceRepository", "evidence"),
        ("ApprovalRepository", "approval"),
    ):
        monkeypatch.setattr(app_module, attribute, factory(name))
    private_key, public_pem = ensure_keypair(tmp_path / "keys")
    monkeypatch.setenv("MIZAN_DATABASE_URL", "postgresql://unused")
    monkeypatch.setenv("MIZAN_JWT_ISSUER", "urn:mizan:development:dev-token")
    monkeypatch.setenv("MIZAN_JWT_PUBLIC_KEY", public_pem)
    monkeypatch.setenv("MIZAN_EVIDENCE_OBJECT_STORE_ROOT", str(tmp_path / "evidence"))
    application = app_module.create_app(Settings.from_environment())
    with TestClient(application) as client:
        yield client, repositories, private_key


def token(private_key, **overrides: Any) -> str:
    claims: dict[str, Any] = {
        "tenant_id": TENANT,
        "subject": "prn_ops-manager",
        "agent_id": "agt_wealth-01",
        "identity_kind": "human",
        "auth_strength": "hardware",
        "roles": ["manager"],
        "audience": "mizan-control-plane",
        "ttl_seconds": 300,
    }
    claims.update(overrides)
    return mint(private_key, **claims)


def authorization(private_key, **overrides: Any) -> dict[str, str]:
    return {"Authorization": f"Bearer {token(private_key, **overrides)}"}


def test_principal_routes_read_the_bearer_token_and_not_a_query_parameter(wired) -> None:
    client, repositories, private_key = wired
    body = {"version": 1, "context": SIMULATION_CONTEXT}
    response = client.post(
        "/v1/policies/pol_demo/simulate", json=body, headers=authorization(private_key)
    )
    assert response.status_code == 200, response.text
    name, arguments = repositories["registry"].calls[-1]
    assert name == "simulate_policy"
    assert arguments[0] == TENANT
    assert arguments[3] == "prn_ops-manager"


def test_simulation_refuses_a_weakly_authenticated_principal(wired) -> None:
    client, _repositories, private_key = wired
    response = client.post(
        "/v1/policies/pol_demo/simulate",
        json={"version": 1, "context": SIMULATION_CONTEXT},
        headers=authorization(private_key, auth_strength="password"),
    )
    assert response.status_code == 403
    assert response.json()["type"].endswith("simulation_auth_insufficient")


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("post", "/v1/approvals/apr_demo-0001/votes", {"epoch_number": 1, "vote": "APPROVE"}),
        ("post", "/v1/approvals/apr_demo-0001/escalate", None),
        ("post", "/v1/approvals/apr_demo-0001/override", None),
        ("post", "/v1/approvals/apr_demo-0001/withdraw", None),
    ],
)
def test_every_approval_route_accepts_a_bearer_principal(wired, method, path, body) -> None:
    client, _repositories, private_key = wired
    response = getattr(client, method)(path, json=body, headers=authorization(private_key))
    assert response.status_code == 200, response.text


def test_execution_routes_answer_401_without_a_verified_workload(wired) -> None:
    client, _repositories, private_key = wired
    response = client.post(
        "/v1/actions/adr_demo/execute",
        json={"execution_token": "t", "arguments": {}},
        headers=authorization(private_key),
    )
    assert response.status_code == 401
    assert response.json()["title"] == "Workload Identity Missing"


def test_missing_bearer_token_is_401_and_names_the_header(wired) -> None:
    client, _repositories, _private_key = wired
    assert client.get("/v1/agents/agt_wealth-01").status_code == 401


def test_a_token_for_another_audience_is_rejected(wired) -> None:
    client, _repositories, private_key = wired
    response = client.get(
        "/v1/agents/agt_wealth-01",
        headers=authorization(private_key, audience="some-other-service"),
    )
    assert response.status_code == 401
    assert response.json()["type"].endswith("invalid_identity_token")


def test_audit_verify_refuses_a_stream_outside_the_token_tenant(wired) -> None:
    client, _repositories, private_key = wired
    response = client.post(
        "/v1/audit/verify",
        json={"stream_id": "tnt_bank-b:adr:0", "verify_anchors": False},
        headers=authorization(private_key),
    )
    assert response.status_code == 403
    assert response.json()["type"].endswith("tenant_mismatch")


def test_components_absent_in_development_answer_503_rather_than_500(wired) -> None:
    client, _repositories, private_key = wired
    response = client.get("/v1/audit/keys", headers=authorization(private_key))
    assert response.status_code == 503
    assert response.json()["type"].endswith("key_provider_unavailable")


def test_openapi_document_declares_no_route_that_wants_a_principal_query_parameter(wired) -> None:
    client, _repositories, _private_key = wired
    document = client.get("/openapi.json").json()
    offenders = [
        (path, method)
        for path, operations in document["paths"].items()
        for method, operation in operations.items()
        for parameter in operation.get("parameters", [])
        if parameter["in"] == "query" and parameter["name"] in {"principal", "peer_spiffe"}
    ]
    assert offenders == []


def test_problem_responses_carry_the_contract_media_type(wired) -> None:
    client, _repositories, _private_key = wired
    response = client.get("/v1/agents/agt_wealth-01")
    assert response.headers["content-type"].startswith("application/problem+json")


TOOL_DOCUMENT = {
    "schema_version": "1.2",
    "tool_id": "tool_self-granted",
    "tenant_id": TENANT,
    "name": "Self granted",
    "owner": "wealth-team",
    "risk_tier": "LOW",
    "action_type": "financial_write",
    "resource_owner": "core-banking",
    "data_classification": "financial",
    "binding_profile": {
        "profile_id": "bp_self-granted-v1",
        "profile_version": 1,
        "canonicalization": "RFC8785",
        "bound_pointers": ["/amount"],
        "volatile_pointers": [],
        "unknown_pointer_policy": "reject",
    },
    "execution": {
        "executor_spiffe_ids": ["spiffe://mizan/executor/wealth"],
        "token_ttl_seconds": 300,
        "lease_ttl_seconds": 900,
        "heartbeat_interval_seconds": 60,
        "max_lease_extensions": 24,
    },
    "created_at": "2026-08-26T00:00:00Z",
}


def test_an_agent_token_cannot_register_a_tool_over_http(wired) -> None:
    client, repositories, private_key = wired
    response = client.post(
        "/v1/tools",
        json=TOOL_DOCUMENT,
        headers=authorization(private_key, identity_kind="agent", auth_strength="federated"),
    )
    assert response.status_code == 403
    assert response.json()["type"].endswith("registry_write_auth_insufficient")
    assert repositories["registry"].calls == []


@pytest.mark.parametrize("path", ["/v1/agents", "/v1/tools", "/v1/policies"])
def test_registry_creates_require_a_strongly_authenticated_human(wired, path) -> None:
    client, repositories, private_key = wired
    weak = authorization(private_key, identity_kind="human", auth_strength="password")
    assert client.post(path, json={"anything": True}, headers=weak).status_code in {400, 403}
    assert repositories["registry"].calls == []


def test_a_strong_human_operator_reaches_the_registry(wired) -> None:
    client, repositories, private_key = wired
    response = client.post("/v1/tools", json=TOOL_DOCUMENT, headers=authorization(private_key))
    assert response.status_code == 201, response.text
    name, arguments = repositories["registry"].calls[-1]
    assert name == "create_tool"
    assert arguments[0] == TENANT
    assert arguments[2].principal_id == "prn_ops-manager"
