"""Routes through the real ASGI app.

Nothing in the suite went through `create_app` before, so every route-level defect was invisible:
the dependency-resolution bug these tests were written for made ten routes demand a query
parameter named `principal` instead of reading the bearer token.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from mizan_control_plane import app as app_module
from mizan_control_plane.canonical import binding_hash
from mizan_control_plane.config import Settings
from mizan_control_plane.dev_token import ensure_keypair, mint, public_jwks
from mizan_control_plane.models import RegistryAgent, RegistryTool
from mizan_control_plane.policy_engine import CedarPolicyEvaluator
from mizan_control_plane.proofs.memtara import JwksCache, MemtaraProofVerifier
from mizan_control_plane.registry import require_registry_authority
from mizan_control_plane.repository import InMemoryAuthorizationRepository

from tests.unit.test_memtara_proof import CHAIN_HEAD as MEMTARA_CHAIN_HEAD
from tests.unit.test_memtara_proof import ISSUER as MEMTARA_ISSUER
from tests.unit.test_memtara_proof import _claims as memtara_claims
from tests.unit.test_memtara_proof import _jwks as memtara_jwks
from tests.unit.test_memtara_proof import _token as memtara_token

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

    def __init__(self, database_url: str, *_arguments: object) -> None:
        # `*_arguments` because `ApprovalRepository` also takes the deployment's
        # `MIZAN_APPROVAL_EPOCH_EXPIRY` mode; these doubles model no expiry behaviour.
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

    def risk_tier(self, *arguments: Any) -> str:
        self.calls.append(("risk_tier", arguments))
        return "LOW"

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
        def build(database_url: str, *arguments: object) -> FakeRepository:
            # `*arguments` because `ApprovalRepository` also takes the deployment's
            # `MIZAN_APPROVAL_EPOCH_EXPIRY` mode; the fakes do not model expiry.
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
    private_key, _public_pem = ensure_keypair(tmp_path / "keys")
    monkeypatch.setenv("MIZAN_DATABASE_URL", "postgresql://unused")
    monkeypatch.setenv("MIZAN_JWT_ISSUER", "urn:mizan:development:dev-token")
    monkeypatch.setenv("MIZAN_IDENTITY_JWKS", public_jwks(private_key))
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
    client, repositories, private_key = wired
    response = getattr(client, method)(path, json=body, headers=authorization(private_key))
    assert response.status_code == 200, response.text
    assert repositories["approval"].calls[0][0] == "risk_tier"


def test_approval_burst_is_refused_before_the_mutation_and_visible_in_metrics(wired) -> None:
    client, repositories, private_key = wired
    headers = authorization(private_key)
    path = "/v1/approvals/apr_demo-0001/escalate"

    for _ in range(60):
        assert client.post(path, headers=headers).status_code == 200
    refused = client.post(path, headers=headers)

    assert refused.status_code == 429
    assert refused.headers["content-type"].startswith("application/problem+json")
    assert refused.json()["type"] == "https://mizan.ai/problems/rate_limit_exceeded"
    assert refused.json()["instance"] == path
    assert [name for name, _arguments in repositories["approval"].calls].count("escalate") == 60
    exposition = client.app.state.metrics.exposition().decode()
    assert (
        'mizan_rate_limit_configured_requests_per_minute{risk_tier="LOW",route_class="approval"} '
        "60.0" in exposition
    )
    assert (
        'mizan_rate_limit_rejections_total{risk_tier="LOW",route_class="approval",'
        'tenant_id="tnt_bank-a"} 1.0' in exposition
    )


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


def test_authorize_fails_closed_when_a_proof_arrives_and_memtara_is_unconfigured(wired) -> None:
    """Named for what it proves. It was `..._accepts_the_memtara_headers_and_...`, which claimed
    an acceptance path this test never reaches: the value it presents is the literal string
    "header.payload.signature", and `create_app` here has no trusted issuer, so the refusal comes
    from `MemtaraProofVerifier.configured` before any parsing. Acceptance is covered by
    `test_a_genuine_suitability_proof_reaches_cedar_and_permits_the_recommendation`.
    """
    client, _repositories, private_key = wired
    headers = authorization(private_key, identity_kind="agent") | {
        "x-memtara-proof": "header.payload.signature",
        "x-memtara-chain-head": "a" * 64,
    }
    response = client.post("/v1/authorize", json=SIMULATION_CONTEXT, headers=headers)
    assert response.status_code == 403
    assert response.json()["type"].endswith("invalid_memtara_proof")
    assert "not configured" in response.json()["detail"]


def test_authorize_refuses_a_chain_head_without_a_proof_token(wired) -> None:
    client, _repositories, private_key = wired
    headers = authorization(private_key, identity_kind="agent") | {
        "x-memtara-chain-head": "a" * 64
    }
    response = client.post("/v1/authorize", json=SIMULATION_CONTEXT, headers=headers)
    assert response.status_code == 403
    assert response.json()["type"].endswith("invalid_memtara_proof")


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
    for path in ("/v1/audit/keys", "/v1/audit/commitment-keys"):
        response = client.get(path, headers=authorization(private_key))
        assert response.status_code == 503
        assert response.json()["type"].endswith("key_provider_unavailable")


def test_the_two_keysets_the_routes_serve_never_overlap() -> None:
    """T-054: the audit commitment key is served, never exported, and never has a public half.

    Both keysets are asserted together because the failure this guards against is one leaking into
    the other. `/v1/audit/keys` is copied verbatim into every export bundle (ADR-004 G.1) and both
    verifiers reject any entry without `public_key` or with an algorithm other than Ed25519 — so a
    commitment entry appearing there would break the exporter and both verifiers at once.
    """
    from mizan_control_plane.keys import (
        KEY_ROLES,
        MAC_ALGORITHM,
        MAC_ROLES,
        development_key_provider,
    )

    provider = development_key_provider()

    verification = provider.verification_keyset()
    commitments = provider.commitment_keyset()

    assert {item["role"] for item in verification} == set(KEY_ROLES)
    assert all("public_key" in item for item in verification)
    assert {item["role"] for item in commitments} == set(MAC_ROLES)
    assert all("public_key" not in item for item in commitments)
    assert all(item["algorithm"] == MAC_ALGORITHM for item in commitments)
    # No commitment key id may appear in the exported keyset, under any role label.
    assert not {i["key_id"] for i in verification} & {i["key_id"] for i in commitments}


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
    """The refusal moved earlier, and is now at the identity layer rather than the authority one.

    T-077a made this a 403 `registry_write_auth_insufficient`: the token authenticated fine and
    was then refused for lacking registry authority. T-112 refuses it a step sooner with 401
    `token_class_mismatch`, because an agent token is not a principal credential at all -- the
    same token used to satisfy both `verify` and `verify_principal`, so one bearer was the agent
    making the request *and* a human holding a role.

    Both refusals are real and both remain: the authority check still fires for a token that
    passes the class check, which `test_a_weak_operator_cannot_reach_the_registry` covers. What
    matters here is unchanged -- the registry is never reached.
    """
    client, repositories, private_key = wired
    response = client.post(
        "/v1/tools",
        json=TOOL_DOCUMENT,
        headers=authorization(private_key, identity_kind="agent", auth_strength="federated"),
    )
    assert response.status_code == 401
    assert response.json()["type"].endswith("token_class_mismatch")
    assert repositories["registry"].calls == []


@pytest.mark.parametrize("path", ["/v1/agents", "/v1/tools", "/v1/policies"])
def test_registry_creates_require_a_strongly_authenticated_human(wired, path) -> None:
    client, repositories, private_key = wired
    weak = authorization(private_key, identity_kind="human", auth_strength="password")
    assert client.post(path, json={"anything": True}, headers=weak).status_code in {400, 403}
    assert repositories["registry"].calls == []


def test_a_strong_human_operator_reaches_the_registry(wired) -> None:
    """Also the other half of T-112's TTL bound: a bound that refuses everything is not a bound.

    The token this mints has an ordinary lifetime and must still be accepted, so this test fails
    if `identity_token_max_ttl_seconds` is ever set low enough to refuse normal credentials.
    """
    client, repositories, private_key = wired
    response = client.post("/v1/tools", json=TOOL_DOCUMENT, headers=authorization(private_key))
    assert response.status_code == 201, response.text
    name, arguments = repositories["registry"].calls[-1]
    assert name == "create_tool"
    assert arguments[0] == TENANT
    assert arguments[2].principal_id == "prn_ops-manager"


def test_the_tenant_api_does_not_serve_metrics(wired) -> None:
    """The counters are cross-tenant, so this listener is the one place they may not appear.

    T-107 added `GET /metrics` here, reasoning that the numbers it exposed carried no tenant
    identifier. That was true of those two counters and is not a property of the endpoint: every
    counter added since is labelled by `tenant_id`, so the route would have published one
    tenant's activity to any other tenant's credential the first time someone labelled a metric
    the obvious way. `MetricsServer` serves them on a private listener instead, which
    `test_the_metrics_listener_serves_the_exposition_and_nothing_else` covers.

    Asserted as a 404 rather than by reading the route table, because what matters is that a
    caller cannot reach it -- a route registered but shadowed would pass the weaker check.
    """
    client, _repositories, _private_key = wired
    assert client.get("/metrics").status_code == 404
    assert "/metrics" not in {route.path for route in client.app.routes}


def test_a_token_with_an_excessive_lifetime_is_refused(wired) -> None:
    """T-112(d). `exp` in the future is not a bounded lifetime.

    PyJWT checks that a token has not expired and has no opinion about how long it lives. A
    ten-year identity token was accepted, and there is no revocation path for identity tokens at
    all, so one leaked credential was a decade of access.
    """
    client, _repositories, private_key = wired
    decade = token(private_key, ttl_seconds=10 * 365 * 24 * 3600)
    response = client.get("/v1/agents", headers={"Authorization": f"Bearer {decade}"})

    assert response.status_code == 401
    assert response.json()["type"].endswith("identity_token_ttl_excessive")



def test_a_body_larger_than_the_limit_is_refused_before_it_is_parsed(wired) -> None:
    """T-112(f). Every write route parses its body before anything authenticates the caller.

    The refusal must therefore come from the ASGI layer: a check inside a route handler runs
    after the allocation it exists to prevent, which is a report rather than a cap. Asserted with
    no credential at all, because that is the case that matters -- an unauthenticated stranger
    choosing how much this process allocates.
    """
    client, repositories, _private_key = wired
    oversized = {"padding": "x" * (2 * 1024 * 1024)}

    response = client.post("/v1/tools", json=oversized)

    assert response.status_code == 413
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.json()["type"].endswith("request_body_too_large")
    assert repositories["registry"].calls == []


# --------------------------------------------------------------------------------------------
# T-133/T-134: the Memtara suitability seam, driven end to end through the real ASGI app.
#
# Everything below runs the shipped pieces: the route's header handling, `MemtaraProofVerifier`
# over a genuine Ed25519 JWS, `AuthorizationService`, the shipped `CedarPolicyEvaluator`, and the
# reference policy file itself. Only the database is a double. Nothing in the suite drove the
# whole seam before -- the verifier was tested in isolation and the policy was tested against a
# hand-built `mapped`, so the wiring between them (the one place a forged projection could enter)
# was covered by nothing at all.
# --------------------------------------------------------------------------------------------

RECOMMENDATION_TOOL = "tool_product-recommendation"
RECOMMENDED_ISIN = "XS1234567890"
REFERENCE_POLICY = Path("policies/reference/require_suitability_proof.json")


class SuitabilityRepository(InMemoryAuthorizationRepository):
    """A registry that permits the recommendation tool and evaluates the shipped policy file.

    `matching_policies` runs the real evaluator rather than returning a canned `PolicyMatch`, so
    an ALLOW here means the reference policy's conditions were actually satisfied by whatever
    projection survived the route.
    """

    instances: list[SuitabilityRepository] = []

    def __init__(self, database_url: str, *_arguments: object) -> None:
        super().__init__(
            agents=[
                RegistryAgent(
                    tenant_id=TENANT,
                    agent_id="agt_wealth-01",
                    version="1.0.0",
                    lifecycle_state="ACTIVE",
                    permitted_tools={RECOMMENDATION_TOOL},
                )
            ],
            tools=[
                RegistryTool(
                    tenant_id=TENANT,
                    tool_id=RECOMMENDATION_TOOL,
                    risk_tier="MEDIUM",
                    resource_owner="core-banking",
                    data_classification="financial",
                    profile_id="bp_recommend-v1",
                    profile_version=1,
                    bound_pointers=["/product_isin"],
                    volatile_pointers=[],
                    executor_spiffe_ids=["spiffe://mizan/executor/wealth"],
                )
            ],
        )
        self.pool = FakePool()
        self.documents = [json.loads(REFERENCE_POLICY.read_text(encoding="utf-8"))]
        SuitabilityRepository.instances.append(self)

    def matching_policies(self, tenant_id: str, context: Any, risk_level: str | None = None):
        return CedarPolicyEvaluator().evaluate(self.documents, context, risk_level)


def recommendation_context(request_id: str, isin: str = RECOMMENDED_ISIN) -> dict[str, Any]:
    arguments = {"product_isin": isin}
    return {
        "schema_version": "1.2",
        "request_id": request_id,
        "principal": {"id": "prn_alice-01", "type": "employee", "auth_strength": "mfa"},
        "agent": {"id": "agt_wealth-01", "version": "1.0.0", "delegation_chain": ["agt_wealth-01"]},
        "intent": "recommend the five-year note",
        "tool": {
            "id": RECOMMENDATION_TOOL,
            "arguments": arguments,
            "parameters_hash": binding_hash(arguments, ["/product_isin"]),
            "binding_profile": {"profile_id": "bp_recommend-v1", "profile_version": 1},
        },
        "action": {"type": "communicate"},
        "resource": {
            "id": "client/42",
            "type": "client_profile",
            "resource_owner": "core-banking",
            "data_classification": "financial",
        },
        "environment": "production",
        "timestamp": "2026-09-02T00:00:00Z",
    }


@pytest.fixture
def seam(monkeypatch, tmp_path):
    """The app wired with a live Memtara verifier whose JWKS holds one generated test key."""
    SuitabilityRepository.instances.clear()
    monkeypatch.setattr(app_module, "PostgresAuthorizationRepository", SuitabilityRepository)
    for attribute in ("RegistryRepository", "EvidenceRepository", "ApprovalRepository"):
        monkeypatch.setattr(
            app_module, attribute, lambda url, *arguments: FakeRepository(url, *arguments)
        )
    identity_key, _public_pem = ensure_keypair(tmp_path / "keys")
    monkeypatch.setenv("MIZAN_DATABASE_URL", "postgresql://unused")
    monkeypatch.setenv("MIZAN_JWT_ISSUER", "urn:mizan:development:dev-token")
    monkeypatch.setenv("MIZAN_IDENTITY_JWKS", public_jwks(identity_key))
    monkeypatch.setenv("MIZAN_EVIDENCE_OBJECT_STORE_ROOT", str(tmp_path / "evidence"))

    memtara_key = Ed25519PrivateKey.generate()
    cache = JwksCache("https://memtara.test/.well-known/jwks.json")
    cache.load(memtara_jwks(memtara_key))
    application = app_module.create_app(
        Settings.from_environment(),
        memtara_verifier=MemtaraProofVerifier(MEMTARA_ISSUER, cache.jwks_url, jwks=cache),
    )
    with TestClient(application) as client:
        yield client, SuitabilityRepository.instances[0], identity_key, memtara_key


def agent_authorization(identity_key) -> dict[str, str]:
    return authorization(identity_key, identity_kind="agent", auth_strength="federated")


def proof_headers(memtara_key, **claim_overrides: Any) -> dict[str, str]:
    # `_claims` already issues over RECOMMENDED_ISIN; overrides replace individual claims.
    claims = memtara_claims(int(time.time()), **claim_overrides)
    return {
        "x-memtara-proof": memtara_token(memtara_key, claims),
        "x-memtara-chain-head": MEMTARA_CHAIN_HEAD,
    }


def test_a_genuine_suitability_proof_reaches_cedar_and_permits_the_recommendation(seam) -> None:
    """UC-2 row 2a, end to end: signed token -> verifier -> `context.mapped` -> reference policy
    -> ALLOW, with the proof carried into the evidence record.

    This is the accepting path of the seam. Every other Memtara test in the suite asserts a
    refusal, which cannot distinguish a working verifier from one that refuses everything.
    """
    client, repository, identity_key, memtara_key = seam
    response = client.post(
        "/v1/authorize",
        json=recommendation_context("018f47a6-7b42-7c00-8000-0000000002a0"),
        headers=agent_authorization(identity_key) | proof_headers(memtara_key),
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["decision"] == "ALLOW"
    assert [policy["policy_id"] for policy in body["policies"]] == [
        "pol_require-suitability-proof"
    ]

    record = repository.adr_documents[0]
    assert record["decision"] == "ALLOW"
    assert record["decision_basis"] == "matched_policy"
    # The evidence carries the issuer, the proof hash and both chain heads -- not a claim the
    # caller made about them.
    assert record["external_proofs"][0]["issuer"] == MEMTARA_ISSUER
    assert record["external_proofs"][0]["proof_hash"] == "b" * 64
    assert record["external_proofs"][0]["memtara_chain_head"] == MEMTARA_CHAIN_HEAD

    # The projection Cedar saw is the signed one, and the compact bearer is not in it.
    normalized = next(iter(repository.normalized_contexts.values()))
    assert normalized["mapped"]["source"] == "memtara"
    assert normalized["mapped"]["fields"]["suitable"] is True
    assert normalized["mapped"]["fields"]["product_isin"] == RECOMMENDED_ISIN
    assert "token" not in normalized["mapped"]["fields"]


def test_a_self_asserted_memtara_projection_never_reaches_the_decision(seam) -> None:
    """The anti-spoofing guard in `authorize`: `mapped` is a public request field, so a caller can
    put `source: "memtara", suitable: true` in its own body. With no proof header the handler
    clears it, and this body -- byte-identical in every other respect to the ALLOW above -- must
    come back DENY on the default-deny path with nothing in evidence.
    """
    client, repository, identity_key, _memtara_key = seam
    forged = recommendation_context("018f47a6-7b42-7c00-8000-0000000002a1")
    forged["mapped"] = {
        "source": "memtara",
        "fields": {
            "proof_hash": "b" * 64,
            "circuit": "wealth_suitability",
            "predicate": "structured_product_suitable",
            "product_isin": RECOMMENDED_ISIN,
            "suitable": True,
            "expires_at": 1_800_000_000,
            "jti": "forged-jti-00000001",
        },
    }

    response = client.post(
        "/v1/authorize", json=forged, headers=agent_authorization(identity_key)
    )

    assert response.status_code == 200, response.text
    assert response.json()["decision"] == "DENY"
    assert response.json()["policies"] == []
    record = repository.adr_documents[0]
    assert record["decision_basis"] == "default_deny"
    assert record["external_proofs"] == []
    # The strongest form of the claim: the asserted projection did not survive into the evidenced
    # context either, so no downstream reader can mistake it for something Mizan verified.
    assert next(iter(repository.normalized_contexts.values()))["mapped"] is None


def test_a_recommendation_with_no_proof_at_all_is_denied_and_evidenced(seam) -> None:
    """UC-2 row 3. Covered until now only as `evaluate(...) == []` inside the policy engine, which
    is a non-match and not a decision: nothing asserted that a non-match reaches the caller as
    DENY or that the refusal is recorded."""
    client, repository, identity_key, _memtara_key = seam
    response = client.post(
        "/v1/authorize",
        json=recommendation_context("018f47a6-7b42-7c00-8000-0000000002a2"),
        headers=agent_authorization(identity_key),
    )

    assert response.status_code == 200, response.text
    assert response.json()["decision"] == "DENY"
    assert repository.adr_documents[0]["decision_basis"] == "default_deny"
    assert repository.adr_documents[0]["external_proofs"] == []


def test_a_verified_decline_is_denied_over_the_wire_and_carries_its_proof(seam) -> None:
    """UC-2 row 4 at the route. `suitable: false` is a signed verdict, not an error: it is a 200
    DENY with the proof in evidence, never a 403 that would leave no record."""
    client, repository, identity_key, memtara_key = seam
    response = client.post(
        "/v1/authorize",
        json=recommendation_context("018f47a6-7b42-7c00-8000-0000000002a3"),
        headers=agent_authorization(identity_key)
        | proof_headers(memtara_key, suitable=False, jti="decline-jti-0001"),
    )

    assert response.status_code == 200, response.text
    assert response.json()["decision"] == "DENY"
    assert response.json()["reasons"] == ["suitability_declined"]
    assert repository.adr_documents[0]["external_proofs"][0]["jti"] == "decline-jti-0001"


def test_a_proof_about_another_instrument_does_not_authorize_this_recommendation(seam) -> None:
    """UC-2 row 5, wrong-ISIN half. The token verifies; `eq_field` against the tool argument is
    what refuses it, so the decision is a recorded DENY rather than a token error."""
    client, repository, identity_key, memtara_key = seam
    response = client.post(
        "/v1/authorize",
        json=recommendation_context("018f47a6-7b42-7c00-8000-0000000002a4"),
        headers=agent_authorization(identity_key)
        | proof_headers(memtara_key, product_isin="XS0000000000", jti="other-isin-0001"),
    )

    assert response.status_code == 200, response.text
    assert response.json()["decision"] == "DENY"
    assert response.json()["policies"] == []
    assert repository.adr_documents[0]["decision_basis"] == "default_deny"
    assert repository.adr_documents[0]["external_proofs"][0]["jti"] == "other-isin-0001"


def test_an_expired_proof_is_refused_at_the_verifier_and_produces_no_decision(seam) -> None:
    """UC-2 row 5, expired half -- recorded as it actually behaves, which is not what the
    catalogue promises.

    The matrix says an expired proof is a DENY. It is not: `validate_proof_token` refuses it
    before `AuthorizationService` is ever called, so the caller gets 403 `invalid_memtara_proof`
    and no ADR is written. That is a defensible design (an expired token is a malformed
    credential, not a suitability verdict) but it is a divergence from the documented matrix, and
    this test pins the real behaviour so the divergence cannot be discovered by surprise.
    """
    client, repository, identity_key, memtara_key = seam
    stale = int(time.time()) - 3600
    response = client.post(
        "/v1/authorize",
        json=recommendation_context("018f47a6-7b42-7c00-8000-0000000002a5"),
        headers=agent_authorization(identity_key)
        | proof_headers(memtara_key, exp=stale, iat=stale - 300, jti="expired-jti-0001"),
    )

    assert response.status_code == 403
    assert response.json()["type"].endswith("invalid_memtara_proof")
    assert "expired" in response.json()["detail"]
    assert repository.adr_documents == []
