"""Live policy-studio replay over immutable decision contexts."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from mizan_control_plane.app import create_app
from mizan_control_plane.canonical import binding_hash
from mizan_control_plane.config import Settings
from mizan_control_plane.dev_token import ensure_keypair, mint
from mizan_control_plane.models import (
    AuthenticatedIdentity,
    AuthenticatedPrincipal,
    EvaluationContext,
)
from mizan_control_plane.registry import RegistryRepository, policy_semantic_hash
from mizan_control_plane.repository import PostgresAuthorizationRepository
from mizan_control_plane.risk import RegistryFloorRiskProvider
from mizan_control_plane.schema_validation import ContractSchemas
from mizan_control_plane.service import AuthorizationService

from tests.unit.test_authorization import context

TENANT = "tnt_bank-a"


def replay_context(
    request_id: str,
    intent: str,
    action_type: str,
    binding_profile: dict,
) -> EvaluationContext:
    document = context(request_id).model_dump(mode="json")
    document["intent"] = intent
    document["action"]["type"] = action_type
    document["tool"]["binding_profile"] = {
        "profile_id": binding_profile["profile_id"],
        "profile_version": binding_profile["profile_version"],
    }
    document["tool"]["parameters_hash"] = binding_hash(
        document["tool"]["arguments"], binding_profile["bound_pointers"]
    )
    return EvaluationContext.model_validate(document)


def headers(private_key: bytes, tenant_id: str = TENANT) -> dict[str, str]:
    token = mint(
        private_key,
        tenant_id=tenant_id,
        subject="prn_policy-author",
        agent_id="agt_wealth-01",
        identity_kind="human",
        auth_strength="hardware",
        roles=["registry.admin"],
        audience="mizan-control-plane",
        ttl_seconds=300,
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.skipif(not os.getenv("MIZAN_TEST_DATABASE_URL"), reason="Postgres not configured")
def test_policy_studio_replay_returns_exactly_the_seeded_flip_set(monkeypatch, tmp_path) -> None:
    database_url = os.environ["MIZAN_TEST_DATABASE_URL"]
    authorization_repository = PostgresAuthorizationRepository(database_url)
    registry_repository = RegistryRepository(database_url)
    service = AuthorizationService(
        authorization_repository,
        RegistryFloorRiskProvider(),
        "policy-studio-integration",
        "8" * 64,
    )
    identity = AuthenticatedIdentity(
        tenant_id=TENANT,
        agent_id="agt_wealth-01",
        subject="spiffe://mizan/agent/wealth-01",
        delegation_chain=["agt_wealth-01"],
    )
    actor = AuthenticatedPrincipal(
        tenant_id=TENANT,
        principal_id="prn_policy-author",
        identity_kind="human",
        auth_strength="hardware",
        roles=["registry.admin"],
    )
    draft = {
        "schema_version": "1.3",
        "policy_id": "pol_studio-replay",
        "tenant_id": TENANT,
        "name": "Policy studio replay fixture",
        "version": 1,
        "status": "DRAFT",
        "author": actor.principal_id,
        "applies_to": {"tool_ids": ["tool_transfer"]},
        "conditions": {"field": "action.type", "op": "eq", "value": "financial_read"},
        "decision": "ALLOW",
        "priority": 200,
        "content_hash": "0" * 64,
        "created_at": "2026-08-27T05:30:00Z",
    }
    draft["content_hash"] = policy_semantic_hash(draft)
    closed_loop_status: str | None = None

    try:
        registry_repository.create_policy(TENANT, draft, actor)
        with registry_repository.pool.connection() as connection, connection.transaction():
            registry_repository._scope(connection, TENANT)
            closed_loop_row = connection.execute(
                "SELECT status FROM mizan.policies "
                "WHERE tenant_id=%s AND policy_id='pol_loop-rebalance' AND version=1",
                (TENANT,),
            ).fetchone()
            if closed_loop_row:
                closed_loop_status = closed_loop_row[0]
                connection.execute(
                    "UPDATE mizan.policies SET status='SUPERSEDED' "
                    "WHERE tenant_id=%s AND policy_id='pol_loop-rebalance' AND version=1",
                    (TENANT,),
                )
        binding_profile = registry_repository.get(TENANT, "tools", "tool_transfer")[
            "binding_profile"
        ]
        historical_allow = service.authorize(
            identity,
            replay_context(
                "018f47a6-7b42-7c00-8000-000000000810",
                "historical-active-match",
                "financial_write",
                binding_profile,
            ),
        )
        historical_deny = service.authorize(
            identity,
            replay_context(
                "018f47a6-7b42-7c00-8000-000000000811",
                "draft-matches-financial-read",
                "financial_read",
                binding_profile,
            ),
        )
        unchanged_deny = service.authorize(
            identity,
            replay_context(
                "018f47a6-7b42-7c00-8000-000000000812",
                "matches-neither-policy",
                "read",
                binding_profile,
            ),
        )
        assert [historical_allow.decision, historical_deny.decision, unchanged_deny.decision] == [
            "ALLOW",
            "DENY",
            "DENY",
        ]

        private_key, public_key = ensure_keypair(tmp_path / "keys")
        monkeypatch.setenv("MIZAN_DATABASE_URL", database_url)
        monkeypatch.setenv("MIZAN_JWT_ISSUER", "urn:mizan:development:dev-token")
        monkeypatch.setenv("MIZAN_JWT_PUBLIC_KEY", public_key)
        monkeypatch.setenv("MIZAN_EVIDENCE_OBJECT_STORE_ROOT", str(tmp_path / "evidence"))
        application = create_app(Settings.from_environment())
        schemas = ContractSchemas(Path("SPEC_v1.md"))

        with TestClient(application) as client:
            auth = headers(private_key)
            page_response = client.get("/v1/decisions?limit=3", headers=auth)
            assert page_response.status_code == 200, page_response.text
            decisions = page_response.json()["items"]
            seeded_ids = {
                historical_allow.decision_id,
                historical_deny.decision_id,
                unchanged_deny.decision_id,
            }
            assert {item["decision_id"] for item in decisions} == seeded_ids

            flips: dict[str, tuple[str, str]] = {}
            for decision in decisions:
                context_response = client.get(
                    f"/v1/decisions/{decision['decision_id']}/context", headers=auth
                )
                assert context_response.status_code == 200, context_response.text
                stored = context_response.json()
                schemas.validate("ContextResponse", stored)
                assert "arguments" not in stored["context"]["tool"]
                simulation_context = stored["context"]
                simulation_context["tool"]["arguments"] = {}
                simulation_response = client.post(
                    f"/v1/policies/{draft['policy_id']}/simulate",
                    json={"version": 1, "context": simulation_context},
                    headers=auth,
                )
                assert simulation_response.status_code == 200, simulation_response.text
                simulated = simulation_response.json()["decision"]
                if simulated != decision["decision"]:
                    flips[decision["decision_id"]] = (decision["decision"], simulated)

            assert flips == {
                historical_allow.decision_id: ("ALLOW", "DENY"),
                historical_deny.decision_id: ("DENY", "ALLOW"),
            }
            assert unchanged_deny.decision_id not in flips

            hidden = client.get(
                f"/v1/decisions/{historical_allow.decision_id}/context",
                headers=headers(private_key, "tnt_bank-b"),
            )
            assert hidden.status_code == 404
            assert hidden.json()["type"].endswith("decision_context_not_found")

            transitioned = client.post(
                f"/v1/policies/{draft['policy_id']}/transition",
                json={"version": 1, "target_status": "TESTED"},
                headers=auth,
            )
            assert transitioned.status_code == 200, transitioned.text
            assert transitioned.json()["status"] == "TESTED"
    finally:
        if closed_loop_status is not None:
            with registry_repository.pool.connection() as connection, connection.transaction():
                registry_repository._scope(connection, TENANT)
                connection.execute(
                    "UPDATE mizan.policies SET status=%s "
                    "WHERE tenant_id=%s AND policy_id='pol_loop-rebalance' AND version=1",
                    (closed_loop_status, TENANT),
                )
        authorization_repository.pool.close()
        registry_repository.pool.close()
