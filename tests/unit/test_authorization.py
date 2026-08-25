from __future__ import annotations

import pytest
from mizan_control_plane.canonical import binding_hash
from mizan_control_plane.models import (
    AuthenticatedIdentity,
    EvaluationContext,
    RegistryAgent,
    RegistryTool,
)
from mizan_control_plane.problems import Problem
from mizan_control_plane.repository import InMemoryAuthorizationRepository
from mizan_control_plane.risk import RegistryFloorRiskProvider
from mizan_control_plane.service import AuthorizationService

TENANT = "tnt_bank-a"
AGENT = "agt_wealth-01"
TOOL = "tool_transfer"


def context(request_id: str = "018f47a6-7b42-7c00-8000-000000000001") -> EvaluationContext:
    parameters = {"amount": 12500, "request_time": "volatile"}
    return EvaluationContext.model_validate(
        {
            "schema_version": "1.1",
            "request_id": request_id,
            "tenant_id": TENANT,
            "principal": {
                "id": "prn_alice-01",
                "type": "employee",
                "role": "advisor",
                "auth_strength": "mfa",
            },
            "agent": {"id": AGENT, "version": "1.0.0", "delegation_chain": [AGENT]},
            "intent": "rebalance portfolio",
            "tool": {
                "id": TOOL,
                "parameters": parameters,
                "parameters_hash": binding_hash(parameters, ["/amount"]),
                "binding_profile": {"profile_id": "bp_transfer-v1", "profile_version": 1},
            },
            "action": {
                "type": "financial_write",
                "estimated_value": {"amount": 12500, "currency": "AED"},
            },
            "resource": {"id": "portfolio/42", "type": "portfolio"},
            "environment": {"trace_id": "a" * 32},
        }
    )


def identity(tenant_id: str = TENANT) -> AuthenticatedIdentity:
    return AuthenticatedIdentity(
        tenant_id=tenant_id,
        agent_id=AGENT,
        subject="spiffe://mizan/agent/wealth-01",
        delegation_chain=[AGENT],
    )


def service() -> tuple[AuthorizationService, InMemoryAuthorizationRepository]:
    repository = InMemoryAuthorizationRepository(
        agents=[
            RegistryAgent(
                tenant_id=TENANT,
                agent_id=AGENT,
                version="1.0.0",
                lifecycle_state="ACTIVE",
                permitted_tools={TOOL},
            )
        ],
        tools=[
            RegistryTool(
                tenant_id=TENANT,
                tool_id=TOOL,
                risk_tier="HIGH",
                resource_owner="core-banking",
                data_classification="financial",
                profile_id="bp_transfer-v1",
                profile_version=1,
                bound_pointers=["/amount"],
                volatile_pointers=["/request_time"],
                executor_spiffe_ids=["spiffe://mizan/executor/wealth"],
            )
        ],
    )
    return AuthorizationService(
        repository, RegistryFloorRiskProvider(), "test", "f" * 64
    ), repository


def test_no_matching_policy_is_recorded_default_deny() -> None:
    subject, repository = service()
    response = subject.authorize(identity(), context())
    assert response.decision == "DENY"
    assert response.policies == []
    assert repository.adr_documents[0]["decision_basis"] == "default_deny"
    assert repository.adr_documents[0]["resource"]["resource_owner"] == "core-banking"
    assert repository.adr_documents[0]["risk"]["level"] == "HIGH"


def test_tenant_is_derived_from_identity() -> None:
    subject, _ = service()
    with pytest.raises(Problem, match="tenant") as raised:
        subject.authorize(identity("tnt_bank-b"), context())
    assert raised.value.status == 403


def test_binding_hash_rejects_parameter_substitution() -> None:
    subject, _ = service()
    request = context()
    request.tool.parameters["amount"] = 99999
    with pytest.raises(Problem, match="binding hash") as raised:
        subject.authorize(identity(), request)
    assert raised.value.status == 400


def test_i14_volatile_retry_fields_do_not_change_binding_hash() -> None:
    first = {"amount": 12500, "request_time": "2026-08-25T00:00:00Z"}
    retry = {"amount": 12500, "request_time": "2026-08-25T00:05:00Z"}
    assert binding_hash(first, ["/amount"]) == binding_hash(retry, ["/amount"])
    retry["amount"] = 12501
    assert binding_hash(first, ["/amount"]) != binding_hash(retry, ["/amount"])


def test_unknown_argument_without_binding_class_is_rejected() -> None:
    subject, _ = service()
    request = context()
    request.tool.parameters["attacker_added"] = True
    with pytest.raises(Problem, match="binding class"):
        subject.authorize(identity(), request)


def test_idempotent_retry_returns_same_decision() -> None:
    subject, repository = service()
    first = subject.authorize(identity(), context())
    second = subject.authorize(identity(), context())
    assert second == first
    assert len(repository.adr_documents) == 1


def test_request_id_reuse_with_different_context_is_conflict() -> None:
    subject, _ = service()
    first = context()
    subject.authorize(identity(), first)
    changed = context()
    changed.intent = "different intent"
    with pytest.raises(Problem) as raised:
        subject.authorize(identity(), changed)
    assert raised.value.status == 409


def test_evidence_failure_prevents_decision_response() -> None:
    subject, repository = service()
    repository.fail_writes = True
    with pytest.raises(Problem) as raised:
        subject.authorize(identity(), context())
    assert raised.value.status == 503


def test_delegation_requires_registered_edge_depth_and_parent_tool_permission() -> None:
    child = "agt_child-01"
    parent = RegistryAgent(
        tenant_id=TENANT,
        agent_id=AGENT,
        version="1.0.0",
        lifecycle_state="ACTIVE",
        permitted_tools={TOOL},
        allowed_agent_ids={child},
        max_delegation_depth=1,
    )
    delegated = RegistryAgent(
        tenant_id=TENANT,
        agent_id=child,
        version="1.0.0",
        lifecycle_state="ACTIVE",
        permitted_tools={TOOL},
        parent_agent_id=AGENT,
    )
    _, template = service()
    repository = InMemoryAuthorizationRepository(
        agents=[parent, delegated],
        tools=template.tools.values(),
    )
    subject = AuthorizationService(repository, RegistryFloorRiskProvider(), "test", "f" * 64)
    request = context()
    request.agent.id = child
    request.agent.delegation_chain = [AGENT, child]
    delegated_identity = AuthenticatedIdentity(
        tenant_id=TENANT,
        agent_id=child,
        subject="spiffe://mizan/agent/child",
        delegation_chain=[AGENT, child],
    )
    assert subject.authorize(delegated_identity, request).decision == "DENY"
    repository.agents[(TENANT, AGENT)].permitted_tools.clear()
    request.request_id = "018f47a6-7b42-7c00-8000-000000000077"
    with pytest.raises(Problem, match="delegate this tool"):
        subject.authorize(delegated_identity, request)
