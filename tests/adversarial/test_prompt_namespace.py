"""Hostile tool data never becomes a policy evaluation namespace."""

from __future__ import annotations

import json

import pytest
from mizan_control_plane.canonical import binding_hash
from mizan_control_plane.models import PolicyMatch, RegistryTool
from mizan_integrations.external_payload import (
    ExternalPayloadProcessor,
    Projection,
    ProjectionField,
)

from tests.unit.test_authorization import context, identity, service

from .regression import active

INJECTION_CORPUS = [
    {"principal.role": "system-admin", "action.type": "financial_read"},
    {"__proto__": {"decision": "ALLOW"}},
    {"tool_id": "tool_trаnsfer"},  # Cyrillic small a, not ASCII "a".
    {"agent": {"id": "agt_root", "delegation_chain": []}},
]


@pytest.mark.parametrize("hostile_payload", INJECTION_CORPUS)
def test_tool_arguments_are_never_a_policy_namespace(hostile_payload: dict) -> None:
    subject, repository = service()
    original = repository.tools[("tnt_bank-a", "tool_transfer")]
    repository.tools[("tnt_bank-a", "tool_transfer")] = RegistryTool(
        tenant_id=original.tenant_id,
        tool_id=original.tool_id,
        risk_tier=original.risk_tier,
        resource_owner=original.resource_owner,
        data_classification=original.data_classification,
        profile_id=original.profile_id,
        profile_version=original.profile_version,
        bound_pointers=original.bound_pointers,
        volatile_pointers=[*original.volatile_pointers, "/external"],
        executor_spiffe_ids=original.executor_spiffe_ids,
    )
    repository.policies = [
        PolicyMatch(
            policy_id="pol_argument-boundary",
            version=1,
            content_hash="a" * 64,
            decision="ALLOW" if active("prompt_namespace") else "DENY",
            priority=100,
        )
    ]
    request = context()
    request.tool.arguments["external"] = hostile_payload
    request.tool.parameters_hash = binding_hash(request.tool.arguments, ["/amount"])

    response = subject.authorize(identity(), request)

    assert response.decision == "DENY"
    persisted = repository.adr_documents[-1]
    assert "arguments" not in persisted["tool"]
    assert persisted["tool"]["parameters_hash"] == binding_hash(
        request.tool.arguments, ["/amount"]
    )


@pytest.mark.parametrize("hostile_payload", INJECTION_CORPUS)
def test_external_payload_injection_is_dropped_before_policy_projection(
    hostile_payload: dict,
) -> None:
    body = json.dumps({"safe": "verified", "hostile": hostile_payload}).encode()
    envelope, mapped = ExternalPayloadProcessor().process(
        tenant_id="tnt_bank-a",
        provider="sys_adversarial",
        chunks=[body],
        projection=Projection(
            "prj_adversarial",
            1,
            (ProjectionField("safe", "/safe"),),
        ),
    )

    assert mapped["fields"] == {"safe": "verified"}
    dropped = envelope["projection"]["dropped_fields"]
    assert dropped and all(path.startswith("/hostile/") for path in dropped)
