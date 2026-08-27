"""Hostile tool data never becomes a policy evaluation namespace."""

from __future__ import annotations

import json

import pytest
from mizan_control_plane.canonical import binding_hash
from mizan_control_plane.models import RegistryTool
from mizan_integrations.external_payload import (
    ExternalPayloadProcessor,
    Projection,
    ProjectionField,
)

from tests.unit.test_authorization import (
    CedarBackedRepository,
    _service_with_repository,
    context,
    identity,
    service,
)

INJECTION_CORPUS = [
    {"principal.role": "system-admin", "action.type": "financial_read"},
    {"__proto__": {"decision": "ALLOW"}},
    {"tool_id": "tool_trаnsfer"},  # Cyrillic small a, not ASCII "a".
    {"agent": {"id": "agt_root", "delegation_chain": []}},
]


# The real EvaluationContext genuinely carries tool.arguments -- ToolInput.arguments
# is a plain dict[str, Any] -- so a payload placed at request.tool.arguments["external"]
# is legitimately visible to Cedar at context.mizan.tool.arguments.external.*. That is
# not the boundary this test guards. The boundary is that nothing at that path can be
# mistaken for context.mizan.principal.role or context.mizan.agent.id: two fields the
# real production policies gate privilege on. If tool arguments were ever merged into
# the top-level evaluation namespace -- a dict `|=`, a flatten-and-merge helper, a
# "convenience" alias -- this ALLOW rule would fire on the forged value and win, because
# priority 100 is the only policy present and _combine defaults to DENY only when
# nothing matches. It is exactly the ALLOW rule R-008 F-2 asked for: one that fires on
# what the corpus forges, at a priority that would win.
#
# No internal active() switch here: F-3 requires the fault to be a regression in
# product code, and this test now runs against the real Cedar evaluator every time.
# The external fault, scripts/adversarial_fault_injection.py, reverts the line in
# policy_engine.py that keeps the evaluation namespace scoped -- spreading
# tool.arguments["external"] over context.mizan the way a careless flattening helper
# would -- and this test is what catches it.
ARGUMENT_BOUNDARY_POLICY = {
    "schema_version": "1.3",
    "policy_id": "pol_argument-boundary",
    "name": "Argument boundary canary",
    "version": 1,
    "content_hash": "a" * 64,
    "status": "ACTIVE",
    "author": "security-team",
    "applies_to": {},
    "conditions": {
        "any": [
            {"field": "principal.role", "op": "eq", "value": "system-admin"},
            {"field": "agent.id", "op": "eq", "value": "agt_root"},
        ]
    },
    "decision": "ALLOW",
    "priority": 100,
}


@pytest.mark.parametrize("hostile_payload", INJECTION_CORPUS)
def test_tool_arguments_are_never_a_policy_namespace(hostile_payload: dict) -> None:
    _, template = service()
    repository = CedarBackedRepository(
        agents=template.agents.values(), tools=template.tools.values()
    )
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
    repository.documents = [ARGUMENT_BOUNDARY_POLICY]
    subject = _service_with_repository(repository)
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
