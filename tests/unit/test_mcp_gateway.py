"""The gateway's contract: nothing reaches the tool server that the control plane did not permit."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import anyio
import httpx
import mcp.types as types
import pytest
from mizan import MizanClient
from mizan_mcp_gateway import (
    ConfigurationError,
    GatewayConfig,
    GatewayHandlers,
    Refusal,
    RegistrySync,
    ToolDeclaration,
    ToolGovernor,
    refusal_result,
    tool_document,
)

PROFILE = {
    "profile_id": "bp_write-file-v1",
    "profile_version": 1,
    "canonicalization": "RFC8785",
    "bound_pointers": ["/contents", "/path"],
    "volatile_pointers": [],
    "unknown_pointer_policy": "reject",
}
ARGUMENTS = {"path": "/data/report.txt", "contents": "hello"}


def config(**updates: Any) -> GatewayConfig:
    base = {
        "upstream_command": "echo",
        "mizan_url": "https://control.test",
        "agent_token": "agent-token",
        "agent_id": "agt_wealth-advisor",
        "default_declaration": ToolDeclaration(
            risk_tier="HIGH", action_type="write", bound_pointers=["/contents", "/path"]
        ),
    }
    return GatewayConfig(**(base | updates)).validated()


class FakeControlPlane:
    def __init__(
        self,
        decision: str = "ALLOW",
        approval_states: list[str] | None = None,
        authorize_status: int = 200,
    ) -> None:
        self.decision = decision
        self.approval_states = approval_states or []
        self.authorize_status = authorize_status
        self.contexts: list[dict[str, Any]] = []
        self.completions: list[dict[str, Any]] = []
        # Problem codes the capability endpoint answers with before it starts issuing.
        self.capability_refusals: list[str] = []
        self.capability_requests = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        import json

        path = request.url.path
        if path.startswith("/v1/tools/"):
            return httpx.Response(200, json={"binding_profile": PROFILE})
        if path == "/v1/authorize":
            if self.authorize_status != 200:
                return httpx.Response(
                    self.authorize_status,
                    json={"type": "https://mizan.ai/problems/evidence_write_failed"},
                )
            self.contexts.append(json.loads(request.content))
            return httpx.Response(
                200,
                json={
                    "decision_id": "adr_" + "a" * 24,
                    "decision": self.decision,
                    "risk": {"level": "HIGH", "floor_source": "tool_registry_floor"},
                    "policies": [],
                    "reasons": ["Matched pol_write v1"],
                    "constraints": None,
                    "degraded": {"is_degraded": False, "reason": "none", "grant_ref": None},
                    "approval": {"approval_id": "apr_1", "status": "PENDING", "required": True}
                    if self.decision == "REQUIRE_APPROVAL"
                    else None,
                },
            )
        if path.startswith("/v1/approvals/"):
            state = self.approval_states.pop(0) if self.approval_states else "PENDING"
            return httpx.Response(200, json={"approval_id": "apr_1", "state": state})
        if path.endswith("/complete"):
            self.completions.append(json.loads(request.content))
            return httpx.Response(200, json={"state": "EXECUTED"})
        if path.endswith("/execution-token"):
            self.capability_requests += 1
            if self.capability_refusals:
                code = self.capability_refusals.pop(0)
                return httpx.Response(403, json={"type": f"https://mizan.ai/problems/{code}"})
            return httpx.Response(200, json={"execution_token": "tok", "reused": False})
        if path.endswith("/execute"):
            return httpx.Response(200, json={"lease_id": "lse_1", "state": "LEASED"})
        return httpx.Response(404, json={"type": "https://mizan.ai/problems/not_found"})


class FakeUpstream:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.tools = [
            types.Tool(
                name="write_file",
                description="Write a file",
                inputSchema={
                    "type": "object",
                    "properties": {"path": {"type": "string"}, "contents": {"type": "string"}},
                },
            )
        ]

    async def list_tools(self) -> list[types.Tool]:
        return self.tools

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> types.CallToolResult:
        self.calls.append((name, arguments))
        return types.CallToolResult(
            content=[types.TextContent(type="text", text="wrote 5 bytes")], isError=False
        )


def handlers(plane: FakeControlPlane, upstream: FakeUpstream, **overrides: Any) -> GatewayHandlers:
    settings = config(**overrides)
    client = MizanClient(
        settings.mizan_url,
        settings.agent_token,
        agent_id=settings.agent_id,
        transport=httpx.Client(
            base_url=settings.mizan_url, transport=httpx.MockTransport(plane.handler)
        ),
    )
    return GatewayHandlers(settings, upstream, ToolGovernor(settings, client))


def call(handler: GatewayHandlers, name: str = "write_file", **meta: Any) -> types.CallToolResult:
    params = types.CallToolRequestParams(name=name, arguments=ARGUMENTS, **meta)
    return anyio.run(handler.call_tool, params)


def test_tools_list_passes_through_unchanged() -> None:
    upstream = FakeUpstream()
    listed = anyio.run(handlers(FakeControlPlane(), upstream).list_tools)
    assert [tool.name for tool in listed.tools] == ["write_file"]
    assert listed.tools[0].description == "Write a file"


def test_an_allowed_call_reaches_the_tool_server_and_carries_its_decision_back() -> None:
    plane, upstream = FakeControlPlane(), FakeUpstream()
    result = call(handlers(plane, upstream))
    assert upstream.calls == [("write_file", ARGUMENTS)]
    assert result.is_error is False
    assert result.structured_content["mizan"]["outcome"] == "allowed"
    assert result.structured_content["mizan"]["decision_id"] == "adr_" + "a" * 24
    assert plane.contexts[0]["tool"]["id"] == "tool_write-file"
    assert plane.contexts[0]["action"]["type"] == "write"


def test_a_denied_call_never_reaches_the_tool_server() -> None:
    plane, upstream = FakeControlPlane(decision="DENY"), FakeUpstream()
    result = call(handlers(plane, upstream))
    assert upstream.calls == []
    assert result.is_error is True
    assert result.structured_content["mizan"]["reason_class"] == "denied"
    assert "Matched pol_write v1" in result.content[0].text


def test_a_call_waiting_for_an_approver_never_reaches_the_tool_server() -> None:
    plane = FakeControlPlane(decision="REQUIRE_APPROVAL", approval_states=[])
    upstream = FakeUpstream()
    result = call(handlers(plane, upstream, approval_timeout_seconds=0.0))
    assert upstream.calls == []
    assert result.structured_content["mizan"]["reason_class"] == "approval_pending"
    assert result.structured_content["mizan"]["approval_id"] == "apr_1"
    assert "has not been performed" in result.content[0].text


def test_an_approved_call_proceeds_once_the_approvers_have_voted() -> None:
    plane = FakeControlPlane(
        decision="REQUIRE_APPROVAL", approval_states=["PENDING", "APPROVED"]
    )
    upstream = FakeUpstream()
    result = call(handlers(plane, upstream, approval_timeout_seconds=5.0))
    assert upstream.calls == [("write_file", ARGUMENTS)]
    assert result.structured_content["mizan"]["outcome"] == "allowed"


def test_an_unreachable_control_plane_refuses_rather_than_forwarding() -> None:
    """"The control plane was unreachable" is not a permission."""
    plane = FakeControlPlane(authorize_status=503)
    upstream = FakeUpstream()
    result = call(handlers(plane, upstream))
    assert upstream.calls == []
    assert result.is_error is True
    assert result.structured_content["mizan"]["reason_class"] == "authorization_unavailable"


def test_a_declared_intent_is_recorded_and_an_undeclared_one_is_not_invented() -> None:
    plane, upstream = FakeControlPlane(), FakeUpstream()
    call(handlers(plane, upstream))
    assert plane.contexts[-1]["intent"] == "MCP tools/call write_file"
    plane2, upstream2 = FakeControlPlane(), FakeUpstream()
    params = types.CallToolRequestParams(
        name="write_file", arguments=ARGUMENTS, meta={"mizan/intent": "file the quarterly report"}
    )
    anyio.run(handlers(plane2, upstream2).call_tool, params)
    assert plane2.contexts[-1]["intent"] == "file the quarterly report"


def test_the_gateway_refuses_to_start_without_an_identity_to_ask_with() -> None:
    with pytest.raises(ConfigurationError, match="agent_id"):
        GatewayConfig(upstream_command="echo", mizan_url="https://x", agent_token="t").validated()
    with pytest.raises(ConfigurationError, match="upstream MCP server command"):
        GatewayConfig(upstream_command="").validated()


def test_registering_unknown_tools_needs_an_operator_credential_not_the_agents() -> None:
    with pytest.raises(ConfigurationError, match="operator credential"):
        config(register_unknown_tools=True)
    assert config(register_unknown_tools=True, operator_token="op").register_unknown_tools


def test_a_declared_tier_below_the_registry_floor_cannot_be_smuggled_in() -> None:
    with pytest.raises(ConfigurationError, match="risk_tier"):
        ToolDeclaration(risk_tier="NEGLIGIBLE").validated("write_file")
    with pytest.raises(ConfigurationError, match="action_type"):
        ToolDeclaration(action_type="do_whatever").validated("write_file")
    with pytest.raises(ConfigurationError, match="overlap"):
        ToolDeclaration(bound_pointers=["/a"], volatile_pointers=["/a"]).validated("write_file")


def test_every_unclassified_argument_is_bound_by_default() -> None:
    document = tool_document(
        config(),
        "write_file",
        ToolDeclaration(),
        "tnt_bank-a",
        {"type": "object", "properties": {"path": {}, "contents": {}}},
    )
    assert document["binding_profile"]["bound_pointers"] == ["/contents", "/path"]
    assert document["binding_profile"]["unknown_pointer_policy"] == "reject"
    assert document["risk_tier"] == "HIGH"


class FakeRegistry:
    def __init__(self, existing: set[str]) -> None:
        self.existing = existing
        self.created: list[dict[str, Any]] = []
        self.authorizations: list[str] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        import json

        self.authorizations.append(request.headers.get("authorization", ""))
        if request.method == "GET":
            tool_id = request.url.path.rsplit("/", 1)[-1]
            if tool_id in self.existing:
                return httpx.Response(200, json={"tool_id": tool_id, "risk_tier": "CRITICAL"})
            return httpx.Response(404, json={"type": "https://mizan.ai/problems/not_found"})
        self.created.append(json.loads(request.content))
        return httpx.Response(201, json=self.created[-1])


def test_registration_skips_governed_tools_and_never_lowers_their_tier() -> None:
    registry = FakeRegistry(existing={"tool_write-file"})
    settings = config(register_unknown_tools=True, operator_token="operator-token")
    sync = RegistrySync(
        settings,
        transport=httpx.Client(
            base_url=settings.mizan_url, transport=httpx.MockTransport(registry.handler)
        ),
    )
    sync.ensure(
        [
            {"name": "write_file", "inputSchema": {"properties": {"path": {}}}},
            {"name": "read_file", "inputSchema": {"properties": {"path": {}}}},
        ],
        "tnt_bank-a",
    )
    assert sync.skipped == ["tool_write-file"]
    assert sync.registered == ["tool_read-file"]
    assert [item["tool_id"] for item in registry.created] == ["tool_read-file"]
    assert all(item == "Bearer operator-token" for item in registry.authorizations)


def test_a_tool_that_could_not_be_registered_is_left_unknown_not_ungoverned() -> None:
    class Refusing(FakeRegistry):
        def handler(self, request: httpx.Request) -> httpx.Response:
            if request.method == "GET":
                return httpx.Response(404, json={})
            return httpx.Response(403, json={"type": ".../registry_write_auth_insufficient"})

    registry = Refusing(existing=set())
    settings = config(register_unknown_tools=True, operator_token="operator-token")
    sync = RegistrySync(
        settings,
        transport=httpx.Client(
            base_url=settings.mizan_url, transport=httpx.MockTransport(registry.handler)
        ),
    )
    sync.ensure([{"name": "write_file", "inputSchema": {"properties": {"path": {}}}}], "tnt_bank-a")
    assert sync.registered == []
    # It is not in the registry, so /v1/authorize answers tool_not_permitted and the call is
    # refused — the failure mode is "refused", never "forwarded ungoverned".


def test_identical_calls_are_each_authorized_because_there_is_no_local_cache() -> None:
    """A second identical call is a second decision. Caching an allow would make the evidence a
    sample rather than a record, and would let a revoked policy keep working."""
    plane, upstream = FakeControlPlane(), FakeUpstream()
    handler = handlers(plane, upstream)
    call(handler)
    call(handler)
    assert len(plane.contexts) == 2
    assert len(upstream.calls) == 2
    assert plane.contexts[0]["request_id"] != plane.contexts[1]["request_id"]


def test_the_governor_cannot_produce_a_permission_the_control_plane_did_not_give() -> None:
    plane, upstream = FakeControlPlane(authorize_status=500), FakeUpstream()
    handler = handlers(plane, upstream)
    for _ in range(3):
        verdict = handler.governor.authorize("write_file", ARGUMENTS, intent="probe")
        assert isinstance(verdict, Refusal)
    assert upstream.calls == []


def test_a_refusal_names_its_reason_class_for_the_model() -> None:
    result = refusal_result(Refusal("denied", "Mizan refused this call.", "adr_x"))
    assert result.is_error is True
    assert "adr_x" in result.content[0].text
    assert result.structured_content["mizan"]["reason_class"] == "denied"


EXECUTOR = {"executor_spiffe_id": "spiffe://mizan/executor/gateway", "mizan_url": "http://cp.test"}


def test_an_authorized_call_whose_capability_is_refused_is_never_performed() -> None:
    """ALLOW is not permission to act; the capability is.

    The control plane can allow a decision and still refuse to issue the execution token that
    binds it — a revoked delegation, an unpublished record, an executor that is no longer
    registered. Forwarding on the strength of the ALLOW alone would be the gateway's only
    fail-open path, so the call is refused and the tool server never hears about it.
    """
    plane, upstream = FakeControlPlane(), FakeUpstream()
    plane.capability_refusals = ["delegation_authority_changed"]
    result = call(handlers(plane, upstream, **EXECUTOR))
    assert upstream.calls == []
    assert result.is_error is True
    assert result.structured_content["mizan"]["reason_class"] == "execution_binding_unavailable"


def test_an_executor_that_arrives_before_the_publisher_waits_rather_than_refusing() -> None:
    """Evidence publication is asynchronous (ADR-004); arriving early is not being refused."""
    plane, upstream = FakeControlPlane(), FakeUpstream()
    plane.capability_refusals = ["immutable_receipt_missing", "immutable_receipt_missing"]
    result = call(handlers(plane, upstream, execution_binding_retry_seconds=5.0, **EXECUTOR))
    assert plane.capability_requests == 3
    assert upstream.calls == [("write_file", ARGUMENTS)]
    assert result.structured_content["mizan"]["lease_id"] == "lse_1"


def test_waiting_for_the_publisher_is_bounded_and_then_the_call_is_refused() -> None:
    plane, upstream = FakeControlPlane(), FakeUpstream()
    plane.capability_refusals = ["immutable_receipt_missing"] * 50
    result = call(handlers(plane, upstream, execution_binding_retry_seconds=0.0, **EXECUTOR))
    assert plane.capability_requests == 1
    assert upstream.calls == []
    assert result.structured_content["mizan"]["reason_class"] == "execution_binding_unavailable"


def test_an_executor_identity_over_tls_without_a_client_certificate_is_refused() -> None:
    """The authorized executor is read off the verified peer certificate, never off a header."""
    with pytest.raises(ConfigurationError, match="mutual TLS"):
        config(executor_spiffe_id="spiffe://mizan/executor/gateway")
    with pytest.raises(ConfigurationError, match="private key"):
        config(client_certificate_file="/tmp/client.pem")


def test_the_documented_example_configuration_is_one_the_gateway_accepts() -> None:
    """The example file is the operator-facing surface; a stale key there is a broken product."""
    from mizan_mcp_gateway.config import load

    settings = load(Path("integrations/mcp/example.toml"))
    assert settings.tool_id("write_file") == "tool_write-file"
    assert settings.declaration("write_file").bound_pointers == ["/contents", "/path"]
    assert settings.declaration("anything_else").risk_tier == "HIGH"
