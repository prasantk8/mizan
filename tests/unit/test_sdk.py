"""The SDK's job is to be correct about the two things a client can get wrong on its own:
the binding hash and the request shape. Everything else it must not decide."""

from __future__ import annotations

import re
from typing import Any

import httpx
import pytest
from mizan.adapters import GovernedTool, GovernedToolRouter
from mizan.binding import UnclassifiedArgument, parameters_hash
from mizan.client import MizanClient, Principal, Resource, rfc3339_now, uuid7
from mizan.decorator import govern
from mizan.errors import ApprovalRejected, ApprovalTimeout, Denied, ProblemError
from mizan_control_plane.canonical import binding_hash

RESOURCE = Resource("portfolio/42", "portfolio", "core-banking", "financial")
ALICE = Principal(id="prn_alice-01", role="advisor")
PROFILE = {
    "profile_id": "bp_transfer-v1",
    "profile_version": 1,
    "canonicalization": "RFC8785",
    "bound_pointers": ["/amount", "/customer_id"],
    "volatile_pointers": ["/request_time"],
    "unknown_pointer_policy": "reject",
}


@pytest.mark.parametrize(
    "arguments",
    [
        {"amount": 12500, "customer_id": "cus_42", "request_time": "x"},
        {"customer_id": "cus_42", "amount": 12500, "request_time": "y"},
        {"amount": 0, "customer_id": "", "request_time": None},
        {"amount": {"value": 1, "currency": "AED"}, "customer_id": ["a", "b"], "request_time": 1},
    ],
)
def test_the_sdk_and_the_control_plane_compute_the_same_binding_hash(arguments: dict) -> None:
    """Two independent implementations, one answer — which is what makes the server's recompute
    a check rather than an echo."""
    assert parameters_hash(arguments, PROFILE["bound_pointers"]) == binding_hash(
        arguments, PROFILE["bound_pointers"]
    )


def test_a_bound_pointer_the_arguments_do_not_carry_is_refused_before_the_call() -> None:
    with pytest.raises(UnclassifiedArgument, match="/customer_id"):
        parameters_hash({"amount": 1}, ["/amount", "/customer_id"])


def test_request_ids_are_uuid7_and_time_ordered() -> None:
    first, second = uuid7(), uuid7()
    assert first.version == 7 and second.version == 7
    assert first.hex[:12] <= second.hex[:12]
    assert len({str(uuid7()) for _ in range(200)}) == 200


def test_timestamps_carry_millisecond_precision_and_a_z_suffix() -> None:
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", rfc3339_now())


class FakeControlPlane:
    """Answers like the control plane does; decides nothing the control plane would not."""

    def __init__(self, decision: str = "ALLOW", approval_states: list[str] | None = None) -> None:
        self.decision = decision
        self.approval_states = approval_states or []
        self.contexts: list[dict[str, Any]] = []
        self.proof_headers: list[str | None] = []
        self.chain_head_headers: list[str | None] = []
        self.token_requests: list[str] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.startswith("/v1/tools/"):
            return httpx.Response(200, json={"tool_id": "tool_transfer", "binding_profile": PROFILE})
        if path == "/v1/authorize":
            import json as _json

            context = _json.loads(request.content)
            self.contexts.append(context)
            self.proof_headers.append(request.headers.get("x-memtara-proof"))
            self.chain_head_headers.append(request.headers.get("x-memtara-chain-head"))
            body = {
                "decision_id": "adr_" + "a" * 24,
                "decision": self.decision,
                "risk": {"level": "HIGH", "floor_source": "tool_registry_floor"},
                "policies": [],
                "reasons": ["Matched pol_transfer v1"],
                "constraints": None,
                "degraded": {"is_degraded": False, "reason": "none", "grant_ref": None},
                "approval": {"approval_id": "apr_1", "status": "PENDING", "required": True}
                if self.decision == "REQUIRE_APPROVAL"
                else None,
            }
            return httpx.Response(200, json=body)
        if path.startswith("/v1/approvals/"):
            state = self.approval_states.pop(0) if self.approval_states else "PENDING"
            return httpx.Response(200, json={"approval_id": "apr_1", "state": state})
        if path.endswith("/execution-token"):
            self.token_requests.append(path)
            return httpx.Response(
                200, json={"execution_token": "tok", "expires_at": "z", "reused": False}
            )
        return httpx.Response(404, json={"type": "https://mizan.ai/problems/not_found"})


def client_for(plane: FakeControlPlane) -> MizanClient:
    transport = httpx.Client(
        base_url="https://control.test", transport=httpx.MockTransport(plane.handler)
    )
    return MizanClient(
        "https://control.test",
        "token",
        agent_id="agt_wealth-01",
        transport=transport,
    )


def test_the_context_the_sdk_builds_is_accepted_by_the_ratified_schema() -> None:
    from pathlib import Path

    from mizan_control_plane.schema_validation import ContractSchemas

    plane = FakeControlPlane()
    with client_for(plane) as mizan:
        context = mizan.build_context(
            tool_id="tool_transfer",
            arguments={"amount": 12500, "customer_id": "cus_42", "request_time": "t"},
            action_type="financial_write",
            intent="rebalance the portfolio",
            principal=ALICE,
            resource=RESOURCE,
            business={"transaction_value": {"amount": 12500, "currency": "AED"}},
        )
    ContractSchemas(Path("SPEC_v1.md")).validate("EvaluationContext", context)
    assert context["tool"]["binding_profile"] == {
        "profile_id": "bp_transfer-v1",
        "profile_version": 1,
    }


def test_the_binding_profile_comes_from_the_registry_not_from_the_caller() -> None:
    plane = FakeControlPlane()
    with client_for(plane) as mizan:
        mizan.decide(
            tool_id="tool_transfer",
            arguments={"amount": 12500, "customer_id": "cus_42", "request_time": "t"},
            action_type="financial_write",
            intent="rebalance",
            principal=ALICE,
            resource=RESOURCE,
        )
    context = plane.contexts[0]
    assert context["tool"]["parameters_hash"] == binding_hash(
        context["tool"]["arguments"], PROFILE["bound_pointers"]
    )


def test_the_client_carries_a_memtara_proof_only_on_the_authorization_request() -> None:
    plane = FakeControlPlane()
    opaque_token = "not.a-token-the-sdk-understands"
    opaque_chain_head = "not-validated-by-the-sdk"
    with client_for(plane) as mizan:
        mizan.decide(
            tool_id="tool_transfer",
            arguments={"amount": 1, "customer_id": "c", "request_time": "t"},
            action_type="financial_write",
            intent="recommend a product",
            principal=ALICE,
            resource=RESOURCE,
            proof_token=opaque_token,
            memtara_chain_head=opaque_chain_head,
        )
        mizan.decide(
            tool_id="tool_transfer",
            arguments={"amount": 2, "customer_id": "c", "request_time": "t"},
            action_type="financial_write",
            intent="read a product",
            principal=ALICE,
            resource=RESOURCE,
        )
    assert plane.proof_headers == [opaque_token, None]
    assert plane.chain_head_headers == [opaque_chain_head, None]
    assert all("proof" not in context for context in plane.contexts)


def test_the_decorator_accepts_static_and_per_call_memtara_proofs() -> None:
    plane = FakeControlPlane()
    mizan = client_for(plane)
    performed: list[int] = []

    @govern(
        tool_id="tool_transfer",
        action_type="financial_write",
        resource=RESOURCE,
        client=mizan,
        proof_token="static.opaque.proof",
        memtara_chain_head="static-opaque-chain-head",
    )
    def static_proof(amount: int, customer_id: str, request_time: str) -> None:
        performed.append(amount)

    @govern(
        tool_id="tool_transfer",
        action_type="financial_write",
        resource=RESOURCE,
        client=mizan,
        proof_token_factory=lambda **arguments: f"proof-for-{arguments['customer_id']}",
        memtara_chain_head_factory=lambda **arguments: f"head-for-{arguments['customer_id']}",
    )
    def fresh_proof(amount: int, customer_id: str, request_time: str) -> None:
        performed.append(amount)

    try:
        static_proof(amount=1, customer_id="c1", request_time="t")
        fresh_proof(amount=2, customer_id="c2", request_time="t")
    finally:
        mizan.close()
    assert performed == [1, 2]
    assert plane.proof_headers == ["static.opaque.proof", "proof-for-c2"]
    assert plane.chain_head_headers == ["static-opaque-chain-head", "head-for-c2"]


def test_the_decorator_refuses_two_proof_sources() -> None:
    with pytest.raises(ValueError, match="proof_token or proof_token_factory"):
        govern(
            tool_id="tool_transfer",
            action_type="financial_write",
            resource=RESOURCE,
            proof_token="one",
            proof_token_factory=lambda **_: "two",
        )
    with pytest.raises(ValueError, match="memtara_chain_head or memtara_chain_head_factory"):
        govern(
            tool_id="tool_transfer",
            action_type="financial_write",
            resource=RESOURCE,
            memtara_chain_head="one",
            memtara_chain_head_factory=lambda **_: "two",
        )


def test_a_denial_is_raised_with_the_recorded_reasons() -> None:
    plane = FakeControlPlane(decision="DENY")
    with client_for(plane) as mizan, pytest.raises(Denied) as raised:
        mizan.decide(
            tool_id="tool_transfer",
            arguments={"amount": 1, "customer_id": "c", "request_time": "t"},
            action_type="financial_write",
            intent="rebalance",
            principal=ALICE,
            resource=RESOURCE,
        )
    assert raised.value.reasons == ["Matched pol_transfer v1"]


def test_require_approval_blocks_until_an_approver_acts() -> None:
    plane = FakeControlPlane(
        decision="REQUIRE_APPROVAL", approval_states=["PENDING", "PARTIALLY_APPROVED", "APPROVED"]
    )
    seen: list[str] = []
    with client_for(plane) as mizan:
        decision = mizan.decide(
            tool_id="tool_transfer",
            arguments={"amount": 1, "customer_id": "c", "request_time": "t"},
            action_type="financial_write",
            intent="rebalance",
            principal=ALICE,
            resource=RESOURCE,
            approval_timeout_seconds=5,
            on_pending=lambda item: seen.append(item.decision_id),
        )
    assert decision.decision == "REQUIRE_APPROVAL"
    assert seen == [decision.decision_id]
    assert plane.approval_states == []


def test_a_rejected_approval_is_not_reported_as_an_allow() -> None:
    plane = FakeControlPlane(decision="REQUIRE_APPROVAL", approval_states=["REJECTED"])
    with client_for(plane) as mizan, pytest.raises(ApprovalRejected):
        mizan.decide(
            tool_id="tool_transfer",
            arguments={"amount": 1, "customer_id": "c", "request_time": "t"},
            action_type="financial_write",
            intent="rebalance",
            principal=ALICE,
            resource=RESOURCE,
        )


def test_giving_up_on_an_approval_does_not_perform_the_action() -> None:
    plane = FakeControlPlane(decision="REQUIRE_APPROVAL", approval_states=[])
    performed: list[str] = []
    router = GovernedToolRouter(
        client_for(plane),
        {
            "transfer": GovernedTool(
                "tool_transfer",
                "financial_write",
                RESOURCE,
                lambda **kwargs: performed.append("ran"),
            )
        },
        principal=ALICE,
        approval_timeout_seconds=0.0,
    )
    outcome = router.invoke(
        "transfer", "call_1", {"amount": 1, "customer_id": "c", "request_time": "t"}
    )
    assert outcome.ok is False
    assert outcome.refusal_class == "approval_pending"
    assert performed == []


def test_a_refusal_reaches_the_model_as_a_tool_result_not_an_exception() -> None:
    plane = FakeControlPlane(decision="DENY")
    router = GovernedToolRouter(
        client_for(plane),
        {"transfer": GovernedTool("tool_transfer", "financial_write", RESOURCE, lambda **k: "ran")},
        principal=ALICE,
    )
    block = {
        "type": "tool_use",
        "id": "toolu_1",
        "name": "transfer",
        "input": {"amount": 1, "customer_id": "c", "request_time": "t"},
    }
    result = router.anthropic_tool_result(block)
    assert result["type"] == "tool_result"
    assert result["is_error"] is True
    assert "Refused by policy" in result["content"]

    message = router.openai_tool_message(
        {
            "id": "call_1",
            "function": {
                "name": "transfer",
                "arguments": '{"amount": 1, "customer_id": "c", "request_time": "t"}',
            },
        }
    )
    assert message["role"] == "tool"
    assert "Refused by policy" in message["content"]


def test_an_allowed_call_runs_the_handler_and_returns_its_value() -> None:
    plane = FakeControlPlane()
    router = GovernedToolRouter(
        client_for(plane),
        {
            "transfer": GovernedTool(
                "tool_transfer",
                "financial_write",
                RESOURCE,
                lambda **kwargs: {"moved": kwargs["amount"]},
            )
        },
        principal=ALICE,
    )
    outcome = router.invoke(
        "transfer", "call_1", {"amount": 12500, "customer_id": "c", "request_time": "t"}
    )
    assert outcome.ok is True
    assert outcome.content == {"moved": 12500}


def test_an_unknown_tool_is_refused_without_asking_the_control_plane() -> None:
    plane = FakeControlPlane()
    router = GovernedToolRouter(client_for(plane), {}, principal=ALICE)
    outcome = router.invoke("nope", "call_1", {})
    assert outcome.refusal_class == "unknown_tool"
    assert plane.contexts == []


def test_a_problem_document_keeps_its_status_and_code() -> None:
    plane = FakeControlPlane()
    with client_for(plane) as mizan, pytest.raises(ProblemError) as raised:
        mizan._request("GET", "/v1/audit/keys")
    assert raised.value.status == 404
    assert raised.value.code == "not_found"


def test_the_client_refuses_to_exist_without_a_url_and_a_token() -> None:
    with pytest.raises(ValueError, match="agent token"):
        MizanClient("", "")


def test_timeout_names_the_approval_that_is_still_open() -> None:
    plane = FakeControlPlane(decision="REQUIRE_APPROVAL", approval_states=[])
    with client_for(plane) as mizan:
        decision = mizan.authorize(
            mizan.build_context(
                tool_id="tool_transfer",
                arguments={"amount": 1, "customer_id": "c", "request_time": "t"},
                action_type="financial_write",
                intent="rebalance",
                principal=ALICE,
                resource=RESOURCE,
            )
        )
        with pytest.raises(ApprovalTimeout) as raised:
            mizan.wait_for_approval(decision, timeout_seconds=0.0, poll_seconds=0.0)
    assert raised.value.approval_id == "apr_1"
