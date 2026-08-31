from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from typing import Any

import pytest
from mizan_control_plane.canonical import binding_hash, canonical_hash
from mizan_control_plane.models import (
    AuthenticatedIdentity,
    EvaluationContext,
    PolicyMatch,
    RegistryAgent,
    RegistryTool,
)
from mizan_control_plane.observability import Metrics
from mizan_control_plane.policy_engine import CedarPolicyEvaluator
from mizan_control_plane.problems import Problem
from mizan_control_plane.rate_limits import RateLimiter
from mizan_control_plane.repository import InMemoryAuthorizationRepository
from mizan_control_plane.risk import RegistryFloorRiskProvider
from mizan_control_plane.schema_validation import ContractSchemas
from mizan_control_plane.service import AuthorizationService

TENANT = "tnt_bank-a"
AGENT = "agt_wealth-01"
TOOL = "tool_transfer"
APPROVAL_REQUIREMENTS = {
    "quorum": 2,
    "approver_roles": ["manager", "risk"],
    "distinct_roles_required": True,
    "expiry_seconds": 3600,
    "rejection_mode": "veto",
}


def context(request_id: str = "018f47a6-7b42-7c00-8000-000000000001") -> EvaluationContext:
    parameters = {"amount": 12500, "request_time": "volatile"}
    return EvaluationContext.model_validate(
        {
            "schema_version": "1.2",
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
                "arguments": parameters,
                "parameters_hash": binding_hash(parameters, ["/amount"]),
                "binding_profile": {"profile_id": "bp_transfer-v1", "profile_version": 1},
            },
            "action": {
                "type": "financial_write",
            },
            "resource": {
                "id": "portfolio/42",
                "type": "portfolio",
                "resource_owner": "core-banking",
                "data_classification": "financial",
            },
            "business": {"transaction_value": {"amount": 12500, "currency": "AED"}},
            "security": {"anomaly_score": 0.0},
            "environment": "production",
            "timestamp": "2026-08-25T00:00:00Z",
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


def test_authorize_uses_the_registered_tool_tier_and_stops_before_evaluation() -> None:
    subject, repository = service()
    metrics = Metrics()
    subject.rate_limiter = RateLimiter(
        {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}, metrics
    )
    for suffix in ("51", "52", "53"):
        request = context(f"018f47a6-7b42-7c00-8000-0000000000{suffix}")
        assert subject.authorize(identity(), request).risk["level"] == "HIGH"

    with pytest.raises(Problem) as refused:
        subject.authorize(identity(), context("018f47a6-7b42-7c00-8000-000000000054"))

    assert refused.value.status == 429
    assert refused.value.code == "rate_limit_exceeded"
    assert len(repository.adr_documents) == 3



@pytest.mark.parametrize(
    ("policy_decision", "expected_status", "expected_record_decision"),
    [
        ("ALLOW", None, "ALLOW"),
        ("DENY", None, "DENY"),
        ("REQUIRE_APPROVAL", None, "REQUIRE_APPROVAL"),
        ("CONSTRAIN", 501, "DENY"),
        ("REDACT", 501, "DENY"),
        ("ESCALATE", 501, "DENY"),
    ],
)
def test_all_policy_decisions_have_explicit_auditable_dispositions(
    policy_decision: str, expected_status: int | None, expected_record_decision: str
) -> None:
    subject, repository = service()
    repository.policies = [
        PolicyMatch(
            policy_id="pol_decision-path",
            version=1,
            content_hash="a" * 64,
            decision=policy_decision,
            priority=100,
            constraints={"max_amount": 100} if policy_decision in {"CONSTRAIN", "REDACT"} else None,
            approval_requirements=APPROVAL_REQUIREMENTS
            if policy_decision == "REQUIRE_APPROVAL"
            else None,
        )
    ]
    if expected_status is None:
        assert subject.authorize(identity(), context()).decision == expected_record_decision
    else:
        with pytest.raises(Problem) as raised:
            subject.authorize(identity(), context())
        assert raised.value.status == expected_status
        assert raised.value.code == "NOT_IMPLEMENTED"
    assert repository.adr_documents[0]["decision"] == expected_record_decision
    ContractSchemas(Path("SPEC_v1.md")).validate("ADR_Record", repository.adr_documents[0])


def test_evaluation_context_matches_ratified_argument_contract() -> None:
    document = context().model_dump(mode="json")
    ContractSchemas(Path("SPEC_v1.md")).validate("EvaluationContext", document)


@pytest.mark.parametrize(
    ("arguments", "code"),
    [
        ({"amount": float("inf")}, "arguments_non_finite"),
        ({"amount": "x" * 66_000}, "arguments_too_large"),
    ],
)
def test_argument_budgets_fail_before_evaluation(arguments: dict, code: str) -> None:
    subject, _ = service()
    request = context()
    request.tool.arguments = arguments
    request.tool.parameters_hash = "0" * 64
    with pytest.raises(Problem) as error:
        subject.authorize(identity(), request)
    assert error.value.code == code


def test_tenant_is_derived_from_identity() -> None:
    subject, _ = service()
    with pytest.raises(Problem, match="tenant") as raised:
        subject.authorize(identity("tnt_bank-b"), context())
    assert raised.value.status == 403


def test_binding_hash_rejects_parameter_substitution() -> None:
    subject, _ = service()
    request = context()
    request.tool.arguments["amount"] = 99999
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
    request.tool.arguments["attacker_added"] = True
    with pytest.raises(Problem, match="binding class"):
        subject.authorize(identity(), request)


def test_idempotent_retry_returns_same_decision() -> None:
    subject, repository = service()
    first = subject.authorize(identity(), context())
    second = subject.authorize(identity(), context())
    assert second == first
    assert len(repository.adr_documents) == 1


def test_allow_response_and_persisted_replay_are_byte_identical_with_stray_policy_constraints() -> None:
    class ReconstructingRepository(InMemoryAuthorizationRepository):
        def find_decision_by_request(self, tenant_id: str, request_id: str):
            persisted = super().find_decision_by_request(tenant_id, request_id)
            if persisted is None:
                return None
            return persisted.model_copy(
                update={"response": persisted.response.model_copy(update={"constraints": None})}
            )

    _, base = service()
    repository = ReconstructingRepository(agents=base.agents.values(), tools=base.tools.values())
    repository.policies = [
        PolicyMatch(
            policy_id="pol_allow-with-stray-obligation",
            version=1,
            content_hash="a" * 64,
            decision="ALLOW",
            priority=100,
            constraints={"max_value": {"amount": 100, "currency": "AED"}},
        )
    ]
    subject = AuthorizationService(repository, RegistryFloorRiskProvider(), "test", "f" * 64)
    first = subject.authorize(identity(), context())
    replay = subject.authorize(identity(), context())
    assert first.model_dump_json() == replay.model_dump_json()


def test_i13_in_memory_repository_assigns_persisted_chain_fields() -> None:
    subject, repository = service()
    subject.authorize(identity(), context("018f47a6-7b42-7c00-8000-000000000051"))
    subject.authorize(identity(), context("018f47a6-7b42-7c00-8000-000000000052"))
    first, second = repository.adr_documents
    assert first["sequence_number"] == 0
    assert first["prev_hash"] == "0" * 64
    assert second["sequence_number"] == 1
    assert second["prev_hash"] == first["record_hash"]
    for record in (first, second):
        assert record["record_hash"] == canonical_hash(
            {name: value for name, value in record.items() if name != "record_hash"}
        )


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


class FailingRiskProvider:
    def evaluate(self, context: EvaluationContext, floor: str) -> dict[str, Any]:
        raise RuntimeError("risk dependency unavailable")


class FailingPolicyRepository(InMemoryAuthorizationRepository):
    def matching_policies(
        self, tenant_id: str, context: EvaluationContext, risk_level: str | None = None
    ) -> list[PolicyMatch]:
        raise RuntimeError("Cedar evaluation error: injected")


class CedarBackedRepository(InMemoryAuthorizationRepository):
    """Runs the shipped evaluator, so an engine failure is raised the way production raises it."""

    documents: list[dict[str, Any]] = []

    def matching_policies(
        self, tenant_id: str, context: EvaluationContext, risk_level: str | None = None
    ) -> list[PolicyMatch]:
        return CedarPolicyEvaluator().evaluate(self.documents, context, risk_level)


class UnexpectedPersistenceRepository(InMemoryAuthorizationRepository):
    def persist_decision(
        self,
        decision: Any,
        adr_document: dict,
        normalized_context: dict,
        approval_request: dict | None = None,
    ) -> None:
        raise ValueError("unexpected persistence defect")


class ConcurrentReplayRepository(InMemoryAuthorizationRepository):
    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.initial_reads = Barrier(2)

    def find_decision_by_request(self, tenant_id: str, request_id: str):
        existing = super().find_decision_by_request(tenant_id, request_id)
        if existing is None and not self.decisions:
            self.initial_reads.wait(timeout=2)
        return existing


def _service_with_repository(
    repository: InMemoryAuthorizationRepository, risk_provider: Any = None
) -> AuthorizationService:
    return AuthorizationService(
        repository,
        risk_provider or RegistryFloorRiskProvider(),
        "test",
        "f" * 64,
    )


def test_i8_risk_engine_failure_persists_system_fail_closed_deny() -> None:
    _, repository = service()
    subject = _service_with_repository(repository, FailingRiskProvider())
    with pytest.raises(Problem) as raised:
        subject.authorize(identity(), context())
    assert raised.value.status == 403
    assert raised.value.code == "authorization_failed_closed"
    assert repository.adr_documents[0]["decision"] == "DENY"
    assert repository.adr_documents[0]["decision_basis"] == "system_fail_closed"
    assert repository.adr_documents[0]["policies"] == []
    ContractSchemas(Path("SPEC_v1.md")).validate("ADR_Record", repository.adr_documents[0])


def test_v15_policy_engine_failure_persists_system_fail_closed_deny() -> None:
    _, template = service()
    repository = FailingPolicyRepository(
        agents=template.agents.values(), tools=template.tools.values()
    )
    subject = _service_with_repository(repository)
    with pytest.raises(Problem) as raised:
        subject.authorize(identity(), context())
    assert raised.value.status == 403
    assert raised.value.code == "authorization_failed_closed"
    assert repository.adr_documents[0]["decision_basis"] == "system_fail_closed"
    ContractSchemas(Path("SPEC_v1.md")).validate("ADR_Record", repository.adr_documents[0])


def test_policy_compile_failure_inside_the_evaluator_records_system_fail_closed() -> None:
    _, template = service()
    repository = CedarBackedRepository(
        agents=template.agents.values(), tools=template.tools.values()
    )
    # A five-fractional-digit context value is unrepresentable as a Cedar decimal, so the shipped
    # evaluator raises PolicyCompileError — a ValueError, not the RuntimeError the handler names.
    repository.documents = [
        {
            "schema_version": "1.3",
            "policy_id": "pol_transfer",
            "tenant_id": TENANT,
            "name": "Transfer policy",
            "version": 1,
            "status": "ACTIVE",
            "author": "risk-team",
            "applies_to": {"tool_ids": [TOOL]},
            "conditions": {"field": "action.type", "op": "eq", "value": "financial_write"},
            "decision": "ALLOW",
            "priority": 100,
            "content_hash": "1" * 64,
            "created_at": "2026-08-25T00:00:00Z",
        }
    ]
    request = context()
    request.security.anomaly_score = 0.12345
    with pytest.raises(Problem) as raised:
        subject = _service_with_repository(repository)
        subject.authorize(identity(), request)
    assert raised.value.status == 403
    assert raised.value.code == "authorization_failed_closed"
    assert repository.adr_documents[0]["decision"] == "DENY"
    assert repository.adr_documents[0]["decision_basis"] == "system_fail_closed"
    assert repository.adr_documents[0]["policies"] == []
    assert repository.adr_documents[0]["reasons"] == ["System failed closed: policy_engine_failure"]
    ContractSchemas(Path("SPEC_v1.md")).validate("ADR_Record", repository.adr_documents[0])


def test_system_fail_closed_evidence_failure_has_distinct_counter_and_alert(
    caplog: pytest.LogCaptureFixture,
) -> None:
    _, repository = service()
    repository.fail_writes = True
    subject = _service_with_repository(repository, FailingRiskProvider())
    with pytest.raises(Problem) as raised:
        subject.authorize(identity(), context())
    assert raised.value.status == 503
    assert raised.value.code == "fail_closed_evidence_write_failed"
    assert subject.failure_counters["system_fail_closed_evidence_write_failed"] == 1
    assert "system_fail_closed_evidence_write_failed" in caplog.text


def test_unexpected_persistence_exception_is_not_swallowed() -> None:
    _, template = service()
    repository = UnexpectedPersistenceRepository(
        agents=template.agents.values(), tools=template.tools.values()
    )
    with pytest.raises(ValueError, match="unexpected persistence defect"):
        _service_with_repository(repository).authorize(identity(), context())


def test_concurrent_duplicate_request_returns_one_persisted_decision() -> None:
    _, template = service()
    repository = ConcurrentReplayRepository(
        agents=template.agents.values(), tools=template.tools.values()
    )
    subject = _service_with_repository(repository)
    with ThreadPoolExecutor(max_workers=2) as workers:
        futures = [workers.submit(subject.authorize, identity(), context()) for _ in range(2)]
        responses = [future.result(timeout=2) for future in futures]
    assert responses[0].decision_id == responses[1].decision_id
    assert responses[0] == responses[1]
    assert len(repository.adr_documents) == 1


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


def test_require_approval_opens_its_approval_in_the_decision_transaction() -> None:
    subject, repository = service()
    repository.policies = [
        PolicyMatch(
            policy_id="pol_rebalance",
            version=1,
            content_hash="b" * 64,
            decision="REQUIRE_APPROVAL",
            priority=100,
            approval_requirements=APPROVAL_REQUIREMENTS,
        )
    ]
    response = subject.authorize(identity(), context())
    assert response.decision == "REQUIRE_APPROVAL"
    assert len(repository.approval_requests) == 1
    request = repository.approval_requests[0]
    assert request["requester_id"] == "prn_alice-01"
    # ADR-007: the principal who asked cannot be the principal who approves.
    assert request["forbidden_approvers"] == ["prn_alice-01"]
    assert request["controls"]["quorum"] == 2
    assert request["controls"]["distinct_control_domains_required"] is True


def test_a_require_approval_policy_without_requirements_is_rejected_not_recorded() -> None:
    subject, repository = service()
    repository.policies = [
        PolicyMatch(
            policy_id="pol_rebalance",
            version=1,
            content_hash="b" * 64,
            decision="REQUIRE_APPROVAL",
            priority=100,
        )
    ]
    with pytest.raises(Problem) as raised:
        subject.authorize(identity(), context())
    assert raised.value.code == "approval_requirements_missing"
    assert repository.adr_documents == []
