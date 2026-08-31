from __future__ import annotations

import json
import logging
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import pytest
from mizan_control_plane.canonical import canonical_hash
from mizan_control_plane.execution import ExecutionService, ExecutionTokenCodec
from mizan_control_plane.keys import local_private_key_for_testing
from mizan_control_plane.observability import Metrics
from mizan_control_plane.problems import Problem
from psycopg import OperationalError
from psycopg_pool import PoolTimeout

from tests.unit.test_authorization import context, identity
from tests.unit.test_authorization import service as authorization_service


def claims() -> dict:
    now = datetime.now(UTC)
    return {
        "token_version": "1.2",
        "jti": "0123456789abcdef",
        "iss": "https://issuer.mizan.test",
        "aud": "mizan-execution-gateway",
        "tenant_id": "tnt_bank-a",
        "agent_id": "agt_wealth-01",
        "principal_id": "prn_alice",
        "delegation_chain_hash": "a" * 64,
        "authorized_executor": "spiffe://mizan/executor/wealth",
        "decision_id": "adr_decision-0001",
        "tool_id": "tool_transfer",
        "parameters_hash": "b" * 64,
        "binding_profile": {"profile_id": "bp_transfer-v1", "profile_version": 1},
        "context_hash": "c" * 64,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
    }


def test_execution_codec_rejects_tampering_and_wrong_issuer() -> None:
    codec = ExecutionTokenCodec("https://issuer.mizan.test", local_private_key_for_testing("execution-1"))
    token = codec.encode(claims())
    assert codec.decode(token)["authorized_executor"] == "spiffe://mizan/executor/wealth"
    header, payload, signature = token.split(".")
    with pytest.raises(Problem):
        codec.decode(f"{header}.{payload[:-1]}A.{signature}")
    other = ExecutionTokenCodec("https://other-issuer.test", codec.private_key)
    with pytest.raises(Problem):
        other.decode(token)


@pytest.mark.parametrize(
    ("mutation", "expected_message"),
    [
        (lambda payload: payload.pop("parameters_hash"), "malformed"),
        (lambda payload: payload.update({"tool_id": "pol_wrong-prefix"}), "malformed"),
        (lambda payload: payload.update({"unbound_claim": "surprise"}), "malformed"),
    ],
)
def test_execution_codec_rejects_signed_but_nonconforming_claims(
    mutation, expected_message
) -> None:
    codec = ExecutionTokenCodec("https://issuer.mizan.test", local_private_key_for_testing("execution-2"))
    payload = claims()
    mutation(payload)
    # Bypass encode's issuer-side contract gate to model a compromised or older issuer.
    token = jwt.encode(payload, codec.private_key, algorithm="EdDSA")
    with pytest.raises(Problem, match=expected_message):
        codec.decode(token)


def test_second_registered_executor_is_selected_and_outsider_fails_both_boundaries() -> None:
    tool = {
        "execution": {
            "executor_spiffe_ids": [
                "spiffe://mizan/executor/wealth",
                "spiffe://mizan/executor/settlement",
            ]
        }
    }
    assert ExecutionService._authorized_executor(
        tool, "spiffe://mizan/executor/settlement"
    ) == "spiffe://mizan/executor/settlement"
    with pytest.raises(Problem) as issue_error:
        ExecutionService._authorized_executor(tool, "spiffe://mizan/executor/attacker")
    assert issue_error.value.status == 403

    codec = ExecutionTokenCodec("https://issuer.mizan.test", local_private_key_for_testing("execution-3"))
    service = object.__new__(ExecutionService)
    service.codec = codec
    token = codec.encode(claims())
    with pytest.raises(Problem) as redeem_error:
        service.redeem(
            token,
            claims()["decision_id"],
            "spiffe://mizan/executor/attacker",
            {},
        )
    assert redeem_error.value.status == 403


def test_delegation_less_stored_document_is_controlled_403() -> None:
    with pytest.raises(Problem) as raised:
        ExecutionService._require_delegation_edge({}, "agt_child-01")
    assert raised.value.status == 403
    assert raised.value.code == "delegation_authority_changed"


class AlwaysTimeoutPool:
    def connection(self):
        raise PoolTimeout("security event pool saturated")


def test_replay_security_events_use_bounded_pool_without_exhausting_primary() -> None:
    service = object.__new__(ExecutionService)
    service.security_event_pool = AlwaysTimeoutPool()
    service.security_event_counters = Counter()
    service.metrics = Metrics()
    service.pool = object()  # A primary-pool access would fail: it has no connection method.

    with ThreadPoolExecutor(max_workers=16) as workers:
        futures = [
            workers.submit(
                service._record_security_event,
                "tnt_bank-a",
                "mizan.security.execution_token_replay",
                "adr_decision-0001",
                f"jti-{index}",
                "spiffe://mizan/executor/wealth",
            )
            for index in range(64)
        ]
        for future in futures:
            future.result(timeout=1)
    assert service.security_event_counters["security_event_pool_timeout"] == 64


class BrokenPool:
    """A security-event sink that fails the way a database actually fails."""

    def __init__(self, failure: Exception) -> None:
        self.failure = failure

    def connection(self):
        raise self.failure


def _isolated_service(pool: Any) -> ExecutionService:
    service = object.__new__(ExecutionService)
    service.security_event_pool = pool
    service.security_event_counters = Counter()
    service.metrics = Metrics()
    service.pool = object()  # a primary-pool access would fail: it has no connection method
    return service


@pytest.mark.parametrize(
    "failure",
    [OperationalError("connection closed"), RuntimeError("sink is gone"), ValueError("bad json")],
)
def test_a_security_event_sink_that_fails_does_not_change_the_security_answer(
    failure: Exception,
) -> None:
    """The audit sink may never decide the outcome it is auditing.

    `_record_security_event` runs *inside* the redemption transaction. Before T-073 it caught
    `PoolTimeout` alone, so any other fault escaped, rolled the redemption back, and turned a
    detected replay of an execution capability into a 500 — telling the attacker to retry, by the
    mechanism whose whole job was to refuse them. Fails on 793a54a: the exception propagates.
    """
    service = _isolated_service(BrokenPool(failure))
    service._record_security_event(
        "tnt_bank-a",
        "mizan.security.execution_token_replay",
        "adr_decision-0001",
        "jti-1",
        "spiffe://mizan/executor/wealth",
    )
    assert service.security_event_counters["security_event_write_failed"] == 1
    exposition = service.metrics.exposition().decode()
    assert 'cause="' + type(failure).__name__ + '"' in exposition
    assert "mizan_security_events_dropped_total" in exposition


def test_a_dropped_security_event_is_written_where_the_siem_can_still_recover_it(caplog) -> None:
    """There is no queue behind this sink, so a dropped event is lost, not deferred.

    The row that could not be written is therefore logged in full at ERROR — the same pipeline that
    ships logs to the SIEM is the last chance to reconstruct it. It carries ids and hashes only,
    which is exactly what the outbox row would have carried.
    """
    service = _isolated_service(BrokenPool(OperationalError("connection closed")))
    with caplog.at_level(logging.ERROR):
        service._record_security_event(
            "tnt_bank-a",
            "mizan.security.execution_token_replay",
            "adr_decision-0001",
            "jti-1",
            "spiffe://mizan/executor/wealth",
        )
    record = next(r for r in caplog.records if r.message == "security event dropped and lost")
    recovered = json.loads(record.dropped_event)
    assert recovered["decision_id"] == "adr_decision-0001"
    assert recovered["authenticated_workload"] == "spiffe://mizan/executor/wealth"
    assert len(recovered["token_jti_hash"]) == 64
    assert record.event_type == "mizan.security.execution_token_replay"


def test_policy_ttl_can_only_clamp_tool_ttl() -> None:
    assert ExecutionService._clamp_token_ttl(300, []) == 300
    assert ExecutionService._clamp_token_ttl(300, [600, 120, 240]) == 120


class QueryResult:
    def __init__(self, row) -> None:
        self.row = row

    def fetchone(self):
        return self.row


class MissingDecisionConnection:
    def __enter__(self):
        return self

    def __exit__(self, *_arguments: object) -> None:
        return None

    def transaction(self):
        return self

    def execute(self, query: str, parameters=None) -> QueryResult:
        if "set_config" in query:
            return QueryResult(("tnt_bank-a",))
        assert "document->'risk'->>'level'" in query
        assert parameters == ("tnt_bank-a", "adr_missing-0001")
        return QueryResult(None)


class MissingDecisionPool:
    def connection(self) -> MissingDecisionConnection:
        return MissingDecisionConnection()


def test_rate_limit_risk_lookup_returns_no_caller_selected_fallback_for_a_missing_decision() -> None:
    service = object.__new__(ExecutionService)
    service.pool = MissingDecisionPool()
    assert service.risk_tier_for_decision("tnt_bank-a", "adr_missing-0001") is None


class RevalidationConnection:
    def __init__(self) -> None:
        self.profile = (["/amount"], ["/request_time"])
        self.agent = (
            "1.0.0",
            None,
            {"delegation": {"allowed_agent_ids": [], "max_delegation_depth": 0}},
        )
        self.chain_rows = [
            (
                None,
                "ACTIVE",
                {"delegation": {"allowed_agent_ids": [], "max_delegation_depth": 0}},
                True,
            )
        ]
        self.approval = None

    def execute(self, query: str, parameters=None) -> QueryResult:
        if "bound_pointers,volatile_pointers" in query:
            return QueryResult(self.profile)
        if "SELECT version,parent_agent_id,document" in query:
            return QueryResult(self.agent)
        if "SELECT parent_agent_id,lifecycle_state,document" in query:
            return QueryResult(self.chain_rows.pop(0))
        if "FROM mizan.approvals" in query:
            return QueryResult(self.approval)
        raise AssertionError(f"unexpected query: {query}")


class FixedRiskProvider:
    def __init__(self, level: str = "HIGH", error: Exception | None = None) -> None:
        self.level = level
        self.error = error

    def evaluate(self, evaluation_context, floor: str) -> dict:
        if self.error:
            raise self.error
        return {"level": self.level, "floor_source": "risk_engine"}


def revalidation_case():
    authorizer, repository = authorization_service()
    response = authorizer.authorize(
        identity(), context("018f47a6-7b42-7c00-8000-000000000061")
    )
    adr = deepcopy(repository.adr_documents[0])
    normalized = deepcopy(repository.normalized_contexts[("tnt_bank-a", response.decision_id)])
    tool = {
        "binding_profile": deepcopy(adr["tool"]["binding_profile"]),
        "execution": {"executor_spiffe_ids": ["spiffe://mizan/executor/wealth"]},
        "risk_tier": "HIGH",
        "resource_owner": "core-banking",
        "data_classification": "financial",
    }
    claims = {
        "tenant_id": adr["tenant_id"],
        "agent_id": adr["agent"]["id"],
        "principal_id": adr["principal"]["id"],
        "tool_id": adr["tool"]["id"],
        "parameters_hash": adr["tool"]["parameters_hash"],
        "context_hash": adr["context_hash"],
        "binding_profile": deepcopy(adr["tool"]["binding_profile"]),
        "delegation_chain_hash": canonical_hash(adr["agent"]["delegation_chain"]),
        "authorized_executor": "spiffe://mizan/executor/wealth",
        "approval_epoch_id": None,
        "decision_id": adr["decision_id"],
    }
    execution = object.__new__(ExecutionService)
    execution.risk_provider = FixedRiskProvider()
    return execution, RevalidationConnection(), claims, adr, tool, normalized


def invoke_revalidation(case, agent_state: str = "ACTIVE") -> None:
    execution, connection, token_claims, adr, tool, normalized = case
    execution._revalidate(
        connection,
        token_claims,
        adr,
        tool,
        agent_state,
        normalized,
        {"amount": 12500, "request_time": "retry"},
    )


def test_revalidate_accepts_unchanged_authoritative_state() -> None:
    invoke_revalidation(revalidation_case())


def test_revalidate_rejects_inactive_agent() -> None:
    with pytest.raises(Problem) as raised:
        invoke_revalidation(revalidation_case(), "SUSPENDED")
    assert raised.value.status == 403
    assert raised.value.code == "agent_not_active"


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        (lambda case: case[2].update({"tool_id": "tool_other"}), "execution_context_drift"),
        (
            lambda case: case[4].update(
                {"binding_profile": {"profile_id": "bp_other-v1", "profile_version": 1}}
            ),
            "binding_profile_mismatch",
        ),
        (
            lambda case: case[4]["execution"].update({"executor_spiffe_ids": []}),
            "executor_mapping_changed",
        ),
        (lambda case: setattr(case[1], "profile", None), "binding_profile_missing"),
        (
            lambda case: setattr(
                case[1],
                "agent",
                ("2.0.0", None, {"delegation": {"max_delegation_depth": 0}}),
            ),
            "agent_version_changed",
        ),
        (
            lambda case: setattr(
                case[1],
                "chain_rows",
                [(None, "SUSPENDED", {"delegation": {}}, True)],
            ),
            "delegation_authority_changed",
        ),
        (
            lambda case: case[4].update({"resource_owner": "changed-owner"}),
            "execution_context_drift",
        ),
        (
            lambda case: setattr(case[0], "risk_provider", FixedRiskProvider("CRITICAL")),
            "execution_risk_increased",
        ),
        (
            lambda case: case[2].update({"approval_epoch_id": "epo_12345678"}),
            "approval_epoch_changed",
        ),
    ],
)
def test_each_revalidate_403_branch_is_reached(mutation, code: str) -> None:
    case = revalidation_case()
    mutation(case)
    with pytest.raises(Problem) as raised:
        invoke_revalidation(case)
    assert raised.value.status == 403
    assert raised.value.code == code


def test_revalidate_rejects_changed_bound_arguments() -> None:
    case = revalidation_case()
    execution, connection, token_claims, adr, tool, normalized = case
    with pytest.raises(Problem) as raised:
        execution._revalidate(
            connection,
            token_claims,
            adr,
            tool,
            "ACTIVE",
            normalized,
            {"amount": 99999, "request_time": "retry"},
        )
    assert raised.value.status == 403
    assert raised.value.code == "execution_arguments_drift"


def test_revalidate_rejects_invalid_stored_context_and_risk_dependency_failure() -> None:
    case = revalidation_case()
    case[5].pop("intent")
    with pytest.raises(Problem) as invalid:
        invoke_revalidation(case)
    assert invalid.value.code == "execution_context_invalid"

    case = revalidation_case()
    case[0].risk_provider = FixedRiskProvider(error=RuntimeError("risk down"))
    with pytest.raises(Problem) as unavailable:
        invoke_revalidation(case)
    assert unavailable.value.status == 503
    assert unavailable.value.code == "risk_engine_unavailable"


@pytest.mark.parametrize("root_document", [{}, {"delegation": {"max_delegation_depth": 0}}])
def test_revalidate_rejects_missing_edge_or_reduced_delegation_depth(root_document) -> None:
    case = revalidation_case()
    execution, connection, token_claims, adr, _tool, normalized = case
    adr["agent"]["delegation_chain"] = ["agt_wealth-01", "agt_child-01"]
    normalized["agent"]["delegation_chain"] = ["agt_wealth-01", "agt_child-01"]
    token_claims["delegation_chain_hash"] = canonical_hash(adr["agent"]["delegation_chain"])
    connection.chain_rows = [
        (None, "ACTIVE", root_document, True),
        (
            "agt_wealth-01",
            "ACTIVE",
            {"delegation": {"allowed_agent_ids": [], "max_delegation_depth": 0}},
            True,
        ),
    ]
    if root_document.get("delegation") is not None:
        root_document["delegation"]["allowed_agent_ids"] = ["agt_child-01"]
    with pytest.raises(Problem) as raised:
        invoke_revalidation(case)
    assert raised.value.status == 403
    assert raised.value.code == "delegation_authority_changed"
