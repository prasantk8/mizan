"""Execution capabilities fail closed under replay, expiry, forgery, and races."""

from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier

import jwt
import pytest
from mizan.client import uuid7
from mizan_control_plane.evidence import (
    Ed25519EvidenceSigner,
    EvidenceRepository,
    LocalImmutableObjectStore,
    ObjectEvidenceVerifier,
    OutboxPublisher,
)
from mizan_control_plane.execution import ExecutionService, ExecutionTokenCodec
from mizan_control_plane.keys import local_private_key_for_testing
from mizan_control_plane.models import AuthenticatedIdentity
from mizan_control_plane.problems import Problem
from mizan_control_plane.repository import PostgresAuthorizationRepository
from mizan_control_plane.risk import RegistryFloorRiskProvider
from mizan_control_plane.service import AuthorizationService

from tests.unit.test_authorization import context

from .regression import active

DATABASE_URL = os.getenv("MIZAN_TEST_DATABASE_URL")
EXECUTOR = "spiffe://mizan/executor/settlement"
ARGUMENTS = {"amount": 12500, "request_time": "adversarial-redemption"}
LIVE_TENANT = "tnt_adversarial"
LIVE_AGENT = "agt_adversarial-token"
LIVE_TOOL = "tool_adversarial-token"
LIVE_PROFILE = "bp_adversarial-token-v1"


def _seed_live_tenant(repository: PostgresAuthorizationRepository) -> None:
    tool = {
        "tenant_id": LIVE_TENANT,
        "tool_id": LIVE_TOOL,
        "risk_tier": "HIGH",
        "owner": "adversarial-suite",
        "resource_owner": "adversarial-suite",
        "data_classification": "financial",
        "binding_profile": {
            "profile_id": LIVE_PROFILE,
            "profile_version": 1,
            "canonicalization": "RFC8785",
            "bound_pointers": ["/amount"],
            "volatile_pointers": ["/request_time"],
            "unknown_pointer_policy": "reject",
        },
        "execution": {
            "executor_spiffe_ids": [EXECUTOR],
            "token_ttl_seconds": 300,
            "lease_ttl_seconds": 900,
            "heartbeat_interval_seconds": 60,
            "max_lease_extensions": 1,
        },
    }
    agent = {
        "tenant_id": LIVE_TENANT,
        "agent_id": LIVE_AGENT,
        "delegation": {
            "allowed_agent_ids": [],
            "max_delegation_depth": 0,
            "inherit_parent_permissions": False,
        },
    }
    policy = {
        "schema_version": "1.3",
        "policy_id": "pol_adversarial-token",
        "tenant_id": LIVE_TENANT,
        "name": "Adversarial token allow fixture",
        "version": 1,
        "status": "ACTIVE",
        "author": "prn_adversarial-author",
        "approver": "prn_adversarial-approver",
        "effective_from": "2026-08-27T00:00:00Z",
        "applies_to": {"tool_ids": [LIVE_TOOL]},
        "conditions": {"field": "action.type", "op": "eq", "value": "financial_write"},
        "decision": "ALLOW",
        "priority": 100,
        "content_hash": "4" * 64,
        "created_at": "2026-08-27T00:00:00Z",
    }
    with repository.pool.connection() as connection, connection.transaction():
        repository._scope(connection, LIVE_TENANT)
        connection.execute(
            "INSERT INTO mizan.tenants(tenant_id,region,status) VALUES (%s,'test','ACTIVE') "
            "ON CONFLICT DO NOTHING",
            (LIVE_TENANT,),
        )
        connection.execute(
            "INSERT INTO mizan.binding_profiles(tenant_id,profile_id,profile_version,canonicalization,"
            "bound_pointers,volatile_pointers,content_hash) VALUES (%s,%s,1,'RFC8785',%s,%s,%s) "
            "ON CONFLICT DO NOTHING",
            (LIVE_TENANT, LIVE_PROFILE, json.dumps(["/amount"]), json.dumps(["/request_time"]), "1" * 64),
        )
        connection.execute(
            "INSERT INTO mizan.tools(tenant_id,tool_id,profile_id,profile_version,document) "
            "VALUES (%s,%s,%s,1,%s) ON CONFLICT DO NOTHING",
            (LIVE_TENANT, LIVE_TOOL, LIVE_PROFILE, json.dumps(tool)),
        )
        connection.execute(
            "INSERT INTO mizan.agents(tenant_id,agent_id,version,lifecycle_state,document,"
            "created_at,updated_at) VALUES (%s,%s,'1.0.0','ACTIVE',%s,clock_timestamp(),"
            "clock_timestamp()) ON CONFLICT DO NOTHING",
            (LIVE_TENANT, LIVE_AGENT, json.dumps(agent)),
        )
        connection.execute(
            "INSERT INTO mizan.agent_tools(tenant_id,agent_id,tool_id) VALUES (%s,%s,%s) "
            "ON CONFLICT DO NOTHING",
            (LIVE_TENANT, LIVE_AGENT, LIVE_TOOL),
        )
        connection.execute(
            "INSERT INTO mizan.policies(tenant_id,policy_id,version,status,effective_from,decision,"
            "content_hash,document,created_at) VALUES (%s,%s,1,'ACTIVE',clock_timestamp(),"
            "'ALLOW',%s,%s,clock_timestamp()) ON CONFLICT DO NOTHING",
            (LIVE_TENANT, policy["policy_id"], policy["content_hash"], json.dumps(policy)),
        )
        connection.execute(
            "INSERT INTO mizan.agent_policies(tenant_id,agent_id,policy_id,policy_version) "
            "VALUES (%s,%s,%s,1) ON CONFLICT DO NOTHING",
            (LIVE_TENANT, LIVE_AGENT, policy["policy_id"]),
        )
        connection.execute(
            "INSERT INTO mizan.evidence_chain_heads(tenant_id,stream_id) VALUES (%s,%s) "
            "ON CONFLICT DO NOTHING",
            (LIVE_TENANT, f"{LIVE_TENANT}:adr:0"),
        )


def _claims(now: datetime | None = None) -> dict:
    now = now or datetime.now(UTC)
    return {
        "token_version": "1.2",
        "jti": "adversarial-token-0001",
        "iss": "https://issuer.mizan.test",
        "aud": "mizan-execution-gateway",
        "tenant_id": "tnt_bank-a",
        "agent_id": "agt_wealth-01",
        "principal_id": "prn_alice-01",
        "delegation_chain_hash": "a" * 64,
        "authorized_executor": EXECUTOR,
        "decision_id": "adr_adversarial-token",
        "tool_id": "tool_transfer",
        "parameters_hash": "b" * 64,
        "binding_profile": {"profile_id": "bp_transfer-v1", "profile_version": 1},
        "context_hash": "c" * 64,
        "approval_epoch_id": None,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
    }


@pytest.fixture(scope="module")
def live_execution(tmp_path_factory):
    if not DATABASE_URL:
        pytest.skip("Postgres not configured")
    repository = PostgresAuthorizationRepository(DATABASE_URL)
    _seed_live_tenant(repository)
    authorization = AuthorizationService(
        repository, RegistryFloorRiskProvider(), "adversarial", "a" * 64
    )
    request = context(str(uuid7()))
    request.tenant_id = LIVE_TENANT
    request.agent.id = LIVE_AGENT
    request.agent.delegation_chain = [LIVE_AGENT]
    request.tool.id = LIVE_TOOL
    request.tool.binding_profile.profile_id = LIVE_PROFILE
    response = authorization.authorize(
        AuthenticatedIdentity(
            tenant_id=LIVE_TENANT,
            agent_id=LIVE_AGENT,
            subject="spiffe://mizan/agent/adversarial",
            delegation_chain=[LIVE_AGENT],
        ),
        request,
    )
    assert response.decision == "ALLOW"

    evidence = EvidenceRepository(DATABASE_URL)
    receipt_signer = Ed25519EvidenceSigner.development("evidence-receipt")
    anchor_signer = Ed25519EvidenceSigner.development("evidence-anchor")
    store = LocalImmutableObjectStore(tmp_path_factory.mktemp("adversarial-evidence"))
    publisher = OutboxPublisher(evidence, store, receipt_signer, anchor_signer)
    assert publisher.drain(LIVE_TENANT) >= 1
    verifier = ObjectEvidenceVerifier(
        evidence,
        store,
        {
            receipt_signer.key_id: receipt_signer.public_key,
            anchor_signer.key_id: anchor_signer.public_key,
        },
    )
    codec = ExecutionTokenCodec(
        "https://issuer.mizan.test",
        local_private_key_for_testing("adversarial-execution"),
        clock_skew_seconds=0,
    )
    execution = ExecutionService(DATABASE_URL, codec, verifier)
    yield execution, codec, response.decision_id
    execution.pool.close()
    execution.security_event_pool.close()
    evidence.pool.close()
    repository.pool.close()


def test_redeemed_execution_token_is_refused_as_consumed(live_execution) -> None:
    execution, codec, decision_id = live_execution
    token = execution.issue(LIVE_TENANT, decision_id, EXECUTOR)
    token_id = codec.decode(token)["jti"]
    execution.redeem(token, decision_id, EXECUTOR, ARGUMENTS, f"first-{token_id}")
    if active("token_replay"):
        with execution.pool.connection() as connection, connection.transaction():
            execution._scope(connection, LIVE_TENANT)
            connection.execute(
                "UPDATE mizan.execution_tokens SET consumed_at=NULL "
                "WHERE tenant_id=%s AND decision_id=%s",
                (LIVE_TENANT, decision_id),
            )
    with pytest.raises(Problem) as replay:
        execution.redeem(token, decision_id, EXECUTOR, ARGUMENTS, f"replay-{token_id}")
    assert (replay.value.status, replay.value.code) == (403, "execution_token_consumed")


def test_execution_token_past_its_ttl_is_refused_as_invalid_or_expired() -> None:
    codec = ExecutionTokenCodec(
        "https://issuer.mizan.test",
        local_private_key_for_testing("adversarial-expired"),
        clock_skew_seconds=0,
    )
    expired = _claims(datetime.now(UTC) - timedelta(minutes=10))
    with pytest.raises(Problem) as rejection:
        codec.decode(codec.encode(expired))
    assert (rejection.value.status, rejection.value.code) == (403, "execution_token_invalid")
    assert "expired" in rejection.value.detail


def test_execution_token_for_another_tenant_is_indistinguishable_from_consumed(
    live_execution,
) -> None:
    execution, codec, decision_id = live_execution
    token = execution.issue(LIVE_TENANT, decision_id, EXECUTOR)
    foreign = codec.decode(token) | {
        "tenant_id": "tnt_bank-a",
        "jti": "adversarial-foreign-tenant",
    }
    forged = jwt.encode(foreign, codec.private_key, algorithm="EdDSA")
    with pytest.raises(Problem) as rejection:
        execution.redeem(forged, decision_id, EXECUTOR, ARGUMENTS, "foreign-tenant")
    assert (rejection.value.status, rejection.value.code) == (
        403,
        "execution_token_consumed",
    )


def test_execution_token_with_unknown_kid_and_wrong_signature_is_refused() -> None:
    verifier = ExecutionTokenCodec(
        "https://issuer.mizan.test",
        local_private_key_for_testing("adversarial-known-key"),
        clock_skew_seconds=0,
    )
    attacker_key = local_private_key_for_testing("adversarial-unknown-key")
    forged = jwt.encode(
        _claims(),
        attacker_key,
        algorithm="EdDSA",
        headers={"kid": "kms://keys/never-signed-this-token"},
    )
    with pytest.raises(Problem) as rejection:
        verifier.decode(forged)
    assert (rejection.value.status, rejection.value.code) == (403, "execution_token_invalid")


def test_concurrent_replay_loses_the_postgres_compare_and_swap(live_execution) -> None:
    execution, codec, decision_id = live_execution
    token = execution.issue(LIVE_TENANT, decision_id, EXECUTOR)
    token_id = codec.decode(token)["jti"]
    start = Barrier(2)

    def redeem(index: int):
        start.wait(timeout=3)
        try:
            lease = execution.redeem(
                token,
                decision_id,
                EXECUTOR,
                ARGUMENTS,
                f"concurrent-{token_id}-{index}",
            )
            return "leased", lease["lease_id"]
        except Problem as problem:
            return "refused", problem.code

    with ThreadPoolExecutor(max_workers=2) as workers:
        outcomes = list(workers.map(redeem, range(2)))
    assert sorted(kind for kind, _detail in outcomes) == ["leased", "refused"]
    assert [detail for kind, detail in outcomes if kind == "refused"] == [
        "execution_token_consumed"
    ]
