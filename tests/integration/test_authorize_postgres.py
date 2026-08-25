from __future__ import annotations

import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mizan_control_plane.approval_repository import ApprovalRepository
from mizan_control_plane.evidence import (
    Ed25519EvidenceSigner,
    EvidenceRepository,
    LocalImmutableObjectStore,
    ObjectEvidenceVerifier,
    OutboxPublisher,
)
from mizan_control_plane.execution import ExecutionService, ExecutionTokenCodec
from mizan_control_plane.models import AuthenticatedIdentity, AuthenticatedPrincipal
from mizan_control_plane.problems import Problem
from mizan_control_plane.registry import RegistryRepository, policy_semantic_hash
from mizan_control_plane.repository import PostgresAuthorizationRepository
from mizan_control_plane.risk import RegistryFloorRiskProvider
from mizan_control_plane.service import AuthorizationService
from mizan_security.redaction import RedactionPolicy, Redactor, RuleBasedDlpScanner

from tests.unit.test_authorization import context
from tests.unit.test_registry import agent_document


@pytest.mark.skipif(not os.getenv("MIZAN_TEST_DATABASE_URL"), reason="Postgres not configured")
def test_live_control_plane_end_to_end(tmp_path: Path) -> None:
    repository = PostgresAuthorizationRepository(os.environ["MIZAN_TEST_DATABASE_URL"])
    service = AuthorizationService(repository, RegistryFloorRiskProvider(), "integration", "f" * 64)
    identity = AuthenticatedIdentity(
        tenant_id="tnt_bank-a",
        agent_id="agt_wealth-01",
        subject="test",
        delegation_chain=["agt_wealth-01"],
    )
    response = service.authorize(identity, context("018f47a6-7b42-7c00-8000-000000000099"))
    assert response.decision == "ALLOW"
    with repository.pool.connection() as connection, connection.transaction():
        repository._scope(connection, "tnt_bank-a")
        adr_count = connection.execute(
            "SELECT count(*) FROM mizan.adr_records WHERE decision_id=%s", (response.decision_id,)
        ).fetchone()[0]
        outbox_count = connection.execute(
            "SELECT count(*) FROM mizan.outbox WHERE aggregate_id=%s", (response.decision_id,)
        ).fetchone()[0]
        adr_sequence = connection.execute(
            "SELECT sequence_number FROM mizan.adr_records WHERE decision_id=%s",
            (response.decision_id,),
        ).fetchone()[0]
    assert (adr_count, outbox_count) == (1, 1)
    evidence_repository = EvidenceRepository(os.environ["MIZAN_TEST_DATABASE_URL"])
    page = evidence_repository.search_decisions(
        "tnt_bank-a", 10, agent_id="agt_wealth-01", decision="ALLOW"
    )
    assert any(item["decision_id"] == response.decision_id for item in page["items"])
    event = evidence_repository.append_decision_event(
        "tnt_bank-a",
        response.decision_id,
        "CAPABILITY_ISSUED",
        {"kind": "system", "id": "mizan-control-plane", "authenticated_workload": None},
        {"token_jti_hash": "d" * 64},
    )
    assert event["decision_sequence"] == 1
    assert event["sequence_number"] == adr_sequence + 1
    retried = evidence_repository.append_decision_event(
        "tnt_bank-a",
        response.decision_id,
        "CAPABILITY_ISSUED",
        {"kind": "system", "id": "mizan-control-plane", "authenticated_workload": None},
        {"token_jti_hash": "d" * 64},
    )
    assert retried["event_id"] == event["event_id"]
    detail = evidence_repository.decision("tnt_bank-a", response.decision_id)
    assert detail["decision"]["decision_id"] == response.decision_id
    assert detail["events"][0]["event_type"] == "CAPABILITY_ISSUED"
    signer = Ed25519EvidenceSigner.generate()
    store = LocalImmutableObjectStore(tmp_path)
    publisher = OutboxPublisher(evidence_repository, store, signer)
    assert publisher.drain("tnt_bank-a") == 2
    assert evidence_repository.has_receipt(
        "tnt_bank-a",
        "tnt_bank-a:adr:0",
        0,
        repository.adr_documents[0]["record_hash"]
        if hasattr(repository, "adr_documents")
        else evidence_repository.stream_records("tnt_bank-a", "tnt_bank-a:adr:0", 0, 0)[0][
            "record_hash"
        ],
    )
    anchor = publisher.anchor("tnt_bank-a", "tnt_bank-a:adr:0")
    assert anchor["to_sequence"] == 1
    assert anchor["anchor_number"] == 0
    assert anchor["prev_anchor_hash"] == "0" * 64
    assert anchor["covered_record_count"] == 2
    verifier = ObjectEvidenceVerifier(
        evidence_repository,
        store,
        {signer.key_id: signer.public_key},
    )
    assert verifier.verify("tnt_bank-a", "tnt_bank-a:adr:0").valid

    codec = ExecutionTokenCodec("https://issuer.mizan.test", Ed25519PrivateKey.generate())
    execution = ExecutionService(os.environ["MIZAN_TEST_DATABASE_URL"], codec, verifier)
    execution_arguments = {"amount": 12500, "request_time": "execution-attempt-1"}
    with pytest.raises(Problem) as invalid_issue_executor:
        execution.issue(
            "tnt_bank-a", response.decision_id, "spiffe://mizan/executor/attacker"
        )
    assert invalid_issue_executor.value.status == 403
    token = execution.issue(
        "tnt_bank-a", response.decision_id, "spiffe://mizan/executor/settlement"
    )
    with pytest.raises(Problem) as wrong_executor:
        execution.redeem(
            token,
            response.decision_id,
            "spiffe://mizan/executor/attacker",
            execution_arguments,
            "attack",
        )
    assert wrong_executor.value.status == 403
    lease = execution.redeem(
        token,
        response.decision_id,
        "spiffe://mizan/executor/settlement",
        execution_arguments,
        "execution-1",
    )
    assert (
        execution.redeem(
            token,
            response.decision_id,
            "spiffe://mizan/executor/settlement",
            {"amount": 12500, "request_time": "legitimate-retry"},
            "execution-1",
        )["lease_id"]
        == lease["lease_id"]
    )
    with pytest.raises(Problem, match="arguments differ"):
        execution.redeem(
            token,
            response.decision_id,
            "spiffe://mizan/executor/settlement",
            {"amount": 99999, "request_time": "same-idempotency-key"},
            "execution-1",
        )
    with pytest.raises(Problem, match="consumed"):
        execution.redeem(
            token,
            response.decision_id,
            "spiffe://mizan/executor/settlement",
            execution_arguments,
            "different-execution",
        )
    with execution.pool.connection() as connection, connection.transaction():
        execution._scope(connection, "tnt_bank-a")
        replay_events = connection.execute(
            "SELECT count(*) FROM mizan.outbox WHERE tenant_id=%s "
            "AND event_type='mizan.security.execution_token_replay'",
            ("tnt_bank-a",),
        ).fetchone()[0]
    assert replay_events == 1
    running = execution.heartbeat(
        "tnt_bank-a",
        response.decision_id,
        lease["lease_id"],
        "spiffe://mizan/executor/settlement",
    )
    assert running["state"] == "EXECUTING"
    completed = execution.complete(
        "tnt_bank-a",
        response.decision_id,
        lease["lease_id"],
        "spiffe://mizan/executor/settlement",
        "e" * 64,
        None,
    )
    assert completed["state"] == "EXECUTED"

    expiring_token = execution.issue(
        "tnt_bank-a", response.decision_id, "spiffe://mizan/executor/wealth"
    )
    expiring_lease = execution.redeem(
        expiring_token,
        response.decision_id,
        "spiffe://mizan/executor/wealth",
        execution_arguments,
        "execution-expiry",
    )
    expired_at = "2020-01-01T00:00:00Z"
    with execution.pool.connection() as connection, connection.transaction():
        execution._scope(connection, "tnt_bank-a")
        connection.execute(
            "UPDATE mizan.execution_leases "
            "SET expires_at=%s, document=jsonb_set(document,'{expires_at}',to_jsonb(%s::text)) "
            "WHERE tenant_id=%s AND lease_id=%s",
            (expired_at, expired_at, "tnt_bank-a", expiring_lease["lease_id"]),
        )
    with pytest.raises(Problem, match="expired"):
        execution.heartbeat(
            "tnt_bank-a",
            response.decision_id,
            expiring_lease["lease_id"],
            "spiffe://mizan/executor/wealth",
        )
    with execution.pool.connection() as connection, connection.transaction():
        execution._scope(connection, "tnt_bank-a")
        expired_state = connection.execute(
            "SELECT state FROM mizan.execution_leases WHERE tenant_id=%s AND lease_id=%s",
            ("tnt_bank-a", expiring_lease["lease_id"]),
        ).fetchone()[0]
        expiry_events = connection.execute(
            "SELECT count(*) FROM mizan.decision_events "
            "WHERE tenant_id=%s AND decision_id=%s AND event_type='LEASE_EXPIRED'",
            ("tnt_bank-a", response.decision_id),
        ).fetchone()[0]
    assert expired_state == "LEASE_EXPIRED"
    assert expiry_events == 1

    approvals = ApprovalRepository(os.environ["MIZAN_TEST_DATABASE_URL"])
    controls = {
        "quorum": 2,
        "approver_roles": ["manager"],
        "expiry_seconds": 900,
        "rejection_mode": "veto",
        "distinct_roles_required": True,
    }
    approval = approvals.create(
        "tnt_bank-a",
        response.decision_id,
        "prn_requester",
        {"prn_requester"},
        "a" * 64,
        controls,
    )
    alice = AuthenticatedPrincipal(
        tenant_id="tnt_bank-a",
        principal_id="prn_alice",
        identity_kind="human",
        auth_strength="mfa",
        roles=["manager"],
    )
    bob = AuthenticatedPrincipal(
        tenant_id="tnt_bank-a",
        principal_id="prn_bob",
        identity_kind="human",
        auth_strength="hardware",
        roles=["manager"],
    )
    partial = approvals.vote(
        "tnt_bank-a",
        approval["approval_id"],
        alice,
        {"epoch_number": 1, "vote": "APPROVE"},
    )
    assert partial["state"] == "PARTIALLY_APPROVED"
    approved = approvals.vote(
        "tnt_bank-a",
        approval["approval_id"],
        bob,
        {"epoch_number": 1, "vote": "APPROVE"},
    )
    assert approved["state"] == "APPROVED"

    review_decision = service.authorize(
        identity, context("018f47a6-7b42-7c00-8000-000000000101")
    )
    review_controls = {
        "quorum": 1,
        "approver_roles": ["manager"],
        "expiry_seconds": 900,
        "rejection_mode": "review_required",
        "distinct_roles_required": False,
        "review": {
            "approver_roles": ["compliance"],
            "quorum": 1,
            "expiry_seconds": 900,
            "distinct_control_domains_required": True,
            "rejection_mode": "veto",
            "carry_forward_votes": False,
        },
    }
    review_approval = approvals.create(
        "tnt_bank-a",
        review_decision.decision_id,
        "prn_requester",
        {"prn_requester"},
        "b" * 64,
        review_controls,
    )
    review_opened = approvals.vote(
        "tnt_bank-a",
        review_approval["approval_id"],
        alice,
        {"epoch_number": 1, "vote": "REJECT"},
    )
    assert review_opened["state"] == "REVIEW_REQUIRED"
    assert review_opened["epochs"][0]["outcome"] == "REVIEW_TRIGGERED"
    assert review_opened["epochs"][1]["kind"] == "review"
    assert review_opened["epochs"][1]["carried_votes"] == []
    with pytest.raises(Problem, match="absent from the epoch snapshot"):
        approvals.vote(
            "tnt_bank-a",
            review_approval["approval_id"],
            alice,
            {"epoch_number": 2, "vote": "APPROVE"},
        )
    compliance = AuthenticatedPrincipal(
        tenant_id="tnt_bank-a",
        principal_id="prn_compliance",
        identity_kind="human",
        auth_strength="hardware",
        roles=["compliance"],
    )
    reviewed = approvals.vote(
        "tnt_bank-a",
        review_approval["approval_id"],
        compliance,
        {"epoch_number": 2, "vote": "APPROVE"},
    )
    assert reviewed["state"] == "APPROVED"
    summary = EvidenceRepository(os.environ["MIZAN_TEST_DATABASE_URL"]).dashboard_summary(
        "tnt_bank-a"
    )
    assert summary["agents"] >= 1
    assert summary["tools"] >= 1
    assert summary["actions_today"] >= 1
    assert summary["high_risk_actions"] >= 1


@pytest.mark.skipif(not os.getenv("MIZAN_TEST_DATABASE_URL"), reason="Postgres not configured")
def test_rls_policy_lookup_and_evaluation_stays_inside_authorization_budget() -> None:
    repository = PostgresAuthorizationRepository(os.environ["MIZAN_TEST_DATABASE_URL"])
    request = context("018f47a6-7b42-7c00-8000-000000000100")
    samples: list[float] = []
    for _ in range(100):
        started = time.perf_counter_ns()
        assert len(repository.matching_policies("tnt_bank-a", request)) == 1
        samples.append((time.perf_counter_ns() - started) / 1_000_000)
    assert sorted(samples)[98] < 50


@pytest.mark.skipif(not os.getenv("MIZAN_TEST_DATABASE_URL"), reason="Postgres not configured")
def test_registry_create_get_and_cursor_list_are_tenant_scoped() -> None:
    repository = RegistryRepository(os.environ["MIZAN_TEST_DATABASE_URL"])
    document = agent_document()
    assert repository.create_agent("tnt_bank-a", document) == document
    assert repository.get("tnt_bank-a", "agents", document["agent_id"]) == document
    page = repository.list("tnt_bank-a", "agents", 200, None)
    assert any(item["agent_id"] == document["agent_id"] for item in page.items)
    assert page.next_cursor is None
    principal = AuthenticatedPrincipal(
        tenant_id="tnt_bank-a",
        principal_id="prn_registry-admin",
        identity_kind="human",
        auth_strength="hardware",
        roles=["registry.admin"],
    )
    updated = document | {"lifecycle_state": "ACTIVE", "updated_at": "2026-08-25T00:01:00Z"}
    assert (
        repository.update_agent(
            "tnt_bank-a",
            document["agent_id"],
            updated,
            principal,
            None,
        )["lifecycle_state"]
        == "ACTIVE"
    )
    profile = {
        "profile_id": "bp_transfer-v1",
        "profile_version": 2,
        "canonicalization": "RFC8785",
        "bound_pointers": ["/amount"],
        "volatile_pointers": ["/request_time"],
        "unknown_pointer_policy": "reject",
    }
    assert (
        repository.publish_binding_profile(
            "tnt_bank-a",
            "tool_transfer",
            profile,
        )["binding_profile"]["profile_version"]
        == 2
    )
    simulation = repository.simulate_policy(
        "tnt_bank-a",
        "pol_blocked-intent",
        context(),
        principal.principal_id,
        1,
    )
    assert simulation["matched"] is True and simulation["decision"] == "ALLOW"

    lifecycle_policy = {
        "schema_version": "1.3",
        "policy_id": "pol_lifecycle-contract",
        "tenant_id": "tnt_bank-a",
        "name": "Lifecycle contract",
        "version": 1,
        "status": "DRAFT",
        "author": "prn_policy-author",
        "applies_to": {"tool_ids": ["tool_transfer"]},
        "conditions": {"field": "action.type", "op": "eq", "value": "financial_write"},
        "decision": "ALLOW",
        "priority": 101,
        "content_hash": "0" * 64,
        "created_at": "2026-08-25T00:00:00Z",
    }
    lifecycle_policy["content_hash"] = policy_semantic_hash(lifecycle_policy)
    repository.create_policy("tnt_bank-a", lifecycle_policy)
    repository.simulate_policy(
        "tnt_bank-a",
        lifecycle_policy["policy_id"],
        context(),
        principal.principal_id,
        1,
    )
    semantic_hash = lifecycle_policy["content_hash"]
    for status in ("TESTED", "APPROVED", "ACTIVE"):
        transitioned = repository.transition_policy(
            "tnt_bank-a", lifecycle_policy["policy_id"], 1, status, principal
        )
        assert transitioned["status"] == status
        assert transitioned["content_hash"] == semantic_hash
    assert transitioned["approver"] == principal.principal_id
    assert transitioned["effective_from"].endswith("Z")


@pytest.mark.skipif(not os.getenv("MIZAN_TEST_DATABASE_URL"), reason="Postgres not configured")
def test_redacted_audit_write_is_chained_without_raw_pii() -> None:
    repository = EvidenceRepository(os.environ["MIZAN_TEST_DATABASE_URL"])
    redactor = Redactor(
        RuleBasedDlpScanner(),
        b"k" * 32,
        "hsm://audit/test-key",
        lambda details: repository.record_redaction_failure("tnt_bank-a", details),
    )
    policy = RedactionPolicy(
        "dlp_banking-v1",
        1,
        "a" * 64,
        {"pii": "mask", "financial": "tokenize", "secret": "drop"},
    )
    redacted = redactor.redact(
        {"email": "alice@example.test", "account_number": "AE001234", "safe": "ok"},
        policy,
    )
    audit = repository.append_audit(
        "tnt_bank-a",
        "mizan.security.redacted",
        {"id": "mizan-redactor", "kind": "service"},
        {"id": "agt_wealth-01", "kind": "agent"},
        redacted,
    )
    assert "alice@example.test" not in json.dumps(audit)
    assert audit["redaction"]["dlp"]["status"] == "findings_redacted"
    page = repository.search_audit("tnt_bank-a", 10, event_type="mizan.security.redacted")
    assert any(item["audit_id"] == audit["audit_id"] for item in page["items"])
    with pytest.raises(Problem, match="payload does not match"):
        repository.append_audit(
            "tnt_bank-a",
            "mizan.security.redacted",
            {"id": "bad-writer", "kind": "service"},
            {"id": "agt_wealth-01", "kind": "agent"},
            SimpleNamespace(
                payload=redacted.payload,
                stored_payload_hash="0" * 64,
                source_commitment=redacted.source_commitment,
                redaction=redacted.redaction,
            ),
        )
    with pytest.raises(Problem, match="attestation"):
        repository.append_audit(
            "tnt_bank-a",
            "mizan.security.redacted",
            {"id": "bad-writer", "kind": "service"},
            {"id": "agt_wealth-01", "kind": "agent"},
            SimpleNamespace(payload={"email": "raw@example.test"}, redaction={}),
        )
    repository.record_redaction_failure(
        "tnt_bank-a",
        {
            "redactor_build": "mizan-redactor-1",
            "scanner_version": "scanner-failed-1",
            "coverage_profile": "banking-core-v1",
        },
    )
    failures = [
        item
        for item in repository.unpublished("tnt_bank-a", 100)
        if item["event_type"] == "mizan.security.redaction_failed"
    ]
    assert failures and "payload" not in failures[-1]["payload"]

class BarrierPostgresAuthorizationRepository(PostgresAuthorizationRepository):
    def __init__(self, database_url: str) -> None:
        super().__init__(database_url)
        self.initial_reads = Barrier(2)

    def find_decision_by_request(self, tenant_id: str, request_id: str):
        prior = super().find_decision_by_request(tenant_id, request_id)
        if prior is None:
            self.initial_reads.wait(timeout=5)
        return prior


@pytest.mark.skipif(not os.getenv("MIZAN_TEST_DATABASE_URL"), reason="Postgres not configured")
def test_concurrent_duplicate_request_returns_one_postgres_decision() -> None:
    repository = BarrierPostgresAuthorizationRepository(os.environ["MIZAN_TEST_DATABASE_URL"])
    service = AuthorizationService(repository, RegistryFloorRiskProvider(), "integration", "f" * 64)
    identity = AuthenticatedIdentity(
        tenant_id="tnt_bank-a",
        agent_id="agt_wealth-01",
        subject="test",
        delegation_chain=["agt_wealth-01"],
    )
    active_tool = repository.get_tool("tnt_bank-a", "tool_transfer")
    assert active_tool is not None

    def concurrent_context():
        request = context("018f47a6-7b42-7c00-8000-000000000199")
        request.tool.binding_profile.profile_id = active_tool.profile_id
        request.tool.binding_profile.profile_version = active_tool.profile_version
        return request

    with ThreadPoolExecutor(max_workers=2) as workers:
        futures = [
            workers.submit(
                service.authorize,
                identity,
                concurrent_context(),
            )
            for _ in range(2)
        ]
        responses = [future.result(timeout=10) for future in futures]
    assert responses[0] == responses[1]
    with repository.pool.connection() as connection, connection.transaction():
        repository._scope(connection, "tnt_bank-a")
        count = connection.execute(
            "SELECT count(*) FROM mizan.adr_records WHERE request_id=%s",
            ("018f47a6-7b42-7c00-8000-000000000199",),
        ).fetchone()[0]
    assert count == 1


def _focused_authorization(request_id: str):
    repository = PostgresAuthorizationRepository(os.environ["MIZAN_TEST_DATABASE_URL"])
    active_tool = repository.get_tool("tnt_bank-a", "tool_transfer")
    assert active_tool is not None
    request = context(request_id)
    request.tool.binding_profile.profile_id = active_tool.profile_id
    request.tool.binding_profile.profile_version = active_tool.profile_version
    principal = AuthenticatedIdentity(
        tenant_id="tnt_bank-a",
        agent_id="agt_wealth-01",
        subject="test",
        delegation_chain=["agt_wealth-01"],
    )
    response = AuthorizationService(
        repository, RegistryFloorRiskProvider(), "integration", "f" * 64
    ).authorize(principal, request)
    return repository, response


def _publish_focused_evidence(repository, tmp_path: Path):
    evidence = EvidenceRepository(os.environ["MIZAN_TEST_DATABASE_URL"])
    signer = Ed25519EvidenceSigner.generate()
    store = LocalImmutableObjectStore(tmp_path)
    publisher = OutboxPublisher(evidence, store, signer)
    publisher.drain("tnt_bank-a")
    publisher.anchor("tnt_bank-a", "tnt_bank-a:adr:0")
    return ObjectEvidenceVerifier(evidence, store, {signer.key_id: signer.public_key})


@pytest.mark.skipif(not os.getenv("MIZAN_TEST_DATABASE_URL"), reason="Postgres not configured")
def test_i1_authorization_commits_one_adr_and_outbox() -> None:
    repository, response = _focused_authorization("018f47a6-7b42-7c00-8000-000000000201")
    with repository.pool.connection() as connection, connection.transaction():
        repository._scope(connection, "tnt_bank-a")
        adr_count = connection.execute(
            "SELECT count(*) FROM mizan.adr_records WHERE decision_id=%s",
            (response.decision_id,),
        ).fetchone()[0]
        outbox_count = connection.execute(
            "SELECT count(*) FROM mizan.outbox WHERE aggregate_type='decision' AND aggregate_id=%s",
            (response.decision_id,),
        ).fetchone()[0]
    assert (adr_count, outbox_count) == (1, 1)


@pytest.mark.skipif(not os.getenv("MIZAN_TEST_DATABASE_URL"), reason="Postgres not configured")
def test_v19_identical_decision_event_retry_returns_same_event() -> None:
    _, response = _focused_authorization("018f47a6-7b42-7c00-8000-000000000202")
    evidence = EvidenceRepository(os.environ["MIZAN_TEST_DATABASE_URL"])
    actor = {"kind": "system", "id": "mizan-control-plane", "authenticated_workload": None}
    payload = {"token_jti_hash": "d" * 64}
    first = evidence.append_decision_event(
        "tnt_bank-a", response.decision_id, "CAPABILITY_ISSUED", actor, payload
    )
    retry = evidence.append_decision_event(
        "tnt_bank-a", response.decision_id, "CAPABILITY_ISSUED", actor, payload
    )
    assert retry["event_id"] == first["event_id"]


@pytest.mark.skipif(not os.getenv("MIZAN_TEST_DATABASE_URL"), reason="Postgres not configured")
def test_i9_bound_argument_change_is_rejected_at_redemption(tmp_path: Path) -> None:
    repository, response = _focused_authorization("018f47a6-7b42-7c00-8000-000000000203")
    verifier = _publish_focused_evidence(repository, tmp_path)
    execution = ExecutionService(
        os.environ["MIZAN_TEST_DATABASE_URL"],
        ExecutionTokenCodec("https://issuer.mizan.test", Ed25519PrivateKey.generate()),
        verifier,
    )
    token = execution.issue(
        "tnt_bank-a", response.decision_id, "spiffe://mizan/executor/wealth"
    )
    with pytest.raises(Problem) as raised:
        execution.redeem(
            token,
            response.decision_id,
            "spiffe://mizan/executor/wealth",
            {"amount": 99999, "request_time": "changed"},
        )
    assert raised.value.code == "execution_arguments_drift"


@pytest.mark.skipif(not os.getenv("MIZAN_TEST_DATABASE_URL"), reason="Postgres not configured")
def test_i10_redeemed_capability_cannot_create_a_second_lease(tmp_path: Path) -> None:
    repository, response = _focused_authorization("018f47a6-7b42-7c00-8000-000000000204")
    verifier = _publish_focused_evidence(repository, tmp_path)
    execution = ExecutionService(
        os.environ["MIZAN_TEST_DATABASE_URL"],
        ExecutionTokenCodec("https://issuer.mizan.test", Ed25519PrivateKey.generate()),
        verifier,
    )
    arguments = {"amount": 12500, "request_time": "first"}
    token = execution.issue(
        "tnt_bank-a", response.decision_id, "spiffe://mizan/executor/wealth"
    )
    execution.redeem(
        token, response.decision_id, "spiffe://mizan/executor/wealth", arguments
    )
    with pytest.raises(Problem) as replay:
        execution.redeem(
            token, response.decision_id, "spiffe://mizan/executor/wealth", arguments
        )
    assert replay.value.code == "execution_token_consumed"


@pytest.mark.skipif(not os.getenv("MIZAN_TEST_DATABASE_URL"), reason="Postgres not configured")
def test_i23_second_registered_executor_redeems_its_own_token(tmp_path: Path) -> None:
    repository, response = _focused_authorization("018f47a6-7b42-7c00-8000-000000000205")
    verifier = _publish_focused_evidence(repository, tmp_path)
    execution = ExecutionService(
        os.environ["MIZAN_TEST_DATABASE_URL"],
        ExecutionTokenCodec("https://issuer.mizan.test", Ed25519PrivateKey.generate()),
        verifier,
    )
    token = execution.issue(
        "tnt_bank-a", response.decision_id, "spiffe://mizan/executor/settlement"
    )
    lease = execution.redeem(
        token,
        response.decision_id,
        "spiffe://mizan/executor/settlement",
        {"amount": 12500, "request_time": "second-executor"},
    )
    assert lease["authorized_executor"] == "spiffe://mizan/executor/settlement"


@pytest.mark.skipif(not os.getenv("MIZAN_TEST_DATABASE_URL"), reason="Postgres not configured")
def test_i25_financial_execution_waits_for_immutable_receipt(tmp_path: Path) -> None:
    repository, response = _focused_authorization("018f47a6-7b42-7c00-8000-000000000206")
    codec = ExecutionTokenCodec("https://issuer.mizan.test", Ed25519PrivateKey.generate())
    execution = ExecutionService(os.environ["MIZAN_TEST_DATABASE_URL"], codec, SimpleNamespace())
    token = execution.issue(
        "tnt_bank-a", response.decision_id, "spiffe://mizan/executor/wealth"
    )
    arguments = {"amount": 12500, "request_time": "receipt-gate"}
    with pytest.raises(Problem) as missing:
        execution.redeem(
            token, response.decision_id, "spiffe://mizan/executor/wealth", arguments
        )
    assert missing.value.code == "immutable_receipt_missing"
    execution.receipt_gate = _publish_focused_evidence(repository, tmp_path)
    lease = execution.redeem(
        token, response.decision_id, "spiffe://mizan/executor/wealth", arguments
    )
    assert lease["state"] == "LEASED"
