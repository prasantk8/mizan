from __future__ import annotations

import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from threading import Barrier
from types import SimpleNamespace

import pytest
from mizan_control_plane.approval_repository import ApprovalRepository
from mizan_control_plane.attestation import AnchorAttestationWorker
from mizan_control_plane.drain_worker import run_once as drain_run_once
from mizan_control_plane.evidence import (
    Ed25519EvidenceSigner,
    EvidenceRepository,
    LocalImmutableObjectStore,
    ObjectEvidenceVerifier,
    OutboxPublisher,
)
from mizan_control_plane.execution import ExecutionService, ExecutionTokenCodec
from mizan_control_plane.keys import local_private_key_for_testing
from mizan_control_plane.models import AuthenticatedIdentity, AuthenticatedPrincipal
from mizan_control_plane.problems import Problem
from mizan_control_plane.registry import RegistryRepository, policy_semantic_hash
from mizan_control_plane.repository import PostgresAuthorizationRepository
from mizan_control_plane.risk import RegistryFloorRiskProvider
from mizan_control_plane.service import AuthorizationService
from mizan_security.redaction import RedactionPolicy, Redactor, RuleBasedDlpScanner

from tests.unit.test_authorization import context
from tests.unit.test_registry import agent_document


def _operator(principal_id: str) -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        tenant_id="tnt_bank-a",
        principal_id=principal_id,
        identity_kind="human",
        auth_strength="hardware",
        roles=["registry.admin"],
    )


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
    receipt_signer = Ed25519EvidenceSigner.development("evidence-receipt")
    anchor_signer = Ed25519EvidenceSigner.development("evidence-anchor")
    store = LocalImmutableObjectStore(tmp_path)
    publisher = OutboxPublisher(evidence_repository, store, receipt_signer, anchor_signer)
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
        {
            receipt_signer.key_id: receipt_signer.public_key,
            anchor_signer.key_id: anchor_signer.public_key,
        },
    )
    assert verifier.verify("tnt_bank-a", "tnt_bank-a:adr:0").valid

    codec = ExecutionTokenCodec("https://issuer.mizan.test", local_private_key_for_testing("integration-execution-1"))
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
    assert repository.create_agent("tnt_bank-a", document, _operator("prn_registry-admin")) == document
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
            principal,
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
    repository.create_policy("tnt_bank-a", lifecycle_policy, principal)
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
    receipt_signer = Ed25519EvidenceSigner.development("evidence-receipt")
    anchor_signer = Ed25519EvidenceSigner.development("evidence-anchor")
    store = LocalImmutableObjectStore(tmp_path)
    publisher = OutboxPublisher(evidence, store, receipt_signer, anchor_signer)
    publisher.drain("tnt_bank-a")
    publisher.anchor("tnt_bank-a", "tnt_bank-a:adr:0")
    return ObjectEvidenceVerifier(
        evidence,
        store,
        {
            receipt_signer.key_id: receipt_signer.public_key,
            anchor_signer.key_id: anchor_signer.public_key,
        },
    )


@pytest.mark.skipif(not os.getenv("MIZAN_TEST_DATABASE_URL"), reason="Postgres not configured")
def test_anchor_attestation_append_reports_insert_idempotence_and_conflict(tmp_path: Path) -> None:
    repository, _ = _focused_authorization("018f47a6-7b42-7c00-8000-000000000299")
    evidence = EvidenceRepository(os.environ["MIZAN_TEST_DATABASE_URL"])
    publisher = OutboxPublisher(
        evidence,
        LocalImmutableObjectStore(tmp_path),
        Ed25519EvidenceSigner.development("evidence-receipt"),
        Ed25519EvidenceSigner.development("evidence-anchor"),
    )
    publisher.drain("tnt_bank-a")
    anchor = publisher.anchor("tnt_bank-a", "tnt_bank-a:adr:0")
    document = {
        "type": "rfc3161", "status": "attested", "authority": "tsa-test",
        "anchor_digest": "a" * 64, "evidence": "AA==",
    }

    assert evidence.record_anchor_attestation(
        "tnt_bank-a", anchor["anchor_id"], document
    ) == "appended"
    assert evidence.record_anchor_attestation(
        "tnt_bank-a", anchor["anchor_id"], document
    ) == "unchanged"
    assert evidence.record_anchor_attestation(
        "tnt_bank-a", anchor["anchor_id"], document | {"evidence": "AQ=="}
    ) == "conflict"
    stored = evidence.anchor_attestation(
        "tnt_bank-a", anchor["anchor_id"], "tsa-test", "rfc3161"
    )
    assert isinstance(stored, dict)
    assert stored == document

    def competing_lease():
        with evidence.lease_anchor_attestation("tnt_bank-a", anchor["anchor_id"]) as value:
            return value

    with evidence.lease_anchor_attestation("tnt_bank-a", anchor["anchor_id"]) as first_lease:
        assert first_lease == [document]
        with ThreadPoolExecutor(max_workers=1) as executor:
            assert executor.submit(competing_lease).result(timeout=2) is None

    pending = document | {
        "status": "pending", "evidence": None,
        "requested_at": datetime.now(UTC).isoformat(),
    }
    observed = []
    provider = SimpleNamespace(
        obtain=lambda item: pytest.fail("a finalized leased sidecar must prevent TSA access"),
        attestation_validation_failure=lambda item, digest, authority: (
            observed.append((item, digest, authority)) or None
        ),
    )
    opened = []
    worker = AnchorAttestationWorker(
        evidence, provider, SimpleNamespace(open=lambda *args: opened.append(args))
    )
    row = evidence.anchors("tnt_bank-a", anchor["stream_id"])[-1]
    row["payload"]["attestations"] = [pending]

    assert worker.process("tnt_bank-a", [row], 900) == 0
    assert isinstance(observed[0][0], dict)
    assert observed[0][0] == document
    assert observed[0][2] == "tsa-test"
    assert opened == []


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
        ExecutionTokenCodec("https://issuer.mizan.test", local_private_key_for_testing("integration-execution-2")),
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
        ExecutionTokenCodec("https://issuer.mizan.test", local_private_key_for_testing("integration-execution-3")),
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
        ExecutionTokenCodec("https://issuer.mizan.test", local_private_key_for_testing("integration-execution-4")),
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
    codec = ExecutionTokenCodec("https://issuer.mizan.test", local_private_key_for_testing("integration-execution-5"))
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


@pytest.mark.skipif(not os.getenv("MIZAN_TEST_DATABASE_URL"), reason="Postgres not configured")
def test_the_shipped_drain_worker_is_what_lets_a_financial_write_execute(tmp_path: Path) -> None:
    """T-099, rule 8. The gap between "Mizan approved the payment" and "Mizan executed it".

    `mizan-drain-outbox` is the entrypoint named by `compose.production.yaml` and
    `charts/mizan/templates/drainer-deployment.yaml`, and until this change it did not exist. No
    worker means `mizan.evidence_receipts` is never written, and `_require_receipts` then refuses
    every `financial_write` with 403 `immutable_receipt_missing` -- permanently, on a decision a
    human already approved.

    Every existing test that got past this point hand-rolled `drain()` and `anchor()` itself, so
    the suite proved the *primitives* worked and never that anything ran them. This one drives
    the shipped worker's own cycle, which is what production launches.
    """
    _repository, response = _focused_authorization("018f47a6-7b42-7c00-8000-000000000207")
    codec = ExecutionTokenCodec(
        "https://issuer.mizan.test", local_private_key_for_testing("integration-execution-9")
    )
    execution = ExecutionService(os.environ["MIZAN_TEST_DATABASE_URL"], codec, SimpleNamespace())
    token = execution.issue("tnt_bank-a", response.decision_id, "spiffe://mizan/executor/wealth")
    arguments = {"amount": 12500, "request_time": "drain-worker-gate"}

    with pytest.raises(Problem) as refused:
        execution.redeem(token, response.decision_id, "spiffe://mizan/executor/wealth", arguments)
    assert refused.value.status == 403
    assert refused.value.code == "immutable_receipt_missing"

    evidence = EvidenceRepository(os.environ["MIZAN_TEST_DATABASE_URL"])
    receipt_signer = Ed25519EvidenceSigner.development("evidence-receipt")
    anchor_signer = Ed25519EvidenceSigner.development("evidence-anchor")
    store = LocalImmutableObjectStore(tmp_path)
    publisher = OutboxPublisher(evidence, store, receipt_signer, anchor_signer)
    report = drain_run_once(
        publisher, evidence, ["tnt_bank-a"], batch_size=100, max_unpublished_seconds=5
    )

    assert report.published > 0, "the worker published nothing, so the lease below proves nothing"
    assert report.anchored > 0, "no anchor means no RFC 3161 token and no exportable bundle"
    assert report.quarantined == 0 and report.failed == 0
    # The queue is empty afterwards, so the publication SLO is not breached.
    assert report.lag_breaches == []
    # The worker discovered the stream itself rather than being handed one, which is what makes
    # it a managed workload instead of a one-shot script.
    assert "tnt_bank-a:adr:0" in evidence.streams("tnt_bank-a")

    execution.receipt_gate = ObjectEvidenceVerifier(
        evidence,
        store,
        {
            receipt_signer.key_id: receipt_signer.public_key,
            anchor_signer.key_id: anchor_signer.public_key,
        },
    )
    lease = execution.redeem(
        token, response.decision_id, "spiffe://mizan/executor/wealth", arguments
    )
    assert lease["state"] == "LEASED"


@pytest.mark.skipif(not os.getenv("MIZAN_TEST_DATABASE_URL"), reason="Postgres not configured")
def test_a_poisoned_outbox_row_is_set_aside_with_its_reason_against_a_live_table() -> None:
    """The quarantine arithmetic from migration 0004, against the real UPDATE.

    The unit tests model `attempts+1 >= budget` by hand. This runs the statement, because the
    half that matters is the `CASE WHEN` that sets `quarantined_at` only on the attempt that
    exhausts the budget -- and because the partial index and the CHECK constraint keeping
    quarantine and publication distinct exist only in the database.
    """
    _focused_authorization("018f47a6-7b42-7c00-8000-000000000208")
    evidence = EvidenceRepository(os.environ["MIZAN_TEST_DATABASE_URL"])
    pending = evidence.unpublished("tnt_bank-a", limit=1)
    assert pending, "the fixture wrote no outbox row, so this test would assert nothing"
    outbox_id = pending[0]["outbox_id"]

    assert evidence.record_publication_failure("tnt_bank-a", outbox_id, "boom", 2) is False
    assert all(row["outbox_id"] != outbox_id for row in evidence.quarantined("tnt_bank-a"))
    assert evidence.record_publication_failure("tnt_bank-a", outbox_id, "boom again", 2) is True

    held = {row["outbox_id"]: row for row in evidence.quarantined("tnt_bank-a")}
    assert outbox_id in held
    assert held[outbox_id]["attempts"] == 2
    assert held[outbox_id]["last_error"] == "boom again"
    assert held[outbox_id]["quarantined_at"] is not None
    # A quarantined row leaves the drain queue, which is what stops it blocking its stream.
    assert all(row["outbox_id"] != outbox_id for row in evidence.unpublished("tnt_bank-a"))


@pytest.mark.skipif(not os.getenv("MIZAN_TEST_DATABASE_URL"), reason="Postgres not configured")
def test_one_operator_cannot_downgrade_a_production_critical_agent() -> None:
    repository = RegistryRepository(os.environ["MIZAN_TEST_DATABASE_URL"])
    protected = agent_document() | {
        "agent_id": "agt_dual-control",
        "environment": "production",
        "risk_tier": "CRITICAL",
    }
    # Creating it already needs four eyes; the point of the test is what happens next.
    repository.create_agent(
        "tnt_bank-a", protected, _operator("prn_admin-a"), _operator("prn_admin-b")
    )
    # The write that removes its own protection: one operator, one PATCH, CRITICAL to LOW.
    downgrade = protected | {"risk_tier": "LOW", "updated_at": "2026-08-25T00:02:00Z"}
    with pytest.raises(Problem) as raised:
        repository.update_agent("tnt_bank-a", "agt_dual-control", downgrade, _operator("prn_admin-a"), None)
    assert raised.value.code == "agent_dual_control_required"
    assert repository.get("tnt_bank-a", "agents", "agt_dual-control")["risk_tier"] == "CRITICAL"
    accepted = repository.update_agent(
        "tnt_bank-a", "agt_dual-control", downgrade, _operator("prn_admin-a"), _operator("prn_admin-b")
    )
    assert accepted["risk_tier"] == "LOW"


@pytest.mark.skipif(not os.getenv("MIZAN_TEST_DATABASE_URL"), reason="Postgres not configured")
def test_patch_cannot_attach_an_agent_to_a_parent_that_did_not_authorize_it() -> None:
    repository = RegistryRepository(os.environ["MIZAN_TEST_DATABASE_URL"])
    parent = agent_document() | {"agent_id": "agt_unwilling-parent"}
    child = agent_document() | {"agent_id": "agt_grafted-child"}
    repository.create_agent("tnt_bank-a", parent, _operator("prn_admin-a"))
    repository.create_agent("tnt_bank-a", child, _operator("prn_admin-a"))
    grafted = child | {
        "parent_agent_id": "agt_unwilling-parent",
        "updated_at": "2026-08-25T00:03:00Z",
    }
    with pytest.raises(Problem) as raised:
        repository.update_agent("tnt_bank-a", "agt_grafted-child", grafted, _operator("prn_admin-a"), None)
    assert raised.value.code == "registry_reference_missing"
    assert repository.get("tnt_bank-a", "agents", "agt_grafted-child").get("parent_agent_id") is None


@pytest.mark.skipif(not os.getenv("MIZAN_TEST_DATABASE_URL"), reason="Postgres not configured")
def test_an_agent_token_cannot_register_a_tool_that_permits_itself() -> None:
    repository = RegistryRepository(os.environ["MIZAN_TEST_DATABASE_URL"])
    agent_principal = AuthenticatedPrincipal(
        tenant_id="tnt_bank-a",
        principal_id="prn_self-serving",
        identity_kind="agent",
        auth_strength="federated",
        roles=["registry.admin"],
    )
    document = {
        "schema_version": "1.2",
        "tool_id": "tool_self-granted",
        "tenant_id": "tnt_bank-a",
        "name": "Self granted",
        "owner": "wealth-team",
        "risk_tier": "LOW",
        "action_type": "financial_write",
        "resource_owner": "core-banking",
        "data_classification": "financial",
        "binding_profile": {
            "profile_id": "bp_self-granted-v1",
            "profile_version": 1,
            "canonicalization": "RFC8785",
            "bound_pointers": ["/amount"],
            "volatile_pointers": [],
            "unknown_pointer_policy": "reject",
        },
        "execution": {
            "executor_spiffe_ids": ["spiffe://mizan/executor/wealth"],
            "token_ttl_seconds": 300,
            "lease_ttl_seconds": 900,
            "heartbeat_interval_seconds": 60,
            "max_lease_extensions": 24,
        },
        "created_at": "2026-08-26T00:00:00Z",
    }
    with pytest.raises(Problem) as raised:
        repository.create_tool("tnt_bank-a", document, agent_principal)
    assert raised.value.code == "registry_write_auth_insufficient"
    with pytest.raises(Problem):
        repository.get("tnt_bank-a", "tools", "tool_self-granted")
    # A weakly authenticated human is refused for the same reason.
    weak = AuthenticatedPrincipal(
        tenant_id="tnt_bank-a",
        principal_id="prn_password-only",
        identity_kind="human",
        auth_strength="password",
        roles=["registry.admin"],
    )
    with pytest.raises(Problem) as weakly:
        repository.create_tool("tnt_bank-a", document, weak)
    assert weakly.value.code == "registry_write_auth_insufficient"
    assert (
        repository.create_tool("tnt_bank-a", document, _operator("prn_registry-admin"))["tool_id"]
        == "tool_self-granted"
    )


@pytest.mark.skipif(not os.getenv("MIZAN_TEST_DATABASE_URL"), reason="Postgres not configured")
def test_a_production_critical_agent_cannot_be_created_by_one_operator() -> None:
    repository = RegistryRepository(os.environ["MIZAN_TEST_DATABASE_URL"])
    document = agent_document() | {
        "agent_id": "agt_four-eyes",
        "environment": "production",
        "risk_tier": "CRITICAL",
    }
    with pytest.raises(Problem) as raised:
        repository.create_agent("tnt_bank-a", document, _operator("prn_admin-a"))
    assert raised.value.code == "registry_dual_control_required"
    with pytest.raises(Problem) as same_person:
        repository.create_agent(
            "tnt_bank-a", document, _operator("prn_admin-a"), _operator("prn_admin-a")
        )
    assert same_person.value.code == "registry_dual_control_required"
    assert (
        repository.create_agent(
            "tnt_bank-a", document, _operator("prn_admin-a"), _operator("prn_admin-b")
        )["agent_id"]
        == "agt_four-eyes"
    )


@pytest.mark.skipif(not os.getenv("MIZAN_TEST_DATABASE_URL"), reason="Postgres not configured")
def test_a_financial_write_is_refused_when_no_receipt_verifier_is_configured() -> None:
    """An operator who deployed without the evidence verifier gets a refusal, not an execution.

    SPEC 5.4 makes durable publication a precondition of a financial write. With no verifier there
    is nothing that can establish it, and "we could not check" is not "it is fine": the 503 says the
    control plane is not currently able to authorize this class of call at all.
    """
    repository, response = _focused_authorization("018f47a6-7b42-7c00-8000-000000000301")
    execution = ExecutionService(
        os.environ["MIZAN_TEST_DATABASE_URL"],
        ExecutionTokenCodec(
            "https://issuer.mizan.test", local_private_key_for_testing("integration-execution-6")
        ),
        None,
    )
    token = execution.issue("tnt_bank-a", response.decision_id, "spiffe://mizan/executor/wealth")
    with pytest.raises(Problem) as refused:
        execution.redeem(
            token,
            response.decision_id,
            "spiffe://mizan/executor/wealth",
            {"amount": 12500, "request_time": "no-verifier"},
        )
    assert refused.value.code == "receipt_verifier_unavailable"
    assert refused.value.status == 503


@pytest.mark.skipif(not os.getenv("MIZAN_TEST_DATABASE_URL"), reason="Postgres not configured")
def test_a_published_receipt_that_does_not_verify_refuses_the_financial_write(
    tmp_path: Path,
) -> None:
    """A receipt row existing is not a receipt verifying, and the gate must not confuse the two.

    The row is present and correctly bound — `immutable_receipt_missing` does not fire — and the
    verifier rejects the signature. That is the shape a tampered or wrongly-keyed evidence store
    takes, and it is a distinct refusal from the publication race the drainer produces.
    """
    repository, response = _focused_authorization("018f47a6-7b42-7c00-8000-000000000302")
    _publish_focused_evidence(repository, tmp_path)
    execution = ExecutionService(
        os.environ["MIZAN_TEST_DATABASE_URL"],
        ExecutionTokenCodec(
            "https://issuer.mizan.test", local_private_key_for_testing("integration-execution-7")
        ),
        SimpleNamespace(verify_record_receipt=lambda *arguments: False),
    )
    token = execution.issue("tnt_bank-a", response.decision_id, "spiffe://mizan/executor/wealth")
    with pytest.raises(Problem) as refused:
        execution.redeem(
            token,
            response.decision_id,
            "spiffe://mizan/executor/wealth",
            {"amount": 12500, "request_time": "unverifiable-receipt"},
        )
    assert refused.value.code == "immutable_receipt_invalid"
