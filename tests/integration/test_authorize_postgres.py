from __future__ import annotations

import json
import os
import time
from pathlib import Path
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
from mizan_control_plane.registry import RegistryRepository
from mizan_control_plane.repository import PostgresAuthorizationRepository
from mizan_control_plane.risk import RegistryFloorRiskProvider
from mizan_control_plane.service import AuthorizationService
from mizan_security.redaction import RedactionPolicy, Redactor, RuleBasedDlpScanner

from tests.unit.test_authorization import context
from tests.unit.test_registry import agent_document


@pytest.mark.skipif(not os.getenv("MIZAN_TEST_DATABASE_URL"), reason="Postgres not configured")
def test_authorize_persists_adr_and_outbox_atomically(tmp_path: Path) -> None:
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
    assert event["sequence_number"] == 1
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
    verifier = ObjectEvidenceVerifier(
        evidence_repository,
        store,
        {signer.key_id: signer.public_key},
    )
    assert verifier.verify("tnt_bank-a", "tnt_bank-a:adr:0").valid

    codec = ExecutionTokenCodec("https://issuer.mizan.test", Ed25519PrivateKey.generate())
    execution = ExecutionService(os.environ["MIZAN_TEST_DATABASE_URL"], codec, verifier)
    token = execution.issue("tnt_bank-a", response.decision_id)
    with pytest.raises(Problem) as wrong_executor:
        execution.redeem(token, response.decision_id, "spiffe://mizan/executor/attacker", "attack")
    assert wrong_executor.value.status == 403
    lease = execution.redeem(
        token,
        response.decision_id,
        "spiffe://mizan/executor/wealth",
        "execution-1",
    )
    assert (
        execution.redeem(
            token,
            response.decision_id,
            "spiffe://mizan/executor/wealth",
            "execution-1",
        )["lease_id"]
        == lease["lease_id"]
    )
    with pytest.raises(Problem, match="consumed"):
        execution.redeem(
            token,
            response.decision_id,
            "spiffe://mizan/executor/wealth",
            "different-execution",
        )
    running = execution.heartbeat(
        "tnt_bank-a",
        response.decision_id,
        lease["lease_id"],
        "spiffe://mizan/executor/wealth",
    )
    assert running["state"] == "EXECUTING"
    completed = execution.complete(
        "tnt_bank-a",
        response.decision_id,
        lease["lease_id"],
        "spiffe://mizan/executor/wealth",
        "e" * 64,
        None,
    )
    assert completed["state"] == "EXECUTED"

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


@pytest.mark.skipif(not os.getenv("MIZAN_TEST_DATABASE_URL"), reason="Postgres not configured")
def test_redacted_audit_write_is_chained_without_raw_pii() -> None:
    redactor = Redactor(RuleBasedDlpScanner(), b"k" * 32, "hsm://audit/test-key")
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
    repository = EvidenceRepository(os.environ["MIZAN_TEST_DATABASE_URL"])
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
    with pytest.raises(Problem, match="attestation"):
        repository.append_audit(
            "tnt_bank-a",
            "mizan.security.redacted",
            {"id": "bad-writer", "kind": "service"},
            {"id": "agt_wealth-01", "kind": "agent"},
            SimpleNamespace(payload={"email": "raw@example.test"}, redaction={}),
        )
