"""Approver inbox route sequence and rendered-field contract."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from mizan_control_plane import app as app_module
from mizan_control_plane.config import Settings
from mizan_control_plane.dev_token import ensure_keypair, mint, public_jwks

TENANT = "tnt_bank-a"
APPROVAL_ID = "apr_inbox-0001"
DECISION_ID = "adr_inbox-0001"
EXPIRES_AT = "2099-08-27T07:00:00Z"

EPOCH = {
    "epoch_id": "epo_inbox-0001",
    "epoch_number": 1,
    "kind": "initial",
    "state": "OPEN",
    "opened_at": "2026-08-27T05:00:00Z",
    "expires_at": EXPIRES_AT,
    "closed_at": None,
    "quorum": 2,
    "distinct_control_domains_required": True,
    "rejection_mode": "veto",
    "rejection_quorum_count": None,
    "eligibility": {
        "roles": ["manager", "risk_officer"],
        "members": [
            {
                "principal_id": "prn_approver",
                "roles": ["manager"],
                "control_domain": "business",
            },
            {
                "principal_id": "prn_risk",
                "roles": ["risk_officer"],
                "control_domain": "risk",
            },
        ],
        "snapshot_hash": "1" * 64,
    },
    "carried_votes": [
        {
            "approver_id": "prn_prior",
            "control_domain": "operations",
            "vote": "APPROVE",
        }
    ],
    "votes": [],
    "outcome": "PENDING",
}
APPROVAL = {
    "schema_version": "1.2",
    "approval_id": APPROVAL_ID,
    "tenant_id": TENANT,
    "decision_id": DECISION_ID,
    "state": "PENDING",
    "current_epoch_id": EPOCH["epoch_id"],
    "epochs": [EPOCH],
    "context_hash_at_request": "2" * 64,
    "created_at": "2026-08-27T05:00:00Z",
}
DECISION = {
    "schema_version": "1.2",
    "decision_id": DECISION_ID,
    "tenant_id": TENANT,
    "trace_id": "trace-inbox-0001",
    "timestamp": "2026-08-27T05:00:00Z",
    "principal": {"id": "prn_customer", "type": "customer", "auth_strength": "mfa"},
    "agent": {
        "id": "agt_wealth-01",
        "version": "1.0.0",
        "delegation_chain": ["agt_parent", "agt_wealth-01"],
    },
    "intent": "transfer funds after settlement",
    "tool": {
        "id": "tool_transfer",
        "parameters_hash": "3" * 64,
        "binding_profile": {"profile_id": "bp_transfer-v1", "profile_version": 1},
    },
    "action": {"type": "financial_write"},
    "resource": {
        "id": "account/42",
        "type": "account",
        "data_classification": "restricted",
    },
    "risk": {"level": "CRITICAL", "floor_source": "registry"},
    "policies": ["pol_transfers"],
    "reasons": [{"code": "HUMAN_APPROVAL_REQUIRED", "message": "requires quorum"}],
    "decision": "REQUIRE_APPROVAL",
}
EVENT = {
    "event_id": "dev_inbox-0001",
    "decision_id": DECISION_ID,
    "decision_sequence": 1,
    "event_type": "APPROVAL_REQUESTED",
    "actor": {"kind": "agent", "id": "agt_wealth-01"},
    "occurred_at": "2026-08-27T05:00:01Z",
}


class FakePool:
    def close(self) -> None:
        pass


class FakeRepository:
    def __init__(self, _database_url: str, *_arguments: object) -> None:
        # `*_arguments` because `ApprovalRepository` also takes the deployment's
        # `MIZAN_APPROVAL_EPOCH_EXPIRY` mode; these doubles model no expiry behaviour.
        self.pool = FakePool()


class FakeApprovalRepository(FakeRepository):
    def __init__(self, database_url: str, *arguments: object) -> None:
        super().__init__(database_url, *arguments)
        self.calls: list[tuple[str, tuple[Any, ...]]] = []

    def pending(self, *arguments: Any) -> dict[str, Any]:
        self.calls.append(("pending", arguments))
        return {
            "items": [
                {
                    "approval_id": APPROVAL_ID,
                    "decision_id": DECISION_ID,
                    "state": "PENDING",
                    "requester_id": "prn_requester",
                    "created_at": "2026-08-27T05:00:00Z",
                    "epoch": {
                        "epoch_id": EPOCH["epoch_id"],
                        "epoch_number": 1,
                        "kind": "initial",
                        "quorum": 2,
                        "expires_at": EXPIRES_AT,
                        "votes_cast": 1,
                        "approver_roles": ["manager", "risk_officer"],
                    },
                }
            ],
            "next_cursor": "cursor-next",
        }

    def get(self, *arguments: Any) -> dict[str, Any]:
        self.calls.append(("get", arguments))
        return deepcopy(APPROVAL)

    def vote(self, *arguments: Any) -> dict[str, Any]:
        self.calls.append(("vote", arguments))
        return deepcopy(APPROVAL)


class FakeEvidenceRepository(FakeRepository):
    def __init__(self, database_url: str, *arguments: object) -> None:
        super().__init__(database_url, *arguments)
        self.calls: list[tuple[str, tuple[Any, ...]]] = []

    def decision(self, *arguments: Any) -> dict[str, Any]:
        self.calls.append(("decision", arguments))
        return {"decision": deepcopy(DECISION), "events": [deepcopy(EVENT)]}


@pytest.fixture
def inbox(monkeypatch, tmp_path):
    repositories: dict[str, FakeRepository] = {}

    def factory(name: str, constructor):
        def build(database_url: str, *arguments: object):
            repositories[name] = constructor(database_url)
            return repositories[name]

        return build

    monkeypatch.setattr(
        app_module,
        "PostgresAuthorizationRepository",
        factory("authorization", FakeRepository),
    )
    monkeypatch.setattr(app_module, "RegistryRepository", factory("registry", FakeRepository))
    monkeypatch.setattr(
        app_module,
        "EvidenceRepository",
        factory("evidence", FakeEvidenceRepository),
    )
    monkeypatch.setattr(
        app_module,
        "ApprovalRepository",
        factory("approval", FakeApprovalRepository),
    )
    private_key, _public_pem = ensure_keypair(tmp_path / "keys")
    monkeypatch.setenv("MIZAN_DATABASE_URL", "postgresql://unused")
    monkeypatch.setenv("MIZAN_JWT_ISSUER", "urn:mizan:development:dev-token")
    monkeypatch.setenv("MIZAN_IDENTITY_JWKS", public_jwks(private_key))
    monkeypatch.setenv("MIZAN_EVIDENCE_OBJECT_STORE_ROOT", str(tmp_path / "evidence"))
    application = app_module.create_app(Settings.from_environment())
    with TestClient(application) as client:
        token = mint(
            private_key,
            tenant_id=TENANT,
            subject="prn_approver",
            agent_id="agt_unused",
            identity_kind="human",
            auth_strength="hardware",
            roles=["manager"],
            audience="mizan-control-plane",
            ttl_seconds=300,
        )
        yield client, repositories, {"Authorization": f"Bearer {token}"}


def assert_keys(document: dict[str, Any], *keys: str) -> None:
    assert set(keys) <= document.keys()


def test_approver_inbox_sequence_returns_every_field_the_console_renders(inbox) -> None:
    client, repositories, headers = inbox

    queue_response = client.get(
        "/v1/approvals?state=PENDING&limit=25", headers=headers
    )
    assert queue_response.status_code == 200, queue_response.text
    queue = queue_response.json()
    assert_keys(queue, "items", "next_cursor")
    item = queue["items"][0]
    assert_keys(item, "approval_id", "decision_id", "state", "requester_id", "created_at", "epoch")
    assert_keys(
        item["epoch"],
        "epoch_id",
        "epoch_number",
        "kind",
        "quorum",
        "expires_at",
        "votes_cast",
        "approver_roles",
    )

    approval_response = client.get(f"/v1/approvals/{APPROVAL_ID}", headers=headers)
    assert approval_response.status_code == 200, approval_response.text
    approval = approval_response.json()
    assert_keys(approval, "approval_id", "decision_id", "state", "current_epoch_id", "epochs")
    epoch = approval["epochs"][0]
    assert_keys(
        epoch,
        "epoch_id",
        "epoch_number",
        "kind",
        "expires_at",
        "quorum",
        "distinct_control_domains_required",
        "eligibility",
        "carried_votes",
        "votes",
    )
    assert_keys(epoch["eligibility"], "roles", "members")
    assert_keys(epoch["carried_votes"][0], "approver_id", "control_domain", "vote")

    decision_response = client.get(f"/v1/decisions/{DECISION_ID}", headers=headers)
    assert decision_response.status_code == 200, decision_response.text
    payload = decision_response.json()
    assert_keys(payload, "decision", "events")
    assert_keys(
        payload["decision"],
        "decision_id",
        "principal",
        "agent",
        "intent",
        "tool",
        "action",
        "resource",
        "risk",
        "policies",
        "reasons",
        "decision",
    )
    assert_keys(payload["decision"]["agent"], "id", "delegation_chain")
    assert_keys(payload["decision"]["tool"], "id", "parameters_hash", "binding_profile")
    assert_keys(payload["decision"]["risk"], "level", "floor_source")
    assert_keys(payload["decision"]["resource"], "data_classification")
    assert_keys(payload["events"][0], "event_type", "actor", "decision_sequence", "occurred_at")
    assert_keys(payload["events"][0]["actor"], "kind", "id")

    vote = {
        "vote": "APPROVE",
        "epoch_number": 1,
        "role_claim": "manager",
        "justification": "verified transfer mandate",
        "comment": "hardware-authenticated review",
    }
    vote_response = client.post(
        f"/v1/approvals/{APPROVAL_ID}/votes", json=vote, headers=headers
    )
    assert vote_response.status_code == 200, vote_response.text
    assert [call[0] for call in repositories["approval"].calls] == ["pending", "get", "vote"]
    assert [call[0] for call in repositories["evidence"].calls] == ["decision"]
    assert repositories["approval"].calls[-1][1][3] == vote

    source = Path("ui/app.js").read_text(encoding="utf-8")
    for rendered_field in (
        "requester_id",
        "votes_cast",
        "approver_roles",
        "current_epoch_id",
        "distinct_control_domains_required",
        "delegation_chain",
        "parameters_hash",
        "binding_profile",
        "floor_source",
        "data_classification",
        "control_domain",
        "decision_sequence",
        "occurred_at",
    ):
        assert rendered_field in source, f"approver inbox has no caller for {rendered_field}"
