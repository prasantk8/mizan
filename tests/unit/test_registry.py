from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from mizan_control_plane.problems import Problem
from mizan_control_plane.registry import RegistryRepository, decode_cursor, encode_cursor
from mizan_control_plane.schema_validation import ContractSchemas


def agent_document() -> dict:
    return {
        "schema_version": "1.1",
        "agent_id": "agt_registry-01",
        "tenant_id": "tnt_bank-a",
        "name": "Registry Agent",
        "version": "1.0.0",
        "owner": "wealth-team",
        "accountable_owner": "alice@example.test",
        "purpose": "Test registry behavior",
        "environment": "development",
        "risk_tier": "LOW",
        "lifecycle_state": "REGISTERED",
        "identity": {"auth_method": "jwt_svid", "credential_ref": "kms://test/agent-key"},
        "tools": [],
        "policies": [],
        "delegation": {
            "allowed_agent_ids": [],
            "max_delegation_depth": 0,
            "inherit_parent_permissions": False,
        },
        "created_at": "2026-08-25T00:00:00Z",
        "updated_at": "2026-08-25T00:00:00Z",
    }


def test_registry_uses_ratified_agent_schema() -> None:
    schemas = ContractSchemas(Path("SPEC_v1.md"))
    schemas.validate("Agent", agent_document())
    invalid = agent_document() | {"agent_id": "pol_wrong-family"}
    with pytest.raises(Problem) as raised:
        schemas.validate("Agent", invalid)
    assert raised.value.status == 400


def test_schema_rejects_unknown_registry_fields() -> None:
    schemas = ContractSchemas(Path("SPEC_v1.md"))
    invalid = agent_document() | {"caller_is_admin": True}
    with pytest.raises(Problem, match="Additional properties"):
        schemas.validate("Agent", invalid)


def test_cursor_round_trip_and_malformed_rejection() -> None:
    created_at = datetime(2026, 8, 25, tzinfo=UTC)
    assert decode_cursor(encode_cursor(created_at, "agt_registry-01")) == (
        created_at,
        "agt_registry-01",
    )
    with pytest.raises(Problem):
        decode_cursor("not-a-cursor")


def test_v1_policy_author_cannot_be_approver() -> None:
    document = {"status": "ACTIVE", "author": "prn_alice", "approver": "prn_alice"}
    with pytest.raises(Problem, match="cannot approve"):
        RegistryRepository._validate_policy(document)


def test_v3_v4_policy_escalation_and_rejection_semantics_are_explicit() -> None:
    base = {
        "status": "DRAFT",
        "author": "prn_alice",
        "approval_requirements": {
            "rejection_mode": "veto",
            "escalation": {"role": "supervisor"},
        },
    }
    with pytest.raises(Problem, match="explicit"):
        RegistryRepository._validate_policy(base)
    invalid = base | {
        "approval_requirements": {
            "rejection_mode": "veto",
            "rejection_quorum_count": 2,
            "escalation": None,
        }
    }
    with pytest.raises(Problem, match="Rejection count"):
        RegistryRepository._validate_policy(invalid)
