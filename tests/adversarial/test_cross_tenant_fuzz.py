"""Property tests make cross-tenant objects indistinguishable from absent objects."""

from __future__ import annotations

import os

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from mizan_control_plane.models import AuthenticatedPrincipal
from mizan_control_plane.problems import Problem
from mizan_control_plane.registry import RegistryRepository

from tests.unit.test_registry import agent_document

DATABASE_URL = os.getenv("MIZAN_TEST_DATABASE_URL")
TENANTS = ("tnt_bank-a", "tnt_bank-b")
AGENTS = {
    "tnt_bank-a": "agt_adversarial-a",
    "tnt_bank-b": "agt_adversarial-b",
}
TENANT_TABLES = (
    "tenants",
    "agents",
    "binding_profiles",
    "tools",
    "policies",
    "agent_tools",
    "agent_policies",
    "agent_delegations",
    "policy_simulations",
    "evidence_chain_heads",
    "adr_records",
    "adr_record_policies",
    "authorization_contexts",
    "approvals",
    "role_authority_versions",
    "approval_epochs",
    "approval_votes",
    "execution_tokens",
    "execution_leases",
    "decision_events",
    "decision_event_heads",
    "audit_trails",
    "external_payload_envelopes",
    "degraded_mode_grants",
    "outbox",
    "evidence_receipts",
    "evidence_anchors",
    "anchor_attestations",
)


def _operator(tenant_id: str) -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        tenant_id=tenant_id,
        principal_id="prn_adversarial-operator",
        identity_kind="human",
        auth_strength="hardware",
        roles=["registry.admin"],
    )


@pytest.fixture(scope="module")
def tenant_registry():
    if not DATABASE_URL:
        pytest.skip("Postgres not configured")
    repository = RegistryRepository(DATABASE_URL)
    for tenant_id, agent_id in AGENTS.items():
        document = agent_document() | {
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "name": f"Adversarial fixture {tenant_id}",
        }
        try:
            repository.create_agent(tenant_id, document, _operator(tenant_id))
        except Problem as problem:
            if problem.code != "agent_exists":
                raise
    yield repository
    repository.pool.close()


@given(
    victim=st.sampled_from(TENANTS),
    operation=st.sampled_from(("read", "write", "list")),
)
@settings(max_examples=24, deadline=None)
def test_random_cross_tenant_registry_read_or_write_looks_absent(
    tenant_registry: RegistryRepository,
    victim: str,
    operation: str,
) -> None:
    # No internal active() switch: F-3 requires the fault to be a regression in
    # product code. attacker is unconditionally the other tenant, and the external
    # fault in scripts/adversarial_fault_injection.py defeats RegistryRepository's
    # real RLS scoping call (repository.py's _scope) to prove this is a genuine
    # cross-tenant read/write, not a test that only ever queries its own tenant.
    attacker = TENANTS[1] if victim == TENANTS[0] else TENANTS[0]
    victim_id = AGENTS[victim]
    if operation == "list":
        page = tenant_registry.list(attacker, "agents", 200, None)
        assert victim_id not in {item["agent_id"] for item in page.items}
        return

    def action() -> None:
        if operation == "read":
            tenant_registry.get(attacker, "agents", victim_id)
            return
        candidate = agent_document() | {
            "tenant_id": attacker,
            "agent_id": victim_id,
        }
        tenant_registry.update_agent(
            attacker,
            victim_id,
            candidate,
            _operator(attacker),
            None,
        )

    with pytest.raises(Problem) as absent:
        action()
    assert (absent.value.status, absent.value.code) == (
        404,
        "registry_object_not_found",
    )


@given(attacker=st.sampled_from(TENANTS))
@settings(max_examples=8, deadline=None)
def test_every_route_backing_table_is_forced_into_the_authenticated_tenant(
    tenant_registry: RegistryRepository,
    attacker: str,
) -> None:
    with tenant_registry.pool.connection() as connection, connection.transaction():
        tenant_registry._scope(connection, attacker)
        for table in TENANT_TABLES:
            visible = connection.execute(
                f"SELECT DISTINCT tenant_id::text FROM mizan.{table}"
            ).fetchall()
            assert {row[0] for row in visible} <= {attacker}, table
