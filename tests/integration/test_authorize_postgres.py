from __future__ import annotations

import os
import time

import pytest
from mizan_control_plane.models import AuthenticatedIdentity
from mizan_control_plane.repository import PostgresAuthorizationRepository
from mizan_control_plane.risk import RegistryFloorRiskProvider
from mizan_control_plane.service import AuthorizationService

from tests.unit.test_authorization import context


@pytest.mark.skipif(not os.getenv("MIZAN_TEST_DATABASE_URL"), reason="Postgres not configured")
def test_authorize_persists_adr_and_outbox_atomically() -> None:
    repository = PostgresAuthorizationRepository(os.environ["MIZAN_TEST_DATABASE_URL"])
    service = AuthorizationService(repository, RegistryFloorRiskProvider(), "integration", "f" * 64)
    identity = AuthenticatedIdentity(
        tenant_id="tnt_bank-a", agent_id="agt_wealth-01", subject="test",
        delegation_chain=["agt_wealth-01"],
    )
    response = service.authorize(identity, context("018f47a6-7b42-7c00-8000-000000000099"))
    assert response.decision == "DENY"
    with repository.pool.connection() as connection, connection.transaction():
        repository._scope(connection, "tnt_bank-a")
        adr_count = connection.execute(
            "SELECT count(*) FROM mizan.adr_records WHERE decision_id=%s", (response.decision_id,)
        ).fetchone()[0]
        outbox_count = connection.execute(
            "SELECT count(*) FROM mizan.outbox WHERE aggregate_id=%s", (response.decision_id,)
        ).fetchone()[0]
    assert (adr_count, outbox_count) == (1, 1)


@pytest.mark.skipif(not os.getenv("MIZAN_TEST_DATABASE_URL"), reason="Postgres not configured")
def test_rls_policy_lookup_and_evaluation_stays_inside_authorization_budget() -> None:
    repository = PostgresAuthorizationRepository(os.environ["MIZAN_TEST_DATABASE_URL"])
    request = context("018f47a6-7b42-7c00-8000-000000000100")
    samples: list[float] = []
    for _ in range(100):
        started = time.perf_counter_ns()
        assert repository.matching_policies("tnt_bank-a", request) == []
        samples.append((time.perf_counter_ns() - started) / 1_000_000)
    assert sorted(samples)[98] < 50
