"""`EXPIRED` was a state nothing reached, and now it is a state a deployment chooses.

Before this, `EXPIRED` was only ever *computed*: an approval whose epoch TTL had elapsed stayed
`PENDING` in the database until the next voter was told "too late". Nothing wrote the state, so an
approval nobody answered again sat `PENDING` for ever, and an auditor reading the row saw a
question that was still open years after everyone had stopped asking it. That is a much weaker
claim than a terminal state the system reached on its own, which is what ADR-007 describes.

Reaching it is also not automatically the right thing to do, which is why there are two modes and
both are exercised here against the real database. `enforced` closes the epoch and emits
`mizan.approval.expired`. `advisory` writes nothing, keeps the epoch `OPEN`, and still reports the
overdue count — for an institution whose position is that no clock may decide a payment. Testing
only the first would leave the second as a claim in a settings table.

These tests fail without `ApprovalRepository.sweep_expired_epochs`: the method does not exist and
`EXPIRED` has no writer.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import UTC, datetime
from typing import Any

import pytest
from mizan_control_plane.approval_repository import ApprovalRepository, open_approval_tx

# A tenant of this file's own. These tests seed ADR_Records and the outbox rows that commit with
# them, and both fixture tenants already have a test asserting an exact tenant-wide drain count
# (`test_authorize_postgres.py` on `tnt_bank-a`, `test_evidence_export_postgres.py` on
# `tnt_bank-b`) -- so writing to either makes an unrelated file fail depending on collection
# order. The behaviour under test is per-tenant anyway, so its own tenant costs nothing and makes
# the scoping part of what is proved.
TENANT = "tnt_expiry-sweep"

pytestmark = pytest.mark.skipif(
    not os.getenv("MIZAN_TEST_DATABASE_URL"), reason="Postgres not configured"
)


def repository(mode: str = "enforced") -> ApprovalRepository:
    return ApprovalRepository(os.environ["MIZAN_TEST_DATABASE_URL"], mode)


def scope(connection: Any) -> None:
    connection.execute("SELECT set_config('app.tenant_id', %s, true)", (TENANT,))


def ensure_registry(approvals: ApprovalRepository) -> None:
    """`tnt_bank-b` exists in the schema contract; its agent and tool do not.

    The tenant itself is seeded by `schema_contract.sql`, because `mizan_app` cannot create one --
    `mizan.tenants` is FORCE RLS with no SECURITY DEFINER path, which is exactly what B-27 is
    about. Everything below it is registry state this file owns.

    `adr_records` has foreign keys onto an agent, a tool and that tool's binding profile, so a
    decision cannot be seeded for a tenant whose registry is empty. The ids are this file's own:
    `test_evidence_export_postgres.py` seeds `bp_transfer-v1`/`tool_transfer` for the same tenant
    with no `ON CONFLICT`, so sharing a name makes whichever file runs second fail on a primary
    key. Idempotent, because every test here calls it.
    """
    with approvals.pool.connection() as connection, connection.transaction():
        scope(connection)
        connection.execute(
            "INSERT INTO mizan.binding_profiles("
            "  tenant_id,profile_id,profile_version,canonicalization,"
            "  bound_pointers,volatile_pointers,content_hash"
            ") VALUES (%s,'bp_expiry-v1',1,'RFC8785','[\"/amount\"]','[\"/request_time\"]',"
            "          repeat('1',64)) ON CONFLICT DO NOTHING",
            (TENANT,),
        )
        connection.execute(
            "INSERT INTO mizan.tools(tenant_id,tool_id,profile_id,profile_version,document) "
            "VALUES (%s,'tool_expiry','bp_expiry-v1',1,%s) ON CONFLICT DO NOTHING",
            (TENANT, json.dumps({"tenant_id": TENANT, "tool_id": "tool_expiry"})),
        )
        connection.execute(
            "INSERT INTO mizan.role_authority_versions("
            "  tenant_id,mapping_version,status,document,approved_at"
            ") VALUES (%s,1,'APPROVED',%s,now()) ON CONFLICT DO NOTHING",
            (
                TENANT,
                json.dumps(
                    {
                        "members": [
                            {
                                "principal_id": "prn_alice",
                                "roles": ["manager"],
                                "control_domain": "business.ops",
                            }
                        ]
                    }
                ),
            ),
        )
        connection.execute(
            "INSERT INTO mizan.agents("
            "  tenant_id,agent_id,version,lifecycle_state,document,created_at,updated_at"
            ") VALUES (%s,'agt_expiry-sweeper','1.0.0','ACTIVE',%s,now(),now()) ON CONFLICT DO NOTHING",
            (TENANT, json.dumps({"tenant_id": TENANT, "agent_id": "agt_expiry-sweeper"})),
        )


def seed_decision(approvals: ApprovalRepository, suffix: str) -> str:
    """Write one ADR_Record on a stream of our own.

    Authorizing through the service instead would make these fixtures depend on which policy some
    earlier test happened to leave ACTIVE -- which is how a gate starts passing for a reason it
    does not name. The sweeper is tested on stored state, so stored state is what it is given.
    """
    ensure_registry(approvals)
    stream = f"{TENANT}:adr:expiry-{suffix}"
    decision_id = f"adr_expiry-{suffix}-0001"
    record_hash = hashlib.sha256(decision_id.encode()).hexdigest()
    with approvals.pool.connection() as connection, connection.transaction():
        scope(connection)
        connection.execute(
            "INSERT INTO mizan.evidence_chain_heads(tenant_id,stream_id) VALUES (%s,%s) "
            "ON CONFLICT DO NOTHING",
            (TENANT, stream),
        )
        sequence = connection.execute(
            "SELECT mizan.reserve_evidence_sequence(%s,%s,%s,%s)",
            (TENANT, stream, "0" * 64, record_hash),
        ).fetchone()[0]
        connection.execute(
            """INSERT INTO mizan.adr_records(
                 tenant_id,decision_id,request_id,trace_id,context_hash,agent_id,tool_id,stream_id,
                 sequence_number,prev_hash,record_hash,decision,document,created_at
               ) VALUES (%s,%s,gen_random_uuid(),%s,%s,'agt_expiry-sweeper','tool_expiry',%s,%s,
                         %s,%s,%s,%s,clock_timestamp())""",
            (
                TENANT,
                decision_id,
                hashlib.sha256(stream.encode()).hexdigest()[:32],
                record_hash,
                stream,
                sequence,
                "0" * 64,
                record_hash,
                "REQUIRE_APPROVAL",
                json.dumps({"tenant_id": TENANT, "decision_id": decision_id}),
            ),
        )
        # The record and its outbox row commit together on the real write path (I-1). Seeding one
        # without the other would leave the stream with a hole no anchor could ever cover.
        connection.execute(
            "INSERT INTO mizan.outbox(tenant_id,aggregate_type,aggregate_id,event_type,payload) "
            "VALUES (%s,'decision',%s,'mizan.decision.created',%s)",
            (
                TENANT,
                decision_id,
                json.dumps(
                    {
                        "decision_id": decision_id,
                        "stream_id": stream,
                        "sequence_number": sequence,
                        "record_hash": record_hash,
                    }
                ),
            ),
        )
    return decision_id


def approval_on_a_fresh_decision(
    approvals: ApprovalRepository, suffix: str, expiry_seconds: int
) -> tuple[str, dict[str, Any]]:
    """Attach an approval the way a REQUIRE_APPROVAL authorization does."""
    decision_id = seed_decision(approvals, suffix)
    record_hash = hashlib.sha256(decision_id.encode()).hexdigest()
    with approvals.pool.connection() as connection, connection.transaction():
        scope(connection)
        approval = open_approval_tx(
            connection,
            TENANT,
            decision_id,
            "prn_requester",
            {"prn_requester"},
            record_hash,
            {
                "quorum": 1,
                "approver_roles": ["manager"],
                "expiry_seconds": expiry_seconds,
                "rejection_mode": "veto",
            },
        )
    return decision_id, approval


def outbox_events(approvals: ApprovalRepository, aggregate_id: str) -> list[str]:
    with approvals.pool.connection() as connection, connection.transaction():
        scope(connection)
        rows = connection.execute(
            "SELECT event_type FROM mizan.outbox WHERE tenant_id=%s AND aggregate_id=%s "
            "ORDER BY outbox_id",
            (TENANT, aggregate_id),
        ).fetchall()
    return [row[0] for row in rows]


def approval_state(approvals: ApprovalRepository, approval_id: str) -> tuple[str, dict[str, Any]]:
    with approvals.pool.connection() as connection, connection.transaction():
        scope(connection)
        return connection.execute(
            "SELECT state,document FROM mizan.approvals WHERE tenant_id=%s AND approval_id=%s",
            (TENANT, approval_id),
        ).fetchone()


def test_an_elapsed_epoch_is_closed_at_rest_with_its_section_4_event() -> None:
    approvals = repository("enforced")
    try:
        decision_id, approval = approval_on_a_fresh_decision(approvals, "501", expiry_seconds=1)
        approval_id = approval["approval_id"]
        # No doctored timestamps: the epoch is given a one-second TTL and allowed to elapse.
        time.sleep(1.2)

        assert approval_id in approvals.sweep_expired_epochs(TENANT, now=datetime.now(UTC))

        state, document = approval_state(approvals, approval_id)
        with approvals.pool.connection() as connection, connection.transaction():
            scope(connection)
            epoch_state, closed_at = connection.execute(
                "SELECT state,closed_at FROM mizan.approval_epochs "
                "WHERE tenant_id=%s AND approval_id=%s",
                (TENANT, approval_id),
            ).fetchone()
            events = connection.execute(
                "SELECT event_type,document FROM mizan.decision_events "
                "WHERE tenant_id=%s AND decision_id=%s ORDER BY decision_sequence",
                (TENANT, decision_id),
            ).fetchall()

        assert state == "EXPIRED"
        assert document["epochs"][0]["outcome"] == "EXPIRED"
        assert (epoch_state, closed_at is not None) == ("CLOSED_TERMINAL", True)
        assert [row[0] for row in events] == ["APPROVAL_EPOCH_OPENED", "APPROVAL_RESOLVED"]
        assert events[-1][1]["payload"]["approval_state"] == "EXPIRED"
        # Named, so the audit trail can say a process closed this and not a person.
        assert events[-1][1]["actor"]["id"] == "mizan-approval-sweeper"
        assert events[-1][1]["payload"]["detected_by"] == "sweep"
        # SPEC §4: the state change and its event commit together or not at all.
        assert "mizan.approval.expired" in outbox_events(approvals, approval_id)
    finally:
        approvals.pool.close()


def test_an_approval_that_still_has_time_is_left_alone() -> None:
    approvals = repository("enforced")
    try:
        _, approval = approval_on_a_fresh_decision(approvals, "502", expiry_seconds=3600)
        approval_id = approval["approval_id"]

        assert approval_id not in approvals.sweep_expired_epochs(TENANT)

        assert approval_state(approvals, approval_id)[0] == "PENDING"
        assert "mizan.approval.expired" not in outbox_events(approvals, approval_id)
    finally:
        approvals.pool.close()


def test_an_advisory_deployment_reports_the_overdue_epoch_and_writes_nothing() -> None:
    """The other half of the ruling, against the real database.

    `advisory` is trivially faked by not running the sweeper at all, which is why this asserts
    both halves: the row is untouched *and* the same overdue epoch is still discoverable. An
    institution that chooses this mode is saying a human decides every payment; it is not saying
    it wants to stop being told which payments are waiting.
    """
    approvals = repository("advisory")
    try:
        _, approval = approval_on_a_fresh_decision(approvals, "503", expiry_seconds=1)
        approval_id = approval["approval_id"]
        time.sleep(1.2)

        assert approval_id in approvals.overdue_epochs(TENANT)
        # And the mode is not a suggestion the repository may ignore.
        with pytest.raises(RuntimeError, match="advisory"):
            approvals.sweep_expired_epochs(TENANT)

        assert approval_state(approvals, approval_id)[0] == "PENDING"
        assert "mizan.approval.expired" not in outbox_events(approvals, approval_id)
    finally:
        approvals.pool.close()


def test_a_person_who_acts_between_the_scan_and_the_lock_wins() -> None:
    """The scan is a hint about where to look, never a decision.

    `overdue_epochs` and the write are separate transactions, so an approver can resolve the
    approval in between. `approval.expire` re-asserts every precondition under the row lock and
    refuses; the sweeper reports the approval as not expired and the person's outcome stands.
    """
    approvals = repository("enforced")
    try:
        _, approval = approval_on_a_fresh_decision(approvals, "504", expiry_seconds=1)
        approval_id = approval["approval_id"]
        time.sleep(1.2)
        assert approval_id in approvals.overdue_epochs(TENANT)

        # The approver gets there first.
        approvals.withdraw(TENANT, approval_id, "prn_requester")

        assert approval_id not in approvals.sweep_expired_epochs(TENANT)
        assert approval_state(approvals, approval_id)[0] == "WITHDRAWN"
        assert "mizan.approval.expired" not in outbox_events(approvals, approval_id)
    finally:
        approvals.pool.close()
