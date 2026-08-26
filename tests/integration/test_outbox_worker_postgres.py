"""T-074's gate: the states nothing used to reach.

Before this worker, `EXPIRED` and `LEASE_EXPIRED` were only ever *reported* — an approval whose TTL
had elapsed stayed `PENDING` in the database until the next voter was told "too late", and a lease
stayed `LEASED` until its executor came back to a lease it had already lost. Neither is a state the
system reached; both are states it computed on demand, which is a much weaker claim to make to an
auditor reading the row.

Every test here fails on 330a2d5: `mizan_control_plane.outbox_worker` does not exist there, and
neither does `approval.expire`.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from mizan_control_plane.approval_repository import open_approval_tx
from mizan_control_plane.evidence import (
    Ed25519EvidenceSigner,
    EvidenceRepository,
    LocalImmutableObjectStore,
    OutboxPublisher,
)
from mizan_control_plane.outbox_worker import DrainPolicy, ExpirySweeper, OutboxWorker

TENANT = "tnt_bank-a"

pytestmark = pytest.mark.skipif(
    not os.getenv("MIZAN_TEST_DATABASE_URL"), reason="Postgres not configured"
)


class RecordingSink:
    def __init__(self) -> None:
        self.published: list[tuple[str, str, dict[str, Any]]] = []

    def publish(self, event_type: str, key: str, payload: dict[str, Any]) -> None:
        self.published.append((event_type, key, payload))


def scope(connection: Any) -> None:
    connection.execute("SELECT set_config('app.tenant_id', %s, true)", (TENANT,))


def seed_decision(sweeper: ExpirySweeper, suffix: str, decision: str = "REQUIRE_APPROVAL") -> str:
    """Write one ADR_Record of our own, on a stream of our own.

    Authorizing through the service instead would make these fixtures depend on which policy some
    earlier test happened to leave ACTIVE — which is how a gate starts passing for a reason it does
    not name. The sweeper is being tested on stored state, so stored state is what it is given.
    """
    stream = f"{TENANT}:adr:t074-{suffix}"
    decision_id = f"adr_t074-{suffix}-0001"
    record_hash = hashlib.sha256(decision_id.encode()).hexdigest()
    with sweeper.pool.connection() as connection, connection.transaction():
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
               ) VALUES (%s,%s,gen_random_uuid(),%s,%s,'agt_wealth-01','tool_transfer',%s,%s,
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
                decision,
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
    sweeper: ExpirySweeper, suffix: str, expiry_seconds: int
) -> tuple[str, dict[str, Any]]:
    """Attach an approval to that decision the way a REQUIRE_APPROVAL path does."""
    decision_id = seed_decision(sweeper, suffix)
    record_hash = hashlib.sha256(decision_id.encode()).hexdigest()
    with sweeper.pool.connection() as connection, connection.transaction():
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


def outbox_events(sweeper: ExpirySweeper, aggregate_id: str) -> list[str]:
    with sweeper.pool.connection() as connection, connection.transaction():
        scope(connection)
        rows = connection.execute(
            "SELECT event_type FROM mizan.outbox WHERE tenant_id=%s AND aggregate_id=%s "
            "ORDER BY outbox_id",
            (TENANT, aggregate_id),
        ).fetchall()
    return [row[0] for row in rows]


def test_an_expired_approval_epoch_is_reached_at_rest_with_its_section_4_event() -> None:
    sweeper = ExpirySweeper(os.environ["MIZAN_TEST_DATABASE_URL"])
    try:
        decision_id, approval = approval_on_a_fresh_decision(
            sweeper, "401", expiry_seconds=1
        )
        approval_id = approval["approval_id"]
        # No doctored timestamps: the epoch is given a one-second TTL and allowed to elapse.
        time.sleep(1.2)
        assert sweeper.expire_approvals(TENANT, datetime.now(UTC)) == [approval_id]

        with sweeper.pool.connection() as connection, connection.transaction():
            scope(connection)
            state, document = connection.execute(
                "SELECT state,document FROM mizan.approvals WHERE tenant_id=%s AND approval_id=%s",
                (TENANT, approval_id),
            ).fetchone()
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
        # SPEC §4: the state change and its event commit together or not at all.
        assert "mizan.approval.expired" in outbox_events(sweeper, approval_id)
    finally:
        sweeper.close()


def test_the_sweeper_leaves_an_approval_that_still_has_time_alone() -> None:
    sweeper = ExpirySweeper(os.environ["MIZAN_TEST_DATABASE_URL"])
    try:
        _, approval = approval_on_a_fresh_decision(
            sweeper, "402", expiry_seconds=3600
        )
        assert sweeper.sweep(TENANT).approvals == ()
        with sweeper.pool.connection() as connection, connection.transaction():
            scope(connection)
            state = connection.execute(
                "SELECT state FROM mizan.approvals WHERE tenant_id=%s AND approval_id=%s",
                (TENANT, approval["approval_id"]),
            ).fetchone()[0]
        assert state == "PENDING"
        assert "mizan.approval.expired" not in outbox_events(sweeper, approval["approval_id"])
    finally:
        sweeper.close()


def test_a_lapsed_lease_becomes_lease_expired_at_rest_with_its_section_4_event() -> None:
    sweeper = ExpirySweeper(os.environ["MIZAN_TEST_DATABASE_URL"])
    decision_id = seed_decision(sweeper, "403", decision="ALLOW")
    lease_id = "lse_t074-403-0001"
    try:
        lease = {
            "lease_id": lease_id,
            "decision_id": decision_id,
            "state": "LEASED",
            "authorized_executor": "spiffe://mizan/executor/wealth",
            "extensions_used": 0,
            "max_extensions": 24,
            "expires_at": "2026-08-27T00:00:00Z",
        }
        with sweeper.pool.connection() as connection, connection.transaction():
            scope(connection)
            # A lease exists only because a capability was redeemed (ADR-008); the schema enforces
            # that with a deferred FK, so the fixture builds the pair rather than the row.
            connection.execute(
                """INSERT INTO mizan.execution_tokens(
                     tenant_id,jti_hash,decision_id,agent_id,tool_id,authorized_executor,claims,
                     expires_at,consumed_at,lease_id
                   ) VALUES (%s,%s,%s,'agt_wealth-01','tool_transfer',
                             'spiffe://mizan/executor/wealth','{}',
                             clock_timestamp() - interval '5 minutes',
                             clock_timestamp() - interval '5 minutes',%s)""",
                (TENANT, "e" * 64, decision_id, lease_id),
            )
            connection.execute(
                """INSERT INTO mizan.execution_leases(
                     tenant_id,lease_id,redeemed_jti_hash,decision_id,agent_id,tool_id,principal_id,
                     authorized_executor,state,max_extensions,heartbeat_interval_seconds,document,
                     expires_at
                   ) VALUES (%s,%s,%s,%s,'agt_wealth-01','tool_transfer','prn_requester',
                             'spiffe://mizan/executor/wealth','LEASED',24,60,%s,
                             clock_timestamp() - interval '1 minute')""",
                (TENANT, lease_id, "e" * 64, decision_id, json.dumps(lease)),
            )
        assert sweeper.expire_leases(
            TENANT, datetime.now(UTC)
        ) == [lease_id]

        with sweeper.pool.connection() as connection, connection.transaction():
            scope(connection)
            state, document = connection.execute(
                "SELECT state,document FROM mizan.execution_leases "
                "WHERE tenant_id=%s AND lease_id=%s",
                (TENANT, lease_id),
            ).fetchone()
            events = connection.execute(
                "SELECT event_type FROM mizan.decision_events "
                "WHERE tenant_id=%s AND decision_id=%s",
                (TENANT, decision_id),
            ).fetchall()
        assert state == "LEASE_EXPIRED"
        assert document["state"] == "LEASE_EXPIRED"
        assert [row[0] for row in events] == ["LEASE_EXPIRED"]
        assert "mizan.execution.lease_expired" in outbox_events(sweeper, lease_id)
        # A lease that already lapsed is not expired twice; the sweep is idempotent at rest.
        assert sweeper.expire_leases(
            TENANT, datetime.now(UTC)
        ) == []
    finally:
        sweeper.close()


def test_one_worker_tick_publishes_evidence_and_relays_events_that_have_no_receipt(
    tmp_path: Path,
) -> None:
    sweeper = ExpirySweeper(os.environ["MIZAN_TEST_DATABASE_URL"])
    _, approval = approval_on_a_fresh_decision(
        sweeper, "404", expiry_seconds=3600
    )
    evidence = EvidenceRepository(os.environ["MIZAN_TEST_DATABASE_URL"])
    sink = RecordingSink()
    try:
        publisher = OutboxPublisher(
            evidence,
            LocalImmutableObjectStore(tmp_path),
            Ed25519EvidenceSigner.development("evidence-receipt"),
            Ed25519EvidenceSigner.development("evidence-anchor"),
            delivery=sink,
        )
        worker = OutboxWorker(
            publisher,
            evidence,
            sweeper,
            (TENANT,),
            DrainPolicy(anchor_interval_seconds=300.0, sweep_interval_seconds=0.0),
        )
        tick = worker.tick_tenant(TENANT)
        assert tick.published > 0, "evidence rows must become signed receipts"
        assert tick.relayed > 0, "approval rows have subscribers and no receipt"
        assert "mizan.approval.requested" in {event for event, _key, _payload in sink.published}
        with evidence.pool.connection() as connection, connection.transaction():
            scope(connection)
            unpublished = connection.execute(
                "SELECT count(*) FROM mizan.outbox WHERE tenant_id=%s AND published_at IS NULL",
                (TENANT,),
            ).fetchone()[0]
        assert unpublished == 0, "a tick that leaves rows behind is a lag SLO that never recovers"
        assert tick.oldest_age_seconds == 0.0
        assert tick.lag_breached is False
        assert approval["approval_id"] is not None
        # A stream that has never been anchored is due on the first tick, so a one-shot run from
        # cron anchors rather than only ever establishing a cadence baseline it then discards.
        stream = f"{TENANT}:adr:t074-404"
        assert stream in tick.anchored
        with evidence.pool.connection() as connection, connection.transaction():
            scope(connection)
            anchors = connection.execute(
                "SELECT count(*) FROM mizan.evidence_anchors WHERE tenant_id=%s AND stream_id=%s",
                (TENANT, stream),
            ).fetchone()[0]
        assert anchors == 1
    finally:
        evidence.pool.close()
        sweeper.close()
