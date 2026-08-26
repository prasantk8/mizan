from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from psycopg_pool import ConnectionPool

from .approval import cast_vote, create_approval, current_epoch, open_next_epoch, withdraw
from .evidence import append_decision_event_tx
from .models import AuthenticatedPrincipal
from .pagination import decode_cursor, encode_cursor
from .problems import Problem

SYSTEM_ACTOR = {"kind": "system", "id": "mizan-approval-service", "authenticated_workload": None}


def authority_snapshot_tx(connection: Any, tenant_id: str, roles: list[str]) -> dict:
    row = connection.execute(
        "SELECT mapping_version,document FROM mizan.role_authority_versions "
        "WHERE tenant_id=%s AND status='APPROVED' ORDER BY mapping_version DESC LIMIT 1",
        (tenant_id,),
    ).fetchone()
    if not row:
        raise Problem(
            422, "authority_mapping_missing", "No approved role-authority mapping exists"
        )
    members = [member for member in row[1]["members"] if set(member["roles"]) & set(roles)]
    if not members:
        raise Problem(422, "approver_pool_empty", "No eligible members exist for required roles")
    return {
        "snapshot_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "authority_source": "mizan_role_registry",
        "authority_mapping_version": row[0],
        "roles": roles,
        "members": members,
    }


def insert_epoch_tx(
    connection: Any, tenant_id: str, approval_id: str, epoch: dict[str, Any]
) -> None:
    connection.execute(
        """INSERT INTO mizan.approval_epochs(
             tenant_id,epoch_id,approval_id,epoch_number,state,eligibility_snapshot,document,
             opened_at,expires_at,closed_at
           ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (
            tenant_id,
            epoch["epoch_id"],
            approval_id,
            epoch["epoch_number"],
            epoch["state"],
            json.dumps(epoch["eligibility"]),
            json.dumps(epoch),
            epoch["opened_at"],
            epoch["expires_at"],
            epoch.get("closed_at"),
        ),
    )


def open_approval_tx(
    connection: Any,
    tenant_id: str,
    decision_id: str,
    requester_id: str,
    forbidden_approvers: set[str],
    context_hash: str,
    controls: dict[str, Any],
) -> dict[str, Any]:
    """Open an approval on an existing connection.

    Called from the ADR_Record transaction so a REQUIRE_APPROVAL decision and the approval that
    lets it resume commit together: a decision that says "wait" with nothing to wait for is not a
    state the evidence should be able to record.
    """
    snapshot = authority_snapshot_tx(connection, tenant_id, controls["approver_roles"])
    approval = create_approval(
        tenant_id, decision_id, context_hash, controls, snapshot, datetime.now(UTC)
    )
    epoch = current_epoch(approval)
    connection.execute(
        """INSERT INTO mizan.approvals(
             tenant_id,approval_id,decision_id,state,active_epoch_id,requester_id,
             controls,forbidden_approvers,document,created_at
           ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (
            tenant_id,
            approval["approval_id"],
            decision_id,
            approval["state"],
            epoch["epoch_id"],
            requester_id,
            json.dumps(controls),
            json.dumps(sorted(forbidden_approvers)),
            json.dumps(approval),
            approval["created_at"],
        ),
    )
    insert_epoch_tx(connection, tenant_id, approval["approval_id"], epoch)
    append_decision_event_tx(
        connection,
        tenant_id,
        decision_id,
        "APPROVAL_EPOCH_OPENED",
        SYSTEM_ACTOR,
        {
            "approval_id": approval["approval_id"],
            "epoch_id": epoch["epoch_id"],
            "approval_state": "PENDING",
        },
        datetime.now(UTC),
    )
    connection.execute(
        "INSERT INTO mizan.outbox(tenant_id,aggregate_type,aggregate_id,event_type,payload) "
        "VALUES (%s,'approval',%s,'mizan.approval.requested',%s)",
        (
            tenant_id,
            approval["approval_id"],
            json.dumps(
                {
                    "approval_id": approval["approval_id"],
                    "decision_id": decision_id,
                    "epoch_id": epoch["epoch_id"],
                    "epoch_number": epoch["epoch_number"],
                    "roles": epoch["eligibility"]["roles"],
                    "quorum": epoch["quorum"],
                    "expires_at": epoch["expires_at"],
                }
            ),
        ),
    )
    return approval


class ApprovalRepository:
    def __init__(self, database_url: str) -> None:
        self.pool = ConnectionPool(database_url, min_size=1, max_size=10, open=True)

    @staticmethod
    def _scope(connection: Any, tenant_id: str) -> None:
        connection.execute("SELECT set_config('app.tenant_id', %s, true)", (tenant_id,))

    def authority_snapshot(self, connection: Any, tenant_id: str, roles: list[str]) -> dict:
        return authority_snapshot_tx(connection, tenant_id, roles)

    def create(
        self,
        tenant_id: str,
        decision_id: str,
        requester_id: str,
        forbidden_approvers: set[str],
        context_hash: str,
        controls: dict[str, Any],
    ) -> dict[str, Any]:
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            return open_approval_tx(
                connection,
                tenant_id,
                decision_id,
                requester_id,
                forbidden_approvers,
                context_hash,
                controls,
            )

    def pending(
        self, tenant_id: str, state: str | None, limit: int, cursor: str | None
    ) -> dict[str, Any]:
        """The approver's queue. Tenant-scoped by RLS and by the predicate (I-3)."""
        clauses = ["tenant_id=%s"]
        parameters: list[Any] = [tenant_id]
        if state:
            clauses.append("state=%s")
            parameters.append(state)
        if cursor:
            created_at, approval_id = decode_cursor(cursor)
            clauses.append("(created_at,approval_id) < (%s,%s)")
            parameters.extend([created_at, approval_id])
        parameters.append(limit)
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            rows = connection.execute(
                "SELECT approval_id,decision_id,state,active_epoch_id,requester_id,document,"
                "created_at FROM mizan.approvals WHERE "
                + " AND ".join(clauses)
                + " ORDER BY created_at DESC, approval_id DESC LIMIT %s",
                tuple(parameters),
            ).fetchall()
        items = []
        for approval_id, decision_id, row_state, epoch_id, requester_id, document, created_at in rows:
            epoch = next(
                (item for item in document["epochs"] if item["epoch_id"] == epoch_id), None
            )
            items.append(
                {
                    "approval_id": approval_id,
                    "decision_id": decision_id,
                    "state": row_state,
                    "requester_id": requester_id,
                    "created_at": created_at.isoformat().replace("+00:00", "Z"),
                    "epoch": None
                    if epoch is None
                    else {
                        "epoch_id": epoch["epoch_id"],
                        "epoch_number": epoch["epoch_number"],
                        "kind": epoch["kind"],
                        "quorum": epoch["quorum"],
                        "expires_at": epoch["expires_at"],
                        "votes_cast": len(epoch["votes"]) + len(epoch.get("carried_votes", [])),
                        "approver_roles": epoch["eligibility"]["roles"],
                    },
                }
            )
        next_cursor = (
            encode_cursor(rows[-1][6], rows[-1][0]) if len(rows) == limit and rows else None
        )
        return {"items": items, "next_cursor": next_cursor}

    def get(self, tenant_id: str, approval_id: str) -> dict[str, Any]:
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            row = connection.execute(
                "SELECT document FROM mizan.approvals WHERE tenant_id=%s AND approval_id=%s",
                (tenant_id, approval_id),
            ).fetchone()
            if not row:
                raise Problem(404, "approval_not_found", "Approval was not found")
            return row[0]

    def vote(
        self,
        tenant_id: str,
        approval_id: str,
        principal: AuthenticatedPrincipal,
        request: dict[str, Any],
    ) -> dict[str, Any]:
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            row = self._locked(connection, tenant_id, approval_id)
            updated, recorded = cast_vote(
                row["document"],
                epoch_number=request["epoch_number"],
                approver_id=principal.principal_id,
                identity_kind=principal.identity_kind,
                auth_strength=principal.auth_strength,
                vote=request["vote"],
                forbidden_approvers=set(row["forbidden_approvers"]),
                role_claim=request.get("role_claim"),
                justification=request.get("justification"),
                comment=request.get("comment"),
            )
            connection.execute(
                """INSERT INTO mizan.approval_votes(
                     tenant_id,vote_id,approval_id,epoch_id,approver_id,control_domain,vote,voted_at,document
                   ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (
                    tenant_id,
                    recorded["vote_id"],
                    approval_id,
                    recorded["epoch_id"],
                    recorded["approver_id"],
                    recorded["control_domain"],
                    recorded["vote"],
                    recorded["timestamp"],
                    json.dumps(recorded),
                ),
            )
            if updated["state"] == "REVIEW_REQUIRED":
                review = row["controls"].get("review")
                if not review:
                    raise Problem(
                        409,
                        "review_configuration_missing",
                        "Review-triggering rejection has no review authority configuration",
                    )
                snapshot = self.authority_snapshot(
                    connection, tenant_id, review["approver_roles"]
                )
                requirements = {
                    "quorum": review["quorum"],
                    "expiry_seconds": review["expiry_seconds"],
                    "rejection_mode": review["rejection_mode"],
                    "rejection_quorum_count": review.get("rejection_quorum_count"),
                    "distinct_control_domains_required": review[
                        "distinct_control_domains_required"
                    ],
                }
                updated = open_next_epoch(
                    updated,
                    kind="review",
                    requirements=requirements,
                    eligibility=snapshot,
                    carry_forward_votes=False,
                    reset_expiry=True,
                )
                self._update_with_new_epoch(connection, tenant_id, updated)
            else:
                self._update(connection, tenant_id, updated)
            append_decision_event_tx(
                connection,
                tenant_id,
                updated["decision_id"],
                "APPROVAL_VOTE_CAST",
                {"kind": "human", "id": principal.principal_id, "authenticated_workload": None},
                {
                    "approval_id": approval_id,
                    "epoch_id": recorded["epoch_id"],
                    "vote_id": recorded["vote_id"],
                    "approval_state": updated["state"],
                },
                datetime.now(UTC),
            )
            if updated["state"] == "REVIEW_REQUIRED":
                self._event_opened(connection, tenant_id, updated)
                review_epoch = current_epoch(updated)
                connection.execute(
                    "INSERT INTO mizan.outbox(tenant_id,aggregate_type,aggregate_id,event_type,payload) "
                    "VALUES (%s,'approval',%s,'mizan.approval.review_required',%s)",
                    (
                        tenant_id,
                        approval_id,
                        json.dumps(
                            {
                                "approval_id": approval_id,
                                "epoch_id": review_epoch["epoch_id"],
                                "epoch_number": review_epoch["epoch_number"],
                                "reviewer_pool": review_epoch["eligibility"]["roles"],
                            }
                        ),
                    ),
                )
            elif updated["state"] in {"APPROVED", "REJECTED", "OVERRIDDEN"}:
                append_decision_event_tx(
                    connection,
                    tenant_id,
                    updated["decision_id"],
                    "APPROVAL_RESOLVED",
                    SYSTEM_ACTOR,
                    {
                        "approval_id": approval_id,
                        "epoch_id": current_epoch(updated)["epoch_id"],
                        "approval_state": updated["state"],
                    },
                    datetime.now(UTC),
                )
            return updated

    def escalate(self, tenant_id: str, approval_id: str) -> dict[str, Any]:
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            row = self._locked(connection, tenant_id, approval_id)
            config = row["controls"].get("escalation")
            if not config:
                raise Problem(409, "escalation_not_configured", "Approval has no escalation policy")
            old = current_epoch(row["document"])
            opened = datetime.fromisoformat(old["opened_at"].replace("Z", "+00:00"))
            expires = datetime.fromisoformat(old["expires_at"].replace("Z", "+00:00"))
            trigger = opened + (expires - opened) * config["trigger_fraction"]
            if datetime.now(UTC) < trigger:
                raise Problem(409, "escalation_not_due", "Escalation trigger time has not arrived")
            if len(row["document"]["epochs"]) >= config.get("max_epochs", 2):
                raise Problem(409, "max_epochs_reached", "Approval reached its epoch limit")
            roles = list(old["eligibility"]["roles"]) if config["pool_mode"] == "augment" else []
            roles = sorted(set([*roles, config["role"]]))
            snapshot = self.authority_snapshot(connection, tenant_id, roles)
            requirements = self._epoch_requirements(row["controls"], old)
            updated = open_next_epoch(
                row["document"],
                kind="escalation",
                requirements=requirements,
                eligibility=snapshot,
                carry_forward_votes=config["carry_forward_votes"],
                reset_expiry=config["reset_expiry"],
            )
            self._update_with_new_epoch(connection, tenant_id, updated)
            self._event_opened(connection, tenant_id, updated)
            return updated

    def override(
        self,
        tenant_id: str,
        approval_id: str,
        principal: AuthenticatedPrincipal,
    ) -> dict[str, Any]:
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            row = self._locked(connection, tenant_id, approval_id)
            config = row["controls"].get("override")
            if not config or not set(principal.roles) & set(config["eligible_roles"]):
                raise Problem(
                    403, "override_forbidden", "Override is absent or caller is ineligible"
                )
            snapshot = self.authority_snapshot(connection, tenant_id, config["eligible_roles"])
            requirements = {
                "quorum": config["quorum"],
                "expiry_seconds": row["controls"]["expiry_seconds"],
                "rejection_mode": "veto",
                "distinct_control_domains_required": config.get(
                    "distinct_control_domains_required", True
                ),
            }
            updated = open_next_epoch(
                row["document"],
                kind="override",
                requirements=requirements,
                eligibility=snapshot,
                carry_forward_votes=False,
                reset_expiry=True,
            )
            self._update_with_new_epoch(connection, tenant_id, updated)
            self._event_opened(connection, tenant_id, updated)
            connection.execute(
                "INSERT INTO mizan.outbox(tenant_id,aggregate_type,aggregate_id,event_type,payload) "
                "VALUES (%s,'approval',%s,'mizan.approval.override_opened',%s)",
                (
                    tenant_id,
                    approval_id,
                    json.dumps({"severity": "high", "notify": config.get("notify", [])}),
                ),
            )
            return updated

    def withdraw(self, tenant_id: str, approval_id: str, requester_id: str) -> dict[str, Any]:
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            row = self._locked(connection, tenant_id, approval_id)
            if row["requester_id"] != requester_id:
                raise Problem(403, "withdraw_forbidden", "Only the requester may withdraw")
            updated = withdraw(row["document"])
            self._update(connection, tenant_id, updated)
            append_decision_event_tx(
                connection,
                tenant_id,
                updated["decision_id"],
                "APPROVAL_RESOLVED",
                SYSTEM_ACTOR,
                {
                    "approval_id": approval_id,
                    "epoch_id": updated["current_epoch_id"],
                    "approval_state": "WITHDRAWN",
                },
                datetime.now(UTC),
            )
            return updated

    @staticmethod
    def _locked(connection: Any, tenant_id: str, approval_id: str) -> dict[str, Any]:
        row = connection.execute(
            "SELECT document,controls,forbidden_approvers,requester_id FROM mizan.approvals "
            "WHERE tenant_id=%s AND approval_id=%s FOR UPDATE",
            (tenant_id, approval_id),
        ).fetchone()
        if not row:
            raise Problem(404, "approval_not_found", "Approval was not found")
        return {
            "document": row[0],
            "controls": row[1],
            "forbidden_approvers": row[2],
            "requester_id": row[3],
        }

    _insert_epoch = staticmethod(insert_epoch_tx)

    @staticmethod
    def _update(connection: Any, tenant_id: str, approval: dict[str, Any]) -> None:
        epoch = current_epoch(approval)
        connection.execute(
            "UPDATE mizan.approvals SET state=%s,active_epoch_id=%s,document=%s "
            "WHERE tenant_id=%s AND approval_id=%s",
            (
                approval["state"],
                epoch["epoch_id"],
                json.dumps(approval),
                tenant_id,
                approval["approval_id"],
            ),
        )
        connection.execute(
            "UPDATE mizan.approval_epochs SET state=%s,document=%s,closed_at=%s "
            "WHERE tenant_id=%s AND epoch_id=%s",
            (
                epoch["state"],
                json.dumps(epoch),
                epoch.get("closed_at"),
                tenant_id,
                epoch["epoch_id"],
            ),
        )

    def _update_with_new_epoch(
        self, connection: Any, tenant_id: str, approval: dict[str, Any]
    ) -> None:
        previous, epoch = approval["epochs"][-2:]
        connection.execute(
            "UPDATE mizan.approval_epochs SET state=%s,document=%s,closed_at=%s "
            "WHERE tenant_id=%s AND epoch_id=%s",
            (
                previous["state"],
                json.dumps(previous),
                previous["closed_at"],
                tenant_id,
                previous["epoch_id"],
            ),
        )
        self._insert_epoch(connection, tenant_id, approval["approval_id"], epoch)
        self._update(connection, tenant_id, approval)

    @staticmethod
    def _epoch_requirements(controls: dict[str, Any], old: dict[str, Any]) -> dict[str, Any]:
        return {
            "quorum": old["quorum"],
            "expiry_seconds": controls["expiry_seconds"],
            "rejection_mode": old["rejection_mode"],
            "rejection_quorum_count": old.get("rejection_quorum_count"),
            "distinct_control_domains_required": old["distinct_control_domains_required"],
        }

    @staticmethod
    def _event_opened(connection: Any, tenant_id: str, approval: dict[str, Any]) -> None:
        epoch = current_epoch(approval)
        append_decision_event_tx(
            connection,
            tenant_id,
            approval["decision_id"],
            "APPROVAL_EPOCH_OPENED",
            SYSTEM_ACTOR,
            {
                "approval_id": approval["approval_id"],
                "epoch_id": epoch["epoch_id"],
                "approval_state": approval["state"],
            },
            datetime.now(UTC),
        )
