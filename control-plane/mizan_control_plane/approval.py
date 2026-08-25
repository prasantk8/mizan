from __future__ import annotations

import copy
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from .canonical import canonical_hash
from .problems import Problem

TERMINAL_STATES = {"APPROVED", "REJECTED", "EXPIRED", "WITHDRAWN", "OVERRIDDEN"}


def _id(prefix: str) -> str:
    return prefix + uuid4().hex


def create_epoch(
    number: int,
    kind: str,
    requirements: dict[str, Any],
    eligibility: dict[str, Any],
    opened_at: datetime,
    expires_at: datetime,
) -> dict[str, Any]:
    snapshot = copy.deepcopy(eligibility)
    supplied_hash = snapshot.pop("snapshot_hash", None)
    calculated_hash = canonical_hash(snapshot)
    if supplied_hash is not None and supplied_hash != calculated_hash:
        raise Problem(
            422, "eligibility_snapshot_hash_mismatch", "Authority snapshot hash is invalid"
        )
    snapshot["snapshot_hash"] = calculated_hash
    domains = {member["control_domain"] for member in snapshot["members"]}
    identities = {member["principal_id"] for member in snapshot["members"]}
    if len(identities) < requirements["quorum"]:
        raise Problem(422, "unsatisfiable_quorum", "Quorum exceeds eligible approvers")
    if (
        requirements.get("distinct_control_domains_required", False)
        and len(domains) < requirements["quorum"]
    ):
        raise Problem(422, "unsatisfiable_dual_control", "Quorum exceeds eligible control domains")
    rejection_mode = requirements.get("rejection_mode", "veto")
    rejection_count = requirements.get("rejection_quorum_count")
    if rejection_mode == "rejection_quorum" and not rejection_count:
        raise Problem(422, "rejection_quorum_missing", "Rejection quorum count is required")
    if rejection_mode != "rejection_quorum" and rejection_count is not None:
        raise Problem(
            422, "unexpected_rejection_quorum", "Rejection count is only valid for quorum mode"
        )
    if rejection_count is not None and rejection_count > len(identities):
        raise Problem(
            422, "unsatisfiable_rejection_quorum", "Rejection quorum exceeds eligible approvers"
        )
    return {
        "epoch_id": _id("epo_"),
        "epoch_number": number,
        "kind": kind,
        "state": "OPEN",
        "opened_at": opened_at.isoformat().replace("+00:00", "Z"),
        "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
        "closed_at": None,
        "quorum": requirements["quorum"],
        "distinct_control_domains_required": requirements.get(
            "distinct_control_domains_required", requirements.get("distinct_roles_required", False)
        ),
        "rejection_mode": rejection_mode,
        "rejection_quorum_count": rejection_count,
        "eligibility": snapshot,
        "carried_votes": [],
        "votes": [],
        "outcome": "PENDING",
    }


def create_approval(
    tenant_id: str,
    decision_id: str,
    context_hash: str,
    requirements: dict[str, Any],
    eligibility: dict[str, Any],
    now: datetime | None = None,
) -> dict[str, Any]:
    now = now or datetime.now(UTC)
    epoch = create_epoch(
        1,
        "initial",
        requirements,
        eligibility,
        now,
        now + timedelta(seconds=requirements["expiry_seconds"]),
    )
    return {
        "schema_version": "1.2",
        "approval_id": _id("apr_"),
        "tenant_id": tenant_id,
        "decision_id": decision_id,
        "state": "PENDING",
        "current_epoch_id": epoch["epoch_id"],
        "epochs": [epoch],
        "context_hash_at_request": context_hash,
        "created_at": now.isoformat().replace("+00:00", "Z"),
    }


def current_epoch(approval: dict[str, Any]) -> dict[str, Any]:
    return next(
        epoch for epoch in approval["epochs"] if epoch["epoch_id"] == approval["current_epoch_id"]
    )


def cast_vote(
    approval: dict[str, Any],
    *,
    epoch_number: int,
    approver_id: str,
    identity_kind: str,
    auth_strength: str,
    vote: str,
    forbidden_approvers: set[str],
    role_claim: str | None = None,
    justification: str | None = None,
    comment: str | None = None,
    now: datetime | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    now = now or datetime.now(UTC)
    updated = copy.deepcopy(approval)
    if updated["state"] in TERMINAL_STATES:
        raise Problem(409, "approval_terminal", "Approval no longer accepts votes")
    epoch = current_epoch(updated)
    if epoch["state"] != "OPEN" or epoch["epoch_number"] != epoch_number:
        raise Problem(409, "stale_approval_epoch", f"Current epoch is {epoch['epoch_number']}")
    if now >= datetime.fromisoformat(epoch["expires_at"].replace("Z", "+00:00")):
        raise Problem(409, "approval_epoch_expired", "Approval epoch has expired")
    if approver_id in forbidden_approvers:
        raise Problem(
            403, "self_approval_forbidden", "Requester or accountable owner cannot approve"
        )
    if identity_kind != "human" or auth_strength not in {"mfa", "hardware"}:
        raise Problem(
            403, "approver_auth_insufficient", "Voting requires a human with MFA or hardware auth"
        )
    if any(existing["approver_id"] == approver_id for existing in epoch["votes"]):
        raise Problem(403, "duplicate_vote", "One identity may vote only once per epoch")
    member = next(
        (item for item in epoch["eligibility"]["members"] if item["principal_id"] == approver_id),
        None,
    )
    if not member:
        raise Problem(403, "approver_ineligible", "Approver is absent from the epoch snapshot")
    if role_claim is not None and role_claim not in member["roles"]:
        raise Problem(
            403, "approver_role_ineligible", "Requested role is absent from the epoch snapshot"
        )
    if epoch["kind"] == "override" and not justification:
        raise Problem(
            403, "override_justification_required", "Override votes require justification"
        )
    recorded = {
        "vote_id": _id("vot_"),
        "epoch_id": epoch["epoch_id"],
        "epoch_number": epoch_number,
        "approver_id": approver_id,
        "approver_role": role_claim or sorted(member["roles"])[0],
        "control_domain": member["control_domain"],
        "auth_strength": auth_strength,
        "vote": vote,
        "justification": justification,
        "comment": comment,
        "timestamp": now.isoformat().replace("+00:00", "Z"),
    }
    epoch["votes"].append(recorded)
    all_votes = [*epoch.get("carried_votes", []), *epoch["votes"]]
    rejects = [item for item in all_votes if item["vote"] == "REJECT"]
    if (
        rejects
        and epoch["rejection_mode"] == "veto"
        or rejects
        and epoch["rejection_mode"] == "rejection_quorum"
        and (len({item["approver_id"] for item in rejects}) >= epoch["rejection_quorum_count"])
    ):
        _close(updated, epoch, "REJECTED", "REJECTED", now)
    elif rejects and epoch["rejection_mode"] == "review_required":
        epoch["state"], epoch["outcome"] = "CLOSED_SUPERSEDED", "REVIEW_TRIGGERED"
        epoch["closed_at"] = now.isoformat().replace("+00:00", "Z")
        updated["state"] = "REVIEW_REQUIRED"
    else:
        approvals = [item for item in all_votes if item["vote"] == "APPROVE"]
        identities = {item["approver_id"] for item in approvals}
        domains = {item["control_domain"] for item in approvals}
        quorum_met = len(identities) >= epoch["quorum"]
        if epoch["distinct_control_domains_required"]:
            quorum_met = quorum_met and len(domains) >= epoch["quorum"]
        if quorum_met:
            final = "OVERRIDDEN" if epoch["kind"] == "override" else "APPROVED"
            _close(updated, epoch, final, "QUORUM_MET", now)
        elif approvals:
            updated["state"] = "PARTIALLY_APPROVED"
    return updated, recorded


def _close(
    approval: dict[str, Any], epoch: dict[str, Any], state: str, outcome: str, now: datetime
) -> None:
    approval["state"] = state
    epoch["state"], epoch["outcome"] = "CLOSED_TERMINAL", outcome
    epoch["closed_at"] = now.isoformat().replace("+00:00", "Z")


def open_next_epoch(
    approval: dict[str, Any],
    *,
    kind: str,
    requirements: dict[str, Any],
    eligibility: dict[str, Any],
    carry_forward_votes: bool = False,
    reset_expiry: bool = True,
    now: datetime | None = None,
) -> dict[str, Any]:
    now = now or datetime.now(UTC)
    updated = copy.deepcopy(approval)
    if updated["state"] in TERMINAL_STATES:
        raise Problem(409, "approval_terminal", "Terminal approval cannot open another epoch")
    old = current_epoch(updated)
    if old["state"] == "OPEN":
        old["state"], old["outcome"] = "CLOSED_SUPERSEDED", "SUPERSEDED"
        old["closed_at"] = now.isoformat().replace("+00:00", "Z")
    number = old["epoch_number"] + 1
    expires_at = (
        now + timedelta(seconds=requirements["expiry_seconds"])
        if reset_expiry
        else datetime.fromisoformat(old["expires_at"].replace("Z", "+00:00"))
    )
    epoch = create_epoch(number, kind, requirements, eligibility, now, expires_at)
    if carry_forward_votes and kind != "override":
        eligible = {member["principal_id"] for member in epoch["eligibility"]["members"]}
        epoch["carried_votes"] = [
            vote
            for vote in [*old.get("carried_votes", []), *old["votes"]]
            if vote["vote"] == "APPROVE" and vote["approver_id"] in eligible
        ]
    updated["epochs"].append(epoch)
    updated["current_epoch_id"] = epoch["epoch_id"]
    updated["state"] = "REVIEW_REQUIRED" if kind == "review" else "PENDING"
    return updated


def withdraw(approval: dict[str, Any], now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now(UTC)
    updated = copy.deepcopy(approval)
    if updated["state"] in TERMINAL_STATES:
        raise Problem(409, "approval_terminal", "Terminal approval cannot be withdrawn")
    _close(updated, current_epoch(updated), "WITHDRAWN", "SUPERSEDED", now)
    return updated
