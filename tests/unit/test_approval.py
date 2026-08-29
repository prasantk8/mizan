from __future__ import annotations

from datetime import UTC, datetime

import pytest
from mizan_control_plane.approval import cast_vote, create_approval, open_next_epoch
from mizan_control_plane.problems import Problem

NOW = datetime(2026, 8, 25, tzinfo=UTC)


def eligibility() -> dict:
    return {
        "snapshot_at": "2026-08-25T00:00:00Z",
        "authority_source": "mizan_role_registry",
        "authority_mapping_version": 3,
        "roles": ["manager", "supervisor", "compliance"],
        "members": [
            {
                "principal_id": "prn_alice",
                "roles": ["manager", "supervisor"],
                "control_domain": "business.ops",
            },
            {"principal_id": "prn_bob", "roles": ["supervisor"], "control_domain": "risk.control"},
            {
                "principal_id": "prn_eve",
                "roles": ["compliance"],
                "control_domain": "compliance.control",
            },
        ],
    }


def requirements(**updates: object) -> dict:
    base = {
        "quorum": 2,
        "expiry_seconds": 900,
        "rejection_mode": "veto",
        "distinct_control_domains_required": True,
    }
    return base | updates


def approval(**updates: object) -> dict:
    return create_approval(
        "tnt_bank-a", "adr_decision-0001", "a" * 64, requirements(**updates), eligibility(), NOW
    )


def vote(subject: dict, approver: str, **updates: object) -> tuple[dict, dict]:
    arguments = {
        "epoch_number": 1,
        "approver_id": approver,
        "identity_kind": "human",
        "auth_strength": "mfa",
        "vote": "APPROVE",
        "forbidden_approvers": set(),
        "now": NOW,
    } | updates
    return cast_vote(subject, **arguments)


def test_multi_role_identity_votes_once_and_cannot_fake_second_role() -> None:
    pending, recorded = vote(approval(), "prn_alice", role_claim="manager")
    assert recorded["control_domain"] == "business.ops"
    with pytest.raises(Problem, match="once"):
        vote(pending, "prn_alice", role_claim="supervisor")


def test_dual_control_counts_distinct_control_domains() -> None:
    # Two approvals from two domains satisfy the quorum...
    pending, _ = vote(approval(), "prn_alice")
    approved, _ = vote(pending, "prn_bob")
    assert approved["state"] == "APPROVED"
    # ...and two approvals from ONE domain do not, which is the half the name claims. The pool
    # still has to be able to satisfy dual control, or V-2 refuses the epoch before any vote.
    pool = eligibility()
    pool["members"][1]["control_domain"] = pool["members"][0]["control_domain"]
    one_domain_twice = create_approval(
        "tnt_bank-a", "adr_decision-0002", "a" * 64, requirements(quorum=2), pool, NOW
    )
    first, _ = vote(one_domain_twice, "prn_alice")
    second, recorded = vote(first, "prn_bob")
    assert recorded["control_domain"] == "business.ops"
    assert second["state"] == "PARTIALLY_APPROVED"
    # The third approver is in a different domain, and that is what carries the quorum.
    third, _ = vote(second, "prn_eve")
    assert third["state"] == "APPROVED"


def test_a_pool_that_cannot_satisfy_dual_control_is_refused_before_any_vote() -> None:
    single_domain = eligibility()
    for member in single_domain["members"]:
        member["control_domain"] = "business.ops"
    with pytest.raises(Problem, match="control domains"):
        create_approval(
            "tnt_bank-a", "adr_decision-0003", "a" * 64, requirements(quorum=2), single_domain, NOW
        )


@pytest.mark.parametrize("kind,strength", [("service", "mfa"), ("human", "password")])
def test_only_strongly_authenticated_humans_vote(kind: str, strength: str) -> None:
    with pytest.raises(Problem):
        vote(approval(), "prn_alice", identity_kind=kind, auth_strength=strength)


def test_requester_and_accountable_owner_cannot_vote() -> None:
    with pytest.raises(Problem, match="owner"):
        vote(approval(), "prn_alice", forbidden_approvers={"prn_alice"})


def test_stale_epoch_vote_loses_escalation_race() -> None:
    escalated = open_next_epoch(
        approval(),
        kind="escalation",
        requirements=requirements(),
        eligibility=eligibility(),
        now=NOW,
    )
    with pytest.raises(Problem) as raised:
        vote(escalated, "prn_alice", epoch_number=1)
    assert raised.value.status == 409


def test_veto_and_rejection_quorum_are_distinct() -> None:
    """One REJECT ends a veto epoch; under rejection_quorum the same vote does not."""
    vetoed, _ = vote(approval(), "prn_alice", vote="REJECT")
    assert vetoed["state"] == "REJECTED"
    quorum_mode = approval(rejection_mode="rejection_quorum", rejection_quorum_count=2)
    once, _ = vote(quorum_mode, "prn_alice", vote="REJECT")
    assert once["state"] == "PENDING"
    twice, _ = vote(once, "prn_bob", vote="REJECT")
    assert twice["state"] == "REJECTED"


def test_review_epoch_is_fresh_and_rejecting_voter_has_no_inherited_authority() -> None:
    triggered, _ = vote(
        approval(rejection_mode="review_required"), "prn_alice", vote="REJECT"
    )
    assert triggered["state"] == "REVIEW_REQUIRED"
    review_eligibility = eligibility() | {
        "roles": ["compliance"],
        "members": [eligibility()["members"][2]],
    }
    review = open_next_epoch(
        triggered,
        kind="review",
        requirements=requirements(quorum=1),
        eligibility=review_eligibility,
        carry_forward_votes=False,
        now=NOW,
    )
    assert review["epochs"][0]["outcome"] == "REVIEW_TRIGGERED"
    assert review["epochs"][1]["carried_votes"] == []
    with pytest.raises(Problem, match="absent from the epoch snapshot"):
        vote(review, "prn_alice", epoch_number=2)
    pending = approval(rejection_mode="rejection_quorum", rejection_quorum_count=2)
    pending, _ = vote(pending, "prn_alice", vote="REJECT")
    assert pending["state"] == "PENDING"
    rejected, _ = vote(pending, "prn_bob", vote="REJECT")
    assert rejected["state"] == "REJECTED"


def test_override_requires_fresh_votes_and_justification() -> None:
    pending, _ = vote(approval(), "prn_alice")
    override = open_next_epoch(
        pending,
        kind="override",
        requirements=requirements(),
        eligibility=eligibility(),
        now=NOW,
    )
    assert override["epochs"][-1]["carried_votes"] == []
    with pytest.raises(Problem, match="justification"):
        cast_vote(
            override,
            epoch_number=2,
            approver_id="prn_bob",
            identity_kind="human",
            auth_strength="hardware",
            vote="APPROVE",
            forbidden_approvers=set(),
            now=NOW,
        )


# ---------------------------------------------------------------------------------------------
# Whether a clock may decide a payment is a deployment decision (H-7, MIZAN_APPROVAL_EPOCH_EXPIRY)
# ---------------------------------------------------------------------------------------------

LATE = datetime(2026, 8, 25, 1, tzinfo=UTC)  # an hour past a 900-second epoch


def test_a_late_vote_is_refused_when_the_deployment_enforces_expiry() -> None:
    """The default, and the behaviour every deployment had before the setting existed."""
    with pytest.raises(Problem, match="Approval epoch has expired"):
        vote(approval(), "prn_alice", role_claim="manager", now=LATE)


def test_a_late_vote_is_accepted_when_the_deployment_does_not_expire_epochs() -> None:
    """`advisory` has to reach the request path, or it is the worst of both answers.

    An institution that says no clock may decide a payment, but whose control plane still refuses
    the late vote, has an epoch that stays OPEN for ever *and* cannot be answered: the approval is
    now undecidable by anyone. Fails before `enforce_expiry`, because the check was unconditional
    and there was no way for a deployment to say it wanted the other behaviour.
    """
    pending, recorded = vote(
        approval(), "prn_alice", role_claim="manager", now=LATE, enforce_expiry=False
    )

    assert recorded["vote"] == "APPROVE"
    # Counted, not merely not-refused: the late vote moved the approval toward its quorum.
    assert pending["state"] == "PARTIALLY_APPROVED"
    # The deadline is still recorded and still reportable; it is a deadline for the people
    # rather than a rule against them.
    assert pending["epochs"][-1]["expires_at"] == "2026-08-25T00:15:00Z"


def test_not_expiring_an_epoch_does_not_also_disable_the_other_refusals() -> None:
    """`enforce_expiry=False` relaxes exactly one check and nothing else.

    A blanket "skip validation when advisory" would have quietly re-opened self-approval and the
    terminal-state guard along with it, which is how a configuration flag becomes a vulnerability.
    """
    subject = approval()
    with pytest.raises(Problem, match="cannot approve"):
        vote(
            subject,
            "prn_alice",
            role_claim="manager",
            now=LATE,
            enforce_expiry=False,
            forbidden_approvers={"prn_alice"},
        )
    with pytest.raises(Problem, match="Current epoch is"):
        vote(
            subject,
            "prn_alice",
            role_claim="manager",
            now=LATE,
            enforce_expiry=False,
            epoch_number=99,
        )
