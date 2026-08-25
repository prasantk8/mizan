from __future__ import annotations

import copy
from datetime import UTC, datetime
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from mizan_control_plane.approval import cast_vote, create_approval, open_next_epoch
from mizan_control_plane.canonical import binding_hash, canonical_hash
from mizan_control_plane.evidence import verify_chain
from mizan_control_plane.problems import Problem
from mizan_control_plane.schema_validation import ContractSchemas

from tests.unit.test_approval import eligibility, requirements
from tests.unit.test_authorization import context, identity, service
from tests.unit.test_registry import agent_document

NOW = datetime(2026, 8, 25, tzinfo=UTC)


@given(st.lists(st.text(max_size=50), min_size=1, max_size=100))
def test_i2_property_hash_chain_is_contiguous(values: list[str]) -> None:
    records, previous = [], "0" * 64
    for sequence, value in enumerate(values):
        record = {"sequence_number": sequence, "prev_hash": previous, "value": value}
        record["record_hash"] = canonical_hash(record)
        records.append(record)
        previous = record["record_hash"]
    assert verify_chain(records, "0" * 64).valid
    broken = copy.deepcopy(records)
    broken[-1]["value"] += "tamper"
    assert not verify_chain(broken, "0" * 64).valid


@given(
    amount=st.integers(min_value=0, max_value=10**9),
    intent=st.text(
        alphabet=st.characters(categories=("L", "N", "P", "Zs")), min_size=1, max_size=80
    ),
)
@settings(max_examples=40)
def test_i13_property_valid_enriched_context_is_always_recordable(amount: int, intent: str) -> None:
    subject, repository = service()
    request = context()
    request.intent = intent
    request.tool.parameters["amount"] = amount
    request.tool.parameters_hash = binding_hash(request.tool.parameters, ["/amount"])
    subject.authorize(identity(), request)
    ContractSchemas(Path("SPEC_v1.md")).validate("ADR_Record", repository.adr_documents[0])


@given(st.sampled_from(["pol_wrong", "agt_wrong", "apr_wrong", "adr_wrong"]))
def test_i16_property_wrong_id_family_is_schema_error(wrong_id: str) -> None:
    document = agent_document() | {"agent_id": wrong_id}
    with pytest.raises(Problem):
        ContractSchemas(Path("SPEC_v1.md")).validate("Agent", document)


@given(st.lists(st.sampled_from(["prn_alice", "prn_bob", "prn_eve"]), unique=True))
def test_i6_i15_approval_state_machine_fuzzer(voters: list[str]) -> None:
    approval = create_approval(
        "tnt_bank-a", "adr_decision-0001", "a" * 64, requirements(), eligibility(), NOW
    )
    for voter in voters:
        if approval["state"] in {"APPROVED", "REJECTED"}:
            with pytest.raises(Problem):
                cast_vote(
                    approval,
                    epoch_number=1,
                    approver_id=voter,
                    identity_kind="human",
                    auth_strength="mfa",
                    vote="APPROVE",
                    forbidden_approvers=set(),
                    now=NOW,
                )
            break
        approval, _ = cast_vote(
            approval,
            epoch_number=1,
            approver_id=voter,
            identity_kind="human",
            auth_strength="mfa",
            vote="APPROVE",
            forbidden_approvers=set(),
            now=NOW,
        )
    epoch = approval["epochs"][0]
    assert len({vote["approver_id"] for vote in epoch["votes"]}) == len(epoch["votes"])
    if approval["state"] == "APPROVED":
        approvals = [vote for vote in epoch["votes"] if vote["vote"] == "APPROVE"]
        assert len({vote["approver_id"] for vote in approvals}) >= epoch["quorum"]
        assert len({vote["control_domain"] for vote in approvals}) >= epoch["quorum"]


def test_v2_v4_unsatisfiable_epoch_configuration_is_rejected() -> None:
    with pytest.raises(Problem, match="eligible approvers"):
        create_approval(
            "tnt_bank-a",
            "adr_decision-0001",
            "a" * 64,
            requirements(quorum=4, distinct_control_domains_required=False),
            eligibility(),
            NOW,
        )
    with pytest.raises(Problem, match="only valid"):
        create_approval(
            "tnt_bank-a",
            "adr_decision-0001",
            "a" * 64,
            requirements(rejection_quorum_count=2),
            eligibility(),
            NOW,
        )


def test_g6_escalation_supersedes_original_epoch_and_stale_votes_fail() -> None:
    original = create_approval(
        "tnt_bank-a", "adr_decision-0001", "a" * 64, requirements(), eligibility(), NOW
    )
    escalated = open_next_epoch(
        original, kind="escalation", requirements=requirements(), eligibility=eligibility(), now=NOW
    )
    assert escalated["epochs"][0]["state"] == "CLOSED_SUPERSEDED"
    with pytest.raises(Problem) as error:
        cast_vote(
            escalated,
            epoch_number=1,
            approver_id="prn_alice",
            identity_kind="human",
            auth_strength="mfa",
            vote="APPROVE",
            forbidden_approvers=set(),
            now=NOW,
        )
    assert error.value.status == 409
