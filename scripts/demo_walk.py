#!/usr/bin/env python3
"""Walk the demo agent all the way through a governed payment, and print what Mizan produced.

This script used to stop at the third call, print `REQUIRE_APPROVAL`, and exit 0 -- one line
before the part of the product that did not work. That is the sentence CP-F opened with: *the
demo passes because it stops immediately before the part that is broken.* Everything after the
approval was untested by anything a reader could run, and it was in fact broken: with no drain
worker (T-099) `mizan.evidence_receipts` was never written and `/v1/actions/{id}/execute`
answered 403 `immutable_receipt_missing` forever, on a decision a human had already approved.

The walk now continues to the end and asserts the **artifact each step produces**, not that the
step was reached:

    authorize  -> a decision id and an approval handle in PENDING
    queue      -> the approval is visible to an approver nobody told about it
    premature  -> a token requested before quorum is refused, by name
    votes      -> two approvers in distinct control domains, and the second flips it to APPROVED
    self-vote  -> the requester approving its own request is refused (ADR-007)
    token      -> one execution token, and asking twice returns the same one
    receipt    -> the drain worker publishes, and only then does execution stop being refused
    execute    -> a lease naming the registered executor
    complete   -> EXECUTED

Nothing here is simulated. These are real HTTPS calls over mutual TLS carrying real signed
tokens, and every line printed corresponds to a record you can fetch from `/v1/decisions` and
find again inside the exported evidence bundle.
"""

from __future__ import annotations

import argparse
import sys
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "control-plane"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import dev_pki  # noqa: E402
from mizan_control_plane.canonical import binding_hash  # noqa: E402
from mizan_control_plane.dev_token import ensure_keypair, mint  # noqa: E402

TENANT = "tnt_demo-bank"
AGENT = "agt_wealth-advisor"
CUSTOMER = "prn_demo-customer"
EXECUTOR = "spiffe://mizan-demo/executor/wealth"
# Seeded by `seed_demo.py` in distinct control domains, which is what the demo policy's
# `distinct_roles_required` clause exists to enforce.
APPROVERS = (("prn_ops-manager", "manager"), ("prn_risk-officer", "risk"))

CALLS = [
    ("tool_portfolio-read", "financial_read", ["/customer_id"], {"customer_id": "cus_42"},
     "review the customer portfolio", "ALLOW"),
    ("tool_riskprofile-read", "financial_read", ["/customer_id"], {"customer_id": "cus_42"},
     "check the customer risk appetite", "ALLOW"),
    ("tool_portfolio-rebalance", "financial_write", ["/customer_id", "/amount"],
     {"customer_id": "cus_42", "amount": 250_000}, "rebalance to the target allocation",
     "REQUIRE_APPROVAL"),
]


class WalkFailed(Exception):
    """A step did not produce the artifact it is supposed to produce."""


def context(tool_id: str, action: str, bound: list[str], arguments: dict, intent: str) -> dict:
    payload = arguments | {"request_time": uuid.uuid4().hex}
    profile = "bp_" + tool_id.removeprefix("tool_").replace("_", "-") + "-v1"
    return {
        "schema_version": "1.2",
        "request_id": str(uuid.uuid4()),
        "principal": {"id": CUSTOMER, "type": "customer", "auth_strength": "mfa"},
        "agent": {"id": AGENT, "version": "1.0.0", "delegation_chain": [AGENT]},
        "intent": intent,
        "tool": {
            "id": tool_id,
            "arguments": payload,
            "parameters_hash": binding_hash(payload, bound),
            "binding_profile": {"profile_id": profile, "profile_version": 1},
        },
        "action": {"type": action},
        "resource": {
            "id": "portfolio/42",
            "type": "portfolio",
            "resource_owner": "core-banking",
            "data_classification": "financial",
        },
        "business": {"transaction_value": {"amount": 250_000, "currency": "AED"}},
        "environment": "development",
        "timestamp": "2026-08-26T00:00:00Z",
    }


def operator_headers(private_key, subject: str, roles: list[str]) -> dict[str, str]:
    token = mint(
        private_key,
        tenant_id=TENANT,
        subject=subject,
        agent_id=None,
        identity_kind="human",
        auth_strength="hardware",
        roles=roles,
        audience="mizan-control-plane",
        ttl_seconds=900,
    )
    return {"Authorization": f"Bearer {token}"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise WalkFailed(message)


_RECORDING: list[str] | None = None


@contextmanager
def recording_steps() -> Iterator[list[str]]:
    """Capture every ``step`` emitted inside the block, in order, exactly as it was printed.

    A demo transcript is only worth committing if it is a *recording*. Nothing here declares
    what the walk is supposed to say; the list this yields is filled by the walk running, so a
    milestone that stops being emitted stops appearing, and one that is renamed appears renamed.
    """
    global _RECORDING
    previous = _RECORDING
    captured: list[str] = []
    _RECORDING = captured
    try:
        yield captured
    finally:
        _RECORDING = previous


def step(label: str, detail: str) -> None:
    line = f"  {label:22s} {detail}"
    if _RECORDING is not None:
        _RECORDING.append(line)
    print(line)


def authorize_three_calls(client: httpx.Client) -> dict:
    """The original walk, unchanged in behaviour, and now only the first third of the story."""
    final: dict = {}
    for tool_id, action, bound, payload, intent, expected in CALLS:
        response = client.post(
            "/v1/authorize", json=context(tool_id, action, bound, payload, intent)
        )
        require(
            response.status_code == 200,
            f"{tool_id}: HTTP {response.status_code}: {response.text}",
        )
        body = response.json()
        require(
            body["decision"] == expected,
            f"{tool_id}: decided {body['decision']}, the demo policy says {expected}",
        )
        print(
            f"  {tool_id:26s} {body['decision']:17s} {body['risk']['level']:9s} "
            f"{body['decision_id']}  {'; '.join(body['reasons'])}"
        )
        final = body
    return final


def clear_the_approval(client: httpx.Client, private_key, decision: dict) -> str:
    approval_id = decision["approval"]["approval_id"]
    decision_id = decision["decision_id"]
    require(decision["approval"]["status"] == "PENDING", "the approval did not open as PENDING")

    queue = client.get("/v1/approvals", params={"state": "PENDING"})
    require(queue.status_code == 200, f"the approver queue answered {queue.status_code}")
    waiting = [item for item in queue.json()["items"] if item["approval_id"] == approval_id]
    require(bool(waiting), "the approval is not in the PENDING queue an approver would read")
    step("approver queue", f"{approval_id} quorum={waiting[0]['epoch']['quorum']}")

    # Asserted because it is the guarantee, not a detail: a token before quorum is refused.
    premature = client.post(
        f"/v1/decisions/{decision_id}/execution-token", json={"executor_spiffe_id": EXECUTOR}
    )
    require(
        premature.status_code == 403
        and premature.json()["type"].endswith("approval_incomplete"),
        f"a token before quorum was not refused: {premature.status_code} {premature.text}",
    )
    step("premature token", "refused: approval_incomplete")

    state = ""
    for subject, role in APPROVERS:
        vote = client.post(
            f"/v1/approvals/{approval_id}/votes",
            json={"epoch_number": 1, "vote": "APPROVE"},
            headers=operator_headers(private_key, subject, [role]),
        )
        require(vote.status_code == 200, f"{subject} could not vote: {vote.text}")
        state = vote.json()["state"]
        step("approval vote", f"{subject} ({role}) -> {state}")
    require(state == "APPROVED", f"two approvals left the request in {state}")

    # ADR-007: the requester may not approve its own request. Demonstrated, not assumed.
    self_vote = client.post(
        f"/v1/approvals/{approval_id}/votes",
        json={"epoch_number": 1, "vote": "APPROVE"},
        headers=operator_headers(private_key, CUSTOMER, ["manager"]),
    )
    require(
        self_vote.status_code == 409,
        f"the requester approved its own request: {self_vote.status_code}",
    )
    step("self-approval", "refused: 409 (ADR-007)")
    return decision_id


def redeem_and_execute(
    client: httpx.Client, decision_id: str, arguments: dict, wait: float
) -> None:
    issued = client.post(
        f"/v1/decisions/{decision_id}/execution-token", json={"executor_spiffe_id": EXECUTOR}
    )
    require(issued.status_code == 200, f"no execution token: {issued.text}")
    require(issued.json()["reused"] is False, "the first token was reported as a reissue")
    token = issued.json()["execution_token"]

    again = client.post(
        f"/v1/decisions/{decision_id}/execution-token", json={"executor_spiffe_id": EXECUTOR}
    )
    require(
        again.json()["reused"] is True and again.json()["execution_token"] == token,
        "asking twice produced a second token; one unconsumed token per decision is the contract",
    )
    step("execution token", "issued once; asking again returns the same token")

    # This is the step that was refused forever before T-099. The drain worker publishes the
    # ADR_Record and the APPROVAL_RESOLVED event asynchronously, so early attempts here can
    # legitimately be refused -- that is the publication SLO working. Never succeeding is not.
    deadline = time.monotonic() + wait
    attempts = 0
    while True:
        attempts += 1
        executed = client.post(
            f"/v1/actions/{decision_id}/execute",
            json={"execution_token": token, "arguments": arguments},
        )
        if executed.status_code == 200:
            break
        refusal = executed.json().get("type", "").rsplit("/", 1)[-1]
        if refusal != "immutable_receipt_missing" or time.monotonic() > deadline:
            raise WalkFailed(
                f"execution refused after {attempts} attempt(s): "
                f"{executed.status_code} {executed.text}"
            )
        time.sleep(0.25)

    lease = executed.json()
    require(lease["state"] == "LEASED", f"execution returned {lease['state']}")
    require(
        lease["authorized_executor"] == EXECUTOR,
        f"the lease authorised {lease['authorized_executor']}, not the registered executor",
    )
    step("evidence receipt", f"published; execution admitted after {attempts} attempt(s)")
    step("execute", f"{lease['state']} executor={lease['authorized_executor']}")

    completed = client.post(
        f"/v1/actions/{decision_id}/lease/{lease['lease_id']}/complete",
        json={"result_hash": "c" * 64},
    )
    require(completed.status_code == 200, f"completion failed: {completed.text}")
    require(
        completed.json()["state"] == "EXECUTED",
        f"the lease finished in {completed.json()['state']}",
    )
    step("complete", "EXECUTED")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the demo agent through the control plane")
    parser.add_argument("--api-url", default="https://127.0.0.1:8787")
    parser.add_argument("--key-dir", type=Path, default=Path("var/demo-keys"))
    parser.add_argument(
        "--tls-dir",
        type=Path,
        default=Path("var/demo/tls"),
        help="the development PKI from scripts/dev_pki.py. Execution endpoints require a "
        "verified peer SPIFFE identity (ADR-001 Amendment B), so the walk presents the "
        "executor's client certificate.",
    )
    parser.add_argument(
        "--receipt-timeout-seconds",
        type=float,
        default=30.0,
        help="how long to let the drain worker publish before calling the walk failed",
    )
    arguments = parser.parse_args(argv)
    private_key, _ = ensure_keypair(arguments.key_dir)
    agent_token = mint(
        private_key,
        tenant_id=TENANT,
        subject=CUSTOMER,
        agent_id=AGENT,
        identity_kind="agent",
        auth_strength="federated",
        roles=[],
        audience="mizan-control-plane",
        ttl_seconds=900,
    )

    client_kwargs: dict = {
        "base_url": arguments.api_url,
        "timeout": 15,
        "headers": {"Authorization": f"Bearer {agent_token}"},
    }
    if arguments.api_url.startswith("https://"):
        client_kwargs["verify"] = dev_pki.client_ssl_context(arguments.tls_dir)

    decision_id = "?"
    print("The wealth advisor calls three tools:")
    try:
        with httpx.Client(**client_kwargs) as client:
            decision = authorize_three_calls(client)
            print("\nThe rebalance stopped for a human. What happens next:")
            decision_id = clear_the_approval(client, private_key, decision)
            sent = context(
                "tool_portfolio-rebalance",
                "financial_write",
                ["/customer_id", "/amount"],
                {"customer_id": "cus_42", "amount": 250_000},
                "rebalance to the target allocation",
            )["tool"]["arguments"]
            redeem_and_execute(client, decision_id, sent, arguments.receipt_timeout_seconds)
    except WalkFailed as failure:
        print(f"\nWALK FAILED: {failure}", file=sys.stderr)
        return 1
    print(f"\n  decision {decision_id} is EXECUTED and its evidence is published.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
