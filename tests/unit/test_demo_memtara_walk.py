"""The UC-2 walk's transcript is a recording, and this proves it.

`test_reference_transcript_is_diff_clean` drives `demo_memtara_walk.main` end to end and compares
the transcript the walk *recorded while running* against the committed fixture. Only the two
edges Mizan does not own are faked -- Memtara's reference prover subprocess and the HTTP surface
of the control plane. Everything between them is the real code: the real argument parsing, the
real Ed25519 keypair and minted tokens, the real binding hash, the real approval and execution
sequence, the real `step()` calls. Rename, drop, reorder or stop emitting a milestone and this
test goes red, because the fixture is a capture of that sequence and nothing else.
"""

from __future__ import annotations

import base64
import json
import os
import uuid
from pathlib import Path

import httpx
import pytest

import scripts.demo_memtara_walk as demo
from scripts.demo_walk import AGENT, APPROVERS, CUSTOMER, EXECUTOR

COMMITTED_TRANSCRIPT = Path("tests/fixtures/demo_memtara/transcript.txt")


def subject_of(request: httpx.Request) -> str:
    """Read the `sub` of the bearer token the walk actually minted for this call."""
    token = request.headers["authorization"].removeprefix("Bearer ")
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))["sub"]


class FakeMizan:
    """The `/v1` surface `clear_the_approval` and `redeem_and_execute` require, and no more.

    Every identifier is fresh per run. A transcript that is stable across runs is therefore a
    transcript that normalised them, not one that happened to be recorded twice from one run.
    """

    def __init__(self) -> None:
        self.decision_id = "adr_" + uuid.uuid4().hex[:24]
        self.approval_id = "apr_" + uuid.uuid4().hex
        self.lease_id = "lse_" + uuid.uuid4().hex
        self.execution_token = "eyJ." + uuid.uuid4().hex + "." + uuid.uuid4().hex
        self.approvers: list[str] = []
        self.token_issued = False
        self.execute_attempts = 0
        self.requests: list[str] = []
        self.authorize_headers: dict[str, str] = {}
        self.authorize_body: dict = {}

    @property
    def approved(self) -> bool:
        return len(self.approvers) >= len(APPROVERS)

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.requests.append(f"{request.method} {path}")
        assert request.headers.get("authorization", "").startswith("Bearer ")
        body = json.loads(request.content) if request.content else {}

        if request.method == "POST" and path == "/v1/authorize":
            self.authorize_headers = dict(request.headers)
            self.authorize_body = body
            assert subject_of(request) == CUSTOMER
            return httpx.Response(
                200,
                json={
                    "decision_id": self.decision_id,
                    "decision": "REQUIRE_APPROVAL",
                    "reasons": ["approval_required"],
                    "risk": {"level": "high", "score": 71},
                    "approval": {"approval_id": self.approval_id, "status": "PENDING"},
                },
            )

        if request.method == "GET" and path == "/v1/approvals":
            assert request.url.params["state"] == "PENDING"
            return httpx.Response(
                200,
                json={
                    "items": [
                        {
                            "approval_id": self.approval_id,
                            "decision_id": self.decision_id,
                            "state": "PENDING",
                            "epoch": {"epoch_number": 1, "quorum": len(APPROVERS)},
                        }
                    ]
                },
            )

        if request.method == "POST" and path == f"/v1/approvals/{self.approval_id}/votes":
            voter = subject_of(request)
            assert body["vote"] == "APPROVE"
            if voter == CUSTOMER:  # ADR-007: the requester may not clear its own request.
                return httpx.Response(
                    409, json={"type": "https://mizan.dev/problems/self_approval_forbidden"}
                )
            self.approvers.append(voter)
            return httpx.Response(
                200,
                json={
                    "approval_id": self.approval_id,
                    "state": "APPROVED" if self.approved else "PENDING",
                },
            )

        if request.method == "POST" and path == f"/v1/decisions/{self.decision_id}/execution-token":
            assert body["executor_spiffe_id"] == EXECUTOR
            if not self.approved:
                return httpx.Response(
                    403, json={"type": "https://mizan.dev/problems/approval_incomplete"}
                )
            reused = self.token_issued
            self.token_issued = True
            return httpx.Response(
                200, json={"execution_token": self.execution_token, "reused": reused}
            )

        if request.method == "POST" and path == f"/v1/actions/{self.decision_id}/execute":
            assert body["execution_token"] == self.execution_token
            self.execute_attempts += 1
            if self.execute_attempts == 1:
                # The drain worker has not published the receipt yet. The walk must retry, and
                # must report how many attempts it took -- a count the transcript normalises.
                return httpx.Response(
                    403, json={"type": "https://mizan.dev/problems/immutable_receipt_missing"}
                )
            return httpx.Response(
                200,
                json={
                    "lease_id": self.lease_id,
                    "state": "LEASED",
                    "authorized_executor": EXECUTOR,
                },
            )

        complete = f"/v1/actions/{self.decision_id}/lease/{self.lease_id}/complete"
        if request.method == "POST" and path == complete:
            return httpx.Response(200, json={"lease_id": self.lease_id, "state": "EXECUTED"})

        raise AssertionError(f"the walk made an unexpected call: {request.method} {path}")


class FakeMemtara:
    """Memtara's reference prover and its audit checkpoint, as opaque as the real ones."""

    def __init__(self) -> None:
        self.chain_head = uuid.uuid4().hex + uuid.uuid4().hex
        self.proof_token = "eyJ." + uuid.uuid4().hex + ".sig"
        self.invocations: list[dict] = []

    def run(self, command, **kwargs):
        self.invocations.append({"command": list(command), "kwargs": kwargs})
        return type(
            "Completed",
            (),
            {
                "returncode": 0,
                "stdout": json.dumps(
                    {
                        "proof_token": self.proof_token,
                        "product_isin": demo.PRODUCT_ISIN,
                        "suitable": True,
                    }
                ),
                "stderr": "",
            },
        )()

    def checkpoint(self, url, **kwargs):
        assert url.endswith("/audit/checkpoints")
        return httpx.Response(
            200, json={"checkpoint": {"head_event_hash": self.chain_head, "tree_size": 12}}
        )


@pytest.fixture
def walk(monkeypatch, tmp_path: Path):
    """The real walk, wired to fake edges. Returns (argv, mizan, memtara)."""
    memtara_repo = tmp_path / "memtara-zkp"
    prover = memtara_repo / "clients" / "prover" / "memtara-prove"
    prover.parent.mkdir(parents=True)
    prover.write_text("reference client", encoding="utf-8")
    vault = memtara_repo / "cro_demo" / "client_42_vault.json"
    vault.parent.mkdir(parents=True)
    vault.write_text("{}", encoding="utf-8")

    mizan, memtara = FakeMizan(), FakeMemtara()
    real_client = httpx.Client

    def client(**kwargs):
        assert "verify" not in kwargs, "a plain-http demo must not build a TLS context"
        return real_client(transport=httpx.MockTransport(mizan.handle), **kwargs)

    monkeypatch.setattr(demo.subprocess, "run", memtara.run)
    monkeypatch.setattr(demo.httpx, "post", memtara.checkpoint)
    monkeypatch.setattr(demo.httpx, "Client", client)

    argv = [
        "--api-url", "http://mizan.test",
        "--key-dir", str(tmp_path / "keys"),
        "--memtara-repo", str(memtara_repo),
        "--memtara-url", "http://memtara.test",
        "--memtara-org-api-key", "secret-key",
        "--memtara-user-id", "user-1",
        "--vault-path", "cro_demo/client_42_vault.json",
        "--receipt-timeout-seconds", "5",
    ]
    return argv, mizan, memtara


def test_reference_transcript_is_diff_clean(walk, tmp_path: Path) -> None:
    argv, mizan, memtara = walk
    recorded = tmp_path / "transcript.txt"

    assert demo.main([*argv, "--write-reference-transcript", str(recorded)]) == 0

    # The walk really ran: both Memtara edges and every Mizan call the journey is made of.
    assert len(memtara.invocations) == 1
    assert mizan.requests == [
        "POST /v1/authorize",
        "GET /v1/approvals",
        f"POST /v1/decisions/{mizan.decision_id}/execution-token",
        f"POST /v1/approvals/{mizan.approval_id}/votes",
        f"POST /v1/approvals/{mizan.approval_id}/votes",
        f"POST /v1/approvals/{mizan.approval_id}/votes",
        f"POST /v1/decisions/{mizan.decision_id}/execution-token",
        f"POST /v1/decisions/{mizan.decision_id}/execution-token",
        f"POST /v1/actions/{mizan.decision_id}/execute",
        f"POST /v1/actions/{mizan.decision_id}/execute",
        f"POST /v1/actions/{mizan.decision_id}/lease/{mizan.lease_id}/complete",
    ]
    assert mizan.authorize_headers["x-memtara-proof"] == memtara.proof_token
    assert mizan.authorize_headers["x-memtara-chain-head"] == memtara.chain_head
    assert mizan.authorize_body["tool"]["arguments"]["product_isin"] == demo.PRODUCT_ISIN
    assert mizan.authorize_body["agent"]["id"] == AGENT

    captured = recorded.read_text(encoding="utf-8")
    if os.environ.get("MIZAN_UPDATE_TRANSCRIPT"):
        # The committed fixture is regenerated from this recording and never written by hand:
        #   MIZAN_UPDATE_TRANSCRIPT=1 uv run pytest tests/unit/test_demo_memtara_walk.py
        # Review the resulting diff as you would any other change to what the demo claims.
        COMMITTED_TRANSCRIPT.write_text(captured, encoding="utf-8")
    # Nothing that changes between two runs of the same journey survives into the transcript.
    for varying in (
        mizan.decision_id,
        mizan.approval_id,
        mizan.lease_id,
        mizan.execution_token,
        memtara.chain_head,
        memtara.chain_head[:16],
        memtara.proof_token,
        "secret-key",
    ):
        assert varying not in captured

    assert captured == COMMITTED_TRANSCRIPT.read_text(encoding="utf-8")


def test_transcript_goes_red_when_a_milestone_stops_being_emitted(
    walk, tmp_path: Path, monkeypatch
) -> None:
    """The comparison above discriminates. Drop one step and the recording no longer matches."""
    argv, _, _ = walk
    recorded = tmp_path / "transcript.txt"
    monkeypatch.setattr(demo, "step", lambda label, detail: None)

    assert demo.main([*argv, "--write-reference-transcript", str(recorded)]) == 0
    assert recorded.read_text(encoding="utf-8") != COMMITTED_TRANSCRIPT.read_text(encoding="utf-8")


def test_reference_prover_keeps_the_org_key_off_the_process_table(
    monkeypatch, tmp_path: Path
) -> None:
    """argv is world-readable through `ps`; the organisation key travels in the environment."""
    prover = tmp_path / "clients" / "prover" / "memtara-prove"
    prover.parent.mkdir(parents=True)
    prover.write_text("reference client", encoding="utf-8")
    vault = tmp_path / "vault.json"
    vault.write_text("{}", encoding="utf-8")
    observed = {}

    def run(command, **kwargs):
        observed["command"] = list(command)
        observed["kwargs"] = kwargs
        return type(
            "Completed",
            (),
            {
                "returncode": 0,
                "stdout": json.dumps(
                    {
                        "proof_token": "header.payload.signature",
                        "product_isin": demo.PRODUCT_ISIN,
                        "suitable": True,
                    }
                ),
                "stderr": "",
            },
        )()

    monkeypatch.setattr(demo.subprocess, "run", run)
    result = demo.run_reference_prover(
        memtara_repo=tmp_path,
        base_url="http://memtara.test",
        org_api_key="secret-key",
        user_id="user-1",
        product_isin=demo.PRODUCT_ISIN,
        vault_path=vault,
    )
    assert result["suitable"] is True
    assert str(prover) in observed["command"]
    assert "secret-key" not in observed["command"]
    assert not any("secret-key" in argument for argument in observed["command"])
    assert "--org-api-key" not in observed["command"]
    assert observed["kwargs"]["env"][demo.ORG_API_KEY_ENV] == "secret-key"
    # The child still inherits the rest of the environment it needs to run.
    assert "PATH" in observed["kwargs"]["env"]
    assert observed["kwargs"]["capture_output"] is True


def test_recommendation_context_binds_product_isin() -> None:
    sent = demo.recommendation_context(demo.PRODUCT_ISIN)
    assert sent["tool"]["arguments"]["product_isin"] == demo.PRODUCT_ISIN
    assert sent["tool"]["binding_profile"]["profile_id"] == "bp_product-recommendation-v1"
    assert len(sent["tool"]["parameters_hash"]) == 64
