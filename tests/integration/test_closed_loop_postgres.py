"""The gate for T-067: PRD §37 pause-and-resume as a running property.

One agent, over real mutual TLS, against the shipped binary: authorize → the approval appears in
the approver queue → two approvers in distinct control domains vote → the agent gets exactly one
execution token → the registered executor redeems it → the work completes. Every step is an HTTP
call; nothing is stubbed but the outbox drain, which the T-074 worker will run continuously.
"""

from __future__ import annotations

import os
import socket
import ssl
import subprocess
import sys
import time
import uuid
from pathlib import Path

import httpx
import pytest
from mizan_control_plane.canonical import binding_hash
from mizan_control_plane.dev_token import DEVELOPMENT_ISSUER, ensure_keypair, mint
from mizan_control_plane.drain_worker import run_once

# The demo's PKI generator, imported rather than duplicated -- see workload_pki below.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import dev_pki  # noqa: E402
from mizan_control_plane.evidence import (
    Ed25519EvidenceSigner,
    EvidenceRepository,
    LocalImmutableObjectStore,
    OutboxPublisher,
)
from mizan_control_plane.registry import RegistryRepository, policy_semantic_hash

TENANT = "tnt_bank-a"
AGENT = "agt_wealth-01"
TOOL = "tool_transfer"
EXECUTOR = "spiffe://mizan/executor/wealth"
CUSTOMER = "prn_demo-customer"
BOOT_DEADLINE_SECONDS = 40

pytestmark = pytest.mark.skipif(
    not os.getenv("MIZAN_TEST_DATABASE_URL"), reason="Postgres not configured"
)


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def workload_pki(directory: Path) -> dict[str, Path]:
    """The demo's generator, not a second copy of it.

    This test has booted the shipped binary behind real mutual TLS since T-067, and its PKI
    builder was the only proven one in the tree -- which is why `make demo` could not reach any
    execution endpoint at all. T-103 moved the generator to `scripts/dev_pki.py`; this test now
    imports it, so the demo and the test agree by construction rather than by two authors
    happening to be careful in the same way.
    """
    return dev_pki.workload_pki(directory, executor_spiffe=EXECUTOR)


def approval_policy() -> dict:
    document = {
        "schema_version": "1.3",
        "policy_id": "pol_loop-rebalance",
        "tenant_id": TENANT,
        "name": "Transfers need two control domains",
        "version": 1,
        "status": "DRAFT",
        "author": "prn_risk-author",
        "applies_to": {"tool_ids": [TOOL]},
        "conditions": {"field": "agent.id", "op": "eq", "value": AGENT},
        "decision": "REQUIRE_APPROVAL",
        "priority": 500,
        "approval_requirements": {
            "quorum": 2,
            "approver_roles": ["manager"],
            "distinct_roles_required": True,
            "expiry_seconds": 3600,
            "rejection_mode": "veto",
        },
        "created_at": "2026-08-26T00:00:00Z",
    }
    document["content_hash"] = policy_semantic_hash(document)
    return document


def activate_policy(database_url: str) -> None:
    """Straight to ACTIVE in the store: the lifecycle itself is covered by its own tests."""
    registry = RegistryRepository(database_url)
    try:
        document = approval_policy() | {"status": "ACTIVE", "approver": "prn_risk-approver"}
        with registry.pool.connection() as connection, connection.transaction():
            registry._scope(connection, TENANT)
            connection.execute(
                "INSERT INTO mizan.policies(tenant_id,policy_id,version,status,effective_from,"
                "decision,content_hash,document,created_at) "
                "VALUES (%s,%s,1,'ACTIVE',now() - interval '1 minute',%s,%s,%s,now()) "
                "ON CONFLICT DO NOTHING",
                (
                    TENANT,
                    document["policy_id"],
                    document["decision"],
                    document["content_hash"],
                    __import__("json").dumps(document),
                ),
            )
    finally:
        registry.pool.close()


def publish_evidence(tmp_path: Path) -> None:
    """One cycle of the real drainer.

    This used to hand-roll `drain` then `anchor` under the docstring *"what the T-074 drainer
    will do continuously"* -- a test standing in for a worker that did not exist, which is how
    the closed loop passed here while every deployed Mizan refused every financial write. It now
    runs the shipped `mizan-drain-outbox` cycle, so what this test exercises and what production
    launches are the same code (T-099).
    """
    evidence = EvidenceRepository(os.environ["MIZAN_TEST_DATABASE_URL"])
    try:
        publisher = OutboxPublisher(
            evidence,
            LocalImmutableObjectStore(tmp_path / "evidence"),
            Ed25519EvidenceSigner.development("evidence-receipt"),
            Ed25519EvidenceSigner.development("evidence-anchor"),
        )
        run_once(publisher, evidence, [TENANT], batch_size=100, max_unpublished_seconds=5)
    finally:
        evidence.pool.close()


def start_service(tmp_path: Path, pki: dict[str, Path], port: int, public_pem: str):
    environment = os.environ | {
        "MIZAN_DATABASE_URL": os.environ["MIZAN_TEST_DATABASE_URL"],
        "MIZAN_JWT_ISSUER": DEVELOPMENT_ISSUER,
        "MIZAN_JWT_PUBLIC_KEY": public_pem,
        "MIZAN_EVIDENCE_OBJECT_STORE_ROOT": str(tmp_path / "evidence"),
        "MIZAN_HTTP_HOST": "127.0.0.1",
        "MIZAN_HTTP_PORT": str(port),
        "MIZAN_TLS_CERTIFICATE_FILE": str(pki["server_certificate"]),
        "MIZAN_TLS_PRIVATE_KEY_FILE": str(pki["server_key"]),
        "MIZAN_TLS_CLIENT_CA_FILE": str(pki["ca"]),
        "PYTHONPATH": "control-plane",
    }
    return subprocess.Popen(
        [sys.executable, "-m", "mizan_control_plane", "--log-level", "warning"],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


def await_ready(process: subprocess.Popen[str], client: httpx.Client) -> None:
    deadline = time.monotonic() + BOOT_DEADLINE_SECONDS
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(f"service exited {process.returncode}: {process.communicate()[0]}")
        try:
            if client.get("/health/ready").status_code == 200:
                return
        except httpx.TransportError:
            pass
        time.sleep(0.25)
    process.terminate()
    raise AssertionError(f"service never became ready: {process.communicate()[0]}")


def evaluation_context(arguments: dict, profile: dict, bound: list[str]) -> dict:
    return {
        "schema_version": "1.2",
        "request_id": str(uuid.uuid4()),
        "principal": {"id": CUSTOMER, "type": "customer", "auth_strength": "mfa"},
        "agent": {"id": AGENT, "version": "1.0.0", "delegation_chain": [AGENT]},
        "intent": "rebalance the portfolio",
        "tool": {
            "id": TOOL,
            "arguments": arguments,
            "parameters_hash": binding_hash(arguments, bound),
            "binding_profile": profile,
        },
        "action": {"type": "financial_write"},
        "resource": {
            "id": "portfolio/42",
            "type": "portfolio",
            "resource_owner": "core-banking",
            "data_classification": "financial",
        },
        "business": {"transaction_value": {"amount": 12500, "currency": "AED"}},
        "environment": "production",
        "timestamp": "2026-08-26T00:00:00Z",
    }


def test_an_agent_pauses_for_two_approvers_and_then_executes(tmp_path: Path) -> None:
    activate_policy(os.environ["MIZAN_TEST_DATABASE_URL"])
    pki = workload_pki(tmp_path / "pki")
    identity_key, public_pem = ensure_keypair(tmp_path / "identity")
    port = _free_port()
    process = start_service(tmp_path, pki, port, public_pem)

    def credential(subject: str, kind: str, roles: list[str]) -> dict[str, str]:
        return {
            "Authorization": "Bearer "
            + mint(
                identity_key,
                tenant_id=TENANT,
                subject=subject,
                agent_id=AGENT,
                identity_kind=kind,
                auth_strength="federated" if kind == "agent" else "hardware",
                roles=roles,
                audience="mizan-control-plane",
                ttl_seconds=900,
            )
        }

    trust = ssl.create_default_context(cafile=str(pki["ca"]))
    trust.load_cert_chain(str(pki["client_certificate"]), str(pki["client_key"]))
    client = httpx.Client(base_url=f"https://127.0.0.1:{port}", verify=trust, timeout=20)
    agent = credential(CUSTOMER, "agent", [])
    try:
        await_ready(process, client)

        # Read the live binding profile rather than assuming one: publishing a new profile
        # version is an ordinary registry operation and this test must not depend on the order
        # other tests ran in.
        registered = client.get(f"/v1/tools/{TOOL}", headers=agent).json()["binding_profile"]
        profile = {
            "profile_id": registered["profile_id"],
            "profile_version": registered["profile_version"],
        }
        bound = registered["bound_pointers"]
        arguments = {"amount": 12500, "request_time": uuid.uuid4().hex}
        authorized = client.post(
            "/v1/authorize",
            json=evaluation_context(arguments, profile, bound),
            headers=agent,
        )
        assert authorized.status_code == 200, authorized.text
        decision = authorized.json()
        assert decision["decision"] == "REQUIRE_APPROVAL"
        assert decision["approval"]["status"] == "PENDING"
        approval_id = decision["approval"]["approval_id"]
        decision_id = decision["decision_id"]

        queue = client.get("/v1/approvals", params={"state": "PENDING"}, headers=agent)
        assert queue.status_code == 200, queue.text
        waiting = [item for item in queue.json()["items"] if item["approval_id"] == approval_id]
        assert waiting and waiting[0]["decision_id"] == decision_id
        assert waiting[0]["epoch"]["quorum"] == 2

        premature = client.post(
            f"/v1/decisions/{decision_id}/execution-token",
            json={"executor_spiffe_id": EXECUTOR},
            headers=agent,
        )
        assert premature.status_code == 403
        assert premature.json()["type"].endswith("approval_incomplete")

        for approver in ("prn_alice", "prn_bob"):
            vote = client.post(
                f"/v1/approvals/{approval_id}/votes",
                json={"epoch_number": 1, "vote": "APPROVE"},
                headers=credential(approver, "human", ["manager"]),
            )
            assert vote.status_code == 200, vote.text
        assert vote.json()["state"] == "APPROVED"

        # The requester may not approve its own request (ADR-007).
        assert (
            client.post(
                f"/v1/approvals/{approval_id}/votes",
                json={"epoch_number": 1, "vote": "APPROVE"},
                headers=credential(CUSTOMER, "human", ["manager"]),
            ).status_code
            == 409
        )

        issued = client.post(
            f"/v1/decisions/{decision_id}/execution-token",
            json={"executor_spiffe_id": EXECUTOR},
            headers=agent,
        )
        assert issued.status_code == 200, issued.text
        assert issued.json()["reused"] is False
        again = client.post(
            f"/v1/decisions/{decision_id}/execution-token",
            json={"executor_spiffe_id": EXECUTOR},
            headers=agent,
        )
        assert again.json()["reused"] is True
        assert again.json()["execution_token"] == issued.json()["execution_token"]

        publish_evidence(tmp_path)
        executed = client.post(
            f"/v1/actions/{decision_id}/execute",
            json={"execution_token": issued.json()["execution_token"], "arguments": arguments},
            headers=agent,
        )
        assert executed.status_code == 200, executed.text
        lease = executed.json()
        assert lease["state"] == "LEASED"
        assert lease["authorized_executor"] == EXECUTOR

        completed = client.post(
            f"/v1/actions/{decision_id}/lease/{lease['lease_id']}/complete",
            json={"result_hash": "c" * 64},
            headers=agent,
        )
        assert completed.status_code == 200, completed.text
        assert completed.json()["state"] == "EXECUTED"
    finally:
        client.close()
        process.terminate()
        process.wait(timeout=15)
