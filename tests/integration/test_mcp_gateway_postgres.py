"""The gate for T-070: an MCP client, the shipped gateway binary, and a real control plane.

Nothing here is stubbed. A real `mcp` client speaks stdio to a real `mizan-mcp-gateway` process,
which speaks stdio to a real upstream MCP tool server and mutual TLS to the shipped control plane
running against PostgreSQL. The claim under test is the product's whole claim:

  * a tool the registry has never seen is registered under an *operator* credential at startup,
    never under the agent identity the gateway calls with — and the gateway cannot grant itself
    the right to call it;
  * `tools/list` reaches the model unchanged, because a governed tool is the same tool;
  * an ALLOWed call reaches the tool server under a capability the control plane issued;
  * a REQUIRE_APPROVAL call does *not* reach the tool server while it is pending, and reaches it
    only after two approvers have voted.

The upstream server appends every tool it actually runs to `MIZAN_TEST_TOOL_LOG`. That file is how
this test tells "refused" apart from "ran, and was then reported as refused".

Like the rest of the PostgreSQL suite this test expects a freshly migrated schema: it asserts that
the two tools are *unknown* before the gateway starts, which is the point of the first claim.
"""

from __future__ import annotations

import json
import os
import ssl
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import anyio
import httpx
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mizan_control_plane.dev_token import (  # noqa: F401
    DEVELOPMENT_ISSUER,
    ensure_keypair,
    mint,
    public_jwks,
)
from mizan_control_plane.evidence import (
    Ed25519EvidenceSigner,
    EvidenceRepository,
    LocalImmutableObjectStore,
    OutboxPublisher,
)
from mizan_control_plane.registry import RegistryRepository, policy_semantic_hash

from tests.integration.test_closed_loop_postgres import (
    EXECUTOR,
    _free_port,
    await_ready,
    start_service,
    workload_pki,
)

TENANT = "tnt_bank-a"
AGENT = "agt_mcp-gateway"
CUSTOMER = "prn_mcp-user"
OPERATOR = "prn_registry-admin"
READ_TOOL = "tool_read-portfolio"
REBALANCE_TOOL = "tool_rebalance-portfolio"
ECHO_SERVER = Path(__file__).parent / "mcp" / "echo_tool_server.py"

pytestmark = pytest.mark.skipif(
    not os.getenv("MIZAN_TEST_DATABASE_URL"), reason="Postgres not configured"
)


def gateway_policy(policy_id: str, tool_id: str, decision: str) -> dict[str, Any]:
    document: dict[str, Any] = {
        "schema_version": "1.3",
        "policy_id": policy_id,
        "tenant_id": TENANT,
        "name": f"{decision} for {tool_id}",
        "version": 1,
        "status": "DRAFT",
        "author": "prn_risk-author",
        "applies_to": {"tool_ids": [tool_id]},
        "conditions": {"field": "agent.id", "op": "eq", "value": AGENT},
        "decision": decision,
        "priority": 500,
        "created_at": "2026-08-26T00:00:00Z",
    }
    if decision == "REQUIRE_APPROVAL":
        document["approval_requirements"] = {
            "quorum": 2,
            "approver_roles": ["manager"],
            "distinct_roles_required": True,
            "expiry_seconds": 3600,
            "rejection_mode": "veto",
        }
    document["content_hash"] = policy_semantic_hash(document)
    return document


def activate_gateway_policies(database_url: str) -> None:
    """Straight to ACTIVE in the store: the policy lifecycle has its own tests."""
    registry = RegistryRepository(database_url)
    try:
        with registry.pool.connection() as connection, connection.transaction():
            registry._scope(connection, TENANT)
            for policy_id, tool_id, decision in (
                ("pol_mcp-read", READ_TOOL, "ALLOW"),
                ("pol_mcp-rebalance", REBALANCE_TOOL, "REQUIRE_APPROVAL"),
            ):
                document = gateway_policy(policy_id, tool_id, decision) | {
                    "status": "ACTIVE",
                    "approver": "prn_risk-approver",
                }
                connection.execute(
                    "INSERT INTO mizan.policies(tenant_id,policy_id,version,status,effective_from,"
                    "decision,content_hash,document,created_at) "
                    "VALUES (%s,%s,1,'ACTIVE',now() - interval '1 minute',%s,%s,%s,now()) "
                    "ON CONFLICT DO NOTHING",
                    (TENANT, policy_id, decision, document["content_hash"], json.dumps(document)),
                )
    finally:
        registry.pool.close()


def agent_document(tools: list[str]) -> dict[str, Any]:
    return {
        "schema_version": "1.1",
        "agent_id": AGENT,
        "tenant_id": TENANT,
        "name": "MCP Gateway Agent",
        "version": "1.0.0",
        "owner": "wealth-team",
        "accountable_owner": "alice@example.test",
        "purpose": "Call MCP tools under governance",
        "environment": "development",
        "risk_tier": "LOW",
        "lifecycle_state": "ACTIVE",
        "identity": {"auth_method": "jwt_svid", "credential_ref": "kms://test/agent-key"},
        "tools": tools,
        "policies": [],
        "delegation": {
            "allowed_agent_ids": [],
            "max_delegation_depth": 0,
            "inherit_parent_permissions": False,
        },
        "created_at": "2026-08-25T00:00:00Z",
        "updated_at": "2026-08-25T00:00:00Z",
    }


def gateway_configuration(
    tmp_path: Path, pki: dict[str, Path], base_url: str, tokens: dict[str, str], log: Path
) -> Path:
    """The whole operator-facing surface of the product: one file, and the tools are governed."""
    quoted = {
        "python": json.dumps(sys.executable),
        "echo": json.dumps(str(ECHO_SERVER)),
        "log": json.dumps(str(log)),
        "path": json.dumps(os.environ.get("PATH", "")),
        "url": json.dumps(base_url),
        "agent_token": json.dumps(tokens["agent"]),
        "operator_token": json.dumps(tokens["operator"]),
        "ca": json.dumps(str(pki["ca"])),
        "certificate": json.dumps(str(pki["client_certificate"])),
        "key": json.dumps(str(pki["client_key"])),
    }
    document = f"""
[server]
name = "mizan-governed-test"

[upstream]
command = {quoted["python"]}
args = [{quoted["echo"]}]

[upstream.env]
MIZAN_TEST_TOOL_LOG = {quoted["log"]}
PATH = {quoted["path"]}

[mizan]
url = {quoted["url"]}
agent_id = "{AGENT}"
agent_token = {quoted["agent_token"]}
operator_token = {quoted["operator_token"]}
environment = "development"
principal_id = "{CUSTOMER}"
principal_type = "application"
principal_auth_strength = "federated"
executor_spiffe_id = "{EXECUTOR}"
ca_file = {quoted["ca"]}
client_certificate_file = {quoted["certificate"]}
client_key_file = {quoted["key"]}
register_unknown_tools = true
approval_timeout_seconds = 90.0
approval_poll_seconds = 0.5

[tools.read_portfolio]
risk_tier = "LOW"
action_type = "financial_read"
data_classification = "financial"
resource_owner = "core-banking"
resource_type = "portfolio"

[tools.rebalance_portfolio]
risk_tier = "HIGH"
action_type = "financial_write"
data_classification = "financial"
resource_owner = "core-banking"
resource_type = "portfolio"
"""
    path = tmp_path / "gateway.toml"
    path.write_text(document, encoding="utf-8")
    return path


def since() -> str:
    """A stale PENDING approval left by another test is not this test's request."""
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def ran(log: Path) -> list[str]:
    return log.read_text(encoding="utf-8").split() if log.exists() else []


class Publisher(threading.Thread):
    """What the T-074 worker will do continuously: drain the outbox into signed receipts.

    A financial write may not execute until its evidence is durably published, so without this
    running the second half of the loop never happens. It is a thread here and a process there.
    """

    def __init__(self, database_url: str, root: Path) -> None:
        super().__init__(daemon=True)
        self.database_url = database_url
        self.root = root
        self.stop = threading.Event()
        self.drained = 0

    def run(self) -> None:
        evidence = EvidenceRepository(self.database_url)
        publisher = OutboxPublisher(
            evidence,
            LocalImmutableObjectStore(self.root),
            Ed25519EvidenceSigner.development("evidence-receipt"),
            Ed25519EvidenceSigner.development("evidence-anchor"),
        )
        try:
            while not self.stop.is_set():
                self.drained += publisher.drain(TENANT)
                self.stop.wait(0.1)
        finally:
            evidence.pool.close()


def approve_when_pending(
    client: httpx.Client, credential: Any, observed: dict[str, Any], log: Path, since: str
) -> None:
    """What the T-072 inbox will do with a mouse: find this request, and vote it through.

    Before voting it records what had already run. A call that is still waiting for a human and
    has already reached the tool server would make the gateway's whole claim false, and this is
    the only place in the suite positioned to see it.
    """
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        queue = client.get("/v1/approvals", params={"state": "PENDING"})
        items = queue.json().get("items", []) if queue.status_code == 200 else []
        mine = [
            item
            for item in items
            if item["requester_id"] == CUSTOMER and item["created_at"] > since
        ]
        if mine:
            observed["ran_while_pending"] = ran(log)
            approval_id = mine[0]["approval_id"]
            observed["approval_id"] = approval_id
            observed["quorum"] = mine[0]["epoch"]["quorum"]
            for approver in ("prn_alice", "prn_bob"):
                vote = client.post(
                    f"/v1/approvals/{approval_id}/votes",
                    json={"epoch_number": 1, "vote": "APPROVE"},
                    headers=credential(approver, "human", ["manager"]),
                )
                observed.setdefault("votes", []).append(vote.status_code)
            observed["final_state"] = vote.json().get("state")
            return
        time.sleep(0.2)
    observed["timed_out"] = True


def gateway_session(configuration: Path, environment: dict[str, str], log_level: str = "warning"):
    parameters = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "mizan_mcp_gateway",
            "--config",
            str(configuration),
            "--log-level",
            log_level,
        ],
        env=environment,
    )
    return stdio_client(parameters)


async def start_once(configuration: Path, environment: dict[str, str]) -> None:
    """Bring the gateway up and straight back down: registration happens before it serves."""
    async with (
        gateway_session(configuration, environment) as (read, write),
        ClientSession(read, write, read_timeout_seconds=60.0) as session,
    ):
        await session.initialize()


async def drive(configuration: Path, environment: dict[str, str]) -> dict[str, Any]:
    """One MCP client session against the gateway, exactly as an agent framework would hold it."""
    async with (
        gateway_session(configuration, environment) as (read, write),
        ClientSession(read, write, read_timeout_seconds=180.0) as session,
    ):
        await session.initialize()
        listed = await session.list_tools()
        read_result = await session.call_tool(
            "read_portfolio",
            {"customer_id": "cust-42"},
            meta={"mizan/intent": "show the customer their holdings"},
        )
        rebalance_result = await session.call_tool(
            "rebalance_portfolio",
            {"customer_id": "cust-42", "amount": 12500},
            meta={"mizan/intent": "rebalance to the target allocation"},
        )
        return {"tools": listed.tools, "read": read_result, "rebalance": rebalance_result}


def test_an_mcp_client_reaches_tools_only_through_a_recorded_decision(tmp_path: Path) -> None:
    database_url = os.environ["MIZAN_TEST_DATABASE_URL"]
    activate_gateway_policies(database_url)
    pki = workload_pki(tmp_path / "pki")
    identity_key, _public_pem = ensure_keypair(tmp_path / "identity")
    port = _free_port()
    base_url = f"https://127.0.0.1:{port}"
    process = start_service(tmp_path, pki, port, public_jwks(identity_key))

    def token(subject: str, kind: str, roles: list[str]) -> str:
        return mint(
            identity_key,
            tenant_id=TENANT,
            subject=subject,
            agent_id=AGENT,
            identity_kind=kind,
            auth_strength="federated" if kind == "agent" else "hardware",
            roles=roles,
            audience="mizan-control-plane",
            ttl_seconds=1800,
        )

    def credential(subject: str, kind: str, roles: list[str]) -> dict[str, str]:
        return {"Authorization": "Bearer " + token(subject, kind, roles)}

    trust = ssl.create_default_context(cafile=str(pki["ca"]))
    trust.load_cert_chain(str(pki["client_certificate"]), str(pki["client_key"]))
    operator = credential(OPERATOR, "human", ["registry.admin"])
    client = httpx.Client(base_url=base_url, verify=trust, timeout=30, headers=operator)
    log = tmp_path / "upstream-calls.log"
    publisher = Publisher(database_url, tmp_path / "evidence")
    # The queue is tenant-scoped from the reader's own token (I-3): an unauthenticated poll
    # returns nothing, which would look exactly like an empty inbox.
    approver_client = httpx.Client(
        base_url=base_url,
        verify=trust,
        timeout=30,
        headers=credential("prn_alice", "human", ["manager"]),
    )
    observed: dict[str, Any] = {}
    try:
        await_ready(process, client)
        created = client.post("/v1/agents", json=agent_document([]))
        assert created.status_code == 201, created.text

        environment = {
            "PATH": os.environ.get("PATH", ""),
            "PYTHONPATH": os.pathsep.join(("control-plane", "integrations/mcp", "sdk/python")),
        }
        configuration = gateway_configuration(
            tmp_path,
            pki,
            base_url,
            {
                "agent": token(CUSTOMER, "agent", []),
                "operator": token(OPERATOR, "human", ["registry.admin"]),
            },
            log,
        )

        assert client.get(f"/v1/tools/{READ_TOOL}").status_code == 404
        anyio.run(start_once, configuration, environment)
        registered = client.get(f"/v1/tools/{REBALANCE_TOOL}")
        assert registered.status_code == 200, registered.text
        assert registered.json()["risk_tier"] == "HIGH"
        assert registered.json()["binding_profile"]["bound_pointers"] == ["/amount", "/customer_id"]

        # Registering a tool is not the same act as being allowed to call it. The gateway holds an
        # operator credential for the first and cannot perform the second at all: an agent that
        # could widen its own permissions would make every later decision meaningless.
        assert AGENT not in registered.json().get("permitted_agents", [])
        granted = client.patch(
            f"/v1/agents/{AGENT}",
            json={"document": agent_document([READ_TOOL, REBALANCE_TOOL])},
        )
        assert granted.status_code == 200, granted.text

        publisher.start()
        voter = threading.Thread(
            target=approve_when_pending,
            args=(approver_client, credential, observed, log, since()),
            daemon=True,
        )
        voter.start()
        outcome = anyio.run(drive, configuration, environment)
        voter.join(timeout=30)
    finally:
        publisher.stop.set()
        # A startup refusal happens before `publisher.start()`. Joining an unstarted Thread raises
        # RuntimeError and used to mask the refusal this test was meant to report.
        if publisher.ident is not None:
            publisher.join(timeout=15)
        approver_client.close()
        client.close()
        process.terminate()
        process.wait(timeout=15)

    names = {tool.name: tool for tool in outcome["tools"]}
    assert set(names) == {"read_portfolio", "rebalance_portfolio"}
    assert names["rebalance_portfolio"].description.startswith("Move money")

    read = outcome["read"]
    assert read.is_error is False, read.content
    assert read.structured_content["mizan"]["outcome"] == "allowed"
    assert read.structured_content["mizan"]["decision"] == "ALLOW"
    assert read.structured_content["mizan"]["lease_id"], "the gateway forwarded without a lease"

    # The approver's side first: it is the precondition for anything the rebalance call returns.
    assert observed.get("timed_out") is not True, observed
    assert observed["quorum"] == 2
    assert observed["votes"] == [200, 200], observed
    assert observed["final_state"] == "APPROVED"
    # The claim the product rests on: while no human had voted, the money-moving tool had not run.
    assert observed["ran_while_pending"] == ["read_portfolio"], observed

    rebalance = outcome["rebalance"]
    assert rebalance.is_error is False, rebalance.content
    assert rebalance.structured_content["mizan"]["decision"] == "REQUIRE_APPROVAL"
    assert rebalance.structured_content["mizan"]["lease_id"]
    assert ran(log) == ["read_portfolio", "rebalance_portfolio"]
