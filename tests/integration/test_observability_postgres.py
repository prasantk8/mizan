"""T-073's gate: the shipped binary, a real caller's trace, and a real scrape.

The unit suite proves each piece in isolation. What it cannot prove is that they are *wired*: that
the process an operator actually starts reads the caller's `traceparent`, carries it through the
authorization, writes it into the row that will be signed and chained, hands it back on the
response, mentions it in the log line, and serves a scrape on its own listener while doing so.
That wiring is where T-070's evidence gap lived — a component that existed and that nothing called.

Everything here goes through `python -m mizan_control_plane`, over a socket, against PostgreSQL.
Fails on 793a54a: `MIZAN_METRICS_PORT` and `MIZAN_LOG_FORMAT` are unread there, and the ADR_Record
carries `sha256(request_id)[:32]` with a null span.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
import uuid
from pathlib import Path

import httpx
import pytest
from mizan_control_plane.canonical import binding_hash
from mizan_control_plane.dev_token import DEVELOPMENT_ISSUER, ensure_keypair, mint, public_jwks
from mizan_control_plane.repository import PostgresAuthorizationRepository

TENANT = "tnt_bank-a"
AGENT = "agt_wealth-01"
TOOL = "tool_transfer"
CUSTOMER = "prn_demo-customer"
BOOT_DEADLINE_SECONDS = 40

CALLER_TRACE = "4bf92f3577b34da6a3ce929d0e0e4736"
TRACEPARENT = f"00-{CALLER_TRACE}-00f067aa0ba902b7-01"

pytestmark = pytest.mark.skipif(
    not os.getenv("MIZAN_TEST_DATABASE_URL"), reason="Postgres not configured"
)


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _start(tmp_path: Path, port: int, metrics_port: int, identity_jwks: str):
    environment = os.environ | {
        "MIZAN_DATABASE_URL": os.environ["MIZAN_TEST_DATABASE_URL"],
        "MIZAN_JWT_ISSUER": DEVELOPMENT_ISSUER,
        "MIZAN_IDENTITY_JWKS": identity_jwks,
        "MIZAN_EVIDENCE_OBJECT_STORE_ROOT": str(tmp_path / "evidence"),
        "MIZAN_HTTP_HOST": "127.0.0.1",
        "MIZAN_HTTP_PORT": str(port),
        "MIZAN_METRICS_HOST": "127.0.0.1",
        "MIZAN_METRICS_PORT": str(metrics_port),
        "MIZAN_LOG_FORMAT": "json",
        "MIZAN_LOG_LEVEL": "INFO",
        "PYTHONPATH": "control-plane",
    }
    for key in ("MIZAN_TLS_CERTIFICATE_FILE", "MIZAN_TLS_PRIVATE_KEY_FILE", "MIZAN_TLS_CLIENT_CA_FILE"):
        environment.pop(key, None)
    return subprocess.Popen(
        [sys.executable, "-m", "mizan_control_plane"],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


def _await_ready(process, client: httpx.Client) -> None:
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


def _evaluation_context(profile: dict, bound: list[str], arguments: dict) -> dict:
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
        "security": {"anomaly_score": 0.0},
        "environment": "production",
        "timestamp": "2026-08-27T00:00:00Z",
    }


def test_the_trace_a_caller_sent_is_the_trace_the_signed_record_names(tmp_path: Path) -> None:
    """One id joins the caller's request, the response, the log line and the evidence row.

    The database is the assertion that matters. `mizan.adr_records.trace_id` is inside the hashed
    document, so this is the value an auditor reads years later out of a chained, anchored record —
    and the only reason it is worth anything is that it is the same value the caller's tracing
    backend has. Everything else here is a way of showing that one id reached all four places
    without being recomputed on the way.
    """
    identity_key, _public_pem = ensure_keypair(tmp_path / "identity")
    port, metrics_port = _free_port(), _free_port()
    process = _start(tmp_path, port, metrics_port, public_jwks(identity_key))
    client = httpx.Client(base_url=f"http://127.0.0.1:{port}", timeout=20)
    agent = {
        "Authorization": "Bearer "
        + mint(
            identity_key,
            tenant_id=TENANT,
            subject=CUSTOMER,
            agent_id=AGENT,
            identity_kind="agent",
            auth_strength="federated",
            roles=[],
            audience="mizan-control-plane",
            ttl_seconds=900,
        )
    }
    try:
        _await_ready(process, client)
        registered = client.get(f"/v1/tools/{TOOL}", headers=agent).json()["binding_profile"]
        profile = {
            "profile_id": registered["profile_id"],
            "profile_version": registered["profile_version"],
        }
        arguments = {"amount": 12500, "request_time": uuid.uuid4().hex}
        document = _evaluation_context(profile, registered["bound_pointers"], arguments)
        authorized = client.post(
            "/v1/authorize",
            json=document,
            headers=agent | {"traceparent": TRACEPARENT},
        )
        assert authorized.status_code == 200, authorized.text
        decision_id = authorized.json()["decision_id"]

        # 1. the response lets the caller join back
        assert authorized.headers["traceparent"].startswith(f"00-{CALLER_TRACE}-")
        assert authorized.headers["x-request-id"]

        # 2. the signed row names the caller's trace
        repository = PostgresAuthorizationRepository(os.environ["MIZAN_TEST_DATABASE_URL"])
        try:
            with repository.pool.connection() as connection, connection.transaction():
                repository._scope(connection, TENANT)
                row = connection.execute(
                    "SELECT trace_id, document FROM mizan.adr_records "
                    "WHERE tenant_id=%s AND decision_id=%s",
                    (TENANT, decision_id),
                ).fetchone()
        finally:
            repository.pool.close()
        assert row is not None, "the decision left no ADR_Record"
        stored_trace, stored_document = row
        assert stored_trace == CALLER_TRACE
        assert stored_document["trace_id"] == CALLER_TRACE
        assert len(stored_document["span_id"]) == 16

        # 3. the scrape is served on its own listener, and counted this decision
        with urllib.request.urlopen(
            f"http://127.0.0.1:{metrics_port}/metrics", timeout=10
        ) as body:
            exposition = body.read().decode()
        assert f'mizan_authorization_decisions_total{{decision="{authorized.json()["decision"]}"' in exposition
        assert f'tenant_id="{TENANT}"' in exposition
        assert 'route="/v1/authorize"' in exposition
        assert decision_id not in exposition, "an identifier must never become a label value"
    finally:
        process.terminate()
        output = process.communicate(timeout=30)[0]
        client.close()

    # 4. the log line for that request carries the trace and the tenant, as JSON
    lines = []
    for line in output.splitlines():
        try:
            lines.append(json.loads(line))
        except ValueError:
            continue
    assert lines, f"no JSON log lines were emitted:\n{output}"
    authorize_lines = [
        line for line in lines if line.get("http_route") == "/v1/authorize"
    ]
    assert authorize_lines, f"the authorize request was not logged:\n{output}"
    assert authorize_lines[0]["trace_id"] == CALLER_TRACE
    assert authorize_lines[0]["tenant_id"] == TENANT
    assert authorize_lines[0]["http_status"] == 200
    assert "arguments" not in output, "tool arguments must never reach a log line"
