"""The gate for T-066: the shipped console script starts and reports what it can actually do."""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from mizan_control_plane.config import Settings
from mizan_control_plane.runtime import build_runtime

BOOT_DEADLINE_SECONDS = 30


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _service_environment(tmp_path: Path, port: int) -> dict[str, str]:
    return os.environ | {
        "MIZAN_DATABASE_URL": os.environ["MIZAN_TEST_DATABASE_URL"],
        "MIZAN_JWT_ISSUER": "https://issuer.mizan.test",
        "MIZAN_JWT_PUBLIC_KEY": "unused-by-readiness",
        "MIZAN_EVIDENCE_OBJECT_STORE_ROOT": str(tmp_path / "evidence"),
        "MIZAN_HTTP_HOST": "127.0.0.1",
        "MIZAN_HTTP_PORT": str(port),
        "PYTHONPATH": "control-plane",
    }


@pytest.mark.skipif(not os.getenv("MIZAN_TEST_DATABASE_URL"), reason="Postgres not configured")
def test_console_script_boots_and_reports_ready_against_a_real_database(tmp_path: Path) -> None:
    port = _free_port()
    process = subprocess.Popen(
        [sys.executable, "-m", "mizan_control_plane", "--log-level", "warning"],
        env=_service_environment(tmp_path, port),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        body = _await_readiness(process, port)
        assert body["status"] == "ready"
        assert body["checks"] == {
            "database": "ok",
            "signing_keys": "ok",
            "evidence_verifier": "ok",
            "execution_service": "ok",
        }
        live = httpx.get(f"http://127.0.0.1:{port}/health/live", timeout=5)
        assert live.status_code == 200
    finally:
        process.terminate()
        process.wait(timeout=15)


def _await_readiness(process: subprocess.Popen[str], port: int) -> dict:
    deadline = time.monotonic() + BOOT_DEADLINE_SECONDS
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(f"service exited {process.returncode}: {process.communicate()[0]}")
        try:
            response = httpx.get(f"http://127.0.0.1:{port}/health/ready", timeout=2)
        except httpx.TransportError:
            time.sleep(0.2)
            continue
        if response.status_code == 200:
            return response.json()
        time.sleep(0.2)
    process.terminate()
    raise AssertionError(f"service never became ready: {process.communicate()[0]}")


@pytest.mark.skipif(not os.getenv("MIZAN_TEST_DATABASE_URL"), reason="Postgres not configured")
def test_shutdown_returns_every_connection_to_the_database(tmp_path: Path) -> None:
    environment = _service_environment(tmp_path, _free_port())
    for name, value in environment.items():
        if name.startswith("MIZAN_"):
            os.environ[name] = value
    runtime = build_runtime(Settings.from_environment())
    pools = list(runtime.app.state.connection_pools)
    with TestClient(runtime.app) as client:
        assert client.get("/health/ready").status_code == 200
        assert all(not pool.closed for pool in pools)
    assert all(pool.closed for pool in pools)
