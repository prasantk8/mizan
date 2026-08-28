from __future__ import annotations

import ssl
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from mizan_control_plane.keys import local_private_key_for_testing
from mizan_control_plane.mtls import VerifiedPeerSpiffeMiddleware, require_workload_spiffe
from mizan_control_plane.problems import Problem, problem_response


class VerifiedSslObject:
    def __init__(self, certificate: bytes) -> None:
        self.context = SimpleNamespace(verify_mode=ssl.CERT_REQUIRED)
        self.certificate = certificate

    def getpeercert(self, binary_form: bool = False):
        assert binary_form
        return self.certificate


class InjectSslObject:
    def __init__(self, app: Any, ssl_object: Any) -> None:
        self.app = app
        self.ssl_object = ssl_object

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        scope = dict(scope)
        scope["ssl_object"] = self.ssl_object
        await self.app(scope, receive, send)


def client_certificate(uri_san: str | None) -> bytes:
    key = local_private_key_for_testing(f"mtls-{uri_san}")
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ignored-cn")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
        .not_valid_after(datetime.now(UTC) + timedelta(minutes=5))
    )
    if uri_san is not None:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(uri_san)]),
            critical=False,
        )
    return builder.sign(key, algorithm=None).public_bytes(serialization.Encoding.DER)


def execution_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(VerifiedPeerSpiffeMiddleware)
    app.add_exception_handler(Problem, problem_response)

    @app.post("/v1/actions/{decision_id}/execute")
    def execute(decision_id: str, request: Request) -> dict[str, str]:
        return {
            "decision_id": decision_id,
            "authorized_executor": require_workload_spiffe(request.scope),
        }

    return app


def test_a_verified_peer_certificate_populates_the_execution_workload_identity() -> None:
    """Unit scope: one URI SAN out of one certificate.

    The end-to-end claim — a real client certificate over a real mutually authenticated
    connection reaching a real execution route — belongs to
    `integration/test_closed_loop_postgres.py::test_an_agent_pauses_for_two_approvers_and_then_executes`,
    which drives the shipped binary. This test injects an SSL object and proves only the parsing.
    """
    certificate = client_certificate("spiffe://mizan/executor/settlement")
    app = InjectSslObject(execution_app(), VerifiedSslObject(certificate))
    response = TestClient(app).post("/v1/actions/adr_decision-0001/execute")
    assert response.status_code == 200
    assert response.json()["authorized_executor"] == "spiffe://mizan/executor/settlement"


def test_missing_peer_certificate_is_401() -> None:
    response = TestClient(execution_app()).post("/v1/actions/adr_decision-0001/execute")
    assert response.status_code == 401
    assert response.json()["title"] == "Workload Identity Missing"


def test_certificate_without_spiffe_uri_san_is_401() -> None:
    certificate = client_certificate(None)
    app = InjectSslObject(execution_app(), VerifiedSslObject(certificate))
    response = TestClient(app).post("/v1/actions/adr_decision-0001/execute")
    assert response.status_code == 401
