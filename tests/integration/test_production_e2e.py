"""T-131: the production journey, from authorization through two independent verifiers."""

from __future__ import annotations

import json
import os
import ssl
import subprocess
import sys
import threading
import uuid
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import jwt
import pytest
from mizan_control_plane.attestation import AnchorAttestationWorker, Rfc3161AnchorProvider
from mizan_control_plane.attestation_runner import ReportingEvidenceBreaker
from mizan_control_plane.config import Settings
from mizan_control_plane.dev_token import DEFAULT_KEY_ID, ensure_keypair, public_jwks
from mizan_control_plane.drain_worker import run_once
from mizan_control_plane.evidence import Ed25519EvidenceSigner, EvidenceRepository, OutboxPublisher
from mizan_control_plane.evidence_export import export_evidence_bundle
from mizan_control_plane.object_store import (
    S3ObjectLockStore,
    build_s3_client,
    provision_object_lock_bucket,
)
from mizan_control_plane.runtime import build_key_provider, verification_public_keys
from mizan_control_plane.workforce import COOKIE_NAME, WorkforceSessionRepository

from tests.integration.test_closed_loop_postgres import (
    AGENT,
    CUSTOMER,
    EXECUTOR,
    TENANT,
    activate_policy,
    await_ready,
    evaluation_context,
    workload_pki,
)

DATABASE = os.getenv("MIZAN_TEST_DATABASE_URL", "")
VAULT = os.getenv("MIZAN_TEST_VAULT_ADDR", "")
VAULT_TOKEN = os.getenv("MIZAN_TEST_VAULT_TOKEN", "")
VAULT_CA = os.getenv("MIZAN_TEST_VAULT_CA_CERT", "")
S3_ENDPOINT = os.getenv("MIZAN_TEST_S3_ENDPOINT_URL", "")
S3_ACCESS_KEY = os.getenv("MIZAN_TEST_S3_ACCESS_KEY_ID", "")
S3_SECRET_KEY = os.getenv("MIZAN_TEST_S3_SECRET_ACCESS_KEY", "")
BUCKET = "mizan-production-e2e"
STREAM = f"{TENANT}:adr:0"

pytestmark = pytest.mark.skipif(
    not (DATABASE and VAULT and VAULT_TOKEN and VAULT_CA and S3_ENDPOINT),
    reason="production E2E needs PostgreSQL, TLS Vault and an Object Lock store",
)


def _run(*command: str) -> None:
    subprocess.run(command, check=True, capture_output=True)


def _make_tsa(root: Path) -> tuple[ThreadingHTTPServer, Path]:
    """Start a local HTTPS RFC 3161 authority with separate TLS and timestamping keys."""
    root.mkdir()
    ca_key, ca_cert = root / "ca.key", root / "ca.pem"
    tsa_key, tsa_csr, tsa_cert = root / "tsa.key", root / "tsa.csr", root / "tsa.pem"
    tls_key, tls_csr, tls_cert = root / "tls.key", root / "tls.csr", root / "tls.pem"
    serial, config = root / "tsa.srl", root / "tsa.cnf"
    _run(
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout",
        str(ca_key), "-out", str(ca_cert), "-days", "1", "-subj", "/CN=Mizan E2E TSA Root",
        "-addext", "basicConstraints=critical,CA:TRUE",
    )
    _run(
        "openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout",
        str(tsa_key), "-out", str(tsa_csr), "-subj", "/CN=Mizan E2E Timestamp Signer",
    )
    (root / "tsa.ext").write_text(
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
        "extendedKeyUsage=critical,timeStamping\n",
        encoding="utf-8",
    )
    _run(
        "openssl", "x509", "-req", "-in", str(tsa_csr), "-CA", str(ca_cert),
        "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(tsa_cert), "-days", "1",
        "-extfile", str(root / "tsa.ext"),
    )
    _run(
        "openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout",
        str(tls_key), "-out", str(tls_csr), "-subj", "/CN=127.0.0.1",
    )
    (root / "tls.ext").write_text(
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n",
        encoding="utf-8",
    )
    _run(
        "openssl", "x509", "-req", "-in", str(tls_csr), "-CA", str(ca_cert),
        "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(tls_cert), "-days", "1",
        "-extfile", str(root / "tls.ext"),
    )
    serial.write_text("01\n", encoding="utf-8")
    config.write_text(
        "\n".join(
            [
                "[tsa]", "default_tsa=tsa_config1", "[tsa_config1]", f"serial={serial}",
                "crypto_device=builtin", f"signer_cert={tsa_cert}", f"certs={ca_cert}",
                f"signer_key={tsa_key}", "signer_digest=sha256", "default_policy=1.2.3.4.1",
                "digests=sha256", "accuracy=secs:1", "ordering=yes", "tsa_name=yes",
                "ess_cert_id_chain=no",
            ]
        ),
        encoding="utf-8",
    )

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            query = root / f"{uuid.uuid4().hex}.tsq"
            reply = query.with_suffix(".tsr")
            query.write_bytes(self.rfile.read(int(self.headers["Content-Length"])))
            completed = subprocess.run(
                [
                    "openssl", "ts", "-reply", "-queryfile", str(query),
                    "-config", str(config), "-out", str(reply),
                ],
                check=False,
                capture_output=True,
            )
            if completed.returncode:
                self.send_error(500, completed.stderr.decode()[:200])
                return
            body = reply.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/timestamp-reply")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(tls_cert, tls_key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, ca_cert


def _environment(tmp_path: Path, pki: dict[str, Path], jwks: str, tsa: str, tsa_root: Path) -> dict[str, str]:
    return {
        "MIZAN_ENV": "production",
        "MIZAN_DATABASE_URL": DATABASE,
        "MIZAN_JWT_ISSUER": "https://customer-idp.production.test",
        "MIZAN_IDENTITY_JWKS": jwks,
        "MIZAN_KEY_CUSTODY_MODE": "vault-transit",
        "MIZAN_VAULT_ADDR": VAULT,
        "MIZAN_VAULT_TOKEN": VAULT_TOKEN,
        "MIZAN_VAULT_CA_CERT": VAULT_CA,
        "MIZAN_EVIDENCE_RECEIPT_KEY_REF": "vault://transit/mizan-evidence-receipt#v1",
        "MIZAN_EVIDENCE_ANCHOR_KEY_REF": "vault://transit/mizan-evidence-anchor#v1",
        "MIZAN_EXECUTION_TOKEN_SIGNING_KEY_REF": "vault://transit/mizan-execution-token#v1",
        "MIZAN_DEGRADED_GRANT_SIGNING_KEY_REF": "vault://transit/mizan-degraded-grant#v1",
        "MIZAN_ANCHOR_PROVIDER": "rfc3161",
        "MIZAN_ANCHOR_TSA_ENDPOINTS": tsa,
        "MIZAN_ANCHOR_TSA_TRUST_ANCHORS": str(tsa_root),
        "MIZAN_EXECUTION_TOKEN_ISSUER": "https://execution.production.test",
        "MIZAN_EVALUATOR_BUILD": "2026.09.01+t131",
        "MIZAN_EVALUATOR_CONFIGURATION_HASH": "b" * 64,
        "MIZAN_TLS_CERTIFICATE_FILE": str(pki["server_certificate"]),
        "MIZAN_TLS_PRIVATE_KEY_FILE": str(pki["server_key"]),
        "MIZAN_TLS_CLIENT_CA_FILE": str(pki["ca"]),
        "MIZAN_EVIDENCE_OBJECT_STORE": "s3",
        "MIZAN_AUDIT_ANCHOR_BUCKET": BUCKET,
        "MIZAN_S3_ENDPOINT_URL": S3_ENDPOINT,
        "MIZAN_S3_ACCESS_KEY_ID": S3_ACCESS_KEY,
        "MIZAN_S3_SECRET_ACCESS_KEY": S3_SECRET_KEY,
        "MIZAN_WORKFORCE_OIDC_AUTHORIZATION_ENDPOINT": "https://customer-idp.production.test/authorize",
        "MIZAN_WORKFORCE_OIDC_TOKEN_ENDPOINT": "https://customer-idp.production.test/token",
        "MIZAN_WORKFORCE_OIDC_CLIENT_ID": "mizan-console",
        "MIZAN_WORKFORCE_OIDC_CLIENT_SECRET": "e2e-only-secret",
        "MIZAN_WORKFORCE_OIDC_REDIRECT_URI": "https://mizan.production.test/auth/callback",
        "MIZAN_WORKFORCE_TENANT_ID": TENANT,
        "MIZAN_WORKFORCE_ROLE_MAPPING": json.dumps(
            {
                "customer-ops": {"roles": ["manager"], "control_domain": "business.ops"},
                "customer-risk": {"roles": ["manager"], "control_domain": "risk.control"},
            }
        ),
        "MIZAN_HTTP_HOST": "127.0.0.1",
        "MIZAN_HTTP_PORT": "18787",
        "PYTHONPATH": "control-plane",
    }


def _verdict(command: list[str]) -> dict:
    completed = subprocess.run(command, check=False, capture_output=True, text=True)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    return json.loads(completed.stdout)


def test_production_journey_attests_exports_and_both_verifiers_agree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    activate_policy(DATABASE)
    pki = workload_pki(tmp_path / "pki")
    identity_key, _ = ensure_keypair(tmp_path / "identity")
    tsa_server, tsa_root = _make_tsa(tmp_path / "tsa")
    tsa_url = f"https://127.0.0.1:{tsa_server.server_address[1]}/timestamp"
    environment = os.environ | _environment(tmp_path, pki, public_jwks(identity_key), tsa_url, tsa_root)
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("SSL_CERT_FILE", str(tsa_root))

    s3 = build_s3_client(S3_ENDPOINT, "us-east-1", S3_ACCESS_KEY, S3_SECRET_KEY)
    provision_object_lock_bucket(s3, BUCKET, "us-east-1", 365)
    process = subprocess.Popen(
        [sys.executable, "-m", "mizan_control_plane", "--log-level", "warning"],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    trust = ssl.create_default_context(cafile=str(pki["ca"]))
    trust.load_cert_chain(str(pki["client_certificate"]), str(pki["client_key"]))
    client = httpx.Client(base_url="https://127.0.0.1:18787", verify=trust, timeout=20)
    now = datetime.now(UTC)
    agent_token = jwt.encode(
        {
            "iss": "https://customer-idp.production.test",
            "aud": "mizan-control-plane",
            "sub": CUSTOMER,
            "tenant_id": TENANT,
            "agent_id": AGENT,
            "identity_kind": "agent",
            "auth_strength": "federated",
            "roles": [],
            "delegation_chain": [AGENT],
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=5)).timestamp()),
        },
        identity_key,
        algorithm="EdDSA",
        headers={"kid": DEFAULT_KEY_ID},
    )
    agent = {"Authorization": f"Bearer {agent_token}"}
    evidence = EvidenceRepository(DATABASE)
    sessions = WorkforceSessionRepository(DATABASE, evidence)
    settings = Settings.from_environment()
    provider = build_key_provider(settings)
    store = S3ObjectLockStore(BUCKET, client=s3, retention_years=1)
    timestamps = Rfc3161AnchorProvider([tsa_url], trust_anchors=[tsa_root])
    publisher = OutboxPublisher(
        evidence,
        store,
        Ed25519EvidenceSigner(provider.active_key("evidence-receipt")),
        Ed25519EvidenceSigner(provider.active_key("evidence-anchor")),
        anchor_provider=timestamps,
    )
    try:
        await_ready(process, client)
        arguments = {"amount": 12500, "request_time": uuid.uuid4().hex}
        authorized = client.post(
            "/v1/authorize",
            json=evaluation_context(
                arguments,
                {"profile_id": "bp_transfer-v1", "profile_version": 1},
                ["/amount"],
            ),
            headers=agent,
        )
        assert authorized.status_code == 200, authorized.text
        decision = authorized.json()
        assert decision["decision"] == "REQUIRE_APPROVAL"
        assert decision["approval"]["status"] == "PENDING"
        decision_id = decision["decision_id"]
        approval_id = decision["approval"]["approval_id"]

        def workforce_cookie(principal_id: str, domain: str, stepped_up: bool) -> str:
            from mizan_control_plane.models import AuthenticatedPrincipal

            principal = AuthenticatedPrincipal(
                tenant_id=TENANT,
                principal_id=principal_id,
                identity_kind="human",
                auth_strength="hardware",
                roles=["manager"],
                control_domains={"manager": domain},
            )
            return sessions.create_session(
                TENANT, principal, f"idp-{principal_id}", 300, stepped_up, None
            )[0]

        stale_cookie = workforce_cookie("prn_alice", "business.ops", False)
        queue = client.get(
            "/v1/approvals", params={"state": "PENDING"},
            headers={"Cookie": f"{COOKIE_NAME}={stale_cookie}"},
        )
        assert queue.status_code == 200
        assert any(item["approval_id"] == approval_id for item in queue.json()["items"])
        refused = client.post(
            f"/v1/approvals/{approval_id}/votes",
            json={"epoch_number": 1, "vote": "APPROVE"},
            headers={"Cookie": f"{COOKIE_NAME}={stale_cookie}"},
        )
        assert refused.status_code == 403
        assert refused.json()["type"].endswith("workforce_step_up_required")

        for principal_id, domain in (
            ("prn_alice", "business.ops"),
            ("prn_bob", "risk.control"),
        ):
            cookie = workforce_cookie(principal_id, domain, True)
            vote = client.post(
                f"/v1/approvals/{approval_id}/votes",
                json={"epoch_number": 1, "vote": "APPROVE"},
                headers={"Cookie": f"{COOKIE_NAME}={cookie}"},
            )
            assert vote.status_code == 200, vote.text
        assert vote.json()["state"] == "APPROVED"

        issued = client.post(
            f"/v1/decisions/{decision_id}/execution-token",
            json={"executor_spiffe_id": EXECUTOR},
            headers=agent,
        )
        assert issued.status_code == 200, issued.text
        execution_token = issued.json()["execution_token"]
        assert execution_token

        first = run_once(publisher, evidence, [TENANT], 100, 5)
        assert first.published > 0 and evidence.receipt_rows(TENANT, STREAM)

        executed = client.post(
            f"/v1/actions/{decision_id}/execute",
            json={"execution_token": execution_token, "arguments": arguments},
            headers=agent,
        )
        assert executed.status_code == 200, executed.text
        lease = executed.json()
        assert lease["state"] == "LEASED" and lease["authorized_executor"] == EXECUTOR
        completed = client.post(
            f"/v1/actions/{decision_id}/lease/{lease['lease_id']}/complete",
            json={"result_hash": "c" * 64},
            headers=agent,
        )
        assert completed.status_code == 200, completed.text
        assert completed.json()["state"] == "EXECUTED"

        second = run_once(publisher, evidence, [TENANT], 100, 5)
        assert second.published > 0
        breaker = ReportingEvidenceBreaker()
        rows = evidence.anchors(TENANT, STREAM)
        assert rows and AnchorAttestationWorker(evidence, timestamps, breaker).process(
            TENANT, rows, 30
        ) == len(rows)
        assert not breaker.opened
        assert all(
            row["attestations"]
            and all(item["status"] == "attested" for item in row["attestations"])
            for row in evidence.anchors(TENANT, STREAM)
        )

        bundle = tmp_path / "production-bundle"
        export_evidence_bundle(
            evidence,
            store,
            verification_public_keys(provider),
            TENANT,
            STREAM,
            bundle,
            key_documents=provider.verification_keyset(),
        )
        manifest = json.loads((bundle / "manifest.json").read_bytes())
        assert manifest["range"]["to_sequence"] >= manifest["range"]["from_sequence"]
        assert manifest["assurance"] == {
            "anchor_attestation": "rfc3161",
            "external_timestamp": True,
        }
        python = _verdict(
            [
                sys.executable, "scripts/verify_evidence_export.py", str(bundle), "--json",
                "--tsa-trust-anchor", str(tsa_root),
            ]
        )
        javascript = _verdict(
            [
                "node", "verifier-two/bin/mizan-verify-two.js", str(bundle), "--json",
                "--trust-root", str(tsa_root),
            ]
        )
        assert python["verdict"] == javascript["verdict"] == "VALID"
        assert python["derived_assurance"] == javascript["derived_assurance"]
    finally:
        client.close()
        process.terminate()
        process.wait(timeout=15)
        sessions.pool.close()
        evidence.pool.close()
        tsa_server.shutdown()
