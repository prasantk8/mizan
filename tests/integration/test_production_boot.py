"""T-101's gate: `MIZAN_ENV=production` builds a runtime, and every other test asserted it could not.

This is the one assertion nothing in this repository had ever made. `ci.yml`'s only container boot
passed `--env MIZAN_ENV=development`, so `app.py`'s production readiness checks had never executed
anywhere, and the suite's production tests were all of the form *"production refuses X"* — a
complete set of refusals with no demonstration that anything is left that starts. A system that can
only be shown to refuse is indistinguishable from one that refuses everything.

Two guards pointed opposite ways for two weeks and neither was wrong on its own: `config.py`
refused `MIZAN_ENV=production` unless custody was **not** `development`, and `build_key_provider`
refused to build a provider unless custody **was** `development`. Between them no production
configuration existed, both shipped manifests named a third value (`kms`) that neither accepted,
and `__main__.py` turned any of it into exit 78 — the same exit code for "you misconfigured this"
and "this cannot be configured".

Everything here is real: a real PostgreSQL with the real schema, a real Vault over TLS holding real
Ed25519 keys it will not release, a real RFC 3161 trust root on disk. The only thing that is not
production is that the CA signing Vault's certificate is one the test made.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from mizan_control_plane.config import Settings
from mizan_control_plane.runtime import StartupRefused, build_runtime

from tests.support import UNUSED_IDENTITY_JWKS

DATABASE = os.getenv("MIZAN_TEST_DATABASE_URL", "")
VAULT = os.getenv("MIZAN_TEST_VAULT_ADDR", "")
TOKEN = os.getenv("MIZAN_TEST_VAULT_TOKEN", "")
CA = os.getenv("MIZAN_TEST_VAULT_CA_CERT", "")
S3_ENDPOINT = os.getenv("MIZAN_TEST_S3_ENDPOINT_URL", "")
S3_ACCESS_KEY = os.getenv("MIZAN_TEST_S3_ACCESS_KEY_ID", "")
S3_SECRET_KEY = os.getenv("MIZAN_TEST_S3_SECRET_ACCESS_KEY", "")
BUCKET = "mizan-production-boot"

pytestmark = pytest.mark.skipif(
    not (DATABASE and VAULT and TOKEN and S3_ENDPOINT),
    reason="production boot needs PostgreSQL, Vault and an Object Lock bucket",
)


@pytest.fixture(scope="module", autouse=True)
def evidence_bucket() -> None:
    """Production refuses a directory (B-21), so the boot gate needs a real Object Lock bucket.

    That is the correct coupling rather than an inconvenience: `"retention_class": "regulatory_7y"`
    is inside every record this system signs, and a gate that booted production onto an `emptyDir`
    would be proving that the configuration we refuse to ship still starts.
    """
    from mizan_control_plane.object_store import build_s3_client

    client = build_s3_client(S3_ENDPOINT, "us-east-1", S3_ACCESS_KEY, S3_SECRET_KEY)
    try:
        client.create_bucket(Bucket=BUCKET, ObjectLockEnabledForBucket=True)
    except Exception as error:
        if "BucketAlreadyOwnedByYou" not in str(error) and "BucketAlreadyExists" not in str(error):
            raise


def production_environment(tmp_path: Path, **overrides: str) -> dict[str, str]:
    """Everything `MIZAN_ENV=production` requires, and nothing it does not."""
    for name in ("server.pem", "server-key.pem", "client-ca.pem", "tsa-root.pem"):
        # Present and readable is all `Settings` asks of these: the TLS material is consumed by
        # uvicorn at listen time and the trust root by the attestation worker, neither of which
        # this test starts. What is under test is that production *builds*.
        (tmp_path / name).write_text("-----BEGIN CERTIFICATE-----\nplaceholder\n", encoding="utf-8")
    environment = {
        "MIZAN_ENV": "production",
        "MIZAN_DATABASE_URL": DATABASE,
        "MIZAN_JWT_ISSUER": "https://issuer.production.test",
        "MIZAN_IDENTITY_JWKS": UNUSED_IDENTITY_JWKS,
        "MIZAN_KEY_CUSTODY_MODE": "vault-transit",
        "MIZAN_VAULT_ADDR": VAULT,
        "MIZAN_VAULT_TOKEN": TOKEN,
        "MIZAN_VAULT_CA_CERT": CA,
        "MIZAN_EVIDENCE_RECEIPT_KEY_REF": "vault://transit/mizan-evidence-receipt#v1",
        "MIZAN_EVIDENCE_ANCHOR_KEY_REF": "vault://transit/mizan-evidence-anchor#v1",
        "MIZAN_EXECUTION_TOKEN_SIGNING_KEY_REF": "vault://transit/mizan-execution-token#v1",
        "MIZAN_DEGRADED_GRANT_SIGNING_KEY_REF": "vault://transit/mizan-degraded-grant#v1",
        "MIZAN_AUDIT_HMAC_KEY_REF": "vault://transit/mizan-audit-commitment#v1",
        "MIZAN_ANCHOR_PROVIDER": "rfc3161",
        "MIZAN_ANCHOR_TSA_ENDPOINTS": "https://tsa.example.test",
        "MIZAN_ANCHOR_TSA_TRUST_ANCHORS": str(tmp_path / "tsa-root.pem"),
        "MIZAN_EXECUTION_TOKEN_ISSUER": "https://execution.production.test",
        "MIZAN_EVALUATOR_BUILD": "2026.08.30+t101prod",
        "MIZAN_EVALUATOR_CONFIGURATION_HASH": "b" * 64,
        "MIZAN_TLS_CERTIFICATE_FILE": str(tmp_path / "server.pem"),
        "MIZAN_TLS_PRIVATE_KEY_FILE": str(tmp_path / "server-key.pem"),
        "MIZAN_TLS_CLIENT_CA_FILE": str(tmp_path / "client-ca.pem"),
        "MIZAN_EVIDENCE_OBJECT_STORE_ROOT": str(tmp_path / "evidence"),
        "MIZAN_EVIDENCE_OBJECT_STORE": "s3",
        "MIZAN_AUDIT_ANCHOR_BUCKET": BUCKET,
        "MIZAN_S3_ENDPOINT_URL": S3_ENDPOINT,
        "MIZAN_S3_ACCESS_KEY_ID": S3_ACCESS_KEY,
        "MIZAN_S3_SECRET_ACCESS_KEY": S3_SECRET_KEY,
    }
    environment.update(overrides)
    return environment


@pytest.fixture
def production(monkeypatch, tmp_path):
    def build(**overrides: str) -> Settings:
        for name, value in production_environment(tmp_path, **overrides).items():
            monkeypatch.setenv(name, value)
        return Settings.from_environment()

    return build


def test_production_builds_a_runtime(production) -> None:
    """The assertion nothing in this repository had ever made.

    Fails on the pre-fix SHA with `StartupRefused: key custody mode 'vault-transit' names no built
    backend. KmsHsmKeyProvider exists but has no implementation to inject; see T-076 and blocker
    B-18.` -- and fails there for *every* value of `MIZAN_KEY_CUSTODY_MODE`, which is the point:
    production had no configuration that started.
    """
    runtime = build_runtime(production())
    try:
        assert runtime.settings.is_production
        assert runtime.app.routes, "a runtime with no routes is not a control plane"

        # Signing works, and its custody is what the exported bundle will claim. This is the
        # difference between "the process started" and "the process can do the thing it exists
        # for": a control plane that boots and cannot sign evidence is not a degraded Mizan.
        keyset = runtime.key_provider.verification_keyset()
        assert {document["custody"] for document in keyset} == {"kms"}
        assert not any(document["key_id"].startswith("local://") for document in keyset)
        signature = runtime.key_provider.active_key("evidence-receipt").sign(b"production boot")
        assert len(signature) == 64
    finally:
        for pool in getattr(runtime.app.state, "connection_pools", []):
            pool.close()


def test_production_refuses_a_directory_for_evidence(production) -> None:
    """B-21. `LocalImmutableObjectStore` calls itself a development WORM analogue in its docstring.

    The chart mounted it as an `emptyDir` under `replicaCount: 2`, so a rollout destroyed the
    corpus -- while every record written claimed `regulatory_7y`.
    """
    with pytest.raises(RuntimeError, match="MIZAN_EVIDENCE_OBJECT_STORE=s3"):
        production(MIZAN_EVIDENCE_OBJECT_STORE="local")


def test_production_still_refuses_development_custody(production) -> None:
    """The refusals are not what broke; the absence of anything else was.

    Asserted beside the boot rather than in another file so that a change which makes production
    start by loosening a guard fails here instead of quietly passing both.
    """
    with pytest.raises(RuntimeError, match="production refuses development custody"):
        production(
            MIZAN_KEY_CUSTODY_MODE="development",
            MIZAN_EVIDENCE_RECEIPT_KEY_REF="local://evidence-receipt/dev-1",
            MIZAN_EVIDENCE_ANCHOR_KEY_REF="local://evidence-anchor/dev-1",
            MIZAN_EXECUTION_TOKEN_SIGNING_KEY_REF="local://execution-token/dev-1",
            MIZAN_DEGRADED_GRANT_SIGNING_KEY_REF="local://degraded-grant/dev-1",
            MIZAN_AUDIT_HMAC_KEY_REF="local://audit-commitment/dev-1",
        )


def test_production_refuses_a_plaintext_vault(production) -> None:
    """The token is a bearer credential for every key that signs this tenant's evidence."""
    plaintext = VAULT.replace("https://", "http://")
    with pytest.raises(RuntimeError, match="https:// MIZAN_VAULT_ADDR"):
        production(MIZAN_VAULT_ADDR=plaintext)


def test_a_production_runtime_that_cannot_reach_vault_refuses_rather_than_starting(
    production,
) -> None:
    """Reading every public key at startup is what buys this.

    Deferred to the first signature instead, the process would report itself ready, accept
    authorizations, and refuse every financial write once the drainer could not publish -- with a
    symptom (`immutable_receipt_missing`) that names nothing about Vault.
    """
    with pytest.raises(StartupRefused, match="vault-transit key backend is not usable"):
        build_runtime(production(MIZAN_VAULT_ADDR="https://vault.unreachable.invalid:8200"))


def test_the_readiness_probe_reports_what_this_process_can_actually_do(production) -> None:
    """`app.py`'s production readiness checks had never executed anywhere.

    CI's only container boot passed `--env MIZAN_ENV=development`, so the branch that reports
    signing-key health in production was unreachable by every gate in the repository.
    """
    from fastapi.testclient import TestClient

    runtime = build_runtime(production())
    try:
        with TestClient(runtime.app) as client:
            body = client.get("/health/ready").json()
        assert body["checks"]["database"] == "ok"
        assert body["checks"]["signing_keys"] == "ok"
    finally:
        for pool in getattr(runtime.app.state, "connection_pools", []):
            pool.close()
