"""The service must start. These tests run the composition root, not a hand-built app."""

from __future__ import annotations

import base64
import json
import sys
import time
from types import SimpleNamespace
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi.testclient import TestClient
from mizan_control_plane import attestation_runner
from mizan_control_plane.config import Settings
from mizan_control_plane.execution import ExecutionTokenCodec
from mizan_control_plane.keys import KEY_ROLES, development_key_provider
from mizan_control_plane.runtime import (
    StartupRefused,
    build_key_provider,
    build_runtime,
    spiffe_scope_protocol_class,
    verification_public_keys,
)

from tests.support import UNUSED_IDENTITY_JWKS

DEVELOPMENT_ENVIRONMENT = {
    "MIZAN_DATABASE_URL": "postgresql://mizan_app:unused@127.0.0.1:1/mizan",
    "MIZAN_JWT_ISSUER": "https://issuer.test",
    "MIZAN_IDENTITY_JWKS": UNUSED_IDENTITY_JWKS,
}


def development_settings(monkeypatch, tmp_path, **overrides: str) -> Settings:
    for name, value in DEVELOPMENT_ENVIRONMENT.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("MIZAN_EVIDENCE_OBJECT_STORE_ROOT", str(tmp_path / "evidence"))
    for name, value in overrides.items():
        monkeypatch.setenv(name, value)
    return Settings.from_environment()


def test_development_boot_wires_every_component_create_app_can_refuse_without(
    monkeypatch, tmp_path
) -> None:
    settings = development_settings(monkeypatch, tmp_path)
    runtime = build_runtime(settings)
    try:
        assert runtime.key_provider is not None
        assert runtime.evidence_verifier is not None
        assert runtime.execution_service is not None
        routes = {getattr(route, "path", None) for route in runtime.app.routes}
        assert {"/v1/authorize", "/health/live", "/health/ready", "/readyz"} <= routes
        # The pools this process owns are the ones it must close: four from create_app plus the
        # evidence repository and the execution service's two.
        assert len(runtime.app.state.connection_pools) == 7
    finally:
        for pool in runtime.app.state.connection_pools:
            pool.close()


def test_shutdown_closes_every_connection_pool(monkeypatch, tmp_path) -> None:
    settings = development_settings(monkeypatch, tmp_path)
    runtime = build_runtime(settings)
    pools = list(runtime.app.state.connection_pools)
    with TestClient(runtime.app):
        assert all(not pool.closed for pool in pools)
    assert all(pool.closed for pool in pools)


def test_readiness_reports_the_unreachable_database_rather_than_reporting_ok(
    monkeypatch, tmp_path
) -> None:
    settings = development_settings(monkeypatch, tmp_path)
    runtime = build_runtime(settings)
    with TestClient(runtime.app) as client:
        response = client.get("/health/ready")
        readyz = client.get("/readyz")
    assert response.status_code == 503
    assert readyz.status_code == response.status_code
    assert readyz.json() == response.json()
    body = response.json()
    assert body["status"] == "not_ready"
    assert body["checks"]["database"].startswith("unavailable")
    assert body["checks"]["signing_keys"] == "ok"
    assert body["checks"]["evidence_verifier"] == "ok"
    assert body["checks"]["evidence_reconciliation"] == "ok"
    assert body["checks"]["execution_service"] == "ok"


def test_production_refuses_to_start_without_a_real_key_backend(monkeypatch, tmp_path) -> None:
    """The refusal moved earlier, and now names the backend that exists.

    It used to happen in `build_key_provider`, which meant `MIZAN_KEY_CUSTODY_MODE=kms_hsm` --
    the spelling SPEC §8 used and no code ever read -- produced a `Settings` that parsed cleanly
    and a refusal only once something asked for a key. Now the value is enumerated where it is
    read, so an operator learns at configuration time that the control they set is not one the
    process understands. Both halves are asserted here: the unknown mode, and a known mode whose
    backend cannot actually be reached.
    """
    def production(**overrides: str):
        return development_settings(
            monkeypatch,
            tmp_path,
            MIZAN_ENV="production",
            MIZAN_ANCHOR_PROVIDER="rfc3161",
            MIZAN_ANCHOR_TSA_ENDPOINTS="https://tsa.example.test",
            MIZAN_ANCHOR_TSA_TRUST_ANCHORS=str(tmp_path / "root.pem"),
            MIZAN_EXECUTION_TOKEN_ISSUER="https://execution.issuer.test",
            MIZAN_EVALUATOR_BUILD="2026.08.26+abc1234",
            MIZAN_EVALUATOR_CONFIGURATION_HASH="a" * 64,
            MIZAN_TLS_CERTIFICATE_FILE=str(tmp_path / "server.pem"),
            MIZAN_TLS_PRIVATE_KEY_FILE=str(tmp_path / "server.key"),
            MIZAN_TLS_CLIENT_CA_FILE=str(tmp_path / "client-ca.pem"),
            # Production also requires an Object Lock bucket (B-21/T-104).
            MIZAN_EVIDENCE_OBJECT_STORE="s3",
            MIZAN_AUDIT_ANCHOR_BUCKET="mizan-evidence",
            **overrides,
        )

    with pytest.raises(RuntimeError, match="names no built backend"):
        production(
            MIZAN_KEY_CUSTODY_MODE="kms_hsm",
            MIZAN_EVIDENCE_RECEIPT_KEY_REF="kms://vault/receipt",
            MIZAN_EVIDENCE_ANCHOR_KEY_REF="kms://vault/anchor",
            MIZAN_EXECUTION_TOKEN_SIGNING_KEY_REF="kms://vault/execution",
            MIZAN_DEGRADED_GRANT_SIGNING_KEY_REF="kms://vault/degraded",
        )

    # And a real backend whose Vault is not there still refuses, rather than starting and failing
    # at the first signature -- which is what `build_key_provider` reading every public key at
    # startup buys.
    settings = production(
        MIZAN_KEY_CUSTODY_MODE="vault-transit",
        MIZAN_VAULT_ADDR="https://vault.invalid.test:8200",
        MIZAN_VAULT_TOKEN="s.unused",
        MIZAN_EVIDENCE_RECEIPT_KEY_REF="vault://transit/receipt#v1",
        MIZAN_EVIDENCE_ANCHOR_KEY_REF="vault://transit/anchor#v1",
        MIZAN_EXECUTION_TOKEN_SIGNING_KEY_REF="vault://transit/execution#v1",
        MIZAN_DEGRADED_GRANT_SIGNING_KEY_REF="vault://transit/degraded#v1",
    )
    with pytest.raises(StartupRefused, match="vault-transit key backend is not usable"):
        build_key_provider(settings)


def test_a_key_provider_signs_execution_tokens_without_exporting_private_material() -> None:
    provider = development_key_provider()
    codec = ExecutionTokenCodec(
        "https://execution.issuer.test",
        signing_key=provider.active_key("execution-token"),
    )
    header, payload, signature = _unsigned_parts(codec)
    assert json.loads(_b64decode(header)) == {"alg": "EdDSA", "typ": "JWT"}
    verified = jwt.decode(
        f"{header}.{payload}.{signature}",
        codec.public_key,
        algorithms=["EdDSA"],
        issuer="https://execution.issuer.test",
        audience="mizan-execution-gateway",
    )
    assert verified["tenant_id"] == "tnt_bank-a"
    assert codec.decode(f"{header}.{payload}.{signature}")["jti"] == verified["jti"]


def test_published_keyset_round_trips_into_verification_keys() -> None:
    provider = development_key_provider()
    keys = verification_public_keys(provider)
    assert len(keys) == len(KEY_ROLES)
    assert all(isinstance(item, Ed25519PublicKey) for item in keys.values())
    for role in KEY_ROLES:
        signing = provider.active_key(role)
        keys[signing.key_id].verify(signing.sign(b"payload"), b"payload")


def test_attest_anchors_entrypoint_builds_its_provider_and_returns(monkeypatch, tmp_path) -> None:
    development_settings(
        monkeypatch,
        tmp_path,
        MIZAN_ANCHOR_PROVIDER="rfc3161",
        MIZAN_ANCHOR_TSA_ENDPOINTS="https://tsa.example.test",
        MIZAN_ANCHOR_TSA_TRUST_ANCHORS=str(tmp_path / "root.pem"),
    )
    closed: list[bool] = []
    monkeypatch.setattr(
        attestation_runner,
        "EvidenceRepository",
        lambda url: SimpleNamespace(
            anchors=lambda tenant_id, stream_id: [],
            pool=SimpleNamespace(close=lambda: closed.append(True)),
        ),
    )
    # Invoked exactly as the console script invokes it, so the only thing under test is what the
    # entrypoint builds: on f4f90a2 this raises TypeError from Rfc3161AnchorProvider(environment=).
    monkeypatch.setattr(
        sys,
        "argv",
        ["mizan-attest-anchors", "--tenant-id", "tnt_bank-a", "--stream-id", "tnt_bank-a:adr:0", "--once"],
    )
    assert attestation_runner.main() == 0
    assert closed == [True]


def test_verified_peer_ssl_object_reaches_the_asgi_scope() -> None:
    protocol_class = spiffe_scope_protocol_class()
    protocol = protocol_class.__new__(protocol_class)
    ssl_object = object()
    protocol.transport = SimpleNamespace(
        get_extra_info=lambda name: ssl_object if name == "ssl_object" else None
    )
    protocol.scope = {"type": "http", "path": "/v1/actions/adr_x/execute"}
    assert protocol.scope["ssl_object"] is ssl_object
    protocol.scope = {"type": "lifespan"}
    assert "ssl_object" not in protocol.scope


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _unsigned_parts(codec: ExecutionTokenCodec) -> tuple[str, str, str]:
    claims: dict[str, Any] = {
        "token_version": "1.2",
        "jti": "f" * 32,
        "iss": codec.issuer,
        "aud": "mizan-execution-gateway",
        "tenant_id": "tnt_bank-a",
        "agent_id": "agt_wealth-01",
        "principal_id": "prn_alice-01",
        "delegation_chain_hash": "a" * 64,
        "authorized_executor": "spiffe://mizan/executor/wealth",
        "decision_id": "adr_" + "b" * 24,
        "tool_id": "tool_transfer",
        "parameters_hash": "c" * 64,
        "binding_profile": {"profile_id": "bp_transfer-v1", "profile_version": 1},
        "context_hash": "d" * 64,
        "approval_epoch_id": None,
        "iat": int(time.time()) - 10,
        "nbf": int(time.time()) - 10,
        "exp": int(time.time()) + 300,
    }
    return tuple(codec.encode(claims).split("."))  # type: ignore[return-value]


def test_the_approval_expiry_mode_defaults_to_enforced_and_refuses_anything_else(
    monkeypatch, tmp_path
) -> None:
    """A misspelled money-movement policy must not silently pick one of the two behaviours.

    `MIZAN_APPROVAL_EPOCH_EXPIRY=advisiory` reading as `enforced` would expire approvals at an
    institution that had written down that it does not, and the typo is invisible in a manifest.
    Refused at startup, where a person is still watching.
    """
    assert development_settings(monkeypatch, tmp_path).approval_epoch_expiry == "enforced"
    assert (
        development_settings(
            monkeypatch, tmp_path, MIZAN_APPROVAL_EPOCH_EXPIRY="ADVISORY"
        ).approval_epoch_expiry
        == "advisory"
    )
    with pytest.raises(RuntimeError, match="MIZAN_APPROVAL_EPOCH_EXPIRY"):
        development_settings(monkeypatch, tmp_path, MIZAN_APPROVAL_EPOCH_EXPIRY="advisiory")


def test_the_repository_refuses_to_sweep_under_a_deployment_that_does_not_expire(
    monkeypatch, tmp_path
) -> None:
    """A repository that quietly did nothing would make `advisory` look like a broken sweeper.

    The two are indistinguishable from the outside -- no approvals expire in either case -- so the
    only way an operator learns which one they have is if the wrong call is an error rather than a
    no-op. `run_once` never makes it; this is the guard for anything that does.
    """
    from mizan_control_plane.approval_repository import ApprovalRepository

    repository = ApprovalRepository.__new__(ApprovalRepository)
    repository.approval_epoch_expiry = "advisory"
    with pytest.raises(RuntimeError, match="advisory"):
        repository.sweep_expired_epochs("tnt_bank-a")


# ---------------------------------------------------------------------------------------------
# The key backend a deployment names (B-18 / T-102)
# ---------------------------------------------------------------------------------------------


def test_a_custody_mode_that_names_no_built_backend_is_refused_at_startup(
    monkeypatch, tmp_path
) -> None:
    """`kms_hsm` is the spelling SPEC §8 used and no code has ever read (B-20).

    An operator who sets it got a `Settings` that parsed, a process that started, and development
    keys signing their evidence -- the one outcome the setting exists to prevent. The refusal names
    the mode that would work rather than only rejecting the one that does not.
    """
    with pytest.raises(RuntimeError, match="names no built backend"):
        development_settings(monkeypatch, tmp_path, MIZAN_KEY_CUSTODY_MODE="kms_hsm")


def test_vault_transit_without_an_address_or_token_is_refused_before_any_request(
    monkeypatch, tmp_path
) -> None:
    with pytest.raises(RuntimeError, match="requires MIZAN_VAULT_ADDR"):
        development_settings(monkeypatch, tmp_path, MIZAN_KEY_CUSTODY_MODE="vault-transit")
    with pytest.raises(RuntimeError, match="MIZAN_VAULT_TOKEN"):
        development_settings(
            monkeypatch,
            tmp_path,
            MIZAN_KEY_CUSTODY_MODE="vault-transit",
            MIZAN_VAULT_ADDR="https://vault.test",
        )


def test_a_vault_token_can_come_from_a_file_so_it_is_not_in_the_environment(
    monkeypatch, tmp_path
) -> None:
    """A token in `os.environ` is a token in anything that dumps the environment into a log.

    A file is what a Kubernetes Secret mount and a Vault Agent sink both produce, and the trailing
    newline they both write is stripped here rather than sent to Vault as part of the credential.
    """
    token_file = tmp_path / "vault-token"
    token_file.write_text("s.from-a-file\n", encoding="utf-8")
    settings = development_settings(
        monkeypatch,
        tmp_path,
        MIZAN_KEY_CUSTODY_MODE="vault-transit",
        MIZAN_VAULT_ADDR="https://vault.test",
        MIZAN_VAULT_TOKEN_FILE=str(token_file),
    )
    assert settings.vault_token == "s.from-a-file"


def test_an_unreadable_token_file_is_refused_rather_than_treated_as_absent(
    monkeypatch, tmp_path
) -> None:
    """Silently falling back would start the process with whatever `MIZAN_VAULT_TOKEN` held."""
    with pytest.raises(RuntimeError, match="could not be read"):
        development_settings(
            monkeypatch,
            tmp_path,
            MIZAN_KEY_CUSTODY_MODE="vault-transit",
            MIZAN_VAULT_ADDR="https://vault.test",
            MIZAN_VAULT_TOKEN_FILE=str(tmp_path / "does-not-exist"),
        )


def test_every_production_requirement_is_reported_at_once(monkeypatch, tmp_path) -> None:
    """An operator bringing up a first deployment should not learn these serially.

    Raising on the first violation means fix, restart, next error, restart -- and each restart is
    a fresh chance to give up. It also let a newly added guard shadow every existing one: three
    production tests broke exactly that way while B-21's check was being written, each asserting a
    refusal that a newer guard had started firing before.
    """
    for name, value in {
        "MIZAN_DATABASE_URL": "postgresql://unused",
        "MIZAN_JWT_ISSUER": "urn:mizan:development:dev-token",
        "MIZAN_IDENTITY_JWKS": UNUSED_IDENTITY_JWKS,
        "MIZAN_ENV": "production",
        "MIZAN_EVIDENCE_OBJECT_STORE_ROOT": str(tmp_path / "evidence"),
    }.items():
        monkeypatch.setenv(name, value)

    with pytest.raises(RuntimeError) as refused:
        Settings.from_environment()

    reported = str(refused.value)
    assert reported.startswith("production configuration is not usable:")
    # Six independent things are wrong with this configuration and the operator is told all six.
    for requirement in (
        "MIZAN_EVIDENCE_OBJECT_STORE=s3",
        "development custody",
        "RFC 3161",
        "mizan-dev-token issuer",
        "MIZAN_EXECUTION_TOKEN_ISSUER",
        "MIZAN_TLS_CERTIFICATE_FILE",
    ):
        assert requirement in reported, requirement
