from __future__ import annotations

import pytest
from mizan_control_plane.config import Settings
from mizan_control_plane.keys import (
    KEY_ROLES,
    KeyVersion,
    KmsHsmKeyProvider,
    LocalKeyProvider,
    local_private_key_for_testing,
)


def versions(*, revoked_receipt: bool = False) -> list[KeyVersion]:
    now = "2026-08-25T00:00:00Z"
    return [
        KeyVersion(
            f"local://{role}/v1",
            role,
            now,
            revoked_at="2026-08-25T01:00:00Z" if revoked_receipt and role == "evidence-receipt" else None,
        )
        for role in KEY_ROLES
    ]


def test_production_refuses_local_keys_at_startup(monkeypatch) -> None:
    monkeypatch.setenv("MIZAN_DATABASE_URL", "postgresql://unused")
    monkeypatch.setenv("MIZAN_JWT_ISSUER", "https://issuer.test")
    monkeypatch.setenv("MIZAN_JWT_PUBLIC_KEY", "unused")
    monkeypatch.setenv("MIZAN_ENV", "production")
    monkeypatch.setenv("MIZAN_KEY_CUSTODY_MODE", "development")
    with pytest.raises(RuntimeError, match="production refuses"):
        Settings.from_environment()


def test_local_provider_refuses_production_even_when_key_ids_claim_kms() -> None:
    disguised = [
        KeyVersion(f"kms://disguised/{role}", role, "2026-08-25T00:00:00Z")
        for role in KEY_ROLES
    ]
    with pytest.raises(RuntimeError, match="development-derived"):
        LocalKeyProvider(disguised, environment="production")


def test_production_requires_rfc3161_provider_and_endpoint(monkeypatch) -> None:
    monkeypatch.setenv("MIZAN_DATABASE_URL", "postgresql://unused")
    monkeypatch.setenv("MIZAN_JWT_ISSUER", "https://issuer.test")
    monkeypatch.setenv("MIZAN_JWT_PUBLIC_KEY", "unused")
    monkeypatch.setenv("MIZAN_ENV", "production")
    monkeypatch.setenv("MIZAN_KEY_CUSTODY_MODE", "kms_hsm")
    refs = {
        "MIZAN_EVIDENCE_RECEIPT_KEY_REF": "kms://vault/receipt",
        "MIZAN_EVIDENCE_ANCHOR_KEY_REF": "kms://vault/anchor",
        "MIZAN_EXECUTION_TOKEN_SIGNING_KEY_REF": "kms://vault/execution",
        "MIZAN_DEGRADED_GRANT_SIGNING_KEY_REF": "kms://vault/degraded",
    }
    for name, value in refs.items():
        monkeypatch.setenv(name, value)
    with pytest.raises(RuntimeError, match="RFC 3161"):
        Settings.from_environment()
    monkeypatch.setenv("MIZAN_ANCHOR_PROVIDER", "rfc3161")
    monkeypatch.setenv("MIZAN_ANCHOR_TSA_ENDPOINTS", "https://tsa.example.test")
    with pytest.raises(RuntimeError, match="trust anchor"):
        Settings.from_environment()
    monkeypatch.setenv("MIZAN_ANCHOR_TSA_TRUST_ANCHORS", "/etc/mizan/tsa-root.pem")
    assert Settings.from_environment().anchor_provider == "rfc3161"


def test_production_refuses_non_tls_tsa_endpoint(monkeypatch) -> None:
    monkeypatch.setenv("MIZAN_DATABASE_URL", "postgresql://unused")
    monkeypatch.setenv("MIZAN_JWT_ISSUER", "https://issuer.test")
    monkeypatch.setenv("MIZAN_JWT_PUBLIC_KEY", "unused")
    monkeypatch.setenv("MIZAN_ENV", "production")
    monkeypatch.setenv("MIZAN_KEY_CUSTODY_MODE", "kms_hsm")
    for role, name in zip(KEY_ROLES, (
        "MIZAN_EVIDENCE_RECEIPT_KEY_REF", "MIZAN_EVIDENCE_ANCHOR_KEY_REF",
        "MIZAN_EXECUTION_TOKEN_SIGNING_KEY_REF", "MIZAN_DEGRADED_GRANT_SIGNING_KEY_REF",
    ), strict=True):
        monkeypatch.setenv(name, f"kms://vault/{role}")
    monkeypatch.setenv("MIZAN_ANCHOR_PROVIDER", "rfc3161")
    monkeypatch.setenv("MIZAN_ANCHOR_TSA_ENDPOINTS", "http://tsa.example.test")
    monkeypatch.setenv("MIZAN_ANCHOR_TSA_TRUST_ANCHORS", "/etc/mizan/tsa-root.pem")

    with pytest.raises(RuntimeError, match="HTTPS"):
        Settings.from_environment()


def test_four_roles_are_distinct_and_rotation_has_no_resign_capability() -> None:
    provider = LocalKeyProvider(versions())
    keys = [provider.active_key(role) for role in KEY_ROLES]
    assert len({key.key_id for key in keys}) == 4
    assert set(vars(type(provider))) >= {"active_key", "verification_keyset"}
    assert "resign" not in vars(type(provider))


def test_revoked_version_remains_in_verification_keyset() -> None:
    old = KeyVersion(
        "local://evidence-receipt/v0",
        "evidence-receipt",
        "2026-08-24T00:00:00Z",
        not_after="2026-08-25T00:00:00Z",
        revoked_at="2026-08-25T01:00:00Z",
    )
    provider = LocalKeyProvider([old, *versions()])
    documents = {item["key_id"]: item for item in provider.verification_keyset()}
    assert documents[old.key_id]["revoked_at"] == "2026-08-25T01:00:00Z"
    assert {item["custody"] for item in documents.values()} == {"development-derived"}
    assert provider.active_key("evidence-receipt").key_id.endswith("/v1")


def test_kms_hsm_provider_publishes_explicit_custody() -> None:
    key = local_private_key_for_testing("custody-test")

    class Backend:
        def sign(self, key_ref, payload):
            return key.sign(payload)

        def public_key(self, key_ref):
            return key.public_key()

    remote_versions = [
        KeyVersion(f"remote-ref:{role}", role, "2026-08-25T00:00:00Z")
        for role in KEY_ROLES
    ]
    provider = KmsHsmKeyProvider(remote_versions, Backend(), custody="hsm")

    assert {item["custody"] for item in provider.verification_keyset()} == {"hsm"}
