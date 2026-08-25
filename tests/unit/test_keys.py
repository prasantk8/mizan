from __future__ import annotations

import pytest
from mizan_control_plane.config import Settings
from mizan_control_plane.keys import KEY_ROLES, KeyVersion, LocalKeyProvider


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
    assert provider.active_key("evidence-receipt").key_id.endswith("/v1")
