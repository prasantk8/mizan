"""`mizan-dev-token` is a demo credential minter. Its job is to stay one."""

from __future__ import annotations

import jwt
import pytest
from mizan_control_plane.config import Settings
from mizan_control_plane.dev_token import DEVELOPMENT_ISSUER, ensure_keypair, main, mint


def test_minted_token_carries_every_claim_the_verifier_requires(tmp_path) -> None:
    private_key, public_pem = ensure_keypair(tmp_path)
    token = mint(
        private_key,
        tenant_id="tnt_demo-bank",
        subject="prn_ops-manager",
        agent_id="agt_wealth-advisor",
        identity_kind="human",
        auth_strength="hardware",
        roles=["manager"],
        audience="mizan-control-plane",
        ttl_seconds=60,
    )
    claims = jwt.decode(
        token,
        public_pem,
        algorithms=["EdDSA"],
        audience="mizan-control-plane",
        issuer=DEVELOPMENT_ISSUER,
        options={"require": ["exp", "iat", "iss", "aud", "sub", "tenant_id"]},
    )
    assert claims["identity_kind"] == "human"
    assert claims["auth_strength"] == "hardware"
    assert claims["delegation_chain"] == ["agt_wealth-advisor"]


def test_the_private_key_is_written_once_and_not_world_readable(tmp_path) -> None:
    first, _ = ensure_keypair(tmp_path)
    second, _ = ensure_keypair(tmp_path)
    assert first.private_bytes_raw() == second.private_bytes_raw()
    assert (tmp_path / "dev-identity.key").stat().st_mode & 0o077 == 0


def test_the_minter_refuses_production(monkeypatch, tmp_path, capsys) -> None:
    monkeypatch.setenv("MIZAN_ENV", "production")
    assert main(["--key-dir", str(tmp_path)]) == 78
    assert "refuses MIZAN_ENV=production" in capsys.readouterr().err
    assert not (tmp_path / "dev-identity.key").exists()


def test_the_control_plane_refuses_the_development_issuer_in_production(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setenv("MIZAN_DATABASE_URL", "postgresql://unused")
    monkeypatch.setenv("MIZAN_JWT_ISSUER", DEVELOPMENT_ISSUER)
    monkeypatch.setenv("MIZAN_JWT_PUBLIC_KEY", "unused")
    monkeypatch.setenv("MIZAN_ENV", "production")
    # `vault-transit` rather than the retired `kms_hsm` spelling: this test is about a
    # different production refusal, and a custody value the config layer now rejects would
    # shadow it (B-20, T-102).
    monkeypatch.setenv("MIZAN_KEY_CUSTODY_MODE", "vault-transit")
    monkeypatch.setenv("MIZAN_VAULT_ADDR", "https://vault.test")
    monkeypatch.setenv("MIZAN_VAULT_TOKEN", "s.unused-by-this-test")
    # Production now also requires an Object Lock bucket (B-21/T-104); set here so the
    # refusal this test is about is the one being asserted rather than the newest guard.
    monkeypatch.setenv("MIZAN_EVIDENCE_OBJECT_STORE", "s3")
    monkeypatch.setenv("MIZAN_AUDIT_ANCHOR_BUCKET", "mizan-evidence")
    for name, role in (
        ("MIZAN_EVIDENCE_RECEIPT_KEY_REF", "receipt"),
        ("MIZAN_EVIDENCE_ANCHOR_KEY_REF", "anchor"),
        ("MIZAN_EXECUTION_TOKEN_SIGNING_KEY_REF", "execution"),
        ("MIZAN_DEGRADED_GRANT_SIGNING_KEY_REF", "degraded"),
    ):
        monkeypatch.setenv(name, f"kms://vault/{role}")
    monkeypatch.setenv("MIZAN_ANCHOR_PROVIDER", "rfc3161")
    monkeypatch.setenv("MIZAN_ANCHOR_TSA_ENDPOINTS", "https://tsa.example.test")
    monkeypatch.setenv("MIZAN_ANCHOR_TSA_TRUST_ANCHORS", str(tmp_path / "root.pem"))
    with pytest.raises(RuntimeError, match="mizan-dev-token issuer"):
        Settings.from_environment()
