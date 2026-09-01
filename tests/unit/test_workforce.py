from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import jwt
import pytest
from mizan_control_plane.config import Settings
from mizan_control_plane.dev_token import DEFAULT_KEY_ID, ensure_keypair, public_jwks
from mizan_control_plane.models import AuthenticatedPrincipal
from mizan_control_plane.problems import Problem
from mizan_control_plane.workforce import WorkforceOidc, WorkforceSession


class FakeRepository:
    def __init__(self) -> None:
        self.created = None

    def begin_login(self, tenant_id, return_to, requested_acr, prior_session_id):
        return f"{tenant_id}.state-secret", "expected-nonce", "pkce-verifier"

    def consume_login(self, state):
        assert state == "tnt_bank-a.state-secret"
        return {
            "tenant_id": "tnt_bank-a",
            "nonce": "expected-nonce",
            "pkce_verifier": "pkce-verifier",
            "return_to": "/approvals",
            "requested_acr": "urn:mizan:hardware urn:mizan:mfa",
            "prior_session_id": "ca5e9fe3-741d-42af-a6b6-34c603dcf792",
        }

    def create_session(self, *arguments):
        self.created = arguments
        principal = arguments[1]
        return "tnt_bank-a.session.secret", WorkforceSession(
            "tnt_bank-a",
            "ca5e9fe3-741d-42af-a6b6-34c603dcf793",
            principal,
            datetime.now(UTC),
            datetime.now(UTC) + timedelta(minutes=15),
        )


def oidc_settings(monkeypatch, tmp_path, private_key) -> Settings:
    values = {
        "MIZAN_DATABASE_URL": "postgresql://unused",
        "MIZAN_JWT_ISSUER": "https://customer-idp.test",
        "MIZAN_IDENTITY_JWKS": public_jwks(private_key),
        "MIZAN_EVIDENCE_OBJECT_STORE_ROOT": str(tmp_path / "evidence"),
        "MIZAN_WORKFORCE_OIDC_AUTHORIZATION_ENDPOINT": "https://customer-idp.test/authorize",
        "MIZAN_WORKFORCE_OIDC_TOKEN_ENDPOINT": "https://customer-idp.test/token",
        "MIZAN_WORKFORCE_OIDC_CLIENT_ID": "mizan-console",
        "MIZAN_WORKFORCE_OIDC_CLIENT_SECRET": "test-secret",
        "MIZAN_WORKFORCE_OIDC_REDIRECT_URI": "https://mizan.test/auth/callback",
        "MIZAN_WORKFORCE_TENANT_ID": "tnt_bank-a",
        "MIZAN_WORKFORCE_ROLE_MAPPING": json.dumps(
            {
                "customer-ops": {
                    "roles": ["manager", "session.admin"],
                    "control_domain": "operations",
                }
            }
        ),
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    return Settings.from_environment()


def id_token(private_key, **overrides) -> str:
    now = datetime.now(UTC)
    claims = {
        "iss": "https://customer-idp.test",
        "aud": "mizan-console",
        "sub": "customer-subject-42",
        "principal_id": "prn_alice",
        "nonce": "expected-nonce",
        "groups": ["customer-ops"],
        "amr": ["mfa", "hwk"],
        "acr": "urn:mizan:hardware",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
    }
    claims.update(overrides)
    return jwt.encode(claims, private_key, algorithm="EdDSA", headers={"kid": DEFAULT_KEY_ID})


def test_oidc_callback_maps_customer_groups_and_records_a_hardware_step_up(
    monkeypatch, tmp_path
) -> None:
    private_key, _ = ensure_keypair(tmp_path / "idp")
    settings = oidc_settings(monkeypatch, tmp_path, private_key)
    repository = FakeRepository()
    response = SimpleNamespace(status_code=200, json=lambda: {"id_token": id_token(private_key)})
    client = WorkforceOidc(settings, repository, post=lambda *args, **kwargs: response)

    cookie, return_to = client.callback("one-time-code", "tnt_bank-a.state-secret")

    assert cookie == "tnt_bank-a.session.secret"
    assert return_to == "/approvals"
    principal = repository.created[1]
    assert principal.roles == ["manager", "session.admin"]
    assert principal.control_domains == {
        "manager": "operations",
        "session.admin": "operations",
    }
    assert principal.auth_strength == "hardware"
    assert repository.created[4] is True


def test_oidc_callback_refuses_an_unmapped_customer_group(monkeypatch, tmp_path) -> None:
    private_key, _ = ensure_keypair(tmp_path / "idp")
    settings = oidc_settings(monkeypatch, tmp_path, private_key)
    repository = FakeRepository()
    response = SimpleNamespace(
        status_code=200,
        json=lambda: {"id_token": id_token(private_key, groups=["unmapped-group"])},
    )

    with pytest.raises(Problem, match="no Mizan role"):
        WorkforceOidc(settings, repository, post=lambda *args, **kwargs: response).callback(
            "one-time-code", "tnt_bank-a.state-secret"
        )


def test_high_risk_step_up_must_be_recent() -> None:
    principal = AuthenticatedPrincipal(
        tenant_id="tnt_bank-a",
        principal_id="prn_alice",
        identity_kind="human",
        auth_strength="hardware",
        roles=["manager"],
        control_domains={"manager": "operations"},
    )
    now = datetime.now(UTC)
    WorkforceSession(
        "tnt_bank-a", "session", principal, now, now + timedelta(minutes=5)
    ).require_fresh_step_up(120, now)
    stale = WorkforceSession(
        "tnt_bank-a", "session", principal, now - timedelta(seconds=121), now + timedelta(minutes=5)
    )
    with pytest.raises(Problem, match="fresh MFA or hardware step-up"):
        stale.require_fresh_step_up(120, now)
