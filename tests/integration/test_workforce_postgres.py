from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient
from mizan_control_plane.app import create_app
from mizan_control_plane.config import Settings
from mizan_control_plane.evidence import EvidenceRepository
from mizan_control_plane.models import AuthenticatedPrincipal
from mizan_control_plane.workforce import COOKIE_NAME, WorkforceSessionRepository

from tests.support import UNUSED_IDENTITY_JWKS

pytestmark = pytest.mark.skipif(
    not os.getenv("MIZAN_TEST_DATABASE_URL"), reason="Postgres not configured"
)


def test_browser_requests_refuse_expired_and_revoked_sessions_and_leave_audit_events(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    database_url = os.environ["MIZAN_TEST_DATABASE_URL"]
    monkeypatch.setenv("MIZAN_DATABASE_URL", database_url)
    monkeypatch.setenv("MIZAN_JWT_ISSUER", "https://customer-idp.test")
    monkeypatch.setenv("MIZAN_IDENTITY_JWKS", UNUSED_IDENTITY_JWKS)
    monkeypatch.setenv("MIZAN_EVIDENCE_OBJECT_STORE_ROOT", str(tmp_path / "evidence"))
    evidence = EvidenceRepository(database_url)
    repository = WorkforceSessionRepository(database_url, evidence)
    app = create_app(Settings.from_environment())
    principal = AuthenticatedPrincipal(
        tenant_id="tnt_bank-a",
        principal_id="prn_alice",
        identity_kind="human",
        auth_strength="hardware",
        roles=["manager", "session.admin"],
        control_domains={"manager": "operations", "session.admin": "operations"},
    )
    try:
        expired_cookie, expired = repository.create_session(
            "tnt_bank-a", principal, "idp-alice", 60, False, None
        )
        with repository.pool.connection() as connection, connection.transaction():
            repository._scope(connection, "tnt_bank-a")
            connection.execute(
                "UPDATE mizan.workforce_sessions SET expires_at=clock_timestamp()-interval '1 second' "
                "WHERE tenant_id=%s AND session_id=%s",
                ("tnt_bank-a", expired.session_id),
            )
        with TestClient(app, base_url="https://mizan.test") as browser:
            browser.cookies.set(COOKIE_NAME, expired_cookie)
            expired_response = browser.get("/auth/session")
            assert expired_response.status_code == 401
            assert expired_response.json()["type"].endswith("workforce_session_expired")

            revoked_cookie, revoked = repository.create_session(
                "tnt_bank-a", principal, "idp-alice", 60, True, None
            )
            repository.revoke_by_id(revoked, revoked.session_id)
            browser.cookies.set(COOKIE_NAME, revoked_cookie)
            revoked_response = browser.get("/auth/session")
            assert revoked_response.status_code == 401
            assert revoked_response.json()["type"].endswith("workforce_session_revoked")

            active_cookie, _active = repository.create_session(
                "tnt_bank-a", principal, "idp-alice", 60, False, None
            )
            browser.cookies.set(COOKIE_NAME, active_cookie)
            assert browser.get("/auth/session").json()["principal_id"] == "prn_alice"
            assert browser.post("/auth/logout").status_code == 204

        events = {
            item["event_type"]
            for item in evidence.search_audit("tnt_bank-a", 50)["items"]
        }
        assert {
            "mizan.identity.login",
            "mizan.identity.step_up",
            "mizan.identity.logout",
            "mizan.identity.session_revoked",
            "mizan.identity.session_refused",
        } <= events
        assert all(
            item["source_commitment"] is None
            for item in evidence.search_audit("tnt_bank-a", 50)["items"]
            if item["event_type"].startswith("mizan.identity.")
        )
    finally:
        if not repository.pool.closed:
            repository.pool.close()
        evidence.pool.close()
