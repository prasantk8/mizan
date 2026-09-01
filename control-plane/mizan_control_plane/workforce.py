from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlencode
from uuid import UUID, uuid4

import httpx
import jwt
from psycopg_pool import ConnectionPool

from .auth import IdentityKeySet
from .canonical import canonical_hash
from .config import Settings
from .evidence import EvidenceRepository
from .models import AuthenticatedPrincipal
from .problems import Problem

COOKIE_NAME = "mizan_workforce_session"
PRINCIPAL_ID = re.compile(r"^prn_[A-Za-z0-9-]{2,64}$")


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _random() -> str:
    return secrets.token_urlsafe(32)


def _split_scoped(value: str | None, kind: str) -> tuple[str, str]:
    try:
        tenant_id, secret = (value or "").split(".", 1)
    except ValueError as error:
        raise Problem(401, f"invalid_workforce_{kind}", f"Workforce {kind} is invalid") from error
    if not re.fullmatch(r"tnt_[a-z0-9-]{4,64}", tenant_id) or not secret:
        raise Problem(401, f"invalid_workforce_{kind}", f"Workforce {kind} is invalid")
    return tenant_id, secret


def _safe_event_payload() -> SimpleNamespace:
    return SimpleNamespace(
        payload=None,
        stored_payload_hash=canonical_hash(None),
        source_commitment=None,
        redaction={
            "applied": False,
            "policy_id": "dlp_identity-events",
            "policy_version": 1,
            "policy_hash": "0" * 64,
            "redactor_build": "not-applicable",
            "input_schema_hash": None,
            "output_schema_hash": None,
            "dlp": {
                "status": "not_applicable",
                "findings_count": 0,
                "scanner_version": "not-applicable",
                "coverage_profile": None,
            },
            "manifest": [],
        },
    )


@dataclass(frozen=True, slots=True)
class WorkforceSession:
    tenant_id: str
    session_id: str
    principal: AuthenticatedPrincipal
    step_up_at: datetime | None
    expires_at: datetime

    def require_fresh_step_up(self, max_age_seconds: int, now: datetime | None = None) -> None:
        now = now or datetime.now(UTC)
        if self.step_up_at is None or (now - self.step_up_at).total_seconds() > max_age_seconds:
            raise Problem(
                403,
                "workforce_step_up_required",
                "A fresh MFA or hardware step-up is required immediately before this vote",
            )


class WorkforceSessionRepository:
    def __init__(self, database_url: str, evidence: EvidenceRepository | None = None) -> None:
        self.pool = ConnectionPool(database_url, min_size=1, max_size=10, open=True)
        self.evidence = evidence or EvidenceRepository(database_url)
        self._owns_evidence = evidence is None

    @staticmethod
    def _scope(connection: Any, tenant_id: str) -> None:
        connection.execute("SELECT set_config('app.tenant_id', %s, true)", (tenant_id,))

    def close(self) -> None:
        self.pool.close()
        if self._owns_evidence:
            self.evidence.pool.close()

    def event(self, tenant_id: str, event_type: str, principal_id: str | None) -> None:
        self.evidence.append_audit(
            tenant_id,
            event_type,
            {
                "id": principal_id or "mizan-workforce-auth",
                "kind": "human" if principal_id else "service",
            },
            {"id": tenant_id, "kind": "tenant"},
            _safe_event_payload(),
        )

    def begin_login(
        self,
        tenant_id: str,
        return_to: str,
        requested_acr: str | None,
        prior_session_id: str | None,
    ) -> tuple[str, str, str]:
        secret, nonce, verifier = _random(), _random(), _random()
        state = f"{tenant_id}.{secret}"
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            connection.execute(
                "DELETE FROM mizan.workforce_login_transactions "
                "WHERE tenant_id=%s AND expires_at<=clock_timestamp()",
                (tenant_id,),
            )
            connection.execute(
                "INSERT INTO mizan.workforce_login_transactions(tenant_id,state_digest,nonce,"
                "pkce_verifier,return_to,requested_acr,prior_session_id,expires_at) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,clock_timestamp()+interval '5 minutes')",
                (
                    tenant_id,
                    _digest(secret),
                    nonce,
                    verifier,
                    return_to,
                    requested_acr,
                    prior_session_id,
                ),
            )
        return state, nonce, verifier

    def consume_login(self, state: str) -> dict[str, Any]:
        tenant_id, secret = _split_scoped(state, "state")
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            row = connection.execute(
                "DELETE FROM mizan.workforce_login_transactions WHERE tenant_id=%s "
                "AND state_digest=%s AND expires_at>clock_timestamp() "
                "RETURNING nonce,pkce_verifier,return_to,requested_acr,prior_session_id",
                (tenant_id, _digest(secret)),
            ).fetchone()
        if not row:
            raise Problem(401, "invalid_workforce_state", "OIDC state is expired or already used")
        return {
            "tenant_id": tenant_id,
            "nonce": row[0],
            "pkce_verifier": row[1],
            "return_to": row[2],
            "requested_acr": row[3],
            "prior_session_id": str(row[4]) if row[4] else None,
        }

    def create_session(
        self,
        tenant_id: str,
        principal: AuthenticatedPrincipal,
        idp_subject: str,
        ttl_seconds: int,
        stepped_up: bool,
        prior_session_id: str | None,
    ) -> tuple[str, WorkforceSession]:
        session_id, secret = str(uuid4()), _random()
        now = datetime.now(UTC)
        expires_at = now + timedelta(seconds=ttl_seconds)
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            if prior_session_id:
                connection.execute(
                    "UPDATE mizan.workforce_sessions SET revoked_at=coalesce(revoked_at,clock_timestamp()) "
                    "WHERE tenant_id=%s AND session_id=%s",
                    (tenant_id, prior_session_id),
                )
            connection.execute(
                "INSERT INTO mizan.workforce_sessions(tenant_id,session_id,secret_digest,"
                "principal_id,idp_subject,roles,control_domains,auth_strength,step_up_at,expires_at) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (
                    tenant_id,
                    session_id,
                    _digest(secret),
                    principal.principal_id,
                    idp_subject,
                    json.dumps(principal.roles),
                    json.dumps(principal.control_domains),
                    principal.auth_strength,
                    now if stepped_up else None,
                    expires_at,
                ),
            )
        self.event(
            tenant_id,
            "mizan.identity.step_up" if stepped_up else "mizan.identity.login",
            principal.principal_id,
        )
        return f"{tenant_id}.{session_id}.{secret}", WorkforceSession(
            tenant_id, session_id, principal, now if stepped_up else None, expires_at
        )

    def authenticate(self, cookie: str | None) -> WorkforceSession:
        try:
            tenant_id, session_id, secret = (cookie or "").split(".", 2)
            UUID(session_id)
        except ValueError as error:
            raise Problem(
                401, "workforce_session_missing", "Workforce login is required"
            ) from error
        _split_scoped(f"{tenant_id}.{secret}", "session")
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            row = connection.execute(
                "SELECT principal_id,idp_subject,roles,control_domains,auth_strength,step_up_at,"
                "expires_at,revoked_at FROM mizan.workforce_sessions WHERE tenant_id=%s "
                "AND session_id=%s AND secret_digest=%s",
                (tenant_id, session_id, _digest(secret)),
            ).fetchone()
            if row and row[7] is None and row[6] > datetime.now(UTC):
                connection.execute(
                    "UPDATE mizan.workforce_sessions SET last_seen_at=clock_timestamp() "
                    "WHERE tenant_id=%s AND session_id=%s",
                    (tenant_id, session_id),
                )
        if not row:
            raise Problem(401, "workforce_session_invalid", "Workforce session is invalid")
        if row[7] is not None:
            self.event(tenant_id, "mizan.identity.session_refused", row[0])
            raise Problem(401, "workforce_session_revoked", "Workforce session was revoked")
        if row[6] <= datetime.now(UTC):
            self.event(tenant_id, "mizan.identity.session_refused", row[0])
            raise Problem(401, "workforce_session_expired", "Workforce session has expired")
        principal = AuthenticatedPrincipal(
            tenant_id=tenant_id,
            principal_id=row[0],
            identity_kind="human",
            auth_strength=row[4],
            roles=row[2],
            control_domains=row[3],
        )
        return WorkforceSession(tenant_id, session_id, principal, row[5], row[6])

    def revoke(self, session: WorkforceSession, event_type: str) -> None:
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, session.tenant_id)
            connection.execute(
                "UPDATE mizan.workforce_sessions SET revoked_at=coalesce(revoked_at,clock_timestamp()) "
                "WHERE tenant_id=%s AND session_id=%s",
                (session.tenant_id, session.session_id),
            )
        self.event(session.tenant_id, event_type, session.principal.principal_id)

    def revoke_by_id(self, actor: WorkforceSession, session_id: str) -> None:
        if "session.admin" not in actor.principal.roles:
            raise Problem(403, "workforce_session_revoke_forbidden", "session.admin is required")
        try:
            UUID(session_id)
        except ValueError as error:
            raise Problem(
                404, "workforce_session_not_found", "Workforce session was not found"
            ) from error
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, actor.tenant_id)
            row = connection.execute(
                "UPDATE mizan.workforce_sessions SET revoked_at=coalesce(revoked_at,clock_timestamp()) "
                "WHERE tenant_id=%s AND session_id=%s RETURNING principal_id",
                (actor.tenant_id, session_id),
            ).fetchone()
        if not row:
            raise Problem(404, "workforce_session_not_found", "Workforce session was not found")
        self.event(actor.tenant_id, "mizan.identity.session_revoked", row[0])


class WorkforceOidc:
    def __init__(
        self,
        settings: Settings,
        repository: WorkforceSessionRepository,
        post: Callable[..., httpx.Response] | None = None,
    ) -> None:
        self.settings = settings
        self.repository = repository
        self.keyset = IdentityKeySet(settings.identity_jwks)
        self.post = post or httpx.post

    def authorization_url(self, return_to: str = "/", prior: WorkforceSession | None = None) -> str:
        if not return_to.startswith("/") or return_to.startswith("//"):
            raise Problem(400, "invalid_return_to", "return_to must be a local absolute path")
        acr = " ".join(self.settings.workforce_step_up_acr_values) if prior else None
        state, nonce, verifier = self.repository.begin_login(
            self.settings.workforce_tenant_id,
            return_to,
            acr,
            prior.session_id if prior else None,
        )
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        parameters = {
            "response_type": "code",
            "client_id": self.settings.workforce_oidc_client_id,
            "redirect_uri": self.settings.workforce_oidc_redirect_uri,
            "scope": "openid profile",
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        if acr:
            parameters.update({"prompt": "login", "max_age": "0", "acr_values": acr})
        return self.settings.workforce_oidc_authorization_endpoint + "?" + urlencode(parameters)

    def callback(self, code: str, state: str) -> tuple[str, str]:
        transaction = self.repository.consume_login(state)
        response = self.post(
            self.settings.workforce_oidc_token_endpoint,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.settings.workforce_oidc_redirect_uri,
                "client_id": self.settings.workforce_oidc_client_id,
                "client_secret": self.settings.workforce_oidc_client_secret,
                "code_verifier": transaction["pkce_verifier"],
            },
            timeout=5,
        )
        if response.status_code != 200:
            raise Problem(401, "workforce_oidc_exchange_failed", "OIDC code exchange failed")
        try:
            token = response.json().get("id_token")
            selected = self.keyset.select(token)
            claims = jwt.decode(
                token,
                selected.key,
                algorithms=[selected.algorithm],
                issuer=self.settings.jwt_issuer,
                audience=self.settings.workforce_oidc_client_id,
                options={"require": ["exp", "iat", "iss", "aud", "sub", "nonce"]},
            )
        except (jwt.PyJWTError, TypeError, ValueError) as error:
            raise Problem(401, "invalid_workforce_id_token", "OIDC ID token is invalid") from error
        if claims["nonce"] != transaction["nonce"]:
            raise Problem(401, "workforce_nonce_mismatch", "OIDC nonce does not match")
        principal_id = claims.get("principal_id")
        if not isinstance(principal_id, str) or not PRINCIPAL_ID.fullmatch(principal_id):
            raise Problem(
                403, "workforce_principal_unmapped", "IdP subject has no Mizan principal mapping"
            )
        groups = claims.get(self.settings.workforce_group_claim, [])
        if not isinstance(groups, list) or not all(isinstance(item, str) for item in groups):
            raise Problem(403, "workforce_groups_invalid", "IdP group claim is invalid")
        roles: set[str] = set()
        domains: dict[str, str] = {}
        for group in groups:
            mapping = (self.settings.workforce_role_mapping or {}).get(group)
            if not mapping:
                continue
            for role in mapping["roles"]:
                existing = domains.get(str(role))
                domain = str(mapping["control_domain"])
                if existing and existing != domain:
                    raise Problem(
                        403, "workforce_mapping_ambiguous", "A role maps to two control domains"
                    )
                roles.add(str(role))
                domains[str(role)] = domain
        if not roles:
            raise Problem(403, "workforce_role_unmapped", "IdP groups grant no Mizan role")
        amr = claims.get("amr", [])
        if not isinstance(amr, list) or not all(isinstance(item, str) for item in amr):
            raise Problem(403, "workforce_amr_invalid", "IdP authentication methods are invalid")
        acr = str(claims.get("acr", ""))
        hardware = "hwk" in amr or "hardware" in amr or "hardware" in acr
        mfa = hardware or "mfa" in amr or acr in self.settings.workforce_step_up_acr_values
        if not mfa:
            raise Problem(403, "workforce_mfa_required", "Workforce login requires MFA")
        stepped_up = transaction["requested_acr"] is not None
        if stepped_up and acr not in self.settings.workforce_step_up_acr_values:
            raise Problem(
                403, "workforce_step_up_unsatisfied", "IdP did not satisfy requested step-up"
            )
        principal = AuthenticatedPrincipal(
            tenant_id=transaction["tenant_id"],
            principal_id=principal_id,
            identity_kind="human",
            auth_strength="hardware" if hardware else "mfa",
            roles=sorted(roles),
            control_domains=domains,
        )
        cookie, _ = self.repository.create_session(
            transaction["tenant_id"],
            principal,
            claims["sub"],
            self.settings.workforce_session_ttl_seconds,
            stepped_up,
            transaction["prior_session_id"],
        )
        return cookie, transaction["return_to"]
