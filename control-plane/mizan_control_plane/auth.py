from __future__ import annotations

from typing import Annotated

import jwt
from fastapi import Header

from .models import AuthenticatedIdentity, AuthenticatedPrincipal
from .problems import Problem


class TokenVerifier:
    def __init__(self, issuer: str, audience: str, public_key: str) -> None:
        self.issuer = issuer
        self.audience = audience
        self.public_key = public_key

    def _claims(self, token: str) -> dict:
        try:
            return jwt.decode(
                token,
                self.public_key,
                algorithms=["RS256", "ES256", "EdDSA"],
                audience=self.audience,
                issuer=self.issuer,
                options={"require": ["exp", "iat", "iss", "aud", "sub", "tenant_id"]},
            )
        except (jwt.PyJWTError, ValueError, KeyError) as exc:
            raise Problem(401, "invalid_identity_token", "Bearer token validation failed") from exc

    def verify(self, token: str) -> AuthenticatedIdentity:
        try:
            claims = self._claims(token)
            return AuthenticatedIdentity(
                tenant_id=claims["tenant_id"],
                agent_id=claims["agent_id"],
                subject=claims["sub"],
                delegation_chain=claims.get("delegation_chain", [claims["agent_id"]]),
            )
        except (ValueError, KeyError) as exc:
            raise Problem(401, "invalid_agent_token", "Agent identity claims are incomplete") from exc

    def verify_principal(self, token: str) -> AuthenticatedPrincipal:
        try:
            claims = self._claims(token)
            return AuthenticatedPrincipal(
                tenant_id=claims["tenant_id"], principal_id=claims["sub"],
                identity_kind=claims["identity_kind"], auth_strength=claims["auth_strength"],
                roles=claims.get("roles", []),
            )
        except (ValueError, KeyError) as exc:
            raise Problem(401, "invalid_principal_token", "Principal claims are incomplete") from exc

    def verify_tenant(self, token: str) -> str:
        return self._claims(token)["tenant_id"]


def bearer_token(authorization: Annotated[str | None, Header()] = None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise Problem(401, "missing_identity_token", "A bearer identity token is required")
    return authorization.removeprefix("Bearer ").strip()
