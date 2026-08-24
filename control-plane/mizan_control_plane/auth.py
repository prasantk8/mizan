from __future__ import annotations

from typing import Annotated

import jwt
from fastapi import Header

from .models import AuthenticatedIdentity
from .problems import Problem


class TokenVerifier:
    def __init__(self, issuer: str, audience: str, public_key: str) -> None:
        self.issuer = issuer
        self.audience = audience
        self.public_key = public_key

    def verify(self, token: str) -> AuthenticatedIdentity:
        try:
            claims = jwt.decode(
                token,
                self.public_key,
                algorithms=["RS256", "ES256", "EdDSA"],
                audience=self.audience,
                issuer=self.issuer,
                options={"require": ["exp", "iat", "iss", "aud", "sub", "tenant_id", "agent_id"]},
            )
            return AuthenticatedIdentity(
                tenant_id=claims["tenant_id"],
                agent_id=claims["agent_id"],
                subject=claims["sub"],
                delegation_chain=claims.get("delegation_chain", [claims["agent_id"]]),
            )
        except (jwt.PyJWTError, ValueError, KeyError) as exc:
            raise Problem(401, "invalid_identity_token", "Bearer token validation failed") from exc


def bearer_token(authorization: Annotated[str | None, Header()] = None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise Problem(401, "missing_identity_token", "A bearer identity token is required")
    return authorization.removeprefix("Bearer ").strip()

