from __future__ import annotations

from typing import Annotated

import jwt
from fastapi import Header

from .models import AuthenticatedIdentity, AuthenticatedPrincipal
from .problems import Problem

# An identity token is a bearer credential: anyone holding it is the subject until it expires.
# `exp` was required and unbounded, so a token minted with a ten-year lifetime was accepted --
# demonstrated, not theorised. One leaked credential was then a decade of access with no
# revocation path, because there is no revocation path for identity tokens at all.
DEFAULT_MAX_TOKEN_TTL_SECONDS = 3600


class TokenVerifier:
    def __init__(
        self,
        issuer: str,
        audience: str,
        public_key: str,
        max_ttl_seconds: int = DEFAULT_MAX_TOKEN_TTL_SECONDS,
    ) -> None:
        self.issuer = issuer
        self.audience = audience
        self.public_key = public_key
        self.max_ttl_seconds = max_ttl_seconds

    def _claims(self, token: str) -> dict:
        try:
            claims = jwt.decode(
                token,
                self.public_key,
                algorithms=["RS256", "ES256", "EdDSA"],
                audience=self.audience,
                issuer=self.issuer,
                options={"require": ["exp", "iat", "iss", "aud", "sub", "tenant_id"]},
            )
        except (jwt.PyJWTError, ValueError, KeyError) as exc:
            raise Problem(401, "invalid_identity_token", "Bearer token validation failed") from exc
        # `exp` in the future is not the same as a bounded lifetime. PyJWT checks the former and
        # has no opinion about the latter, so the bound has to be applied here.
        lifetime = int(claims["exp"]) - int(claims["iat"])
        if lifetime > self.max_ttl_seconds:
            raise Problem(
                401,
                "identity_token_ttl_excessive",
                f"Identity token lifetime {lifetime}s exceeds the {self.max_ttl_seconds}s maximum",
            )
        return claims

    def verify(self, token: str) -> AuthenticatedIdentity:
        """The agent acting. Refuses a token that is not an agent token.

        A single token carrying both `agent_id` and `identity_kind: "human"` used to satisfy this
        *and* `verify_principal` -- so one bearer was simultaneously the agent making a request
        and a hardware-authenticated human holding the `manager` role. That is the credential a
        governed agent already possesses, and it could have voted on its own approvals with it.
        The claim to separate them was always present; nothing read it.
        """
        claims = self._claims(token)
        if claims.get("identity_kind") != "agent":
            raise Problem(
                401,
                "token_class_mismatch",
                "An agent identity requires a token whose identity_kind is 'agent'",
            )
        try:
            return AuthenticatedIdentity(
                tenant_id=claims["tenant_id"],
                agent_id=claims["agent_id"],
                subject=claims["sub"],
                delegation_chain=claims.get("delegation_chain", [claims["agent_id"]]),
            )
        except (ValueError, KeyError) as exc:
            raise Problem(
                401, "invalid_agent_token", "Agent identity claims are incomplete"
            ) from exc

    def verify_principal(self, token: str) -> AuthenticatedPrincipal:
        """A human or service principal. Refuses an agent token, which is the other half of the
        separation above: an agent must not be able to present its own credential where an
        operator is required."""
        claims = self._claims(token)
        if claims.get("identity_kind") == "agent":
            raise Problem(
                401,
                "token_class_mismatch",
                "A principal identity requires a token that is not an agent token",
            )
        try:
            return AuthenticatedPrincipal(
                tenant_id=claims["tenant_id"],
                principal_id=claims["sub"],
                identity_kind=claims["identity_kind"],
                auth_strength=claims["auth_strength"],
                roles=claims.get("roles", []),
            )
        except (ValueError, KeyError) as exc:
            raise Problem(
                401, "invalid_principal_token", "Principal claims are incomplete"
            ) from exc

    def verify_tenant(self, token: str) -> str:
        return self._claims(token)["tenant_id"]


def bearer_token(authorization: Annotated[str | None, Header()] = None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise Problem(401, "missing_identity_token", "A bearer identity token is required")
    return authorization.removeprefix("Bearer ").strip()
