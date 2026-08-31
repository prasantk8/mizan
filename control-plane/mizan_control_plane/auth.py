from __future__ import annotations

import json
from dataclasses import dataclass
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
IDENTITY_ALGORITHMS = frozenset({"RS256", "ES256", "EdDSA"})
PRIVATE_JWK_PARAMETERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth"})


@dataclass(frozen=True, slots=True)
class IdentityVerificationKey:
    kid: str
    algorithm: str
    key: object


class IdentityKeySet:
    """A startup-pinned, public-only JWKS used exclusively for identity verification.

    Rotation is additive: deploy old+new to every verifier, switch the issuer, wait at least the
    maximum token TTL, then deploy new-only. The source is deliberately local configuration rather
    than a token-selected URL or a per-request network lookup; neither a caller nor an IdP outage
    may select or remove a trust root while an authorization request is being evaluated.
    """

    def __init__(self, document: str) -> None:
        try:
            parsed = json.loads(document)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError("MIZAN_IDENTITY_JWKS must be a JSON object") from exc
        if not isinstance(parsed, dict) or set(parsed) != {"keys"}:
            raise ValueError("MIZAN_IDENTITY_JWKS must contain exactly one top-level 'keys' member")
        documents = parsed["keys"]
        if not isinstance(documents, list) or not documents:
            raise ValueError("MIZAN_IDENTITY_JWKS.keys must be a non-empty array")

        keys: dict[str, IdentityVerificationKey] = {}
        for position, raw in enumerate(documents):
            if not isinstance(raw, dict):
                raise ValueError(f"MIZAN_IDENTITY_JWKS.keys[{position}] must be an object")
            kid = raw.get("kid")
            algorithm = raw.get("alg")
            if not isinstance(kid, str) or not kid.strip():
                raise ValueError(f"MIZAN_IDENTITY_JWKS.keys[{position}].kid must be non-empty")
            if kid in keys:
                raise ValueError(f"MIZAN_IDENTITY_JWKS contains duplicate kid {kid!r}")
            if not isinstance(algorithm, str) or algorithm not in IDENTITY_ALGORITHMS:
                raise ValueError(
                    f"MIZAN_IDENTITY_JWKS key {kid!r} must declare one of "
                    f"{', '.join(sorted(IDENTITY_ALGORITHMS))}"
                )
            if raw.get("use") != "sig":
                raise ValueError(f"MIZAN_IDENTITY_JWKS key {kid!r} must declare use='sig'")
            if PRIVATE_JWK_PARAMETERS.intersection(raw):
                raise ValueError(f"MIZAN_IDENTITY_JWKS key {kid!r} contains private key material")
            try:
                parsed_key = jwt.PyJWK.from_dict(raw)
            except (jwt.PyJWTError, TypeError, ValueError, KeyError) as exc:
                raise ValueError(f"MIZAN_IDENTITY_JWKS key {kid!r} is not a valid JWK") from exc
            if parsed_key.key_type == "oct":
                raise ValueError(f"MIZAN_IDENTITY_JWKS key {kid!r} is symmetric")
            if parsed_key.algorithm_name != algorithm:
                raise ValueError(
                    f"MIZAN_IDENTITY_JWKS key {kid!r} declares alg={algorithm!r} but its key "
                    f"requires {parsed_key.algorithm_name!r}"
                )
            keys[kid] = IdentityVerificationKey(kid, algorithm, parsed_key.key)
        self._keys = keys

    def select(self, token: str) -> IdentityVerificationKey:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise Problem(401, "invalid_identity_token", "Bearer token validation failed") from exc
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise Problem(
                401,
                "identity_token_kid_missing",
                "Identity tokens must name a verification key",
            )
        selected = self._keys.get(kid)
        if selected is None:
            raise Problem(
                401,
                "identity_token_kid_unknown",
                "Identity token names an unknown or retired verification key",
            )
        if header.get("alg") != selected.algorithm:
            raise Problem(
                401,
                "identity_token_algorithm_mismatch",
                "Identity token algorithm does not match its verification key",
            )
        return selected


class TokenVerifier:
    def __init__(
        self,
        issuer: str,
        audience: str,
        identity_jwks: str,
        max_ttl_seconds: int = DEFAULT_MAX_TOKEN_TTL_SECONDS,
    ) -> None:
        self.issuer = issuer
        self.audience = audience
        self.keyset = IdentityKeySet(identity_jwks)
        self.max_ttl_seconds = max_ttl_seconds

    def _claims(self, token: str) -> dict:
        selected = self.keyset.select(token)
        try:
            claims = jwt.decode(
                token,
                selected.key,
                algorithms=[selected.algorithm],
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
