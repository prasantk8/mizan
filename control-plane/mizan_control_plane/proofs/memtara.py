"""Offline verification and typed projection of Memtara suitability tokens.

The compact JWS is transport input, never policy input.  Only ``VerifiedProof``
values produced here may enter ``EvaluationContext.mapped``.
"""

from __future__ import annotations

import base64
import json
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..models import MappedInput

PROOF_HEADER = "x-memtara-proof"
REQUIRED_ALG = "EdDSA"
CLOCK_SKEW_SECONDS = 30
MAX_TOKEN_BYTES = 16_384
MAX_JWKS_BYTES = 65_536
MAX_JWKS_KEYS = 32


class ProofTokenError(ValueError):
    """The presented value is not a usable Memtara proof token."""


def _b64url_decode(segment: str) -> bytes:
    try:
        return base64.b64decode(
            segment + "=" * (-len(segment) % 4), altchars=b"-_", validate=True
        )
    except (ValueError, TypeError) as exc:
        raise ProofTokenError("invalid base64url encoding") from exc


@dataclass(frozen=True, slots=True)
class VerifiedProof:
    """The suitability claims of a token that passed every check."""

    proof_hash: str
    circuit: str
    predicate: str
    product_isin: str
    suitable: bool
    issuer: str
    jti: str
    expires_at: int
    memtara_chain_head: str
    token: str = field(repr=False, compare=False)
    raw_claims: dict[str, Any] = field(repr=False, compare=False, default_factory=dict)

    def mapped_input(self) -> MappedInput:
        return MappedInput(
            source="memtara",
            fields={
                "proof_hash": self.proof_hash,
                "circuit": self.circuit,
                "predicate": self.predicate,
                "product_isin": self.product_isin,
                "suitable": self.suitable,
                "expires_at": self.expires_at,
                "jti": self.jti,
            },
        )

    def external_proof(self) -> dict[str, str]:
        """Evidence-only carrier; the compact bearer never enters policy context or logs."""
        return {
            "issuer": self.issuer,
            "proof_hash": self.proof_hash,
            "jti": self.jti,
            "memtara_chain_head": self.memtara_chain_head,
            "token": self.token,
        }


class JwksCache:
    """Bounded, explicitly refreshed cache of public Ed25519 verification keys."""

    def __init__(self, jwks_url: str, timeout: float = 5.0) -> None:
        self.jwks_url = jwks_url
        self.timeout = timeout
        self._keys: dict[str, Ed25519PublicKey] = {}
        self.fetch_count = 0

    def load(self, jwks: dict[str, Any] | None = None) -> None:
        if jwks is None:
            try:
                with urllib.request.urlopen(self.jwks_url, timeout=self.timeout) as response:
                    announced = response.headers.get("content-length")
                    if announced is not None and int(announced) > MAX_JWKS_BYTES:
                        raise ProofTokenError("Memtara JWKS exceeds the size limit")
                    encoded = response.read(MAX_JWKS_BYTES + 1)
            except ProofTokenError:
                raise
            except Exception as exc:
                raise ProofTokenError("Memtara JWKS could not be fetched") from exc
            self.fetch_count += 1
            if len(encoded) > MAX_JWKS_BYTES:
                raise ProofTokenError("Memtara JWKS exceeds the size limit")
            try:
                jwks = json.loads(encoded)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ProofTokenError("Memtara JWKS is not valid JSON") from exc

        if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
            raise ProofTokenError("Memtara JWKS must contain a keys array")
        if len(jwks["keys"]) > MAX_JWKS_KEYS:
            raise ProofTokenError("Memtara JWKS contains too many keys")

        keys: dict[str, Ed25519PublicKey] = {}
        for jwk in jwks["keys"]:
            if not isinstance(jwk, dict):
                raise ProofTokenError("Memtara JWKS contains a malformed key")
            if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
                continue
            if jwk.get("alg") not in (None, REQUIRED_ALG):
                continue
            if jwk.get("use") not in (None, "sig"):
                continue
            kid = jwk.get("kid")
            if not isinstance(kid, str) or not kid or kid in keys:
                raise ProofTokenError("Memtara JWKS has a missing or duplicate kid")
            try:
                key_bytes = _b64url_decode(jwk["x"])
                keys[kid] = Ed25519PublicKey.from_public_bytes(key_bytes)
            except (KeyError, ValueError, TypeError) as exc:
                raise ProofTokenError(f"Memtara JWKS key {kid!r} is malformed") from exc
        if not keys:
            raise ProofTokenError("Memtara JWKS contains no usable Ed25519 keys")
        self._keys = keys

    def key_for(self, kid: str) -> Ed25519PublicKey:
        if not self._keys:
            raise ProofTokenError("Memtara JWKS cache is empty")
        try:
            return self._keys[kid]
        except KeyError:
            raise ProofTokenError(f"unknown Memtara kid {kid!r}") from None

    @property
    def loaded(self) -> bool:
        return bool(self._keys)


class JtiReplaySet:
    """Atomic, tenant-scoped process replay set with expiry-based pruning."""

    def __init__(self) -> None:
        self._expires: dict[tuple[str, str, str], int] = {}
        self._lock = threading.Lock()

    def claim(self, tenant_id: str, proof: VerifiedProof, *, now: float | None = None) -> None:
        current = time.time() if now is None else now
        key = (tenant_id, proof.issuer, proof.jti)
        with self._lock:
            self._expires = {
                item: expiry
                for item, expiry in self._expires.items()
                if expiry + CLOCK_SKEW_SECONDS >= current
            }
            if key in self._expires:
                raise ProofTokenError(f"token jti {proof.jti!r} has already been used")
            self._expires[key] = proof.expires_at


def _required_string(claims: dict[str, Any], name: str, *, maximum: int = 256) -> str:
    value = claims.get(name)
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ProofTokenError(f"token has no valid {name} claim")
    return value


def validate_proof_token(
    token: str,
    jwks: JwksCache,
    *,
    expected_issuer: str,
    memtara_chain_head: str = "0" * 64,
    now: float | None = None,
) -> VerifiedProof:
    """Validate one compact Ed25519 JWS and return its typed signed claims."""

    current = time.time() if now is None else now
    if len(memtara_chain_head) != 64 or any(
        character not in "0123456789abcdef" for character in memtara_chain_head
    ):
        raise ProofTokenError("Memtara chain head is not lowercase SHA-256 hex")
    if not isinstance(token, str) or len(token.encode("utf-8")) > MAX_TOKEN_BYTES:
        raise ProofTokenError("Memtara token exceeds the size limit")
    parts = token.split(".")
    if len(parts) != 3 or any(not part for part in parts):
        raise ProofTokenError("not a compact JWS")
    header_b64, payload_b64, signature_b64 = parts
    try:
        header = json.loads(_b64url_decode(header_b64))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProofTokenError("unreadable JWS header") from exc
    if not isinstance(header, dict) or header.get("alg") != REQUIRED_ALG:
        raise ProofTokenError("Memtara tokens must use EdDSA")
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise ProofTokenError("JWS header has no kid")

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    public_key = jwks.key_for(kid)
    signature = _b64url_decode(signature_b64)
    try:
        public_key.verify(signature, signing_input)
    except InvalidSignature as exc:
        raise ProofTokenError("Memtara token signature does not verify") from exc

    try:
        claims = json.loads(_b64url_decode(payload_b64))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProofTokenError("unreadable JWS payload") from exc
    if not isinstance(claims, dict):
        raise ProofTokenError("JWS payload must be an object")
    if claims.get("iss") != expected_issuer:
        raise ProofTokenError("Memtara token issuer is not trusted")
    if claims.get("verified") is not True:
        raise ProofTokenError("Memtara token does not assert verified=true")
    exp = claims.get("exp")
    if not isinstance(exp, int) or isinstance(exp, bool):
        raise ProofTokenError("Memtara token has no integer exp claim")
    if current > exp + CLOCK_SKEW_SECONDS:
        raise ProofTokenError("Memtara token has expired")
    issued_at = claims.get("iat")
    if issued_at is not None and (
        not isinstance(issued_at, int)
        or isinstance(issued_at, bool)
        or issued_at > current + CLOCK_SKEW_SECONDS
    ):
        raise ProofTokenError("Memtara token has an invalid iat claim")
    if claims.get("suitable") is not True and claims.get("suitable") is not False:
        raise ProofTokenError("Memtara token has no boolean suitable claim")

    proof_hash = _required_string(claims, "proof_hash", maximum=64)
    if len(proof_hash) != 64 or any(character not in "0123456789abcdef" for character in proof_hash):
        raise ProofTokenError("Memtara proof_hash is not lowercase SHA-256 hex")
    return VerifiedProof(
        proof_hash=proof_hash,
        circuit=_required_string(claims, "circuit", maximum=120),
        predicate=_required_string(claims, "predicate", maximum=120),
        product_isin=_required_string(claims, "product_isin", maximum=32),
        suitable=claims["suitable"],
        issuer=expected_issuer,
        jti=_required_string(claims, "jti", maximum=128),
        expires_at=exp,
        memtara_chain_head=memtara_chain_head,
        token=token,
        raw_claims=claims,
    )


class MemtaraProofVerifier:
    """Deployment-pinned verifier plus tenant-scoped replay claim."""

    def __init__(
        self,
        expected_issuer: str | None,
        jwks_url: str | None,
        *,
        jwks: JwksCache | None = None,
        replay: JtiReplaySet | None = None,
    ) -> None:
        self.expected_issuer = expected_issuer
        self.jwks = jwks or (JwksCache(jwks_url) if jwks_url else None)
        self.replay = replay or JtiReplaySet()
        self._load_lock = threading.Lock()

    @property
    def configured(self) -> bool:
        return bool(self.expected_issuer and self.jwks)

    def verify(
        self,
        token: str,
        tenant_id: str,
        *,
        memtara_chain_head: str | None,
        now: float | None = None,
    ) -> VerifiedProof:
        if not self.configured or self.jwks is None or self.expected_issuer is None:
            raise ProofTokenError("Memtara proof verification is not configured")
        if not self.jwks.loaded:
            with self._load_lock:
                if not self.jwks.loaded:
                    self.jwks.load()
        if memtara_chain_head is None:
            raise ProofTokenError("Memtara suitability proof requires a chain head")
        proof = validate_proof_token(
            token,
            self.jwks,
            expected_issuer=self.expected_issuer,
            memtara_chain_head=memtara_chain_head,
            now=now,
        )
        self.replay.claim(tenant_id, proof, now=now)
        return proof
