from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mizan_control_plane.proofs.memtara import (
    JwksCache,
    MemtaraProofVerifier,
    ProofTokenError,
    validate_proof_token,
)

from tests.support import UNUSED_IDENTITY_JWKS

ISSUER = "https://api.memtara.test"
KID = "memtara-test-1"
CHAIN_HEAD = "a" * 64


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _jwks(private_key: Ed25519PrivateKey, kid: str = KID) -> dict[str, Any]:
    public = private_key.public_key().public_bytes_raw()
    return {
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "use": "sig",
                "kid": kid,
                "x": _b64url(public),
            }
        ]
    }


def _claims(now: int, **overrides: Any) -> dict[str, Any]:
    claims: dict[str, Any] = {
        "iss": ISSUER,
        "sub": "client-42",
        "user_id": "client-42",
        "predicate": "structured_product_suitable",
        "verified": True,
        "circuit": "wealth_suitability",
        "proof_hash": "b" * 64,
        "product_isin": "XS1234567890",
        "suitable": True,
        "iat": now,
        "exp": now + 300,
        "jti": "33333333-3333-3333-3333-333333333333",
    }
    claims.update(overrides)
    return claims


def _token(private_key: Ed25519PrivateKey, claims: dict[str, Any], kid: str = KID) -> str:
    header = _b64url(json.dumps({"alg": "EdDSA", "typ": "JWT", "kid": kid}).encode())
    payload = _b64url(json.dumps(claims).encode())
    signing_input = f"{header}.{payload}"
    signature = _b64url(private_key.sign(signing_input.encode("ascii")))
    return f"{signing_input}.{signature}"


def _unsigned_token(header: dict[str, Any], claims: dict[str, Any], signature: bytes) -> str:
    """A token whose signature segment is whatever the attacker chose to put there."""
    header_b64 = _b64url(json.dumps(header).encode())
    payload_b64 = _b64url(json.dumps(claims).encode())
    return f"{header_b64}.{payload_b64}.{_b64url(signature)}"


@pytest.fixture
def material() -> tuple[int, Ed25519PrivateKey, JwksCache]:
    now = int(time.time())
    private_key = Ed25519PrivateKey.generate()
    cache = JwksCache("https://unused.test/.well-known/jwks.json")
    cache.load(_jwks(private_key))
    return now, private_key, cache


def test_verified_suitability_claims_are_the_only_values_mapped_for_cedar(material) -> None:
    now, private_key, cache = material
    token = _token(private_key, _claims(now))
    proof = validate_proof_token(
        token,
        cache,
        expected_issuer=ISSUER,
        memtara_chain_head=CHAIN_HEAD,
        now=now,
    )

    assert proof.mapped_input().model_dump() == {
        "source": "memtara",
        "projection_id": None,
        "projection_version": None,
        "raw_envelope_hash": None,
        "fields": {
            "proof_hash": "b" * 64,
            "circuit": "wealth_suitability",
            "predicate": "structured_product_suitable",
            "product_isin": "XS1234567890",
            "suitable": True,
            "expires_at": now + 300,
            "jti": "33333333-3333-3333-3333-333333333333",
        },
    }
    assert proof.external_proof() == {
        "issuer": ISSUER,
        "proof_hash": "b" * 64,
        "jti": "33333333-3333-3333-3333-333333333333",
        "memtara_chain_head": CHAIN_HEAD,
        "token": token,
    }


@pytest.mark.parametrize(
    ("claim_overrides", "expected"),
    [
        ({"exp": 1}, "expired"),
        ({"iss": "https://attacker.test"}, "issuer"),
        ({"suitable": None}, "suitable"),
        ({"verified": False}, "verified"),
    ],
)
def test_adversarial_claims_are_refused(material, claim_overrides, expected) -> None:
    now, private_key, cache = material
    with pytest.raises(ProofTokenError, match=expected):
        validate_proof_token(
            _token(private_key, _claims(now, **claim_overrides)),
            cache,
            expected_issuer=ISSUER,
            memtara_chain_head=CHAIN_HEAD,
            now=now,
        )


def test_wrong_kid_is_refused_without_a_network_refresh(material) -> None:
    now, private_key, cache = material
    with pytest.raises(ProofTokenError, match="unknown Memtara kid"):
        validate_proof_token(
            _token(private_key, _claims(now), kid="attacker-key"),
            cache,
            expected_issuer=ISSUER,
            memtara_chain_head=CHAIN_HEAD,
            now=now,
        )
    assert cache.fetch_count == 0


def test_a_token_signed_by_a_key_other_than_the_published_one_is_refused(material) -> None:
    """The guard the whole seam rests on: a well-formed token, a `kid` that resolves, and a
    signature made by a key Memtara never published. Key *lookup* succeeds here; only
    ``Ed25519PublicKey.verify`` stands between a forger and a signed suitability verdict."""

    now, honest_key, cache = material
    forger_key = Ed25519PrivateKey.generate()
    assert forger_key.public_key().public_bytes_raw() != honest_key.public_key().public_bytes_raw()

    honest = _token(honest_key, _claims(now))
    forged = _token(forger_key, _claims(now))
    # Identical up to the signature: same header (so the same published kid), same claims.
    assert forged.rsplit(".", 1)[0] == honest.rsplit(".", 1)[0]
    assert forged.rsplit(".", 1)[1] != honest.rsplit(".", 1)[1]
    # The honest token verifies against this very cache, so the refusal below is the signature
    # check and not some unrelated claim or lookup failure.
    assert validate_proof_token(
        honest, cache, expected_issuer=ISSUER, memtara_chain_head=CHAIN_HEAD, now=now
    ).suitable is True

    with pytest.raises(ProofTokenError, match="signature does not verify"):
        validate_proof_token(
            forged,
            cache,
            expected_issuer=ISSUER,
            memtara_chain_head=CHAIN_HEAD,
            now=now,
        )


def test_claims_swapped_under_a_genuine_signature_are_refused(material) -> None:
    """A real Memtara signature over `suitable: false` cannot be lifted onto `suitable: true`."""

    now, private_key, cache = material
    declined = _token(private_key, _claims(now, suitable=False))
    header_b64, _declined_payload, signature_b64 = declined.split(".")
    approving_payload = _b64url(json.dumps(_claims(now, suitable=True)).encode())
    tampered = f"{header_b64}.{approving_payload}.{signature_b64}"

    with pytest.raises(ProofTokenError, match="signature does not verify"):
        validate_proof_token(
            tampered,
            cache,
            expected_issuer=ISSUER,
            memtara_chain_head=CHAIN_HEAD,
            now=now,
        )
    # The untampered decline is a valid token; only the swap is refused.
    assert (
        validate_proof_token(
            declined, cache, expected_issuer=ISSUER, memtara_chain_head=CHAIN_HEAD, now=now
        ).suitable
        is False
    )


def test_a_truncated_or_bit_flipped_signature_is_refused(material) -> None:
    now, private_key, cache = material
    header_b64, payload_b64, signature_b64 = _token(private_key, _claims(now)).split(".")
    signature = base64.urlsafe_b64decode(signature_b64 + "=" * (-len(signature_b64) % 4))
    flipped = bytes([signature[0] ^ 0x01]) + signature[1:]

    with pytest.raises(ProofTokenError, match="signature does not verify"):
        validate_proof_token(
            f"{header_b64}.{payload_b64}.{_b64url(flipped)}",
            cache,
            expected_issuer=ISSUER,
            memtara_chain_head=CHAIN_HEAD,
            now=now,
        )
    with pytest.raises(ProofTokenError, match="signature does not verify"):
        validate_proof_token(
            f"{header_b64}.{payload_b64}.{_b64url(signature[:-1])}",
            cache,
            expected_issuer=ISSUER,
            memtara_chain_head=CHAIN_HEAD,
            now=now,
        )


def test_alg_none_is_refused_before_any_key_is_consulted(material) -> None:
    """`alg: "none"` with a syntactically present signature segment: the classic unsigned-token
    forgery. It must die on the algorithm guard, not later on a claim."""

    now, _private_key, cache = material
    token = _unsigned_token(
        {"alg": "none", "typ": "JWT", "kid": KID}, _claims(now), b"\x00"
    )
    with pytest.raises(ProofTokenError, match="Memtara tokens must use EdDSA"):
        validate_proof_token(
            token, cache, expected_issuer=ISSUER, memtara_chain_head=CHAIN_HEAD, now=now
        )


def test_hs256_signed_with_the_published_public_key_is_refused(material) -> None:
    """Algorithm confusion: the attacker treats the published Ed25519 *public* key as an HMAC
    secret. The digest is genuine for HS256, so only the `alg` guard refuses it."""

    now, private_key, cache = material
    header = {"alg": "HS256", "typ": "JWT", "kid": KID}
    header_b64 = _b64url(json.dumps(header).encode())
    payload_b64 = _b64url(json.dumps(_claims(now)).encode())
    mac = hmac.new(
        private_key.public_key().public_bytes_raw(),
        f"{header_b64}.{payload_b64}".encode("ascii"),
        hashlib.sha256,
    ).digest()

    with pytest.raises(ProofTokenError, match="Memtara tokens must use EdDSA"):
        validate_proof_token(
            f"{header_b64}.{payload_b64}.{_b64url(mac)}",
            cache,
            expected_issuer=ISSUER,
            memtara_chain_head=CHAIN_HEAD,
            now=now,
        )


def test_a_header_without_an_alg_at_all_is_refused(material) -> None:
    now, private_key, cache = material
    token = _unsigned_token({"typ": "JWT", "kid": KID}, _claims(now), b"\x00")
    with pytest.raises(ProofTokenError, match="Memtara tokens must use EdDSA"):
        validate_proof_token(
            token, cache, expected_issuer=ISSUER, memtara_chain_head=CHAIN_HEAD, now=now
        )


def test_missing_or_malformed_chain_head_is_refused_by_the_uc2_verifier(material) -> None:
    now, private_key, cache = material
    verifier = MemtaraProofVerifier(ISSUER, cache.jwks_url, jwks=cache)
    token = _token(private_key, _claims(now))
    # Two different guards, two patterns that only one of them can produce.
    with pytest.raises(ProofTokenError, match=r"^Memtara suitability proof requires a chain head$"):
        verifier.verify(token, "tnt_bank-a", memtara_chain_head=None, now=now)
    with pytest.raises(
        ProofTokenError, match=r"^Memtara chain head is not lowercase SHA-256 hex$"
    ):
        verifier.verify(token, "tnt_bank-a", memtara_chain_head="ABC", now=now)
    # Right length, wrong case: hex is not enough, the encoding is pinned.
    with pytest.raises(
        ProofTokenError, match=r"^Memtara chain head is not lowercase SHA-256 hex$"
    ):
        verifier.verify(token, "tnt_bank-a", memtara_chain_head="A" * 64, now=now)


def test_jti_replay_claim_is_atomic_and_tenant_scoped(material) -> None:
    now, private_key, cache = material
    verifier = MemtaraProofVerifier(ISSUER, cache.jwks_url, jwks=cache)
    token = _token(private_key, _claims(now))

    with ThreadPoolExecutor(max_workers=2) as workers:
        futures = [
            workers.submit(
                verifier.verify,
                token,
                "tnt_bank-a",
                memtara_chain_head=CHAIN_HEAD,
                now=now,
            )
            for _ in range(2)
        ]
    successes = [future.result() for future in futures if future.exception() is None]
    failures = [future.exception() for future in futures if future.exception() is not None]
    assert len(successes) == 1
    assert len(failures) == 1
    assert isinstance(failures[0], ProofTokenError)
    assert "already been used" in str(failures[0])

    # Tenant scope prevents one tenant's accepted proof from poisoning another tenant's set.
    assert verifier.verify(
        token, "tnt_bank-b", memtara_chain_head=CHAIN_HEAD, now=now
    ).jti == successes[0].jti


def test_partial_memtara_configuration_is_refused(monkeypatch) -> None:
    from mizan_control_plane.config import Settings

    monkeypatch.setenv("MIZAN_DATABASE_URL", "postgresql://unused")
    monkeypatch.setenv("MIZAN_JWT_ISSUER", "issuer")
    monkeypatch.setenv("MIZAN_IDENTITY_JWKS", UNUSED_IDENTITY_JWKS)
    monkeypatch.setenv("MIZAN_MEMTARA_TRUSTED_ISSUER", ISSUER)
    monkeypatch.delenv("MIZAN_MEMTARA_JWKS_URL", raising=False)
    with pytest.raises(RuntimeError, match="must be set together"):
        Settings.from_environment()
