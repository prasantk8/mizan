from __future__ import annotations

import base64
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


def test_missing_or_malformed_chain_head_is_refused_by_the_uc2_verifier(material) -> None:
    now, private_key, cache = material
    verifier = MemtaraProofVerifier(ISSUER, cache.jwks_url, jwks=cache)
    token = _token(private_key, _claims(now))
    with pytest.raises(ProofTokenError, match="requires a chain head"):
        verifier.verify(token, "tnt_bank-a", memtara_chain_head=None, now=now)
    with pytest.raises(ProofTokenError, match="chain head"):
        verifier.verify(token, "tnt_bank-a", memtara_chain_head="ABC", now=now)


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
    monkeypatch.setenv("MIZAN_JWT_PUBLIC_KEY", "key")
    monkeypatch.setenv("MIZAN_MEMTARA_TRUSTED_ISSUER", ISSUER)
    monkeypatch.delenv("MIZAN_MEMTARA_JWKS_URL", raising=False)
    with pytest.raises(RuntimeError, match="must be set together"):
        Settings.from_environment()
