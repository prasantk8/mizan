from __future__ import annotations

import json
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mizan_control_plane.auth import IdentityKeySet, TokenVerifier
from mizan_control_plane.dev_token import public_jwks
from mizan_control_plane.problems import Problem


def test_rotation_drill_accepts_both_keys_only_during_overlap() -> None:
    from scripts.identity_key_rotation_drill import run_drill, validate_report

    report = run_drill()
    assert validate_report(report) == []
    assert report["stages"][-1]["old_token"] == "refused:identity_token_kid_unknown"


def test_rotation_gate_rejects_the_static_pem_replacement_output() -> None:
    from scripts.identity_key_rotation_drill import validate_report

    report = json.loads(
        Path("tests/fixtures/identity-key-rotation/pre-fix-8047820.json").read_text(
            encoding="utf-8"
        )
    )
    assert validate_report(report) == [
        "rotation stages must prove old-only, old+new overlap, and new-only retirement with the "
        "expected accept/refuse outcomes"
    ]


def test_identity_token_without_kid_is_refused_before_signature_verification() -> None:
    private_key = Ed25519PrivateKey.generate()
    verifier = TokenVerifier("issuer", "audience", public_jwks(private_key, "identity-1"))
    token = jwt.encode({}, private_key, algorithm="EdDSA")
    with pytest.raises(Problem) as raised:
        verifier.verify(token)
    assert raised.value.code == "identity_token_kid_missing"


def test_identity_token_cannot_change_the_algorithm_bound_to_its_kid() -> None:
    private_key = Ed25519PrivateKey.generate()
    verifier = TokenVerifier("issuer", "audience", public_jwks(private_key, "identity-1"))
    token = jwt.encode({}, private_key, algorithm="EdDSA", headers={"kid": "identity-1"})
    header, payload, signature = token.split(".")
    confused_header = jwt.utils.base64url_encode(
        json.dumps({"alg": "ES256", "kid": "identity-1", "typ": "JWT"}).encode()
    ).decode()
    confused = ".".join((confused_header, payload, signature))
    with pytest.raises(Problem) as raised:
        verifier.verify(confused)
    assert raised.value.code == "identity_token_algorithm_mismatch"


def test_identity_keyset_rejects_duplicate_kids() -> None:
    private_key = Ed25519PrivateKey.generate()
    key = json.loads(public_jwks(private_key, "identity-1"))["keys"][0]
    with pytest.raises(ValueError, match="duplicate kid"):
        IdentityKeySet(json.dumps({"keys": [key, key]}))


def test_identity_keyset_rejects_private_key_material() -> None:
    private_key = Ed25519PrivateKey.generate()
    key = json.loads(public_jwks(private_key, "identity-1"))["keys"][0]
    key["d"] = "must-not-enter-the-control-plane"
    with pytest.raises(ValueError, match="private key material"):
        IdentityKeySet(json.dumps({"keys": [key]}))


def test_identity_keyset_rejects_symmetric_algorithms() -> None:
    with pytest.raises(ValueError, match="must declare one of"):
        IdentityKeySet(
            json.dumps(
                {
                    "keys": [
                        {"kid": "shared-secret", "kty": "oct", "alg": "HS256", "use": "sig", "k": "YWJj"}
                    ]
                }
            )
        )
