from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mizan_control_plane.execution import ExecutionTokenCodec
from mizan_control_plane.problems import Problem


def claims() -> dict:
    now = datetime.now(UTC)
    return {
        "token_version": "1.2",
        "jti": "0123456789abcdef",
        "iss": "https://issuer.mizan.test",
        "aud": "mizan-execution-gateway",
        "tenant_id": "tnt_bank-a",
        "agent_id": "agt_wealth-01",
        "principal_id": "prn_alice",
        "delegation_chain_hash": "a" * 64,
        "authorized_executor": "spiffe://mizan/executor/wealth",
        "decision_id": "adr_decision-0001",
        "tool_id": "tool_transfer",
        "parameters_hash": "b" * 64,
        "binding_profile": {"profile_id": "bp_transfer-v1", "profile_version": 1},
        "context_hash": "c" * 64,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
    }


def test_execution_codec_rejects_tampering_and_wrong_issuer() -> None:
    codec = ExecutionTokenCodec("https://issuer.mizan.test", Ed25519PrivateKey.generate())
    token = codec.encode(claims())
    assert codec.decode(token)["authorized_executor"] == "spiffe://mizan/executor/wealth"
    header, payload, signature = token.split(".")
    with pytest.raises(Problem):
        codec.decode(f"{header}.{payload[:-1]}A.{signature}")
    other = ExecutionTokenCodec("https://other-issuer.test", codec.private_key)
    with pytest.raises(Problem):
        other.decode(token)


@pytest.mark.parametrize(
    ("mutation", "expected_message"),
    [
        (lambda payload: payload.pop("parameters_hash"), "malformed"),
        (lambda payload: payload.update({"tool_id": "pol_wrong-prefix"}), "malformed"),
        (lambda payload: payload.update({"unbound_claim": "surprise"}), "malformed"),
    ],
)
def test_execution_codec_rejects_signed_but_nonconforming_claims(
    mutation, expected_message
) -> None:
    codec = ExecutionTokenCodec("https://issuer.mizan.test", Ed25519PrivateKey.generate())
    payload = claims()
    mutation(payload)
    # Bypass encode's issuer-side contract gate to model a compromised or older issuer.
    token = jwt.encode(payload, codec.private_key, algorithm="EdDSA")
    with pytest.raises(Problem, match=expected_message):
        codec.decode(token)
