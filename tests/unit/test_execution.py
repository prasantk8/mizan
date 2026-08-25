from __future__ import annotations

from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mizan_control_plane.execution import ExecutionService, ExecutionTokenCodec
from mizan_control_plane.problems import Problem
from psycopg_pool import PoolTimeout


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


def test_second_registered_executor_is_selected_and_outsider_fails_both_boundaries() -> None:
    tool = {
        "execution": {
            "executor_spiffe_ids": [
                "spiffe://mizan/executor/wealth",
                "spiffe://mizan/executor/settlement",
            ]
        }
    }
    assert ExecutionService._authorized_executor(
        tool, "spiffe://mizan/executor/settlement"
    ) == "spiffe://mizan/executor/settlement"
    with pytest.raises(Problem) as issue_error:
        ExecutionService._authorized_executor(tool, "spiffe://mizan/executor/attacker")
    assert issue_error.value.status == 403

    codec = ExecutionTokenCodec("https://issuer.mizan.test", Ed25519PrivateKey.generate())
    service = object.__new__(ExecutionService)
    service.codec = codec
    token = codec.encode(claims())
    with pytest.raises(Problem) as redeem_error:
        service.redeem(
            token,
            claims()["decision_id"],
            "spiffe://mizan/executor/attacker",
            {},
        )
    assert redeem_error.value.status == 403


def test_delegation_less_stored_document_is_controlled_403() -> None:
    with pytest.raises(Problem) as raised:
        ExecutionService._require_delegation_edge({}, "agt_child-01")
    assert raised.value.status == 403
    assert raised.value.code == "delegation_authority_changed"


class AlwaysTimeoutPool:
    def connection(self):
        raise PoolTimeout("security event pool saturated")


def test_replay_security_events_use_bounded_pool_without_exhausting_primary() -> None:
    service = object.__new__(ExecutionService)
    service.security_event_pool = AlwaysTimeoutPool()
    service.security_event_counters = Counter()
    service.pool = object()  # A primary-pool access would fail: it has no connection method.

    with ThreadPoolExecutor(max_workers=16) as workers:
        futures = [
            workers.submit(
                service._record_security_event,
                "tnt_bank-a",
                "mizan.security.execution_token_replay",
                "adr_decision-0001",
                f"jti-{index}",
                "spiffe://mizan/executor/wealth",
            )
            for index in range(64)
        ]
        for future in futures:
            future.result(timeout=1)
    assert service.security_event_counters["security_event_pool_timeout"] == 64
