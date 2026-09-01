from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mizan_control_plane.keys import local_private_key_for_testing
from mizan_control_plane.schema_validation import ContractSchemas
from mizan_security.degraded import (
    DegradedAllowGate,
    DegradedGrantVerifier,
    DegradedModeError,
    EncryptedDegradedWal,
    InMemoryNonceRegistry,
    TrustedGrantIssuer,
)


def signed_grant(key: Ed25519PrivateKey, **updates: object) -> dict:
    now = datetime.now(UTC)
    grant = {
        "schema_version": "1.2",
        "grant_id": "dgr_test-grant-0001",
        "tenant_id": "tnt_bank-a",
        "risk_ceiling": "LOW",
        "allowed_components": ["risk_engine"],
        "max_duration_seconds": 3600,
        "issued_at": now.isoformat().replace("+00:00", "Z"),
        "not_before": (now - timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
        "issued_by": "mizan-tenant-admin",
        "signature_algorithm": "EdDSA",
        "canonicalization": "RFC8785",
        "key_ref": "kms://degraded/issuer-1",
        "nonce": "dgn_0123456789abcdef",
    } | updates
    grant["signature"] = (
        base64.urlsafe_b64encode(key.sign(rfc8785.dumps(grant))).decode().rstrip("=")
    )
    return grant


def gate(tmp_path, *, enabled: bool = True, max_bytes: int = 100_000):
    issuer_key = local_private_key_for_testing("degraded-issuer")
    verifier = DegradedGrantVerifier(
        [
            TrustedGrantIssuer(
                "mizan-tenant-admin", "kms://degraded/issuer-1", "EdDSA", issuer_key.public_key()
            )
        ],
        InMemoryNonceRegistry(),
    )
    wal = EncryptedDegradedWal(
        tmp_path / "degraded.wal",
        b"k" * 32,
        local_private_key_for_testing("degraded-receipt"),
        "kms://degraded/wal-1",
        max_bytes=max_bytes,
    )
    return DegradedAllowGate(enabled, verifier, wal), issuer_key


def test_i21_i26_degraded_allow_requires_all_gates_and_fsynced_receipt(tmp_path) -> None:
    subject, issuer_key = gate(tmp_path)
    grant = signed_grant(issuer_key)
    ContractSchemas(Path("SPEC_v1.md")).validate("DegradedModeGrant", grant)
    result = subject.authorize(
        tenant_id="tnt_bank-a",
        risk_level="LOW",
        policy={"decision": "ALLOW", "fail_open_allowed": True},
        failed_component="risk_engine",
        grant=grant,
        adr_record={"decision": "ALLOW", "payload": "safe"},
    )
    assert result["record"]["degraded"]["is_degraded"] is True
    assert result["record"]["degraded"]["reason"] == "risk_engine_down"
    assert result["record"]["degraded"]["buffered_at"].endswith("Z")
    assert len(result["local_receipt"]["signature"]) >= 64
    assert (tmp_path / "degraded.wal").read_bytes() != rfc8785.dumps(result["record"])


@pytest.mark.parametrize(
    "risk,policy_enabled,component",
    [
        ("MEDIUM", True, "risk_engine"),
        ("LOW", False, "risk_engine"),
        ("LOW", True, "policy_engine"),
    ],
)
def test_degraded_path_fails_closed(
    risk: str, policy_enabled: bool, component: str, tmp_path
) -> None:
    subject, issuer_key = gate(tmp_path)
    with pytest.raises(DegradedModeError):
        subject.authorize(
            tenant_id="tnt_bank-a",
            risk_level=risk,
            policy={"decision": "ALLOW", "fail_open_allowed": policy_enabled},
            failed_component=component,
            grant=signed_grant(issuer_key),
            adr_record={"decision": "ALLOW"},
        )


def test_grant_replay_and_wal_capacity_fail_closed(tmp_path) -> None:
    subject, issuer_key = gate(tmp_path, max_bytes=1024)
    grant = signed_grant(issuer_key)
    arguments = dict(
        tenant_id="tnt_bank-a",
        risk_level="LOW",
        policy={"decision": "ALLOW", "fail_open_allowed": True},
        failed_component="risk_engine",
        grant=grant,
        adr_record={"decision": "ALLOW", "data": "x" * 100},
    )
    subject.authorize(**arguments)
    with pytest.raises(DegradedModeError, match="nonce"):
        subject.authorize(**arguments)
    fresh = signed_grant(issuer_key, nonce="dgn_fedcba9876543210")
    with pytest.raises(DegradedModeError, match="capacity"):
        subject.authorize(**(arguments | {"grant": fresh, "adr_record": {"data": "x" * 5000}}))


def test_caller_supplied_unknown_key_never_establishes_trust(tmp_path) -> None:
    subject, _ = gate(tmp_path)
    attacker = local_private_key_for_testing("degraded-attacker")
    with pytest.raises(DegradedModeError, match="trusted"):
        subject.authorize(
            tenant_id="tnt_bank-a",
            risk_level="LOW",
            policy={"decision": "ALLOW", "fail_open_allowed": True},
            failed_component="risk_engine",
            grant=signed_grant(attacker, key_ref="kms://attacker/key"),
            adr_record={"decision": "ALLOW"},
        )
