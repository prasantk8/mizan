from __future__ import annotations

import base64
import hashlib
import os
import struct
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class DegradedModeError(RuntimeError):
    pass


class DegradedState:
    """Build the one truthful dependency-state vocabulary used by authorization evidence."""

    _REASONS = {
        "risk_engine": "risk_engine_down",
        "policy_cache": "policy_cache_down",
        "record_store": "store_down",
        # The policy engine is deliberately reportable but never eligible for degraded ALLOW.
        "policy_engine": "policy_engine_down",
    }

    @staticmethod
    def healthy() -> dict[str, Any]:
        return {"is_degraded": False, "reason": "none", "grant_ref": None}

    @classmethod
    def dependency_failure(
        cls,
        failed_component: str,
        *,
        grant_ref: str | None = None,
        buffered_at: datetime | None = None,
    ) -> dict[str, Any]:
        try:
            reason = cls._REASONS[failed_component]
        except KeyError as exc:
            raise DegradedModeError(
                f"unknown degraded dependency {failed_component!r}"
            ) from exc
        state: dict[str, Any] = {
            "is_degraded": True,
            "reason": reason,
            "grant_ref": grant_ref,
        }
        if buffered_at is not None:
            state["buffered_at"] = buffered_at.isoformat().replace("+00:00", "Z")
        return state


class NonceRegistry(Protocol):
    def consume(self, tenant_id: str, nonce: str) -> bool: ...


class InMemoryNonceRegistry:
    def __init__(self) -> None:
        self.used: set[tuple[str, str]] = set()

    def consume(self, tenant_id: str, nonce: str) -> bool:
        key = tenant_id, nonce
        if key in self.used:
            return False
        self.used.add(key)
        return True


@dataclass(frozen=True, slots=True)
class TrustedGrantIssuer:
    issued_by: str
    key_ref: str
    algorithm: str
    public_key: Ed25519PublicKey


class DegradedGrantVerifier:
    def __init__(self, issuers: list[TrustedGrantIssuer], nonces: NonceRegistry) -> None:
        self.issuers = {(issuer.issued_by, issuer.key_ref): issuer for issuer in issuers}
        self.nonces = nonces

    def verify(
        self,
        grant: dict[str, Any],
        tenant_id: str,
        failed_component: str,
        now: datetime | None = None,
    ) -> None:
        now = now or datetime.now(UTC)
        issuer = self.issuers.get((grant.get("issued_by"), grant.get("key_ref")))
        if (
            not issuer
            or issuer.algorithm != grant.get("signature_algorithm")
            or issuer.algorithm != "EdDSA"
        ):
            raise DegradedModeError("grant issuer/key/algorithm is not trusted")
        if grant.get("tenant_id") != tenant_id or grant.get("risk_ceiling") != "LOW":
            raise DegradedModeError("grant tenant or risk ceiling mismatch")
        if failed_component not in grant.get("allowed_components", []):
            raise DegradedModeError("grant does not cover failed component")
        issued = datetime.fromisoformat(grant["issued_at"].replace("Z", "+00:00"))
        not_before = datetime.fromisoformat(grant["not_before"].replace("Z", "+00:00"))
        expires = datetime.fromisoformat(grant["expires_at"].replace("Z", "+00:00"))
        if not (
            not_before <= now < expires <= issued + timedelta(seconds=grant["max_duration_seconds"])
        ):
            raise DegradedModeError("grant is outside its trusted time window")
        unsigned = {key: value for key, value in grant.items() if key != "signature"}
        try:
            signature = base64.urlsafe_b64decode(
                grant["signature"] + "=" * (-len(grant["signature"]) % 4)
            )
            issuer.public_key.verify(signature, rfc8785.dumps(unsigned))
        except Exception as exc:
            raise DegradedModeError("grant signature is invalid") from exc
        if not self.nonces.consume(tenant_id, grant["nonce"]):
            raise DegradedModeError("grant nonce is revoked or already used")


class EncryptedDegradedWal:
    """Capacity-bounded encrypted append WAL; receipt is signed only after fsync."""

    def __init__(
        self,
        path: Path,
        encryption_key: bytes,
        receipt_key: Ed25519PrivateKey,
        key_ref: str,
        max_bytes: int = 1_073_741_824,
        replay_deadline_seconds: int = 300,
    ) -> None:
        if len(encryption_key) != 32:
            raise ValueError("degraded WAL requires a 256-bit encryption key")
        if max_bytes < 1024:
            raise ValueError("degraded WAL capacity is too small")
        self.path = path.resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.cipher = AESGCM(encryption_key)
        self.receipt_key = receipt_key
        self.key_ref = key_ref
        self.max_bytes = max_bytes
        self.replay_deadline_seconds = replay_deadline_seconds

    def append(self, tenant_id: str, record: dict[str, Any]) -> dict[str, Any]:
        plaintext = rfc8785.dumps(record)
        nonce = os.urandom(12)
        ciphertext = self.cipher.encrypt(nonce, plaintext, tenant_id.encode())
        frame = struct.pack(">I", len(nonce) + len(ciphertext)) + nonce + ciphertext
        current_size = self.path.stat().st_size if self.path.exists() else 0
        if current_size + len(frame) > self.max_bytes:
            raise DegradedModeError("degraded WAL capacity exhausted")
        try:
            descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(descriptor, "ab") as handle:
                handle.write(frame)
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            raise DegradedModeError("degraded WAL fsync failed") from exc
        now = datetime.now(UTC)
        receipt = {
            "tenant_id": tenant_id,
            "record_hash": hashlib.sha256(plaintext).hexdigest(),
            "wal_offset": current_size,
            "wal_length": len(frame),
            "key_ref": self.key_ref,
            "written_at": now.isoformat().replace("+00:00", "Z"),
            "replay_deadline": (now + timedelta(seconds=self.replay_deadline_seconds))
            .isoformat()
            .replace("+00:00", "Z"),
        }
        receipt["signature"] = (
            base64.urlsafe_b64encode(self.receipt_key.sign(rfc8785.dumps(receipt)))
            .decode()
            .rstrip("=")
        )
        return receipt


class DegradedAllowGate:
    def __init__(
        self,
        enabled: bool,
        verifier: DegradedGrantVerifier,
        wal: EncryptedDegradedWal,
    ) -> None:
        self.enabled = enabled
        self.verifier = verifier
        self.wal = wal

    def authorize(
        self,
        *,
        tenant_id: str,
        risk_level: str,
        policy: dict[str, Any],
        failed_component: str,
        grant: dict[str, Any],
        adr_record: dict[str, Any],
    ) -> dict[str, Any]:
        if not self.enabled or not policy.get("fail_open_allowed", False):
            raise DegradedModeError("degraded allow is not explicitly enabled")
        if risk_level != "LOW" or policy.get("decision") not in {"ALLOW", "CONSTRAIN", "REDACT"}:
            raise DegradedModeError("degraded allow is restricted to LOW-risk executable policies")
        if failed_component == "policy_engine":
            raise DegradedModeError("policy engine failure can never degrade open")
        self.verifier.verify(grant, tenant_id, failed_component)
        record = dict(adr_record)
        record["decision_basis"] = "degraded_grant"
        record["degraded"] = DegradedState.dependency_failure(
            failed_component,
            grant_ref=grant["grant_id"],
            buffered_at=datetime.now(UTC),
        )
        return {"record": record, "local_receipt": self.wal.append(tenant_id, record)}
