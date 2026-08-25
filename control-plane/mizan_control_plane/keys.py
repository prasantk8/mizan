from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal, Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

KeyRole = Literal["evidence-receipt", "evidence-anchor", "execution-token", "degraded-grant"]
KEY_ROLES: tuple[KeyRole, ...] = (
    "evidence-receipt",
    "evidence-anchor",
    "execution-token",
    "degraded-grant",
)


class SigningKey(Protocol):
    key_id: str
    role: KeyRole

    def sign(self, payload: bytes) -> bytes: ...

    def public_key(self) -> Ed25519PublicKey: ...


class KeyProvider(Protocol):
    def active_key(self, role: KeyRole) -> SigningKey: ...

    def verification_keyset(self) -> list[dict[str, Any]]: ...


@dataclass(frozen=True, slots=True)
class KeyVersion:
    key_id: str
    role: KeyRole
    not_before: str
    not_after: str | None = None
    revoked_at: str | None = None


@dataclass(frozen=True, slots=True)
class LocalSigningKey:
    key_id: str
    role: KeyRole
    _key: Ed25519PrivateKey

    def sign(self, payload: bytes) -> bytes:
        return self._key.sign(payload)

    def public_key(self) -> Ed25519PublicKey:
        return self._key.public_key()


class LocalKeyProvider:
    """Deterministic development adapter; forbidden in production."""

    def __init__(self, versions: list[KeyVersion], environment: str = "development") -> None:
        if environment == "production" and any(item.key_id.startswith("local://") for item in versions):
            raise RuntimeError("production refuses local:// signing keys")
        roles = {item.role for item in versions}
        if roles != set(KEY_ROLES):
            raise RuntimeError("all four separately-held key roles must be configured")
        active_refs = [item.key_id for item in versions if item.not_after is None and item.revoked_at is None]
        if len(active_refs) != len(set(active_refs)):
            raise RuntimeError("active signing key references must be distinct across roles")
        self.versions = list(versions)
        self._keys = {
            item.key_id: LocalSigningKey(
                item.key_id,
                item.role,
                Ed25519PrivateKey.from_private_bytes(hashlib.sha256(item.key_id.encode()).digest()),
            )
            for item in versions
        }

    def active_key(self, role: KeyRole) -> SigningKey:
        candidates = [
            item for item in self.versions
            if item.role == role and item.not_after is None and item.revoked_at is None
        ]
        if len(candidates) != 1:
            raise RuntimeError(f"role {role} must have exactly one active signing key")
        return self._keys[candidates[0].key_id]

    def verification_keyset(self) -> list[dict[str, Any]]:
        return [
            {
                "key_id": item.key_id,
                "role": item.role,
                "algorithm": "Ed25519",
                "public_key": base64.urlsafe_b64encode(
                    self._keys[item.key_id].public_key().public_bytes(
                        serialization.Encoding.Raw, serialization.PublicFormat.Raw
                    )
                ).decode(),
                "not_before": item.not_before,
                "not_after": item.not_after,
                "revoked_at": item.revoked_at,
            }
            for item in self.versions
        ]


class KmsHsmBackend(Protocol):
    def sign(self, key_ref: str, payload: bytes) -> bytes: ...

    def public_key(self, key_ref: str) -> Ed25519PublicKey: ...


@dataclass(frozen=True, slots=True)
class KmsSigningKey:
    key_id: str
    role: KeyRole
    backend: KmsHsmBackend

    def sign(self, payload: bytes) -> bytes:
        return self.backend.sign(self.key_id, payload)

    def public_key(self) -> Ed25519PublicKey:
        return self.backend.public_key(self.key_id)


class KmsHsmKeyProvider:
    """Vendor-neutral working sign-in-place adapter; the injected backend owns private material."""

    def __init__(self, versions: list[KeyVersion], backend: KmsHsmBackend) -> None:
        if any(item.key_id.startswith("local://") for item in versions):
            raise RuntimeError("KMS/HSM provider rejects local:// key references")
        self.versions = list(versions)
        self.backend = backend

    def active_key(self, role: KeyRole) -> SigningKey:
        candidates = [
            item for item in self.versions
            if item.role == role and item.not_after is None and item.revoked_at is None
        ]
        if len(candidates) != 1:
            raise RuntimeError(f"role {role} must have exactly one active signing key")
        item = candidates[0]
        return KmsSigningKey(item.key_id, item.role, self.backend)

    def verification_keyset(self) -> list[dict[str, Any]]:
        documents = []
        for item in self.versions:
            key = self.backend.public_key(item.key_id)
            documents.append({
                "key_id": item.key_id,
                "role": item.role,
                "algorithm": "Ed25519",
                "public_key": base64.urlsafe_b64encode(key.public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw
                )).decode(),
                "not_before": item.not_before,
                "not_after": item.not_after,
                "revoked_at": item.revoked_at,
            })
        return documents


def development_key_provider(environment: str = "development") -> LocalKeyProvider:
    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    return LocalKeyProvider(
        [KeyVersion(f"local://{role}/dev-1", role, now) for role in KEY_ROLES],
        environment,
    )


def local_private_key_for_testing(label: str) -> Ed25519PrivateKey:
    """Test-only deterministic key material; never selected by runtime configuration."""
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode()).digest())
