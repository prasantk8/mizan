from __future__ import annotations

import base64
import hashlib
import hmac
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal, Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

KeyRole = Literal["evidence-receipt", "evidence-anchor", "execution-token", "degraded-grant"]
KeyCustody = Literal["development-derived", "kms", "hsm"]
KEY_ROLES: tuple[KeyRole, ...] = (
    "evidence-receipt",
    "evidence-anchor",
    "execution-token",
    "degraded-grant",
)

# The fifth role, and the one that is not a signing key (T-054, B-30 ruled 2026-09-02).
#
# `MIZAN_AUDIT_HMAC_KEY_REF` has been registered in `SPEC_v1.md` and contracted by ADR-004
# Amendment A as "held under separate authority" since the baseline, with **no custody**: it was
# not one of G.1's four ratified roles and the check below enforced that set literally, so the one
# key in the system that touches customer data directly was the only one outside the module whose
# entire subject is key custody. That is TM-001 R-2.
#
# It cannot be a fifth `KeyRole`, and the reason is not a naming inconvenience: a MAC key has no
# public half. `SigningKey` requires `public_key() -> Ed25519PublicKey`, and a symmetric key that
# grew such a member would be a defect waiting to be called by anything that iterates roles.
MacRole = Literal["audit-commitment"]
MAC_ROLES: tuple[MacRole, ...] = ("audit-commitment",)
AnyRole = KeyRole | MacRole

# HMAC-SHA256 per ADR-004 Amendment A. Named here rather than spelled in four places, because the
# commitment algorithm appears in every stored audit record and changing it is a schema decision.
MAC_ALGORITHM = "HMAC-SHA256"
MAC_DIGEST_BYTES = 32


class SigningKey(Protocol):
    key_id: str
    role: KeyRole

    def sign(self, payload: bytes) -> bytes: ...

    def public_key(self) -> Ed25519PublicKey: ...


class MacKey(Protocol):
    """A key that authenticates a commitment and **cannot** verify one to a third party.

    Deliberately not a `SigningKey`, and deliberately without a `public_key()` member. ADR-004 §96
    states the property this protocol exists to preserve: the pre-redaction commitment is
    *"keyed, so dictionary attack fails; verification requires the key, which is the point."*
    Anyone who could verify a `source_commitment` could also mount the dictionary attack that
    invariant I-12 exists to defeat, because the committed values are low-entropy PII.
    """

    key_id: str
    role: MacRole

    def mac(self, payload: bytes) -> bytes: ...


class KeyProvider(Protocol):
    def active_key(self, role: KeyRole) -> SigningKey: ...

    def active_mac_key(self, role: MacRole) -> MacKey: ...

    def verification_keyset(self) -> list[dict[str, Any]]: ...

    def commitment_keyset(self) -> list[dict[str, Any]]: ...


# Why `commitment_keyset()` is a second method and not five more rows in the first one.
#
# **This corrects B-30's own recommendation**, which said the published keyset "needs entries that
# deliberately carry no key". It does not, and following that advice would have broken the product
# in three places for a key no recipient can ever use:
#
#   * `evidence_export.load_public_keyset` raises `ValueError` on any `algorithm != "Ed25519"`, so
#     the exporter would have **refused to produce a bundle at all** -- and `scripts/demo.sh` pipes
#     `/v1/audit/keys` straight into `--keyset`, so that is the documented operator path;
#   * `scripts/verify_evidence_export.py` requires `public_key` on every entry and raises
#     `VerificationFailure` on a foreign algorithm;
#   * `verifier-two` reports `MALFORMED` for the same input -- a *different verdict for the same
#     cause*, which is B-29's disagreement reappearing in a new place.
#
# Three independent refusals are the system being right, not three obstacles to route around.
# `verification_keyset()` means *the keys with which a third party verifies a signature*, it is
# copied verbatim into every export bundle under ADR-004 G.1, and **no third party can ever verify
# an HMAC** -- that is the ratified point of the construction, not an omission. A MAC entry there
# would be a category error that also happens to be a bundle-format change.
#
# So the commitment keyset is served to the tenant operator who *holds* the key, at
# `/v1/audit/commitment-keys`, and never enters a bundle. It publishes `key_id`, `role`, `custody`,
# `algorithm` and the rotation window -- everything needed to resolve `source_commitment.key_ref`
# and to tell which key was in force -- and no key material. Bundle format 1.1 is untouched, both
# verifiers are untouched, and B-24's demonstration requirement is not triggered.


@dataclass(frozen=True, slots=True)
class KeyVersion:
    key_id: str
    role: AnyRole
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


@dataclass(frozen=True, slots=True)
class LocalMacKey:
    """Development commitment key, derived exactly as the development signing keys are.

    `sha256(key_id)` and the `key_id` is quoted in every record that used it, so **every
    development `source_commitment` is forgeable by anyone who reads one**, in the same way and for
    the same reason that a development-signed bundle is. That is deliberate and is the reason
    `LocalKeyProvider` refuses production; `custody` says `development-derived` so nothing
    downstream has to infer it.
    """

    key_id: str
    role: MacRole
    _secret: bytes

    def mac(self, payload: bytes) -> bytes:
        return hmac.new(self._secret, payload, hashlib.sha256).digest()


def _split_roles(versions: list[KeyVersion]) -> tuple[list[KeyVersion], list[KeyVersion]]:
    signing = [item for item in versions if item.role in KEY_ROLES]
    mac = [item for item in versions if item.role in MAC_ROLES]
    unknown = {item.role for item in versions} - set(KEY_ROLES) - set(MAC_ROLES)
    if unknown:
        raise RuntimeError(f"unknown key roles configured: {sorted(unknown)}")
    return signing, mac


def _sole_active(versions: list[KeyVersion], role: AnyRole, noun: str) -> KeyVersion:
    candidates = [
        item for item in versions
        if item.role == role and item.not_after is None and item.revoked_at is None
    ]
    if len(candidates) != 1:
        raise RuntimeError(f"role {role} must have exactly one active {noun}")
    return candidates[0]


class LocalKeyProvider:
    """Deterministic development adapter; forbidden in production."""

    def __init__(self, versions: list[KeyVersion], environment: str = "development") -> None:
        if environment == "production":
            raise RuntimeError("production refuses development-derived signing keys")
        signing, mac = _split_roles(versions)
        if {item.role for item in signing} != set(KEY_ROLES):
            raise RuntimeError("all four separately-held signing key roles must be configured")
        if {item.role for item in mac} != set(MAC_ROLES):
            # Not optional, and not defaulted. An audit write whose commitment key is missing must
            # fail closed at startup rather than at the write -- I-19 makes a missing redaction
            # attestation a refused write, and a provider that quietly omitted the key would turn
            # that into a runtime outage on the everything-else ledger.
            raise RuntimeError("the audit commitment MAC key role must be configured (T-054)")
        active_refs = [item.key_id for item in versions if item.not_after is None and item.revoked_at is None]
        if len(active_refs) != len(set(active_refs)):
            raise RuntimeError("active key references must be distinct across roles")
        self.versions = list(signing)
        self.mac_versions = list(mac)
        self._keys = {
            item.key_id: LocalSigningKey(
                item.key_id,
                item.role,
                Ed25519PrivateKey.from_private_bytes(hashlib.sha256(item.key_id.encode()).digest()),
            )
            for item in signing
        }
        self._mac_keys = {
            item.key_id: LocalMacKey(
                item.key_id, item.role, hashlib.sha256(item.key_id.encode()).digest()
            )
            for item in mac
        }

    def active_key(self, role: KeyRole) -> SigningKey:
        return self._keys[_sole_active(self.versions, role, "signing key").key_id]

    def active_mac_key(self, role: MacRole) -> MacKey:
        return self._mac_keys[_sole_active(self.mac_versions, role, "commitment key").key_id]

    def verification_keyset(self) -> list[dict[str, Any]]:
        return [
            {
                "key_id": item.key_id,
                "role": item.role,
                "custody": "development-derived",
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

    def commitment_keyset(self) -> list[dict[str, Any]]:
        return _commitment_documents(self.mac_versions, "development-derived")


def _commitment_documents(
    versions: list[KeyVersion], custody: KeyCustody
) -> list[dict[str, Any]]:
    """The published shape of a commitment key: everything but the key.

    `public_key` is **absent**, not `null`. A member present and empty invites a reader to treat it
    as material that failed to load; a member that is not there says the object has no such thing.
    """
    return [
        {
            "key_id": item.key_id,
            "role": item.role,
            "custody": custody,
            "algorithm": MAC_ALGORITHM,
            "not_before": item.not_before,
            "not_after": item.not_after,
            "revoked_at": item.revoked_at,
        }
        for item in versions
    ]


class KmsHsmBackend(Protocol):
    def sign(self, key_ref: str, payload: bytes) -> bytes: ...

    def public_key(self, key_ref: str) -> Ed25519PublicKey: ...

    def mac(self, key_ref: str, payload: bytes) -> bytes: ...


@dataclass(frozen=True, slots=True)
class KmsSigningKey:
    key_id: str
    role: KeyRole
    backend: KmsHsmBackend

    def sign(self, payload: bytes) -> bytes:
        return self.backend.sign(self.key_id, payload)

    def public_key(self) -> Ed25519PublicKey:
        return self.backend.public_key(self.key_id)


@dataclass(frozen=True, slots=True)
class KmsCommitmentKey:
    key_id: str
    role: MacRole
    backend: KmsHsmBackend

    def mac(self, payload: bytes) -> bytes:
        return self.backend.mac(self.key_id, payload)


class KmsHsmKeyProvider:
    """Vendor-neutral working sign-in-place adapter; the injected backend owns private material."""

    def __init__(
        self,
        versions: list[KeyVersion],
        backend: KmsHsmBackend,
        custody: Literal["kms", "hsm"] = "kms",
    ) -> None:
        if any(item.key_id.startswith("local://") for item in versions):
            raise RuntimeError("KMS/HSM provider rejects local:// key references")
        signing, mac = _split_roles(versions)
        self.versions = signing
        self.mac_versions = mac
        self.backend = backend
        self.custody = custody

    def active_key(self, role: KeyRole) -> SigningKey:
        item = _sole_active(self.versions, role, "signing key")
        return KmsSigningKey(item.key_id, item.role, self.backend)

    def active_mac_key(self, role: MacRole) -> MacKey:
        item = _sole_active(self.mac_versions, role, "commitment key")
        return KmsCommitmentKey(item.key_id, item.role, self.backend)

    def commitment_keyset(self) -> list[dict[str, Any]]:
        return _commitment_documents(self.mac_versions, self.custody)

    def verification_keyset(self) -> list[dict[str, Any]]:
        documents = []
        for item in self.versions:
            key = self.backend.public_key(item.key_id)
            documents.append({
                "key_id": item.key_id,
                "role": item.role,
                "custody": self.custody,
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
        [
            KeyVersion(f"local://{role}/dev-1", role, now)
            for role in (*KEY_ROLES, *MAC_ROLES)
        ],
        environment,
    )


def local_private_key_for_testing(label: str) -> Ed25519PrivateKey:
    """Test-only deterministic key material; never selected by runtime configuration."""
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode()).digest())
