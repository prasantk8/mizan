"""The composition root.

Everything that turns configuration into a running control plane happens here and nowhere else.
Production refuses to boot without a signing key provider, an evidence verifier and an execution
service: a control plane that authorizes but cannot sign, verify or bind execution is not a
degraded Mizan, it is a different product.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import FastAPI

from .app import create_app
from .config import Settings
from .evidence import EvidenceRepository, LocalImmutableObjectStore, ObjectEvidenceVerifier
from .execution import ExecutionService, ExecutionTokenCodec
from .keys import KEY_ROLES, KeyProvider, KeyVersion, LocalKeyProvider


class StartupRefused(RuntimeError):
    """Configuration that would run, but not with the guarantees Mizan claims."""


def build_key_provider(settings: Settings) -> KeyProvider:
    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    versions = [
        KeyVersion(reference, role, now)
        for role, reference in zip(KEY_ROLES, settings.signing_key_refs, strict=True)
    ]
    if settings.key_custody_mode == "development":
        return LocalKeyProvider(versions, settings.environment)
    raise StartupRefused(
        f"key custody mode {settings.key_custody_mode!r} names no built backend. "
        "KmsHsmKeyProvider exists but has no implementation to inject; see T-076 and blocker B-18. "
        "Refusing to start rather than signing evidence with publicly derivable development keys."
    )


def verification_public_keys(provider: KeyProvider) -> dict[str, Ed25519PublicKey]:
    return {
        document["key_id"]: Ed25519PublicKey.from_public_bytes(
            base64.urlsafe_b64decode(document["public_key"])
        )
        for document in provider.verification_keyset()
    }


def build_evidence_verifier(
    settings: Settings, provider: KeyProvider
) -> tuple[ObjectEvidenceVerifier, EvidenceRepository]:
    repository = EvidenceRepository(settings.database_url)
    store = LocalImmutableObjectStore(Path(settings.evidence_object_store_root))
    return (
        ObjectEvidenceVerifier(
            repository,
            store,
            verification_public_keys(provider),
            settings.hash_verify_checkpoint_interval,
        ),
        repository,
    )


def build_execution_service(
    settings: Settings, provider: KeyProvider, receipt_gate: Any
) -> ExecutionService:
    codec = ExecutionTokenCodec(
        settings.execution_token_issuer,
        signing_key=provider.active_key("execution-token"),
        clock_skew_seconds=settings.execution_token_clock_skew_seconds,
    )
    return ExecutionService(
        settings.database_url,
        codec,
        receipt_gate=receipt_gate,
        security_event_pool_max_size=settings.security_event_pool_max_size,
        security_event_pool_timeout_seconds=settings.security_event_pool_timeout_seconds,
    )


@dataclass(frozen=True, slots=True)
class Runtime:
    app: FastAPI
    settings: Settings
    key_provider: KeyProvider
    evidence_verifier: ObjectEvidenceVerifier
    execution_service: ExecutionService


def build_runtime(settings: Settings | None = None) -> Runtime:
    settings = settings or Settings.from_environment()
    provider = build_key_provider(settings)
    verifier, evidence_repository = build_evidence_verifier(settings, provider)
    execution_service = build_execution_service(settings, provider, verifier)
    app = create_app(settings, verifier, execution_service, provider)
    app.state.connection_pools.extend(
        [evidence_repository.pool, execution_service.pool, execution_service.security_event_pool]
    )
    return Runtime(app, settings, provider, verifier, execution_service)


def spiffe_scope_protocol_class() -> type:
    """Publish the verified peer's SSLObject in the ASGI scope.

    uvicorn never puts `ssl_object` in the scope, so `VerifiedPeerSpiffeMiddleware` — and with it
    every execution endpoint — reads nothing behind a real listener. Intercepting the assignment
    of `scope` is version-independent in a way that copying uvicorn's request handler is not.
    """
    try:
        from uvicorn.protocols.http.httptools_impl import HttpToolsProtocol as base
    except ImportError:  # pragma: no cover - fallback when httptools is unavailable
        from uvicorn.protocols.http.h11_impl import H11Protocol as base

    class VerifiedPeerScopeProtocol(base):  # type: ignore[valid-type, misc]
        @property
        def scope(self) -> Any:
            return self._mizan_scope

        @scope.setter
        def scope(self, value: Any) -> None:
            transport = getattr(self, "transport", None)
            if isinstance(value, dict) and value.get("type") == "http" and transport is not None:
                ssl_object = transport.get_extra_info("ssl_object")
                if ssl_object is not None:
                    value["ssl_object"] = ssl_object
            self._mizan_scope = value

    return VerifiedPeerScopeProtocol
