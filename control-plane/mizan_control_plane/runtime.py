"""The composition root.

Everything that turns configuration into a running control plane happens here and nowhere else.
Production refuses to boot without a signing key provider, an evidence verifier and an execution
service: a control plane that authorizes but cannot sign, verify or bind execution is not a
degraded Mizan, it is a different product.
"""

from __future__ import annotations

import base64
import logging
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
from .keys import KEY_ROLES, KeyProvider, KeyVersion, KmsHsmKeyProvider, LocalKeyProvider
from .object_store import (
    ImmutableObjectStore,
    ObjectStoreRefused,
    S3ObjectLockStore,
    build_s3_client,
)
from .observability import (
    Metrics,
    MetricsServer,
    Tracer,
    TracingRefused,
    build_tracer,
    configure_logging,
)
from .vault_transit import VaultRefused, VaultTransitBackend

LOGGER = logging.getLogger(__name__)


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
    if settings.key_custody_mode == "vault-transit":
        try:
            backend = VaultTransitBackend(
                settings.vault_address,
                settings.vault_token,
                namespace=settings.vault_namespace or None,
                ca_certificate=settings.vault_ca_certificate or None,
            )
            provider = KmsHsmKeyProvider(versions, backend, custody="kms")
            # Every role is resolved and its public key read here, at startup, rather than at the
            # first signature. A missing key, a wrong key type, an unreachable Vault and a policy
            # that does not permit `sign` are all configuration errors, and the difference between
            # finding one now and finding one later is the difference between a process that
            # refuses to start and a drain worker that refuses every financial write at three in
            # the morning with a message about HTTP. It also makes `verification_keyset()` --
            # copied verbatim into every exported bundle -- known-good before anything is signed.
            provider.verification_keyset()
        except (VaultRefused, RuntimeError) as refused:
            raise StartupRefused(f"vault-transit key backend is not usable: {refused}") from refused
        return provider
    raise StartupRefused(
        f"key custody mode {settings.key_custody_mode!r} names no built backend. "
        "'vault-transit' is the one KMS backend that exists (B-18, delivered by T-102); PKCS#11 "
        "is not built. Refusing to start rather than signing evidence with publicly derivable "
        "development keys."
    )


def build_object_store(settings: Settings) -> ImmutableObjectStore:
    """Where evidence goes, and whether anything but our own care keeps it there.

    `local` is a directory. Its own docstring calls it a development WORM *analogue*, and the chart
    mounted it as an `emptyDir` under `replicaCount: 2` -- so a bundle exported by pod A could not
    read segments published by pod B, and a rollout destroyed the corpus. Meanwhile every record
    this system signs carries `"retention_class": "regulatory_7y"`.

    `s3` is B-21's answer: a bucket with Object Lock in COMPLIANCE mode, where no principal --
    including us -- can delete or overwrite an object before its retention date. The bucket is
    checked here, at startup, because Object Lock can only be enabled when a bucket is *created*:
    a deployment pointed at an ordinary bucket cannot be repaired in place, and until it is
    replaced every record it writes claims a retention nothing enforces.
    """
    if settings.evidence_object_store == "local":
        return LocalImmutableObjectStore(Path(settings.evidence_object_store_root))
    try:
        store = S3ObjectLockStore(
            settings.audit_anchor_bucket,
            client=build_s3_client(
                settings.s3_endpoint_url,
                settings.s3_region,
                settings.s3_access_key_id,
                settings.s3_secret_access_key,
            ),
            retention_years=settings.object_lock_retention_years,
        )
        store.assert_object_lock_enabled()
    except ObjectStoreRefused as refused:
        raise StartupRefused(f"evidence object store is not usable: {refused}") from refused
    return store


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
    store = build_object_store(settings)
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
    settings: Settings, provider: KeyProvider, receipt_gate: Any, metrics: Metrics | None = None
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
        default_token_ttl_seconds=settings.execution_token_default_ttl_seconds,
        metrics=metrics,
    )


def build_observability(settings: Settings) -> tuple[Metrics, Tracer, MetricsServer | None]:
    """Logs, metrics and trace context, decided once, before anything can emit any of them.

    A configured OTLP endpoint with no exporter installed raises `TracingRefused` here rather
    than degrading quietly — see `observability.build_tracer`.
    """
    configure_logging(settings.log_level, json_output=settings.log_format == "json")
    metrics = Metrics()
    tracer = build_tracer(
        settings.otel_exporter_endpoint, settings.otel_service_name, settings.environment
    )
    server: MetricsServer | None = None
    if settings.metrics_enabled:
        server = MetricsServer(metrics, settings.metrics_host, settings.metrics_port).start()
        if settings.metrics_host not in ("127.0.0.1", "::1", "localhost"):
            LOGGER.warning(
                "metrics listener is bound off-loopback and is unauthenticated: it publishes "
                "per-tenant decision volumes, publication lag and breaker state to anything that "
                "can reach it. Restrict it at the network, or bind it to loopback and scrape via "
                "a sidecar.",
                extra={"metrics_host": settings.metrics_host, "metrics_port": server.port},
            )
    return metrics, tracer, server


@dataclass(frozen=True, slots=True)
class Runtime:
    app: FastAPI
    settings: Settings
    key_provider: KeyProvider
    evidence_verifier: ObjectEvidenceVerifier
    execution_service: ExecutionService
    metrics: Metrics
    metrics_server: MetricsServer | None = None


def build_runtime(settings: Settings | None = None) -> Runtime:
    settings = settings or Settings.from_environment()
    try:
        metrics, tracer, metrics_server = build_observability(settings)
    except TracingRefused as refused:
        raise StartupRefused(str(refused)) from refused
    provider = build_key_provider(settings)
    verifier, evidence_repository = build_evidence_verifier(settings, provider)
    execution_service = build_execution_service(settings, provider, verifier, metrics)
    app = create_app(settings, verifier, execution_service, provider, metrics, tracer)
    app.state.connection_pools.extend(
        [evidence_repository.pool, execution_service.pool, execution_service.security_event_pool]
    )
    app.state.metrics_server = metrics_server
    return Runtime(
        app, settings, provider, verifier, execution_service, metrics, metrics_server
    )


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
