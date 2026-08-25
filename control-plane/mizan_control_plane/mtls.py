from __future__ import annotations

import ssl
from collections.abc import Awaitable, Callable
from typing import Any

from cryptography import x509
from cryptography.x509 import ExtensionNotFound

from .problems import Problem

AsgiApp = Callable[[dict[str, Any], Callable[..., Awaitable[dict]], Callable[..., Awaitable[None]]], Awaitable[None]]


def spiffe_id_from_verified_peer(scope: dict[str, Any]) -> str | None:
    """Return one SPIFFE URI SAN from an in-process, mutually authenticated TLS peer."""
    ssl_object = scope.get("ssl_object")
    context = getattr(ssl_object, "context", None)
    if ssl_object is None or context is None or context.verify_mode != ssl.CERT_REQUIRED:
        return None
    try:
        der_certificate = ssl_object.getpeercert(binary_form=True)
    except (ValueError, ssl.SSLError):
        return None
    if not der_certificate:
        return None
    try:
        certificate = x509.load_der_x509_certificate(der_certificate)
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except (ValueError, ExtensionNotFound):
        return None
    identities = [
        value
        for value in san.get_values_for_type(x509.UniformResourceIdentifier)
        if value.startswith("spiffe://")
    ]
    return identities[0] if len(identities) == 1 else None


class VerifiedPeerSpiffeMiddleware:
    """Populate identity only from the verified TLS transport, never request metadata."""

    def __init__(self, app: AsgiApp) -> None:
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") == "http":
            scope.pop("client_cert_spiffe", None)
            identity = spiffe_id_from_verified_peer(scope)
            if identity is not None:
                scope["client_cert_spiffe"] = identity
        await self.app(scope, receive, send)


def require_workload_spiffe(scope: dict[str, Any]) -> str:
    identity = scope.get("client_cert_spiffe")
    if not isinstance(identity, str) or not identity.startswith("spiffe://"):
        raise Problem(401, "workload_identity_missing", "A verified peer SPIFFE identity is required")
    return identity

