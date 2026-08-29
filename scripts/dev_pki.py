#!/usr/bin/env python3
"""A throwaway CA, a server certificate, and a client certificate carrying a SPIFFE URI SAN.

**Development only, and it says so twice.** These keys are written unencrypted next to the
process that uses them and the CA signs anything asked of it. `main` refuses to run when
`MIZAN_ENV=production`, and every file is written under a directory the caller names so nothing
lands in a place a deployment would pick up by accident.

It exists because `make demo` could not reach the half of the product that matters. ADR-001
Amendment B requires a verified peer SPIFFE identity on every execution endpoint, so without
mutual TLS `/v1/decisions/{id}/execute` answers 401 and the demo stops one call before the tool
runs -- which is the sentence CP-F exists to make false.

The generator is lifted verbatim from `tests/integration/test_closed_loop_postgres.py`, which has
booted the shipped binary behind real mutual TLS since T-067. That test now imports this module
rather than keeping its own copy: one implementation, already exercised against a live listener,
instead of a second one written for the demo and proven by nothing.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import ssl
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

DEFAULT_EXECUTOR = "spiffe://mizan-demo/executor/wealth"


def _issue(
    subject: str,
    issuer_key: rsa.RSAPrivateKey,
    issuer_name: x509.Name,
    *,
    uri_san: str | None,
    server: bool,
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    alternatives: list[x509.GeneralName] = []
    if server:
        alternatives = [
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        ]
    if uri_san:
        alternatives.append(x509.UniformResourceIdentifier(uri_san))
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=5))
        .not_valid_after(datetime.now(UTC) + timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName(alternatives), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage(
                [
                    x509.ExtendedKeyUsageOID.SERVER_AUTH
                    if server
                    else x509.ExtendedKeyUsageOID.CLIENT_AUTH
                ]
            ),
            critical=False,
        )
    )
    return builder.sign(issuer_key, hashes.SHA256()), key


def _write_key(path: Path, key: rsa.RSAPrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    # The demo writes these beside the repository. Nothing else should be able to read them,
    # even on a shared developer machine.
    path.chmod(0o600)


def workload_pki(directory: Path, executor_spiffe: str = DEFAULT_EXECUTOR) -> dict[str, Path]:
    """A throwaway CA, one server certificate, and one client certificate with a SPIFFE URI SAN."""
    directory.mkdir(parents=True, exist_ok=True)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mizan-development-ca")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=5))
        .not_valid_after(datetime.now(UTC) + timedelta(hours=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    server_certificate, server_key = _issue("localhost", ca_key, ca_name, uri_san=None, server=True)
    client_certificate, client_key = _issue(
        "executor", ca_key, ca_name, uri_san=executor_spiffe, server=False
    )
    paths = {
        "ca": directory / "ca.pem",
        "server_certificate": directory / "server.pem",
        "server_key": directory / "server.key",
        "client_certificate": directory / "client.pem",
        "client_key": directory / "client.key",
    }
    paths["ca"].write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    paths["server_certificate"].write_bytes(
        server_certificate.public_bytes(serialization.Encoding.PEM)
    )
    _write_key(paths["server_key"], server_key)
    paths["client_certificate"].write_bytes(
        client_certificate.public_bytes(serialization.Encoding.PEM)
    )
    _write_key(paths["client_key"], client_key)
    return paths


def client_ssl_context(directory: Path) -> ssl.SSLContext:
    """How a client presents the executor identity to a mutual-TLS Mizan.

    It builds an `ssl.SSLContext` rather than passing httpx `verify=<ca path>` alongside
    `cert=(certificate, key)`. On httpx 0.28 that combination does not present the client
    certificate: the listener asks for one, gets none, and closes the connection -- which surfaces
    as `RemoteProtocolError: Server disconnected without sending a response` on **every** request,
    including GET /health/ready, and with nothing in the server log because the connection never
    became a request. The closed-loop integration test has always used the context form, which is
    why it worked while the demo did not.

    One helper, so a caller cannot rediscover that the slow way.
    """
    context = ssl.create_default_context(cafile=str(directory / "ca.pem"))
    context.load_cert_chain(str(directory / "client.pem"), str(directory / "client.key"))
    return context


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--executor-spiffe", default=DEFAULT_EXECUTOR)
    arguments = parser.parse_args(argv)

    if os.environ.get("MIZAN_ENV") == "production":
        print(
            "dev_pki refuses to run with MIZAN_ENV=production. These are unencrypted development "
            "keys from a CA that signs anything; a production deployment gets its workload "
            "identity from its own issuer.",
            file=sys.stderr,
        )
        return 78  # EX_CONFIG, the same code the control plane uses to refuse a bad start.

    paths = workload_pki(arguments.directory, arguments.executor_spiffe)
    for name, path in sorted(paths.items()):
        print(f"{name}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
