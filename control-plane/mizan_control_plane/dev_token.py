"""`mizan-dev-token` — mints identity tokens for a local demo.

This is a stand-in for a real IdP and nothing else. It refuses to run in production, and the
control plane refuses its issuer there, so a demo credential cannot follow a deployment out of a
laptop. Key material is written to a directory the operator names; nothing is embedded here.
"""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime, timedelta
from os import environ
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

DEVELOPMENT_ISSUER = "urn:mizan:development:dev-token"
DEVELOPMENT_ISSUER_PREFIX = "urn:mizan:development:"
PRIVATE_KEY_NAME = "dev-identity.key"
PUBLIC_KEY_NAME = "dev-identity.pub"


class DevelopmentOnly(RuntimeError):
    """Raised when a development credential is asked for in an environment that forbids one."""


def ensure_keypair(directory: Path) -> tuple[Ed25519PrivateKey, str]:
    directory.mkdir(parents=True, exist_ok=True)
    private_path = directory / PRIVATE_KEY_NAME
    public_path = directory / PUBLIC_KEY_NAME
    if not private_path.exists():
        key = Ed25519PrivateKey.generate()
        private_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        private_path.chmod(0o600)
        public_path.write_bytes(
            key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
    private_key = serialization.load_pem_private_key(private_path.read_bytes(), password=None)
    return private_key, public_path.read_text(encoding="utf-8")


def mint(
    private_key: Ed25519PrivateKey,
    *,
    tenant_id: str,
    subject: str,
    agent_id: str,
    identity_kind: str,
    auth_strength: str,
    roles: list[str],
    audience: str,
    ttl_seconds: int,
    delegation_chain: list[str] | None = None,
) -> str:
    now = datetime.now(UTC)
    claims = {
        "iss": DEVELOPMENT_ISSUER,
        "aud": audience,
        "sub": subject,
        "tenant_id": tenant_id,
        "agent_id": agent_id,
        "identity_kind": identity_kind,
        "auth_strength": auth_strength,
        "roles": roles,
        "delegation_chain": delegation_chain or [agent_id],
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl_seconds)).timestamp()),
    }
    return jwt.encode(claims, private_key, algorithm="EdDSA")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Mint a development identity token")
    parser.add_argument("--key-dir", type=Path, default=Path("var/demo-keys"))
    parser.add_argument("--tenant-id", default="tnt_demo-bank")
    parser.add_argument("--subject", default="prn_demo-operator")
    parser.add_argument("--agent-id", default="agt_wealth-advisor")
    parser.add_argument("--identity-kind", choices=["human", "agent", "service"], default="human")
    parser.add_argument(
        "--auth-strength",
        choices=["password", "mfa", "hardware", "federated"],
        default="hardware",
    )
    parser.add_argument("--roles", default="registry.admin,manager")
    parser.add_argument("--audience", default="mizan-control-plane")
    parser.add_argument("--ttl-seconds", type=int, default=3600)
    parser.add_argument("--print-public-key", action="store_true")
    arguments = parser.parse_args(argv)
    if environ.get("MIZAN_ENV") == "production":
        print(
            "mizan-dev-token refuses MIZAN_ENV=production: a development credential is not an "
            "identity provider.",
            file=sys.stderr,
        )
        return 78  # EX_CONFIG
    private_key, public_pem = ensure_keypair(arguments.key_dir)
    if arguments.print_public_key:
        print(public_pem.strip())
        return 0
    print(
        mint(
            private_key,
            tenant_id=arguments.tenant_id,
            subject=arguments.subject,
            agent_id=arguments.agent_id,
            identity_kind=arguments.identity_kind,
            auth_strength=arguments.auth_strength,
            roles=[item for item in arguments.roles.split(",") if item],
            audience=arguments.audience,
            ttl_seconds=arguments.ttl_seconds,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
