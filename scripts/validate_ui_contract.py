#!/usr/bin/env python3
"""Reject UI API calls that are absent from the control-plane OpenAPI contract."""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "control-plane"))

from mizan_control_plane import app as app_module  # noqa: E402
from mizan_control_plane.config import Settings  # noqa: E402

CALL = re.compile(
    r'request\(\s*"(?P<method>GET|POST|PUT|PATCH|DELETE)"\s*,\s*"(?P<path>/v1/[^"?]+)"'
)
UNUSED_IDENTITY_JWKS = (
    '{"keys":[{"alg":"EdDSA","crv":"Ed25519","kid":"unused","kty":"OKP",'
    '"use":"sig","x":"O-cX0g0xmFjyu_3CjAJd4swlM1Caf0u_X4JNwl6nEHs"}]}'
)


class _Pool:
    def close(self) -> None:
        pass


class _Repository:
    def __init__(self, _database_url: str, *_arguments: object) -> None:
        # `*_arguments` because `ApprovalRepository` also takes the deployment's
        # `MIZAN_APPROVAL_EPOCH_EXPIRY` mode. This stub exists to let `create_app` build a route
        # table without a database; it models no repository behaviour.
        self.pool = _Pool()


def _openapi_operations() -> set[tuple[str, str]]:
    constructors = (
        "PostgresAuthorizationRepository",
        "RegistryRepository",
        "EvidenceRepository",
        "ApprovalRepository",
    )
    originals = {name: getattr(app_module, name) for name in constructors}
    try:
        for name in constructors:
            setattr(app_module, name, _Repository)
        os.environ["MIZAN_ENV"] = "development"
        os.environ["MIZAN_DATABASE_URL"] = "postgresql://contract:contract@localhost/contract"
        os.environ["MIZAN_JWT_ISSUER"] = "https://issuer.invalid"
        os.environ["MIZAN_IDENTITY_JWKS"] = UNUSED_IDENTITY_JWKS
        settings = Settings.from_environment()
        document: dict[str, Any] = app_module.create_app(settings=settings).openapi()
    finally:
        for name, constructor in originals.items():
            setattr(app_module, name, constructor)
    return {
        (method.upper(), path)
        for path, item in document["paths"].items()
        for method in item
        if method.upper() in {"GET", "POST", "PUT", "PATCH", "DELETE"}
    }


def validate(source_path: Path) -> list[str]:
    source = source_path.read_text(encoding="utf-8")
    calls = {(match["method"], match["path"]) for match in CALL.finditer(source)}
    failures: list[str] = []
    if not calls:
        failures.append("no statically declared UI API contracts were found")

    bypass_source = re.sub(r"async function api\(", "", source)
    bypass_source = bypass_source.replace("return api(path, options);", "")
    if "api(" in bypass_source:
        failures.append("direct api() call bypasses the statically checked request() wrapper")
    if source.count("fetch(") != 1:
        failures.append("fetch() must appear only inside the checked api() transport")

    registered = _openapi_operations()
    for call in sorted(calls - registered):
        failures.append(f"UI calls unregistered operation: {call[0]} {call[1]}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=ROOT / "ui" / "app.js")
    arguments = parser.parse_args()
    failures = validate(arguments.source)
    if failures:
        for failure in failures:
            print(f"UI contract validation failed: {failure}", file=sys.stderr)
        return 1
    print(f"UI contract validation passed: {arguments.source}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
