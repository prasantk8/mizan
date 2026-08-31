#!/usr/bin/env python3
"""Run and validate the identity-verification-key rotation drill.

This is intentionally a process-level sequence over the shipped TokenVerifier, not a restatement
of its key-selection logic. CI runs the same three stages an operator follows: old-only, overlap,
and new-only after waiting out the maximum identity-token TTL.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mizan_control_plane.auth import TokenVerifier
from mizan_control_plane.dev_token import public_jwks
from mizan_control_plane.problems import Problem

EXPECTED_STAGES = [
    {
        "name": "old-only",
        "old_token": "accepted",
        "new_token": "refused:identity_token_kid_unknown",
    },
    {"name": "overlap", "old_token": "accepted", "new_token": "accepted"},
    {
        "name": "new-only-after-overlap",
        "old_token": "refused:identity_token_kid_unknown",
        "new_token": "accepted",
    },
]


def _key_document(private_key: Ed25519PrivateKey, kid: str) -> dict[str, Any]:
    return json.loads(public_jwks(private_key, kid))["keys"][0]


def _token(private_key: Ed25519PrivateKey, kid: str) -> str:
    now = datetime.now(UTC)
    return jwt.encode(
        {
            "iss": "urn:mizan:rotation-drill",
            "aud": "mizan-control-plane",
            "sub": "spiffe://mizan/agent/rotation-drill",
            "tenant_id": "tnt_rotation-drill",
            "agent_id": "agt_rotation-drill",
            "identity_kind": "agent",
            "auth_strength": "federated",
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=300)).timestamp()),
        },
        private_key,
        algorithm="EdDSA",
        headers={"kid": kid},
    )


def _outcome(verifier: TokenVerifier, token: str) -> str:
    try:
        verifier.verify(token)
    except Problem as exc:
        return f"refused:{exc.code}"
    return "accepted"


def run_drill() -> dict[str, Any]:
    old_private = Ed25519PrivateKey.generate()
    new_private = Ed25519PrivateKey.generate()
    old_key = _key_document(old_private, "identity-2026-08-old")
    new_key = _key_document(new_private, "identity-2026-09-new")
    old_token = _token(old_private, old_key["kid"])
    new_token = _token(new_private, new_key["kid"])

    stages = []
    for name, keys in (
        ("old-only", [old_key]),
        ("overlap", [old_key, new_key]),
        ("new-only-after-overlap", [new_key]),
    ):
        verifier = TokenVerifier(
            "urn:mizan:rotation-drill",
            "mizan-control-plane",
            json.dumps({"keys": keys}),
        )
        stages.append(
            {
                "name": name,
                "old_token": _outcome(verifier, old_token),
                "new_token": _outcome(verifier, new_token),
            }
        )
    return {"schema_version": "1.0", "stages": stages}


def validate_report(report: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if report.get("schema_version") != "1.0":
        failures.append("rotation report must declare schema_version 1.0")
    stages = report.get("stages")
    if stages != EXPECTED_STAGES:
        failures.append(
            "rotation stages must prove old-only, old+new overlap, and new-only retirement "
            "with the expected accept/refuse outcomes"
        )
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--validate",
        type=Path,
        help="validate a previously captured JSON report instead of running the drill",
    )
    arguments = parser.parse_args(argv)
    if arguments.validate:
        try:
            report = json.loads(arguments.validate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"FAIL: cannot read rotation report: {exc}", file=sys.stderr)
            return 1
    else:
        report = run_drill()
        print(json.dumps(report, sort_keys=True))
    failures = validate_report(report)
    for failure in failures:
        print(f"FAIL: {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
