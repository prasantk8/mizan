#!/usr/bin/env python3
"""Reject an operator surface that cannot describe the production path end to end."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REQUIRED_FILES = (
    ".env.example",
    "INSTALL.md",
    "scripts/bootstrap_credentials.sh",
    "scripts/provision_object_store.py",
    "scripts/provision_vault.sh",
    "docs/reviews/CP-F-WALKTHROUGH.md",
)
INSTALL_MARKERS = (
    "bootstrap_credentials.sh",
    "provision_vault.sh",
    "provision_object_store.py",
    "Object Lock",
    "workforce-oidc-client-secret-file",
    "group-to-role/control-domain mapping",
    "COMPLIANCE",
    "--profile production",
    "/readyz",
    "outside the build team",
)


def validate(root: Path) -> list[str]:
    failures = [f"missing {name}" for name in REQUIRED_FILES if not (root / name).is_file()]
    install = root / "INSTALL.md"
    if install.is_file():
        text = install.read_text(encoding="utf-8")
        searchable = " ".join(text.split())
        failures.extend(
            f"INSTALL.md does not name {marker!r}"
            for marker in INSTALL_MARKERS
            if marker not in searchable
        )
    example = root / ".env.example"
    if example.is_file():
        text = example.read_text(encoding="utf-8")
        for secret in ("MIZAN_POSTGRES_OWNER_PASSWORD", "MIZAN_APP_PASSWORD"):
            if secret not in text:
                failures.append(f".env.example omits {secret}")
        if "validation-secret" in text or "ci-only" in text:
            failures.append(".env.example contains a CI credential")
    walkthrough = root / "docs/reviews/CP-F-WALKTHROUGH.md"
    if walkthrough.is_file():
        text = walkthrough.read_text(encoding="utf-8")
        for marker in ("Named participant", "First run timings", "Corrections", "Clean rerun"):
            if marker not in text:
                failures.append(f"walkthrough record omits {marker!r}")
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    arguments = parser.parse_args(argv)
    failures = validate(arguments.root)
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        return 1
    print("PASS: production installation surface is complete and walkthrough fields are explicit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
