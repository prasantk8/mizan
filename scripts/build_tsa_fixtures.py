#!/usr/bin/env python3
"""Rebuild the RFC 3161 test fixtures, by hand, when a test TSA has to change.

Not a gate and not run by CI. It exists so that the two committed test timestamp authorities are
reproducible, and so that the reason for their validity windows is written down next to the command
that sets them.

Two fixtures, and the difference between them is the whole point:

  attested/  a signer certificate with a realistic ten-year lifetime. This is what a bundle from a
             competently operated TSA looks like, and it stays verifiable until 2036.
  expired/   a signer certificate whose validity window closed in 2016 and can never reopen. Its
             expected verdict is EXPIRED with the record chain still valid, and it is the only way
             the post-horizon path stays tested after the day it was written.

The expired window is hard-coded in the past deliberately. R-008 F-10 was a twenty-four-hour
certificate that turned the offline-verifier job red the day after it was generated; the repair for
that is not a longer-lived certificate, because a longer-lived certificate hides the same defect for
longer. Do not "fix" a red expired fixture by moving its dates forward. If it is red, either the
verifier stopped reporting EXPIRED or it stopped verifying the rest of the bundle, and both of those
are the defect this fixture exists to catch.

Requires OpenSSL 3.5 or newer for `req -not_before/-not_after`. CI verifies these fixtures with any
OpenSSL 3.x; only regeneration needs the newer flags.

    uv run --frozen python scripts/build_tsa_fixtures.py
"""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import rfc8785

sys.path.insert(0, str(Path(__file__).parent))
from verify_evidence_export import declared_horizon  # noqa: E402

ROOT = Path("tests/fixtures/evidence_export")
BUNDLES_WITH_TOKENS = (
    ROOT / "attested" / "bundle",
    ROOT / "expired" / "bundle",
    ROOT / "public-tsa" / "bundle",
    Path("tests/fixtures/conformance/valid-public"),
)


def anchor_core_digest(payload: dict[str, Any]) -> str:
    core = {
        key: value
        for key, value in payload.items()
        if key not in {"attestations", "object_key", "object_version"}
    }
    return hashlib.sha256(rfc8785.dumps(core)).hexdigest()


def openssl(*arguments: str, cwd: Path | None = None) -> None:
    completed = subprocess.run(
        ["openssl", *arguments], check=False, capture_output=True, text=True, cwd=cwd
    )
    if completed.returncode != 0:
        raise SystemExit(f"openssl {arguments[0]} failed: {completed.stderr}")


def mint_authority(directory: Path, common_name: str, not_before: str, not_after: str) -> Path:
    """A self-signed root that is also the timestamping signer, as small as RFC 3161 allows."""
    certificate = directory / "tsa.pem"
    openssl(
        "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(directory / "tsa.key"), "-out", str(certificate), "-sha256",
        "-subj", f"/CN={common_name}",
        "-not_before", not_before, "-not_after", not_after,
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "extendedKeyUsage=critical,timeStamping",
    )
    (directory / "tsa.serial").write_text("01\n", encoding="utf-8")
    (directory / "tsa.cnf").write_text(
        "[ tsa_config ]\n"
        "signer_cert = tsa.pem\n"
        "signer_key = tsa.key\n"
        "certs = tsa.pem\n"
        "signer_digest = sha256\n"
        "default_policy = 1.3.6.1.4.1.99999.1.1\n"
        "digests = sha256, sha512\n"
        "accuracy = secs:1\n"
        "ordering = yes\n"
        "tsa_name = yes\n"
        "ess_cert_id_chain = no\n"
        "serial = tsa.serial\n",
        encoding="utf-8",
    )
    return certificate


def mint_token(directory: Path, digest: str) -> bytes:
    openssl(
        "ts", "-query", "-digest", digest, "-sha256", "-cert",
        "-out", str(directory / "request.tsq"),
    )
    openssl(
        "ts", "-reply", "-config", "tsa.cnf", "-section", "tsa_config",
        "-queryfile", "request.tsq", "-out", "response.tsr",
        cwd=directory,
    )
    return (directory / "response.tsr").read_bytes()


def stamp_expiry(bundle: Path) -> list[str]:
    """Write each RFC 3161 sidecar's declared horizon, read out of the token it already carries."""
    anchors = json.loads((bundle / "anchors.json").read_bytes())
    written = []
    for row in anchors:
        for sidecar in row.get("attestations", []):
            if sidecar.get("type") != "rfc3161" or not sidecar.get("evidence"):
                continue
            horizon = declared_horizon(base64.b64decode(sidecar["evidence"]))
            if horizon is None:
                raise SystemExit(f"{bundle}: an RFC 3161 token carries no certificate to expire")
            sidecar["expires_at"] = horizon.strftime("%Y-%m-%dT%H:%M:%SZ")
            written.append(f"{bundle.parent.name}/{sidecar['authority']} -> {sidecar['expires_at']}")
    (bundle / "anchors.json").write_bytes(rfc8785.dumps(anchors))
    reseal(bundle)
    return written


def reseal(bundle: Path) -> None:
    manifest = json.loads((bundle / "manifest.json").read_bytes())
    for name in manifest["files"]:
        manifest["files"][name] = hashlib.sha256((bundle / name).read_bytes()).hexdigest()
    (bundle / "manifest.json").write_bytes(rfc8785.dumps(manifest))


def rebuild(fixture: Path, common_name: str, not_before: str, not_after: str) -> None:
    bundle = fixture / "bundle"
    anchors = json.loads((bundle / "anchors.json").read_bytes())
    with tempfile.TemporaryDirectory(prefix="mizan-tsa-fixture-") as name:
        directory = Path(name)
        certificate = mint_authority(directory, common_name, not_before, not_after)
        for row in anchors:
            digest = anchor_core_digest(row["payload"])
            token = mint_token(directory, digest)
            for sidecar in row.get("attestations", []):
                if sidecar.get("type") != "rfc3161":
                    continue
                sidecar["evidence"] = base64.b64encode(token).decode()
                sidecar["anchor_digest"] = digest
        (fixture / "tsa-root.pem").write_bytes(certificate.read_bytes())
    (bundle / "anchors.json").write_bytes(rfc8785.dumps(anchors))


def main() -> int:
    minted = datetime.now(UTC).replace(microsecond=0)
    rebuild(
        ROOT / "attested",
        "committed-test-tsa",
        (minted - timedelta(days=1)).strftime("%Y%m%d%H%M%SZ"),
        (minted + timedelta(days=3653)).strftime("%Y%m%d%H%M%SZ"),
    )
    # Fixed, in the past, forever. See the module docstring before changing either literal.
    rebuild(ROOT / "expired", "expired-test-tsa", "20150101000000Z", "20160101000000Z")
    for bundle in BUNDLES_WITH_TOKENS:
        for line in stamp_expiry(bundle):
            print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
