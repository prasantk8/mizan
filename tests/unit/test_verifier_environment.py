from __future__ import annotations

import os
import subprocess
import sys


def test_attested_cli_without_openssl_exits_cannot_check_without_traceback() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "scripts/verify_evidence_export.py",
            "tests/fixtures/evidence_export/attested/bundle",
            "--tsa-trust-anchor",
            "tests/fixtures/evidence_export/attested/tsa-root.pem",
        ],
        check=False,
        capture_output=True,
        text=True,
        env=os.environ | {"PATH": "/nonexistent"},
    )
    assert result.returncode == 2
    assert "CANNOT CHECK: OpenSSL executable is unavailable" in result.stderr
    assert "ASSURANCE NOT DERIVED" in result.stderr
    assert "Traceback" not in result.stderr
