import json
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

import pytest

FIXTURE = Path("tests/fixtures/evidence_export/public-tsa")


def _assert_two_independent_public_authorities(fixture: Path) -> None:
    assert (fixture / "provenance.json").is_file(), "public authority provenance is missing"
    provenance = json.loads((fixture / "provenance.json").read_bytes())
    authorities = provenance["authorities"]
    assert len(authorities) >= 2
    assert len({urlparse(item["url"]).hostname for item in authorities}) >= 2
    for item in authorities:
        assert (fixture / item["token"]).is_file()
        assert (fixture / item["root"]).is_file()
        assert item["root_sha256_fingerprint"].count(":") == 31


def test_public_tsa_fixture_names_two_independent_authorities() -> None:
    _assert_two_independent_public_authorities(FIXTURE)


def test_pre_interop_local_tsa_artifact_is_rejected_by_public_authority_gate() -> None:
    with pytest.raises(AssertionError, match="public authority provenance is missing"):
        _assert_two_independent_public_authorities(
            Path("tests/fixtures/evidence_export/attested")
        )


def test_public_tsa_bundle_verifies_offline() -> None:
    result = subprocess.run(
        [
            sys.executable, "scripts/verify_evidence_export.py", str(FIXTURE / "bundle"),
            "--tsa-trust-anchor", str(FIXTURE / "freetsa-root.pem"),
            "--tsa-trust-anchor", str(FIXTURE / "usertrust-rsa-root.pem"),
        ],
        check=False, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == (FIXTURE / "verification-result.txt").read_text()
