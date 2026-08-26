import json
import subprocess
import sys
from pathlib import Path


def test_normative_format_pins_closed_anchor_core_projection() -> None:
    contract = Path("docs/adr/ADR-004-audit-immutability.md").read_text()
    assert "closed projection excluding exactly" in contract
    specification = " ".join(
        Path("docs/spec/EVIDENCE-BUNDLE-FORMAT.md").read_text().split()
    )
    assert "No other current or future member is removed" in specification


def test_standalone_verifier_matches_normative_conformance_corpus() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/check_evidence_conformance.py"],
        check=False, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr


def test_conformance_corpus_distinguishes_malformed_from_invalid() -> None:
    cases = json.loads(Path("tests/fixtures/conformance/verdicts.json").read_bytes())
    verdicts = {case["bundle"]: case["verdict"] for case in cases}
    assert verdicts["invalid-record-checksum"] == "INVALID"
    assert verdicts["malformed-failed-status"] == "MALFORMED"
    assert verdicts["malformed-attested-signed-payload"] == "MALFORMED"
    assert verdicts["malformed-unattested-rfc3161"] == "MALFORMED"


def test_deterministic_evidence_mutation_result_is_current() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/check_evidence_mutations.py"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
