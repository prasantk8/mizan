from __future__ import annotations

import hashlib

import pytest
import rfc8785
from mizan_security.redaction import (
    Finding,
    RedactionError,
    RedactionPolicy,
    Redactor,
    RuleBasedDlpScanner,
    ScanResult,
)

POLICY = RedactionPolicy(
    policy_id="dlp_banking-v1",
    version=1,
    content_hash="a" * 64,
    transformations={"pii": "mask", "secret": "drop", "financial": "tokenize"},
)


def test_redaction_hashes_stored_payload_and_commits_to_source() -> None:
    source = {
        "customer": {"email": "alice@example.test", "national_id": "784-1234"},
        "account_number": "AE001234",
        "safe": "visible",
        "secret": "never-store",
    }
    result = Redactor(
        RuleBasedDlpScanner(), b"k" * 32, "hsm://audit/commitment-1", lambda _: None
    ).redact(source, POLICY)
    assert "alice@example.test" not in str(result.payload)
    assert "784-1234" not in str(result.payload)
    assert "never-store" not in str(result.payload)
    assert result.payload["safe"] == "visible"
    assert result.stored_payload_hash == hashlib.sha256(rfc8785.dumps(result.payload)).hexdigest()
    assert result.source_commitment["value"] != hashlib.sha256(rfc8785.dumps(source)).hexdigest()
    assert len(result.redaction["manifest"]) == 4


def test_commitment_is_keyed_against_dictionary_attack() -> None:
    source = {"national_id": "123456789"}
    first = Redactor(RuleBasedDlpScanner(), b"a" * 32, "hsm://audit/a", lambda _: None).redact(
        source, POLICY
    )
    second = Redactor(RuleBasedDlpScanner(), b"b" * 32, "hsm://audit/b", lambda _: None).redact(
        source, POLICY
    )
    assert first.source_commitment["value"] != second.source_commitment["value"]


class FailedScanner:
    def scan(self, payload: dict) -> ScanResult:
        return ScanResult("scan_failed", [], "scanner-1", "banking-v1")


def test_scan_failure_rejects_write() -> None:
    failures = []
    with pytest.raises(RedactionError, match="rejected"):
        Redactor(FailedScanner(), b"k" * 32, "hsm://audit/key", failures.append).redact(
            {"safe": "x"}, POLICY
        )
    assert failures == [
        {
            "event_type": "mizan.security.redaction_failed",
            "redactor_build": "mizan-redactor-1",
            "scanner_version": "scanner-1",
            "coverage_profile": "banking-v1",
        }
    ]


def test_sensitive_finding_without_transform_rejects_write() -> None:
    incomplete = RedactionPolicy("dlp_banking-v1", 1, "a" * 64, {"pii": "mask"})
    with pytest.raises(RedactionError, match="secret"):
        Redactor(RuleBasedDlpScanner(), b"k" * 32, "hsm://audit/key", lambda _: None).redact(
            {"secret": "value"},
            incomplete,
        )


class ArrayScanner:
    def scan(self, payload: dict) -> ScanResult:
        return ScanResult(
            "findings_redacted",
            [Finding("/values/2", "secret"), Finding("/values/10", "secret")],
            "array-scanner-1",
            "array-v1",
        )


def test_array_drops_are_applied_in_numeric_descending_order() -> None:
    result = Redactor(ArrayScanner(), b"k" * 32, "hsm://audit/key", lambda _: None).redact(
        {"values": list(range(12))}, POLICY
    )
    assert result.payload["values"] == [0, 1, 3, 4, 5, 6, 7, 8, 9, 11]
