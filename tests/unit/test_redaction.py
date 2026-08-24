from __future__ import annotations

import hashlib

import pytest
import rfc8785
from mizan_security.redaction import (
    RedactionError,
    RedactionPolicy,
    Redactor,
    RuleBasedDlpScanner,
    ScanResult,
)

POLICY = RedactionPolicy(
    policy_id="dlp_banking-v1",version=1,content_hash="a" * 64,
    transformations={"pii":"mask","secret":"drop","financial":"tokenize"},
)


def test_redaction_hashes_stored_payload_and_commits_to_source() -> None:
    source = {
        "customer":{"email":"alice@example.test","national_id":"784-1234"},
        "account_number":"AE001234","safe":"visible","secret":"never-store",
    }
    result = Redactor(RuleBasedDlpScanner(),b"k" * 32,"hsm://audit/commitment-1").redact(source,POLICY)
    assert "alice@example.test" not in str(result.payload)
    assert "784-1234" not in str(result.payload)
    assert "never-store" not in str(result.payload)
    assert result.payload["safe"] == "visible"
    assert result.stored_payload_hash == hashlib.sha256(rfc8785.dumps(result.payload)).hexdigest()
    assert result.source_commitment["value"] != hashlib.sha256(rfc8785.dumps(source)).hexdigest()
    assert len(result.redaction["manifest"]) == 4


def test_commitment_is_keyed_against_dictionary_attack() -> None:
    source = {"national_id":"123456789"}
    first = Redactor(RuleBasedDlpScanner(),b"a" * 32,"hsm://audit/a").redact(source,POLICY)
    second = Redactor(RuleBasedDlpScanner(),b"b" * 32,"hsm://audit/b").redact(source,POLICY)
    assert first.source_commitment["value"] != second.source_commitment["value"]


class FailedScanner:
    def scan(self, payload: dict) -> ScanResult:
        return ScanResult("scan_failed", [], "scanner-1", "banking-v1")


def test_scan_failure_rejects_write() -> None:
    with pytest.raises(RedactionError, match="rejected"):
        Redactor(FailedScanner(),b"k" * 32,"hsm://audit/key").redact({"safe":"x"},POLICY)


def test_sensitive_finding_without_transform_rejects_write() -> None:
    incomplete = RedactionPolicy("dlp_banking-v1",1,"a" * 64,{"pii":"mask"})
    with pytest.raises(RedactionError, match="secret"):
        Redactor(RuleBasedDlpScanner(),b"k" * 32,"hsm://audit/key").redact(
            {"secret":"value"},incomplete,
        )

