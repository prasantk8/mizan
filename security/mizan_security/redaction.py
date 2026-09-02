from __future__ import annotations

import copy
import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal, Protocol

import rfc8785

Classification = Literal["public", "internal", "confidential", "pii", "financial", "secret"]
Transformation = Literal["drop", "mask", "tokenize", "hash", "generalize"]


class RedactionError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class Finding:
    pointer: str
    classification: Classification


@dataclass(frozen=True, slots=True)
class ScanResult:
    status: Literal["clean", "findings_redacted", "scan_failed", "not_applicable"]
    findings: list[Finding]
    scanner_version: str
    coverage_profile: str


class DlpScanner(Protocol):
    def scan(self, payload: dict[str, Any]) -> ScanResult: ...


class RuleBasedDlpScanner:
    EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    SENSITIVE_KEYS = {
        "email": "pii",
        "phone": "pii",
        "national_id": "pii",
        "passport": "pii",
        "account_number": "financial",
        "iban": "financial",
        "secret": "secret",
        "password": "secret",
        "token": "secret",
    }

    def __init__(
        self, version: str = "rules-1.0", coverage_profile: str = "banking-core-v1"
    ) -> None:
        self.version = version
        self.coverage_profile = coverage_profile

    def scan(self, payload: dict[str, Any]) -> ScanResult:
        findings: list[Finding] = []

        def visit(value: Any, pointer: str) -> None:
            if isinstance(value, dict):
                for key, item in value.items():
                    escaped = key.replace("~", "~0").replace("/", "~1")
                    child = f"{pointer}/{escaped}"
                    classification = self.SENSITIVE_KEYS.get(key.lower())
                    if classification:
                        findings.append(Finding(child, classification))
                    elif isinstance(item, str) and self.EMAIL.fullmatch(item):
                        findings.append(Finding(child, "pii"))
                    else:
                        visit(item, child)
            elif isinstance(value, list):
                for index, item in enumerate(value):
                    visit(item, f"{pointer}/{index}")

        visit(payload, "")
        return ScanResult(
            status="findings_redacted" if findings else "clean",
            findings=findings,
            scanner_version=self.version,
            coverage_profile=self.coverage_profile,
        )


@dataclass(frozen=True, slots=True)
class RedactionPolicy:
    policy_id: str
    version: int
    content_hash: str
    transformations: dict[Classification, Transformation]


@dataclass(frozen=True, slots=True)
class RedactionResult:
    payload: dict[str, Any]
    stored_payload_hash: str
    source_commitment: dict[str, str]
    redaction: dict[str, Any]


class CommitmentKey(Protocol):
    """The `MacKey` half of the key provider, restated here so this package imports nothing.

    `security/` is a separate distribution from the control plane and must stay that way; the
    structural typing is the contract. `mizan_control_plane.keys.MacKey` satisfies it, and so does
    a test double, and neither has to know about the other.
    """

    key_id: str

    def mac(self, payload: bytes) -> bytes: ...


def _commit(key: CommitmentKey, value: Any) -> str:
    return key.mac(rfc8785.dumps(value)).hex()


def _resolve_parent(document: Any, pointer: str) -> tuple[Any, str]:
    parts = pointer.removeprefix("/").split("/")
    current = document
    for encoded in parts[:-1]:
        part = encoded.replace("~1", "/").replace("~0", "~")
        current = current[int(part)] if isinstance(current, list) else current[part]
    return current, parts[-1].replace("~1", "/").replace("~0", "~")


def _transform(
    document: dict[str, Any], pointer: str, operation: Transformation, commitment: str
) -> None:
    parent, key = _resolve_parent(document, pointer)
    if operation == "drop":
        parent.pop(int(key)) if isinstance(parent, list) else parent.pop(key)
        return
    replacements = {
        "mask": "***REDACTED***",
        "tokenize": "tok_" + commitment[:24],
        "hash": "hmac_" + commitment,
        "generalize": "[generalized]",
    }
    replacement = replacements[operation]
    if isinstance(parent, list):
        parent[int(key)] = replacement
    else:
        parent[key] = replacement


def _transform_order(finding: Finding) -> tuple[int, str, int, str]:
    parts = finding.pointer.removeprefix("/").split("/")
    final = parts[-1]
    return (len(parts), "/".join(parts[:-1]), int(final) if final.isdigit() else -1, final)


class Redactor:
    def __init__(
        self,
        scanner: DlpScanner,
        commitment_key: CommitmentKey,
        failure_sink: Callable[[dict[str, str]], None],
        build: str = "mizan-redactor-1",
    ) -> None:
        """Takes a key that *computes* a commitment, never the key material itself (T-054, B-30).

        This used to take raw `bytes` and HMAC them in process, which contradicted ADR-004 G.1's
        *"private key material never enters the control-plane process"* the moment custody became
        real: under `custody=kms` there are no bytes to pass, because the secret lives in Vault and
        Transit MACs in place. Taking the key *object* is what makes the KMS and development paths
        the same code.

        `key_ref` is no longer a separate argument either. It was possible to pass key material
        under one reference and label the commitment with another, and the label is what a record
        cites forever — so it now comes from the key that did the work.
        """
        self.scanner = scanner
        self.commitment_key = commitment_key
        self.key_ref = commitment_key.key_id
        self.build = build
        self.failure_sink = failure_sink

    def redact(self, payload: dict[str, Any], policy: RedactionPolicy) -> RedactionResult:
        source = copy.deepcopy(payload)
        scan = self.scanner.scan(source)
        if scan.status == "scan_failed":
            try:
                self.failure_sink(
                    {
                        "event_type": "mizan.security.redaction_failed",
                        "redactor_build": self.build,
                        "scanner_version": scan.scanner_version,
                        "coverage_profile": scan.coverage_profile,
                    }
                )
            except Exception as exc:
                raise RedactionError(
                    "DLP scan and failure-event emission failed; audit write rejected"
                ) from exc
            raise RedactionError("DLP scan failed; audit write rejected")
        if not scan.coverage_profile or not scan.scanner_version:
            raise RedactionError("DLP attestation is incomplete")
        stored = copy.deepcopy(source)
        manifest: list[dict[str, str]] = []
        # Descending pointers keep list indices stable when fields are dropped.
        for finding in sorted(scan.findings, key=_transform_order, reverse=True):
            operation = policy.transformations.get(finding.classification)
            if finding.classification in {"pii", "secret"} and operation is None:
                raise RedactionError(
                    f"no transformation for {finding.classification} at {finding.pointer}"
                )
            if operation is None:
                continue
            parent, key = _resolve_parent(source, finding.pointer)
            original = parent[int(key)] if isinstance(parent, list) else parent[key]
            commitment = _commit(self.commitment_key, original)
            _transform(stored, finding.pointer, operation, commitment)
            manifest.append(
                {
                    "pointer": finding.pointer,
                    "classification": finding.classification,
                    "transformation": operation,
                    "commitment": commitment,
                }
            )
        stored_hash = hashlib.sha256(rfc8785.dumps(stored)).hexdigest()
        source_value = _commit(self.commitment_key, source)
        return RedactionResult(
            payload=stored,
            stored_payload_hash=stored_hash,
            source_commitment={
                "alg": "HMAC-SHA256",
                "key_ref": self.key_ref,
                "value": source_value,
            },
            redaction={
                "applied": bool(manifest),
                "policy_id": policy.policy_id,
                "policy_version": policy.version,
                "policy_hash": policy.content_hash,
                "input_schema_hash": None,
                "output_schema_hash": None,
                "redactor_build": self.build,
                "dlp": {
                    "status": scan.status,
                    "findings_count": len(scan.findings),
                    "scanner_version": scan.scanner_version,
                    "coverage_profile": scan.coverage_profile,
                },
                "manifest": manifest,
                "evidence_ref": None,
            },
        )
