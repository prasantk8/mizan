from __future__ import annotations

import hashlib
import json
import os
import re
import time
import zlib
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal, Protocol


class ExternalPayloadError(RuntimeError):
    """A controlled integration/tool error; never a control-plane service fault."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


@dataclass(frozen=True, slots=True)
class ParserBudgets:
    max_compressed_bytes: int = 262_144
    max_decompressed_bytes: int = 1_048_576
    max_depth: int = 32
    max_keys: int = 4096
    timeout_ms: int = 2000

    def __post_init__(self) -> None:
        if not 1 <= self.max_compressed_bytes <= 1_048_576:
            raise ValueError("compressed payload limit must be between 1 and 1048576")
        if not 1 <= self.max_decompressed_bytes <= 1_048_576:
            raise ValueError("decompressed payload limit must be between 1 and 1048576")
        if not 1 <= self.max_depth <= 64 or not 1 <= self.max_keys <= 16_384:
            raise ValueError("parser structural budget exceeds the supported hard cap")
        if not 1 <= self.timeout_ms <= 30_000:
            raise ValueError("adapter timeout must be between 1 and 30000ms")

    @classmethod
    def from_environment(cls) -> ParserBudgets:
        return cls(
            max_compressed_bytes=int(os.getenv("MIZAN_EXTERNAL_PAYLOAD_MAX_BYTES", "262144")),
            max_decompressed_bytes=int(
                os.getenv("MIZAN_EXTERNAL_PAYLOAD_MAX_DECOMPRESSED_BYTES", "1048576")
            ),
            max_depth=int(os.getenv("MIZAN_EXTERNAL_PAYLOAD_MAX_DEPTH", "32")),
            max_keys=int(os.getenv("MIZAN_EXTERNAL_PAYLOAD_MAX_KEYS", "4096")),
            timeout_ms=int(os.getenv("MIZAN_EXTERNAL_ADAPTER_TIMEOUT_MS", "2000")),
        )


Scalar = str | int | float | bool | None


@dataclass(frozen=True, slots=True)
class ProjectionField:
    output_name: str
    json_pointer: str

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,63}", self.output_name):
            raise ValueError("projection output names must be bounded identifiers")
        if self.json_pointer != "" and not self.json_pointer.startswith("/"):
            raise ValueError("projection source must be an RFC 6901 JSON pointer")


@dataclass(frozen=True, slots=True)
class Projection:
    projection_id: str
    version: int
    fields: tuple[ProjectionField, ...]

    def __post_init__(self) -> None:
        if not re.fullmatch(r"prj_[a-z0-9_.-]{3,64}", self.projection_id):
            raise ValueError("invalid projection id")
        if self.version < 1 or not 1 <= len(self.fields) <= 64:
            raise ValueError("projection must have a positive version and 1-64 fields")
        names = [field.output_name for field in self.fields]
        pointers = [field.json_pointer for field in self.fields]
        if len(names) != len(set(names)) or len(pointers) != len(set(pointers)):
            raise ValueError("projection fields and source pointers must be unique")


class DriftTelemetry(Protocol):
    def emit(self, event: str, attributes: dict[str, Any]) -> None: ...


class RawPersistence(Protocol):
    def encrypted_evidence(self, payload: bytes, reference: str) -> None: ...
    def redacted_payload(self, payload: Any, attestation_reference: str) -> None: ...


def _elapsed_ms(started: float) -> float:
    return (time.monotonic() - started) * 1000


def _check_time(started: float, budget: ParserBudgets) -> None:
    if _elapsed_ms(started) > budget.timeout_ms:
        raise ExternalPayloadError(
            "ADAPTER_TIMEOUT", "external payload processing exceeded its budget"
        )


def _bounded_decode(
    chunks: Iterable[bytes], encoding: str, budget: ParserBudgets, started: float
) -> bytes:
    if encoding not in {"identity", "gzip"}:
        raise ExternalPayloadError(
            "UNSUPPORTED_ENCODING", "content encoding must be identity or gzip"
        )
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS) if encoding == "gzip" else None
    compressed = 0
    output = bytearray()
    for chunk in chunks:
        _check_time(started, budget)
        if not isinstance(chunk, bytes):
            raise ExternalPayloadError("INVALID_TRANSPORT", "payload chunks must be bytes")
        compressed += len(chunk)
        if compressed > budget.max_compressed_bytes:
            raise ExternalPayloadError(
                "PAYLOAD_TOO_LARGE", "compressed/received byte limit exceeded"
            )
        try:
            decoded = (
                decoder.decompress(chunk, budget.max_decompressed_bytes + 1 - len(output))
                if decoder
                else chunk
            )
        except zlib.error as exc:
            raise ExternalPayloadError("MALFORMED_GZIP", "gzip transport decoding failed") from exc
        output.extend(decoded)
        if len(output) > budget.max_decompressed_bytes:
            raise ExternalPayloadError("PAYLOAD_TOO_LARGE", "decompressed byte limit exceeded")
    if decoder:
        try:
            output.extend(decoder.flush(budget.max_decompressed_bytes + 1 - len(output)))
        except zlib.error as exc:
            raise ExternalPayloadError("MALFORMED_GZIP", "gzip stream is incomplete") from exc
        if not decoder.eof:
            raise ExternalPayloadError("MALFORMED_GZIP", "gzip stream is incomplete")
        if decoder.unused_data:
            raise ExternalPayloadError(
                "MALFORMED_GZIP", "concatenated/trailing gzip data is forbidden"
            )
    if len(output) > budget.max_decompressed_bytes:
        raise ExternalPayloadError("PAYLOAD_TOO_LARGE", "decompressed byte limit exceeded")
    return bytes(output)


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ExternalPayloadError("MALFORMED_JSON", f"duplicate object key: {key}")
        result[key] = value
    return result


def _validate_structure(value: Any, budget: ParserBudgets, started: float) -> None:
    keys = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        _check_time(started, budget)
        node, depth = stack.pop()
        if depth > budget.max_depth:
            raise ExternalPayloadError("JSON_DEPTH_EXCEEDED", "JSON nesting limit exceeded")
        if isinstance(node, dict):
            keys += len(node)
            if keys > budget.max_keys:
                raise ExternalPayloadError("JSON_KEYS_EXCEEDED", "JSON total-key limit exceeded")
            stack.extend(
                (child, depth + 1) for child in node.values() if isinstance(child, (dict, list))
            )
        elif isinstance(node, list):
            stack.extend((child, depth + 1) for child in node if isinstance(child, (dict, list)))


def _pointer_get(document: Any, pointer: str) -> Any:
    current = document
    if pointer == "":
        return current
    for token in pointer[1:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        try:
            current = current[int(token)] if isinstance(current, list) else current[token]
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise ExternalPayloadError(
                "PROJECTION_FAILED", f"projection source not found: {pointer}"
            ) from exc
    return current


def _leaf_pointers(value: Any, pointer: str = "") -> set[str]:
    if isinstance(value, dict):
        result: set[str] = set()
        for key, child in value.items():
            escaped = key.replace("~", "~0").replace("/", "~1")
            result |= _leaf_pointers(child, f"{pointer}/{escaped}")
        return result
    if isinstance(value, list):
        result = set()
        for index, child in enumerate(value):
            result |= _leaf_pointers(child, f"{pointer}/{index}")
        return result
    return {pointer}


class ExternalPayloadProcessor:
    def __init__(
        self,
        budgets: ParserBudgets | None = None,
        telemetry: DriftTelemetry | None = None,
        persistence: RawPersistence | None = None,
    ) -> None:
        self.budgets = budgets or ParserBudgets()
        self.telemetry = telemetry
        self.persistence = persistence

    def process(
        self,
        *,
        tenant_id: str,
        provider: str,
        chunks: Iterable[bytes],
        projection: Projection,
        content_type: str = "application/json",
        content_encoding: Literal["identity", "gzip"] = "identity",
        disposition: Literal[
            "discarded_after_projection", "encrypted_evidence", "redacted_payload"
        ] = "discarded_after_projection",
        encrypted_evidence_ref: str | None = None,
        redaction_attestation_ref: str | None = None,
        redacted_payload: Any = None,
        schema_uri: str | None = None,
        schema_version_declared: str | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        started = time.monotonic()
        if not re.fullmatch(r"tnt_[a-z0-9-]{4,64}", tenant_id):
            raise ExternalPayloadError("INVALID_ENVELOPE", "invalid tenant id")
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{1,63}", provider):
            raise ExternalPayloadError("INVALID_ENVELOPE", "invalid provider system id")
        if schema_uri is not None and len(schema_uri) > 256:
            raise ExternalPayloadError("INVALID_ENVELOPE", "schema URI is too long")
        if schema_version_declared is not None and len(schema_version_declared) > 64:
            raise ExternalPayloadError("INVALID_ENVELOPE", "declared schema version is too long")
        if redaction_attestation_ref is not None and len(redaction_attestation_ref) > 256:
            raise ExternalPayloadError("INVALID_ENVELOPE", "redaction attestation reference is too long")
        if encrypted_evidence_ref is not None and len(encrypted_evidence_ref) > 256:
            raise ExternalPayloadError("INVALID_ENVELOPE", "encrypted evidence reference is too long")
        if content_type.split(";", 1)[0].strip().lower() != "application/json":
            raise ExternalPayloadError(
                "UNSUPPORTED_CONTENT_TYPE", "external payload must be application/json"
            )
        raw = _bounded_decode(chunks, content_encoding, self.budgets, started)
        try:
            payload = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_pairs,
                parse_constant=lambda value: (_ for _ in ()).throw(
                    ExternalPayloadError("MALFORMED_JSON", f"non-finite number: {value}")
                ),
            )
        except ExternalPayloadError:
            raise
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ExternalPayloadError("MALFORMED_JSON", "payload is not valid UTF-8 JSON") from exc
        _validate_structure(payload, self.budgets, started)
        raw_hash = hashlib.sha256(raw).hexdigest()
        mapped: dict[str, Scalar] = {}
        for field in projection.fields:
            value = _pointer_get(payload, field.json_pointer)
            if isinstance(value, (dict, list)):
                raise ExternalPayloadError(
                    "PROJECTION_FAILED", f"non-scalar projection: {field.json_pointer}"
                )
            mapped[field.output_name] = value
        selected = {field.json_pointer for field in projection.fields}
        dropped = sorted(path[:120] for path in _leaf_pointers(payload) - selected)
        if dropped and self.telemetry:
            self.telemetry.emit(
                "mizan.integration.schema_drift",
                {
                    "tenant_id": tenant_id,
                    "provider": provider,
                    "projection_id": projection.projection_id,
                    "projection_version": projection.version,
                    "dropped_fields": dropped,
                },
            )
        if disposition == "encrypted_evidence":
            if not encrypted_evidence_ref or not self.persistence:
                raise ExternalPayloadError(
                    "PERSISTENCE_FAILED", "encrypted evidence reference and sink are required"
                )
            self.persistence.encrypted_evidence(raw, encrypted_evidence_ref)
        elif disposition == "redacted_payload":
            if not redaction_attestation_ref or not self.persistence or redacted_payload is None:
                raise ExternalPayloadError(
                    "PERSISTENCE_FAILED", "redacted payload, attestation, and sink are required"
                )
            self.persistence.redacted_payload(redacted_payload, redaction_attestation_ref)
        elif disposition != "discarded_after_projection":
            raise ExternalPayloadError("PERSISTENCE_FAILED", "unknown persistence disposition")
        _check_time(started, self.budgets)
        envelope = {
            "schema_version": "1.2",
            "tenant_id": tenant_id,
            "provider": provider,
            "schema_uri": schema_uri,
            "schema_version_declared": schema_version_declared,
            "received_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "raw_hash": raw_hash,
            "size_bytes": len(raw),
            "content_type": "application/json",
            "content_encoding": content_encoding,
            "payload": payload,
            "persistence": {
                "disposition": disposition,
                "redaction_attestation_ref": redaction_attestation_ref,
                "encrypted_evidence_ref": encrypted_evidence_ref,
            },
            "projection": {
                "projection_id": projection.projection_id,
                "projection_version": projection.version,
                "mapped_fields": sorted(mapped),
                "dropped_fields": dropped,
            },
        }
        mapped_context = {
            "source": provider,
            "projection_id": projection.projection_id,
            "projection_version": projection.version,
            "raw_envelope_hash": raw_hash,
            "fields": mapped,
        }
        return envelope, mapped_context

    @staticmethod
    def operational_record(envelope: dict[str, Any]) -> dict[str, Any]:
        """Strip raw payload before writing searchable operational metadata."""
        return {key: value for key, value in envelope.items() if key != "payload"}
