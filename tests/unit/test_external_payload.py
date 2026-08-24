from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest
from mizan_control_plane.schema_validation import ContractSchemas
from mizan_integrations.external_payload import (
    ExternalPayloadError,
    ExternalPayloadProcessor,
    ParserBudgets,
    Projection,
    ProjectionField,
)

PROJECTION = Projection(
    "prj_kyc_v1",
    1,
    (
        ProjectionField("customer_risk", "/customer/risk"),
        ProjectionField("verified", "/verified"),
    ),
)


class Telemetry:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict]] = []

    def emit(self, event: str, attributes: dict) -> None:
        self.events.append((event, attributes))


class Persistence:
    def __init__(self) -> None:
        self.encrypted: tuple[bytes, str] | None = None
        self.redacted: tuple[object, str] | None = None

    def encrypted_evidence(self, payload: bytes, reference: str) -> None:
        self.encrypted = payload, reference

    def redacted_payload(self, payload: object, attestation_reference: str) -> None:
        self.redacted = payload, attestation_reference


def test_projects_only_allowlisted_scalars_and_reports_drift() -> None:
    telemetry = Telemetry()
    body = json.dumps(
        {"customer": {"risk": "HIGH", "name": "PII"}, "verified": True, "new": 7}
    ).encode()
    envelope, mapped = ExternalPayloadProcessor(telemetry=telemetry).process(
        tenant_id="tnt_bank",
        provider="sys_kyc",
        chunks=[body],
        projection=PROJECTION,
    )
    assert mapped["fields"] == {"customer_risk": "HIGH", "verified": True}
    assert envelope["size_bytes"] == len(body)
    assert envelope["projection"]["dropped_fields"] == ["/customer/name", "/new"]
    assert telemetry.events[0][0] == "mizan.integration.schema_drift"
    assert "payload" not in ExternalPayloadProcessor.operational_record(envelope)
    ContractSchemas(Path("SPEC_v1.md")).validate("ExternalPayloadEnvelope", envelope)


def test_streaming_gzip_enforces_decompressed_limit_before_parse() -> None:
    compressed = gzip.compress(json.dumps({"value": "x" * 1000}).encode())
    processor = ExternalPayloadProcessor(
        ParserBudgets(
            max_compressed_bytes=1024,
            max_decompressed_bytes=100,
        )
    )
    with pytest.raises(ExternalPayloadError) as error:
        processor.process(
            tenant_id="tnt_bank",
            provider="sys_kyc",
            chunks=[compressed],
            content_encoding="gzip",
            projection=Projection("prj_value", 1, (ProjectionField("value", "/value"),)),
        )
    assert error.value.code == "PAYLOAD_TOO_LARGE"


@pytest.mark.parametrize(
    ("body", "code"),
    [
        (b'{"a":1,"a":2}', "MALFORMED_JSON"),
        (b'{"a":NaN}', "MALFORMED_JSON"),
        (b"not-json", "MALFORMED_JSON"),
    ],
)
def test_rejects_ambiguous_or_malformed_json(body: bytes, code: str) -> None:
    projection = Projection("prj_value", 1, (ProjectionField("value", "/a"),))
    with pytest.raises(ExternalPayloadError) as error:
        ExternalPayloadProcessor().process(
            tenant_id="tnt_bank",
            provider="sys_kyc",
            chunks=[body],
            projection=projection,
        )
    assert error.value.code == code


def test_enforces_depth_and_total_key_budgets() -> None:
    deep = json.dumps({"a": {"b": {"c": 1}}}).encode()
    many = json.dumps({"a": 1, "b": 2, "c": 3}).encode()
    projection = Projection("prj_value", 1, (ProjectionField("value", "/a"),))
    for body, budgets, code in [
        (deep, ParserBudgets(max_depth=2), "JSON_DEPTH_EXCEEDED"),
        (many, ParserBudgets(max_keys=2), "JSON_KEYS_EXCEEDED"),
    ]:
        with pytest.raises(ExternalPayloadError) as error:
            ExternalPayloadProcessor(budgets).process(
                tenant_id="tnt_bank",
                provider="sys_kyc",
                chunks=[body],
                projection=projection,
            )
        assert error.value.code == code


def test_nested_projection_is_rejected_and_raw_retention_requires_sink() -> None:
    body = b'{"customer":{"risk":"HIGH"}}'
    nested = Projection("prj_customer", 1, (ProjectionField("customer", "/customer"),))
    with pytest.raises(ExternalPayloadError) as error:
        ExternalPayloadProcessor().process(
            tenant_id="tnt_bank",
            provider="sys_kyc",
            chunks=[body],
            projection=nested,
        )
    assert error.value.code == "PROJECTION_FAILED"
    with pytest.raises(ExternalPayloadError) as error:
        ExternalPayloadProcessor().process(
            tenant_id="tnt_bank",
            provider="sys_kyc",
            chunks=[body],
            projection=Projection("prj_risk", 1, (ProjectionField("risk", "/customer/risk"),)),
            disposition="encrypted_evidence",
            encrypted_evidence_ref="obj://evidence/1",
        )
    assert error.value.code == "PERSISTENCE_FAILED"


def test_persistence_dispositions_are_explicitly_acknowledged() -> None:
    sink = Persistence()
    body = b'{"customer":{"risk":"HIGH"},"verified":true}'
    ExternalPayloadProcessor(persistence=sink).process(
        tenant_id="tnt_bank",
        provider="sys_kyc",
        chunks=[body],
        projection=PROJECTION,
        disposition="encrypted_evidence",
        encrypted_evidence_ref="obj://evidence/1",
    )
    assert sink.encrypted == (body, "obj://evidence/1")
    ExternalPayloadProcessor(persistence=sink).process(
        tenant_id="tnt_bank",
        provider="sys_kyc",
        chunks=[body],
        projection=PROJECTION,
        disposition="redacted_payload",
        redaction_attestation_ref="att://1",
        redacted_payload={"safe": True},
    )
    assert sink.redacted == ({"safe": True}, "att://1")
