from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("validate_baseline", ROOT / "scripts/validate_baseline.py")
assert SPEC and SPEC.loader
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


def fixtures() -> dict[str, dict]:
    return {
        path.stem: json.loads(path.read_text(encoding="utf-8"))
        for path in (ROOT / "tests/fixtures/baseline_drift").glob("*.json")
    }


def test_meta_schema_negative_fixture_is_rejected() -> None:
    fixture = fixtures()["meta-schema"]
    assert validator.meta_schema_errors([(Path("fixture.json"), fixture["schema"])], Path("."))


def test_i16_typed_id_negative_fixture_is_rejected() -> None:
    fixture = fixtures()["typed-id"]
    assert validator.typed_id_errors([(Path("fixture.json"), fixture["schema"])], Path("."))


def test_spec_behavioural_promises_are_reachable_or_explicitly_waived() -> None:
    assert validator.reachability_errors(ROOT) == []


def test_closed_schema_negative_fixture_is_rejected() -> None:
    fixture = fixtures()["closed-schema"]
    assert fixture["record_decision"] not in fixture["adr_decisions"]
    assert set(fixture["required_record_fields"]) - set(fixture["adr_properties"])


def test_all_four_negative_fixture_classes_are_committed() -> None:
    assert {fixture["check"] for fixture in fixtures().values()} == {
        "meta_schema", "typed_id", "reachability", "closed_schema"
    }
