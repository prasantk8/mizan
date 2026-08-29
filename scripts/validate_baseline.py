#!/usr/bin/env python3
"""Blocking structural and contract-drift checks for the Mizan baseline."""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

ROOT = Path(__file__).resolve().parents[1]
# This list used to require twenty-three further README files -- one per directory under
# `control-plane/`, `security/`, `integrations/`, `sdk/` and `examples/` that contained nothing
# but a one-line claim. `security/pii/README.md` said "CLAUDE-owned PII classification and
# protection boundary" and there is no such code; `control-plane/decisions/README.md` described
# work that actually lives in `control-plane/mizan_control_plane/evidence.py`, one level up. A
# browsing design partner reads a directory as shipped surface, and a gate that *required* those
# directories to exist was enforcing the roadmap rather than the product (T-115). The directories
# are deleted and `docs/product/MODULE_LEDGER.md` now names, for each claimed module, the code
# that backs it -- or says none.
REQUIRED_PATHS = (
    "AGENT_ALLOCATION.md", "SPEC_v1.md", "WORK_LOG.md",
    "docs/product/MODULE_LEDGER.md",
    "sdk/python/README.md", "threat-models/README.md", "ui/README.md", "tests/README.md",
)
BEHAVIOURAL_TOKENS = (
    "NOT_IMPLEMENTED", "system_fail_closed", "default_deny", "degraded_grant",
    "constraints_hash",
)
IMPLEMENTATION_ROOTS = ("control-plane", "security", "integrations", "sdk", "ui")
JSON_FENCE = re.compile(r"```json\s*\n(.*?)\n```", re.DOTALL)
ABSOLUTE_REF = re.compile(r'"\$ref"\s*:\s*"(https?://[^"#]+)(?:#[^"]*)?"')
WAIVER_ROW = re.compile(
    r"^\|\s*`(?P<token>[^`]+)`\s*\|\s*(?P<date>\d{4}-\d{2}-\d{2})\s*\|\s*(?P<reason>.+?)\s*\|$",
    re.MULTILINE,
)


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)


def extracted_schemas(root: Path) -> tuple[list[tuple[Path, dict[str, Any]]], int]:
    markdown_files = sorted(root.glob("*.md")) + sorted((root / "docs").rglob("*.md"))
    schemas: list[tuple[Path, dict[str, Any]]] = []
    parse_errors = 0
    for path in markdown_files:
        for index, raw_block in enumerate(JSON_FENCE.findall(path.read_text(encoding="utf-8")), 1):
            try:
                value = json.loads(raw_block)
            except json.JSONDecodeError as exc:
                fail(f"{path.relative_to(root)} JSON block {index}: {exc}")
                parse_errors += 1
                continue
            if isinstance(value, dict):
                schemas.append((path, value))
    return schemas, parse_errors


def meta_schema_errors(schemas: Iterable[tuple[Path, dict[str, Any]]], root: Path) -> list[str]:
    errors: list[str] = []
    for path, schema in schemas:
        if "$schema" not in schema and "$id" not in schema:
            continue
        try:
            Draft202012Validator.check_schema(schema)
        except SchemaError as exc:
            errors.append(f"{path.relative_to(root)} invalid Draft 2020-12 schema: {exc.message}")
    return errors


def _typed_id_ref(node: Any, plural: bool) -> bool:
    if not isinstance(node, dict):
        return False
    if plural:
        return node.get("type") == "array" and _typed_id_ref(node.get("items"), False)
    ref = node.get("$ref")
    if isinstance(ref, str) and (ref.startswith("common#/$defs/") or "/schemas/common/" in ref):
        return ref.rsplit("/", 1)[-1].endswith("Id")
    return any(_typed_id_ref(item, False) for item in node.get("oneOf", []))


def typed_id_errors(schemas: Iterable[tuple[Path, dict[str, Any]]], root: Path) -> list[str]:
    errors: list[str] = []

    def walk(node: Any, path: Path, pointer: str = "") -> None:
        if isinstance(node, dict):
            properties = node.get("properties", {})
            if isinstance(properties, dict):
                for name, definition in properties.items():
                    if name.endswith("_id") and not _typed_id_ref(definition, False):
                        errors.append(f"{path.relative_to(root)} {pointer}/properties/{name} is not a typed common Id reference")
                    if name.endswith("_ids") and not _typed_id_ref(definition, True):
                        errors.append(f"{path.relative_to(root)} {pointer}/properties/{name} is not an array of typed common Id references")
            for key, value in node.items():
                walk(value, path, f"{pointer}/{key}")
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, path, f"{pointer}/{index}")

    for path, schema in schemas:
        if "$id" in schema:
            walk(schema, path)
    return errors


def reachability_errors(root: Path, tokens: Iterable[str] = BEHAVIOURAL_TOKENS) -> list[str]:
    source = "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for directory in IMPLEMENTATION_ROOTS
        if (root / directory).exists()
        for path in sorted((root / directory).rglob("*.py"))
    )
    waiver_path = root / "docs/reviews/UNIMPLEMENTED.md"
    waiver_text = waiver_path.read_text(encoding="utf-8") if waiver_path.exists() else ""
    waivers = {match.group("token") for match in WAIVER_ROW.finditer(waiver_text) if match.group("reason").strip()}
    return [
        f"SPEC behavioural token {token!r} is unreachable and has no dated UNIMPLEMENTED waiver"
        for token in tokens if token not in source and token not in waivers
    ]


def closed_schema_errors(schemas: Iterable[tuple[Path, dict[str, Any]]], root: Path) -> list[str]:
    titled = {schema.get("title"): schema for _, schema in schemas}
    policy, adr = titled.get("Policy"), titled.get("ADR_Record")
    manifest_path = root / "docs/contracts/decision-paths.json"
    if not policy or not adr or not manifest_path.exists():
        return ["closed-schema producibility requires Policy, ADR_Record, and docs/contracts/decision-paths.json"]
    paths = json.loads(manifest_path.read_text(encoding="utf-8")).get("paths", {})
    policy_values = set(policy["properties"]["decision"]["enum"])
    record_values = set(adr["properties"]["decision"]["enum"])
    errors: list[str] = []
    if set(paths) != policy_values:
        errors.append(f"decision-path manifest keys differ from Policy enum: expected {sorted(policy_values)}, got {sorted(paths)}")
    record_properties = set(adr.get("properties", {}))
    for value in sorted(policy_values & set(paths)):
        disposition = paths[value]
        emitted = disposition.get("record_decision")
        if emitted not in record_values:
            errors.append(f"decision path {value} emits ADR decision {emitted!r}, which closed ADR_Record cannot represent")
        missing = set(disposition.get("required_record_fields", [])) - record_properties
        if missing:
            errors.append(f"decision path {value} requires fields absent from closed ADR_Record: {sorted(missing)}")
    return errors


def policy_iff_errors(policy: dict[str, Any]) -> list[str]:
    """Require both directions of Policy.constraints' documented decision iff."""
    all_of = policy.get("allOf", [])
    allowed = {"CONSTRAIN", "REDACT"}
    forward = any(
        set(rule.get("if", {}).get("properties", {}).get("decision", {}).get("enum", [])) == allowed
        and "constraints" in rule.get("then", {}).get("required", [])
        for rule in all_of
    )
    reverse = any(
        set(rule.get("if", {}).get("properties", {}).get("decision", {}).get("not", {}).get("enum", [])) == allowed
        and "constraints" in rule.get("then", {}).get("not", {}).get("required", [])
        for rule in all_of
    )
    return [] if forward and reverse else ["Policy constraints says iff but schema does not encode both implications"]


def negative_fixture_errors(root: Path) -> list[str]:
    fixture_dir = root / "tests/fixtures/baseline_drift"
    errors: list[str] = []
    checks = {
        "meta_schema": lambda data: bool(meta_schema_errors([(fixture_dir / "fixture.json", data["schema"])], root)),
        "typed_id": lambda data: bool(typed_id_errors([(fixture_dir / "fixture.json", data["schema"])], root)),
        "reachability": lambda data: data["token"] not in data.get("source", "") and not data.get("waived", False),
        "closed_schema": lambda data: data["record_decision"] not in data["adr_decisions"] or bool(set(data["required_record_fields"]) - set(data["adr_properties"])),
        "policy_iff": lambda data: bool(policy_iff_errors(data["schema"])),
    }
    seen: set[str] = set()
    for path in sorted(fixture_dir.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        check = data.get("check")
        seen.add(check)
        if check not in checks or not checks[check](data):
            errors.append(f"negative fixture does not make its gate fail: {path.relative_to(root)}")
    if set(checks) - seen:
        errors.append("each baseline drift gate requires a committed negative fixture")
    return errors


def main() -> int:
    messages = [f"required repository boundary missing: {path}" for path in REQUIRED_PATHS if not (ROOT / path).is_file()]
    schemas, parse_errors = extracted_schemas(ROOT)
    messages.extend(["malformed fenced JSON"] * parse_errors)
    known_ids = {schema["$id"] for _, schema in schemas if isinstance(schema.get("$id"), str)}
    for path, schema in schemas:
        for schema_ref in ABSOLUTE_REF.findall(json.dumps(schema, separators=(",", ":"))):
            if schema_ref not in known_ids:
                messages.append(f"{path.relative_to(ROOT)} has unresolved schema reference: {schema_ref}")
    messages.extend(meta_schema_errors(schemas, ROOT))
    messages.extend(typed_id_errors(schemas, ROOT))
    messages.extend(reachability_errors(ROOT))
    messages.extend(closed_schema_errors(schemas, ROOT))
    policy_schema = next((schema for _, schema in schemas if schema.get("title") == "Policy"), {})
    messages.extend(policy_iff_errors(policy_schema))
    messages.extend(negative_fixture_errors(ROOT))
    for message in messages:
        fail(message)
    if messages:
        print(f"Baseline validation failed with {len(messages)} error(s).", file=sys.stderr)
        return 1
    print(f"Baseline valid: {len(REQUIRED_PATHS)} boundaries, {len(schemas)} JSON blocks, {len(known_ids)} schema IDs; five drift gates proven.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
