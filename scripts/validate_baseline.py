#!/usr/bin/env python3
"""Dependency-free structural checks for the ratified Mizan baseline."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_PATHS = (
    "AGENT_ALLOCATION.md",
    "SPEC_v1.md",
    "WORK_LOG.md",
    "control-plane/agents/README.md",
    "control-plane/tools/README.md",
    "control-plane/authorization/README.md",
    "control-plane/policies/README.md",
    "control-plane/approvals/README.md",
    "control-plane/decisions/README.md",
    "control-plane/execution/README.md",
    "security/pii/README.md",
    "security/redaction/README.md",
    "security/prompt-security/README.md",
    "security/threat-engine/README.md",
    "security/behavioral/README.md",
    "integrations/kafka/README.md",
    "integrations/redis/README.md",
    "integrations/iam/README.md",
    "integrations/siem/README.md",
    "integrations/workflow/README.md",
    "integrations/external/README.md",
    "sdk/python/README.md",
    "sdk/java/README.md",
    "sdk/typescript/README.md",
    "examples/customer-support/README.md",
    "examples/wealth-agent/README.md",
    "policies/README.md",
    "threat-models/README.md",
    "ui/README.md",
    "tests/README.md",
)
JSON_FENCE = re.compile(r"```json\s*\n(.*?)\n```", re.DOTALL)
ABSOLUTE_REF = re.compile(r'"\$ref"\s*:\s*"(https?://[^"#]+)(?:#[^"]*)?"')


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)


def main() -> int:
    errors = 0
    for relative_path in REQUIRED_PATHS:
        if not (ROOT / relative_path).is_file():
            fail(f"required repository boundary missing: {relative_path}")
            errors += 1

    markdown_files = sorted(ROOT.glob("*.md")) + sorted((ROOT / "docs").rglob("*.md"))
    known_schema_ids: set[str] = set()
    parsed_blocks: list[tuple[Path, dict[str, object] | list[object]]] = []

    for path in markdown_files:
        text = path.read_text(encoding="utf-8")
        for index, raw_block in enumerate(JSON_FENCE.findall(text), start=1):
            try:
                value = json.loads(raw_block)
            except json.JSONDecodeError as exc:
                fail(f"{path.relative_to(ROOT)} JSON block {index}: {exc}")
                errors += 1
                continue
            parsed_blocks.append((path, value))
            if isinstance(value, dict) and isinstance(value.get("$id"), str):
                known_schema_ids.add(value["$id"])

    for path, value in parsed_blocks:
        serialized = json.dumps(value, separators=(",", ":"))
        for schema_ref in ABSOLUTE_REF.findall(serialized):
            if schema_ref not in known_schema_ids:
                fail(f"{path.relative_to(ROOT)} has unresolved schema reference: {schema_ref}")
                errors += 1

    if errors:
        print(f"Baseline validation failed with {errors} error(s).", file=sys.stderr)
        return 1

    print(
        f"Baseline valid: {len(REQUIRED_PATHS)} boundaries, "
        f"{len(parsed_blocks)} JSON blocks, {len(known_schema_ids)} schema IDs."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

