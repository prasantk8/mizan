#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import random
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import rfc8785

SEED = 58058
OFFSETS_PER_FILE = 16
VERIFIER_TIMEOUT_SECONDS = 5
BUNDLE = Path("tests/fixtures/evidence_export/golden/bundle")
RESULT = Path("tests/fixtures/conformance/mutation-result.json")
FILES = (
    "anchors.json",
    "checkpoints.json",
    "keys.json",
    "manifest.json",
    "receipts.json",
    "records.json",
)


def verdict(returncode: int) -> str:
    return {0: "VALID", 1: "INVALID", 2: "CANNOT_CHECK", 3: "MALFORMED"}.get(
        returncode, "VERIFIER_ERROR"
    )


def mutations(data: bytes, offsets: list[int]):
    for offset in offsets:
        yield offset, "flip", data[:offset] + bytes([data[offset] ^ 1]) + data[offset + 1:]
        yield offset, "delete", data[:offset] + data[offset + 1:]
        yield offset, "insert-space", data[:offset] + b" " + data[offset:]


def semantic_value(data: bytes) -> Any:
    try:
        return json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def evaluate() -> dict[str, Any]:
    cases = []
    semantic_survivors = []
    holes = []
    misclassified = []
    with tempfile.TemporaryDirectory(prefix="mizan-mutation-") as directory:
        mutated_bundle = Path(directory) / "bundle"
        shutil.copytree(BUNDLE, mutated_bundle)
        for name in FILES:
            source = (BUNDLE / name).read_bytes()
            original_value = semantic_value(source)
            offsets = sorted(random.Random(SEED).sample(
                range(len(source)), min(OFFSETS_PER_FILE, len(source))
            ))
            target = mutated_bundle / name
            for offset, operation, changed in mutations(source, offsets):
                target.write_bytes(changed)
                try:
                    completed = subprocess.run(
                        [sys.executable, "scripts/verify_evidence_export.py", str(mutated_bundle)],
                        check=False,
                        capture_output=True,
                        text=True,
                        timeout=VERIFIER_TIMEOUT_SECONDS,
                    )
                    actual = verdict(completed.returncode)
                except subprocess.TimeoutExpired:
                    actual = "VERIFIER_TIMEOUT"
                finally:
                    target.write_bytes(source)
                changed_value = semantic_value(changed)
                case = f"{name}:{offset}:{operation}"
                cases.append({"case": case, "verdict": actual})
                if actual == "VALID":
                    finding = {
                        "case": case,
                        "classification": (
                            "benign-semantically-identical"
                            if changed_value == original_value
                            else "integrity-hole"
                        ),
                    }
                    target_list = semantic_survivors if changed_value == original_value else holes
                    target_list.append(finding)
                elif changed_value is None and actual != "MALFORMED":
                    misclassified.append({
                        "case": case,
                        "expected": "MALFORMED",
                        "actual": actual,
                    })
    return {
        "seed": SEED,
        "offsets_per_file": OFFSETS_PER_FILE,
        "operations": ["flip-low-bit", "delete", "insert-space"],
        "maximum_verifier_invocations": len(FILES) * OFFSETS_PER_FILE * 3,
        "per_invocation_timeout_seconds": VERIFIER_TIMEOUT_SECONDS,
        "cases": cases,
        "semantic_survivors": semantic_survivors,
        "holes": holes,
        "misclassified": misclassified,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run deterministic evidence-bundle mutations")
    parser.add_argument("--record", action="store_true")
    args = parser.parse_args()
    result = evaluate()
    if args.record:
        RESULT.write_bytes(rfc8785.dumps(result))
    elif not RESULT.exists() or json.loads(RESULT.read_bytes()) != result:
        print("mutation result differs from the committed result", file=sys.stderr)
        return 1
    if result["holes"] or result["misclassified"]:
        print(json.dumps({
            "holes": result["holes"],
            "misclassified": result["misclassified"],
        }, indent=2), file=sys.stderr)
        return 1
    print(
        "evidence mutation gate: all semantic mutations rejected; "
        f"{len(result['semantic_survivors'])} byte edits were classified as semantically identical"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
