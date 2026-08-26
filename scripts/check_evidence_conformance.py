#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def main() -> int:
    root = Path("tests/fixtures/conformance")
    verifier = Path("scripts/verify_evidence_export.py")
    failures = []
    for case in json.loads((root / "verdicts.json").read_bytes()):
        command = [sys.executable, str(verifier), str(root / case["bundle"])]
        for trust_root in case["trust_roots"]:
            command.extend(["--tsa-trust-anchor", str(root / trust_root)])
        result = subprocess.run(command, check=False, capture_output=True, text=True)
        accepted = result.returncode == 0
        message_matches = case["valid"] or case["message"] in result.stderr
        if accepted is not case["valid"] or not message_matches:
            failures.append(case["bundle"])
    if failures:
        print("conformance mismatch: " + ", ".join(failures), file=sys.stderr)
        return 1
    print("evidence conformance corpus: all verdicts matched")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
