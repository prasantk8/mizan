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
        # Section 2.1's Memtara roots are a second, independent operator input. Without this the
        # corpus could hold a proof-bearing bundle but never hand the verifier the key that makes
        # it checkable, and the VALID case would report CANNOT CHECK.
        for trust_root in case.get("memtara_trust_roots", []):
            command.extend(["--memtara-trust-root", str(root / trust_root)])
        result = subprocess.run(command, check=False, capture_output=True, text=True)
        # "CANNOT CHECK" with a space: the spelling the verifier prints, verdicts.json declares,
        # and compare_verifiers.py compares. The old underscore here could only ever have matched
        # a corpus entry that no other consumer of verdicts.json would have accepted.
        actual_verdict = {0: "VALID", 1: "INVALID", 2: "CANNOT CHECK", 3: "MALFORMED", 4: "EXPIRED"}.get(
            result.returncode, "VERIFIER_ERROR"
        )
        message_matches = case.get("message") is None or case["message"] in result.stderr
        if actual_verdict != case["verdict"] or not message_matches:
            failures.append(
                f"{case['bundle']} (expected {case['verdict']}, got {actual_verdict})"
            )
    if failures:
        print("conformance mismatch: " + ", ".join(failures), file=sys.stderr)
        return 1
    print("evidence conformance corpus: all verdicts matched")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
