#!/usr/bin/env python3
"""The gates only ratchet upward. Removing one is a deliberate act, not a quiet one.

R-005 F-18: this repository has drift gates and no anti-rot gates. Everything here can be
weakened by *subtraction* without a single assertion going red -- delete a CI job, shrink the
conformance corpus, drop a fault category, remove a console script, and every remaining check
still passes. The build goes green faster and nobody is told anything.

That is not hypothetical. This stage found `validate_baseline.py` requiring twenty-three README
files that described code which did not exist (T-115), a packaging test asserting the presence of
a service pointing at a binary nobody had written (T-100), and a benchmark provenance gate wired
against a temporary directory so it never examined the committed corpus (T-099). In each case the
gate was present and passing. The failure mode of a gate is not that it goes red; it is that it
stops looking.

So the counts are committed. This script recomputes them and fails when one has **decreased**
without `tests/gate-inventory.json` being updated in the same change. Growth is silent, which is
the right asymmetry: adding a test should never require editing a manifest, and removing one
should require saying so out loud where a reviewer sees it in the diff.

It is not a coverage metric and it does not know whether a gate is any good. It knows how many
there were yesterday.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import yaml

INVENTORY = Path("tests/gate-inventory.json")


def ci_jobs(root: Path) -> int:
    workflow = yaml.safe_load((root / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    return len(workflow["jobs"])


def conformance_bundles(root: Path) -> int:
    path = root / "tests/fixtures/conformance/verdicts.json"
    return len(json.loads(path.read_text(encoding="utf-8")))


def adversarial_faults(root: Path) -> int:
    """Counted by asking the script, not by parsing it -- `--list` is its own inventory."""
    completed = subprocess.run(
        [sys.executable, "scripts/adversarial_fault_injection.py", "--list"],
        capture_output=True,
        text=True,
        cwd=root,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"adversarial_fault_injection.py --list failed:\n{completed.stderr}")
    return len([line for line in completed.stdout.splitlines() if line.strip()])


def console_scripts(root: Path) -> int:
    manifest = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    return len(manifest["project"]["scripts"])


def required_boundaries(root: Path) -> int:
    source = (root / "scripts/validate_baseline.py").read_text(encoding="utf-8")
    block = re.search(r"REQUIRED_PATHS = \((.*?)\n\)", source, re.DOTALL)
    if block is None:
        raise RuntimeError("REQUIRED_PATHS not found in validate_baseline.py")
    return len(re.findall(r'"[^"]+"', block.group(1)))


def verifier_two_tests(root: Path) -> int:
    """`verifier-two` runs `node --test` from its own package root; anything else finds nothing."""
    completed = subprocess.run(
        ["node", "--test"], capture_output=True, text=True, cwd=root / "verifier-two"
    )
    match = re.search(r"^. tests (\d+)$", completed.stdout, re.MULTILINE)
    if match is None:
        raise RuntimeError(f"could not read a test count from node --test:\n{completed.stdout[-400:]}")
    return int(match.group(1))


COUNTERS = {
    "ci_jobs": ci_jobs,
    "conformance_bundles": conformance_bundles,
    "adversarial_fault_categories": adversarial_faults,
    "console_scripts": console_scripts,
    "required_boundaries": required_boundaries,
    "verifier_two_tests": verifier_two_tests,
}


def measure(root: Path) -> dict[str, int]:
    return {name: counter(root) for name, counter in COUNTERS.items()}


def main(argv: list[str] | None = None) -> int:
    root = Path.cwd()
    record = "--record" in (argv if argv is not None else sys.argv[1:])
    measured = measure(root)

    if record:
        (root / INVENTORY).write_text(
            json.dumps(
                {
                    "_comment": (
                        "Counts of the checks this repository runs. A decrease fails "
                        "scripts/validate_gate_inventory.py; growth is silent. Regenerate with "
                        "--record only when a gate is deliberately removed, and say why in the "
                        "commit."
                    ),
                    "counts": measured,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"recorded {len(measured)} gate counts")
        return 0

    path = root / INVENTORY
    if not path.is_file():
        print(f"FAIL: {INVENTORY} does not exist; run with --record", file=sys.stderr)
        return 1
    recorded = json.loads(path.read_text(encoding="utf-8"))["counts"]

    regressions: list[str] = []
    for name, value in sorted(measured.items()):
        previous = recorded.get(name)
        if previous is None:
            regressions.append(f"{name}: not in {INVENTORY}; run with --record to adopt it")
        elif value < previous:
            regressions.append(
                f"{name}: {previous} -> {value}. A gate was removed. If that is deliberate, "
                f"re-record the inventory in the same commit and say why -- the point is that "
                f"it appears in the diff a reviewer reads."
            )
        else:
            marker = "" if value == previous else f"  (+{value - previous})"
            print(f"  {name:32} {value}{marker}")

    if regressions:
        print(file=sys.stderr)
        for entry in regressions:
            print(f"FAIL: {entry}", file=sys.stderr)
        return 1
    print(f"\nPASS: {len(measured)} gate counts, none reduced.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
