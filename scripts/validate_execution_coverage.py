#!/usr/bin/env python3
"""Gate the execution security module on which refusals run, not on how much of it does.

R-008 F-12. The gate this replaces was `pytest tests/unit/test_execution.py --cov-fail-under=50`,
and three things were wrong with it at once.

It measured one test file against a module whose transactional paths — `redeem`, `_transition_lease`,
`_require_receipts` — cannot execute without a database, so the number it produced was "what
proportion of `execution.py` happens not to need PostgreSQL". Those paths *are* tested, by
`tests/integration/`, in a job that was already green.

Because of that, **the number fell as the module got better.** Every transactional line added moved
it down. `main` cleared fifty by 0.92 of a point; `track-b/stage-5`, which is strictly better tested,
sits at 48.31 and is red (PR #3, `python-contract`). A gate that a lane fails for improving the code
is not measuring the thing its name claims.

And a percentage was never the claim anyone wanted. Measured across both suites this module is at
90%, and inside that 90% **seventeen of its thirty-eight `raise Problem(...)` refusals had never been
executed by any test** — including four in `_require_receipts`, the guard that stops a financial
write executing before its ADR_Record and approval are durably published (SPEC 5.4). Averaging hid
them, and a floor of fifty would have gone on hiding them at any percentage.

So the gate now asserts two things and says which is which:

  1. **Every refusal in `execution.py` is exercised, or is written down.** The unexercised set is
     committed in `tests/execution-refusal-debt.json` and is a ratchet: a refusal that leaves the
     file may not come back, and one that becomes covered must be removed from it. Refusals are
     keyed by their `Problem` code rather than by line number, so the gate survives edits to the
     module it guards.
  2. **A module floor, as a regression tripwire and not a quality claim.** 80%, below both 90.77%
     (main's 271-statement execution.py) and 83.28% (T-062/T-084's 317-statement variant, which
     carries Track-B growth main hasn't merged yet), measured 2026-08-28. Set below the lower of the
     two so an honest branch difference in module size doesn't trip it — same principle as T-090/F-9
     ("set the budget from the slowest machine measured, not the fastest"), applied to module variants
     instead of hardware. It exists to catch a suite that stopped running, which is the failure a
     per-refusal rule cannot see.

Run where the database is, because that is the only place the answer is true:

    uv run --frozen pytest tests/unit tests/integration \\
      --cov=mizan_control_plane.execution --cov-report=json:.coverage-execution.json
    uv run --frozen python scripts/validate_execution_coverage.py

`--record` rewrites the debt file. Removing an entry is the point; adding one needs a reviewer to
ask why a refusal shipped that nothing refuses with.
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "control-plane/mizan_control_plane/execution.py"
DEBT = ROOT / "tests/execution-refusal-debt.json"
COVERAGE = ROOT / ".coverage-execution.json"

# Measured across tests/unit + tests/integration on 2026-08-28: 90.77% on main (271 statements).
# T-062 and T-084 both carry a larger execution.py (317 statements — Track-B growth that never
# reached main) that measures 83.28% against the same suite plus this change-set's two new tests,
# because the extra statements are less thoroughly exercised than the rest of the module. The floor
# sits below both real measurements, with margin, so an honest branch difference in module size
# doesn't trip it — same principle as T-090/F-9 ("the budget must be one any machine we support
# clears, set from the slowest one measured, not the fastest"), applied to module variants instead
# of hardware. It is still a tripwire for a suite that stopped running, not a statement about how
# well tested this module is; rule 1 above is the statement about that.
FLOOR_PERCENT = 80.0
FLOOR_BASIS = "90.77% (main, 271 stmt) and 83.28% (T-062/T-084, 317 stmt) measured on 2026-08-28"


def refusal_sites(source: str) -> dict[str, int]:
    """Every `raise Problem(<status>, "<code>", ...)` in the module, keyed `code#n` by source order.

    Keyed by code because line numbers move whenever the module is edited, and a gate that has to be
    re-recorded after every edit is a gate that gets re-recorded without being read.
    """
    seen: Counter[str] = Counter()
    sites: dict[str, int] = {}
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Raise) or not isinstance(node.exc, ast.Call):
            continue
        if getattr(node.exc.func, "id", None) != "Problem":
            continue
        code = next(
            (
                argument.value
                for argument in node.exc.args
                if isinstance(argument, ast.Constant) and isinstance(argument.value, str)
            ),
            None,
        )
        if code is None:
            continue
        seen[code] += 1
        sites[f"{code}#{seen[code]}"] = node.lineno
    return sites


def evaluate(coverage_path: Path) -> tuple[list[str], float]:
    try:
        report = json.loads(coverage_path.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(
            f"{coverage_path} is missing or malformed ({exc}). Produce it with:\n"
            "  uv run --frozen pytest tests/unit tests/integration "
            "--cov=mizan_control_plane.execution --cov-report=json:.coverage-execution.json"
        ) from exc
    files = [data for name, data in report["files"].items() if name.endswith("execution.py")]
    if len(files) != 1:
        raise SystemExit(f"{coverage_path} does not report exactly one execution.py")
    executed = set(files[0]["executed_lines"])
    sites = refusal_sites(MODULE.read_text(encoding="utf-8"))
    unexercised = sorted(key for key, line in sites.items() if line not in executed)
    return unexercised, files[0]["summary"]["percent_covered"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--coverage", type=Path, default=COVERAGE)
    parser.add_argument("--record", action="store_true")
    arguments = parser.parse_args()
    unexercised, percent = evaluate(arguments.coverage)
    if arguments.record:
        DEBT.write_text(
            json.dumps(
                {
                    "module": "control-plane/mizan_control_plane/execution.py",
                    "measured_total_percent": round(percent, 2),
                    "unexercised_refusals": unexercised,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"recorded {len(unexercised)} unexercised refusals at {percent:.2f}% total coverage")
        return 0
    recorded = set(json.loads(DEBT.read_bytes())["unexercised_refusals"])
    failures = []
    for key in sorted(set(unexercised) - recorded):
        failures.append(
            f"refusal {key} is raised by no test. Cover it, or record it with a reviewer's "
            f"agreement using --record."
        )
    for key in sorted(recorded - set(unexercised)):
        failures.append(
            f"refusal {key} is now exercised and is still recorded as debt. Re-record: the "
            f"ratchet only turns one way."
        )
    if percent < FLOOR_PERCENT:
        failures.append(
            f"execution.py total coverage {percent:.2f}% is below the {FLOOR_PERCENT}% tripwire "
            f"({FLOOR_BASIS}). This floor catches a suite that stopped running; if the drop is "
            f"real work, the refusal rule above is what should be failing."
        )
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(
        f"execution refusals: {len(unexercised)} of {len(refusal_sites(MODULE.read_text()))} "
        f"unexercised and recorded, none new; module at {percent:.2f}% "
        f"(tripwire {FLOOR_PERCENT}%)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
