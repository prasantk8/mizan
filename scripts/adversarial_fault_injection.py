#!/usr/bin/env python3
"""Prove the adversarial suite is adversarial, by breaking the guards on purpose.

R-008 F-3: three of the four categories in tests/adversarial/ toggled behaviour
inside the TEST itself -- a stub verifier swapped in for chain_tamper, a static
policy decision flipped for prompt_namespace, which tenant is used as attacker for
cross_tenant -- and a fault applied that way proves nothing about the product. Only
token_replay ever touched real state (clearing a row's consumed_at in PostgreSQL),
and that is the shape every category now has: this script reverts one real guard
in control-plane/mizan_control_plane/ per category, runs exactly the test that
guard exists to satisfy, and requires red.

token_replay needed no source patch -- it already manipulates real state through
tests/adversarial/.regression, so this script only sets the marker for it.

Usage: python3 scripts/adversarial_fault_injection.py [--list]

Requires MIZAN_TEST_DATABASE_URL for cross_tenant and token_replay, which use
PostgreSQL directly; chain_tamper and prompt_namespace do not.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MARKER = ROOT / "tests/adversarial/.regression"

FAULTS = [
    {
        "name": "chain_tamper",
        "proves": "a tampered record body is caught by hash comparison, not accepted by a stub",
        "file": "control-plane/mizan_control_plane/evidence.py",
        "find": (
            '        actual = canonical_hash(\n'
            '            {key: value for key, value in record.items() if key != "record_hash"}\n'
            '        )\n'
            '        if actual != record["record_hash"]:'
        ),
        "replace": (
            '        actual = canonical_hash(\n'
            '            {key: value for key, value in record.items() if key != "record_hash"}\n'
            '        )\n'
            '        if False:'
        ),
        "test": "tests/adversarial/test_chain_tamper.py",
        "needs_db": False,
    },
    {
        "name": "prompt_namespace",
        "proves": "tool arguments never enter the policy evaluation namespace, even if flattened",
        "file": "control-plane/mizan_control_plane/policy_engine.py",
        "find": '            "context": {"mizan": _cedar_context(context.model_dump(mode="json"))},',
        "replace": (
            '            "context": {"mizan": {**_cedar_context(context.model_dump(mode="json")), '
            '**(context.tool.arguments.get("external") or {})}},'
        ),
        "test": "tests/adversarial/test_prompt_namespace.py",
        "needs_db": False,
    },
    {
        "name": "cross_tenant",
        "proves": "every registry query is scoped to the authenticated tenant by RLS, not by convention",
        "file": "control-plane/mizan_control_plane/repository.py",
        "find": (
            "    def _scope(connection: psycopg.Connection, tenant_id: str) -> None:\n"
            "        connection.execute(\"SELECT set_config('app.tenant_id', %s, true)\", (tenant_id,))"
        ),
        "replace": (
            "    def _scope(connection: psycopg.Connection, tenant_id: str) -> None:\n"
            "        pass"
        ),
        "test": "tests/adversarial/test_cross_tenant_fuzz.py",
        "needs_db": True,
    },
    {
        "name": "token_replay",
        "proves": "a redeemed execution token is refused as consumed, not merely as concurrently modified",
        "file": None,
        "test": "tests/adversarial/test_token_replay.py::test_redeemed_execution_token_is_refused_as_consumed",
        "needs_db": True,
    },
    {
        "name": "rate_limit",
        "proves": "a burst is stopped by the shipped admission guard before the handler runs",
        "file": "control-plane/mizan_control_plane/rate_limits.py",
        "find": "            if bucket.tokens < 1.0:",
        "replace": "            if False:",
        "test": "tests/adversarial/test_rate_limits.py",
        "needs_db": False,
    },
]


def run_pytest(*nodeids: str) -> tuple[bool, str]:
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", *nodeids],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0, result.stdout + result.stderr


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true")
    arguments = parser.parse_args()

    if arguments.list:
        for fault in FAULTS:
            print(f"{fault['name']}: {fault['proves']}")
        return 0

    database_url = os.environ.get("MIZAN_TEST_DATABASE_URL")
    needing_db = [fault["name"] for fault in FAULTS if fault["needs_db"] and not database_url]
    if needing_db and os.environ.get("CI"):
        # T-035, skipped-is-not-passed. On a developer's machine, skipping the categories that
        # need PostgreSQL is a convenience. On a build machine it is a false green: this gate
        # would report that every fault was caught while having injected fewer of them, and the
        # reason -- an unset environment variable -- is exactly the kind of thing that changes
        # silently when a workflow is edited. The job that runs this provisions a database; if
        # it stops doing so, that must be a red build rather than a quieter one.
        print(
            f"MIZAN_TEST_DATABASE_URL is not set under CI. These categories cannot be injected "
            f"and a partial run must not report success: {', '.join(needing_db)}",
            file=sys.stderr,
        )
        return 1
    if needing_db:
        print(
            f"MIZAN_TEST_DATABASE_URL is not set; skipping (not failing) categories that need "
            f"PostgreSQL: {', '.join(needing_db)}. Under CI this is an error, not a skip.",
            file=sys.stderr,
        )

    baseline_targets = [
        f["test"].split("::")[0] for f in FAULTS if not (f["needs_db"] and not database_url)
    ]
    green, output = run_pytest(*baseline_targets)
    if not green:
        print("the suite is already red before any fault was injected; fix that first", file=sys.stderr)
        print(output, file=sys.stderr)
        return 1
    print("baseline: green\n")

    survivors: list[str] = []
    skipped: list[str] = []
    for fault in FAULTS:
        if fault["needs_db"] and not database_url:
            print(f"SKIPPED {fault['name']}\n        MIZAN_TEST_DATABASE_URL not set")
            skipped.append(fault["name"])
            continue

        if fault["file"] is None:
            # token_replay: no source to patch, only the marker.
            MARKER.write_text(fault["name"], encoding="utf-8")
            try:
                passed, output = run_pytest(fault["test"])
            finally:
                MARKER.unlink(missing_ok=True)
            if not passed:
                print(f"RED     {fault['name']}\n        caught by: {_first_failure(output)}")
            else:
                print(f"SURVIVED {fault['name']}\n        nothing failed. {fault['proves']} is not actually tested.")
                survivors.append(fault["name"])
            continue

        target = ROOT / fault["file"]
        original = target.read_text(encoding="utf-8")
        if fault["find"] not in original:
            print(f"STALE   {fault['name']}\n        anchor text not found in {fault['file']}")
            survivors.append(f"{fault['name']} (stale)")
            continue

        target.write_text(original.replace(fault["find"], fault["replace"], 1), encoding="utf-8")
        try:
            passed, output = run_pytest(fault["test"])
            if not passed:
                print(f"RED     {fault['name']}\n        caught by: {_first_failure(output)}")
            else:
                print(f"SURVIVED {fault['name']}\n        nothing failed. {fault['proves']} is not actually tested.")
                survivors.append(fault["name"])
        finally:
            target.write_text(original, encoding="utf-8")

    attempted = len(FAULTS) - len(skipped)
    caught = attempted - len(survivors)
    print(f"\n{caught}/{attempted} faults caught" + (f" ({len(skipped)} skipped: {', '.join(skipped)})" if skipped else ""))
    if survivors:
        print(f"uncaught: {', '.join(survivors)}")
        return 1
    if skipped:
        # A skip is not a pass. CI always has MIZAN_TEST_DATABASE_URL; a local
        # run without it is informational and must not report false confidence.
        return 2
    return 0


def _first_failure(output: str) -> str:
    for line in output.splitlines():
        if line.startswith("FAILED ") or line.startswith("ERROR "):
            return line.split("::", 1)[-1].split(" - ")[0]
    return "(see full output)"


if __name__ == "__main__":
    raise SystemExit(main())
