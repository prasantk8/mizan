"""`make check` must run on a machine that has never been a developer's machine.

R-008 F-8: `baseline-contract` was red on the first CI run this repository ever had, because
`validate-baseline` invoked a bare `python3` and the job installed no dependencies at all.
`jsonschema` is a declared, locked dependency -- it was present on both engineers' laptops
and nowhere else. The two tests below are the two halves of that failure, and each of them
is red at f4f90a2.

Rule 11: the name of each test is the claim.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
MAKEFILE = REPO / "Makefile"
WORKFLOW = REPO / ".github" / "workflows" / "ci.yml"

# A recipe line is a tab-indented line under a target. `make` requires the tab, so this is
# the whole grammar we need.
TARGET = re.compile(r"^([A-Za-z0-9_.-]+):\s*(.*)$")
JOB = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")


def make_targets() -> dict[str, tuple[list[str], list[str]]]:
    """Map each target to its (prerequisites, recipe lines)."""
    targets: dict[str, tuple[list[str], list[str]]] = {}
    current: str | None = None
    for line in MAKEFILE.read_text(encoding="utf-8").splitlines():
        if line.startswith("\t"):
            if current is not None:
                targets[current][1].append(line.strip())
            continue
        match = TARGET.match(line)
        if match and match.group(1) != ".PHONY":
            current = match.group(1)
            targets[current] = (match.group(2).split(), [])
        elif not line.strip():
            current = None
    return targets


def recipes_reachable_from(target: str) -> list[tuple[str, str]]:
    """Every (target, recipe line) `make <target>` would execute, prerequisites included."""
    targets = make_targets()
    seen: set[str] = set()
    collected: list[tuple[str, str]] = []

    def walk(name: str) -> None:
        if name in seen or name not in targets:
            return
        seen.add(name)
        prerequisites, recipe = targets[name]
        for prerequisite in prerequisites:
            walk(prerequisite)
        collected.extend((name, line) for line in recipe)

    walk(target)
    return collected


def job_steps(name: str) -> str:
    """The text of one workflow job, sliced on indentation."""
    lines = WORKFLOW.read_text(encoding="utf-8").splitlines()
    start = next(index for index, line in enumerate(lines) if line == f"  {name}:")
    end = len(lines)
    for index in range(start + 1, len(lines)):
        if JOB.match(lines[index]):
            end = index
            break
    return "\n".join(lines[start:end])


def test_no_make_check_recipe_runs_python_outside_the_locked_environment() -> None:
    """A recipe that reaches the interpreter directly is a recipe that only runs here."""
    offenders = [
        f"{target}: {line}"
        for target, line in recipes_reachable_from("check")
        if re.search(r"\bpython3?\b", line) and "uv run" not in line
    ]
    assert offenders == [], (
        "these `make check` recipes bypass the locked environment, so they pass only on a "
        f"machine that already has the dependencies installed: {offenders}"
    )


def test_the_baseline_contract_job_installs_the_locked_environment_before_running_make_check() -> None:
    """A green job that installed nothing proved the runner's image, not the repository."""
    job = job_steps("baseline-contract")
    # `run: make check` and not `make check`: a comment in the job that mentions the command
    # is not the command, and matching loosely made the ordering assertion below read the
    # wrong offset -- the first version of this test failed against the fix it was written for.
    assert "run: make check" in job, "this test is about the job that runs `make check`"
    install = job.find("uv sync --locked")
    check = job.find("run: make check")
    assert install != -1, (
        "baseline-contract runs `make check` without installing the locked dependencies. "
        "`jsonschema` is declared in pyproject.toml and present in uv.lock; the job has to "
        "actually install it."
    )
    assert install < check, "the dependencies have to be installed before `make check` reads them"
