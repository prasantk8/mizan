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

# CODEX, reviewing PR #4: "the hand-written graph is not GNU Make's graph." Two edges the
# first version followed nowhere -- a recipe that re-enters make, and a recipe that shells
# out to a script which then reaches the interpreter. Both hide a bare `python3` one hop
# past where the walk stopped. R-008 F-14.
SUB_MAKE = re.compile(r"(?:\$[({]MAKE[)}]|(?<![\w./-])make)\s+([A-Za-z0-9_.-]+)")
SHELL_SCRIPT = re.compile(r"(?<![\w=/-])((?:\./)?[\w][\w./-]*\.sh)")

# Constructs this parser does not model. It is honest about them by refusing to sit in a
# Makefile that uses one, rather than by walking past it silently.
UNMODELLED = re.compile(r"^\s*(?:-?include|ifeq|ifneq|ifdef|ifndef|else|endif)\b")


def make_targets(makefile: Path = MAKEFILE) -> dict[str, tuple[list[str], list[str]]]:
    """Map each target to its (prerequisites, recipe lines)."""
    targets: dict[str, tuple[list[str], list[str]]] = {}
    current: str | None = None
    for line in makefile.read_text(encoding="utf-8").splitlines():
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


def recipes_reachable_from(
    target: str, makefile: Path = MAKEFILE, root: Path = REPO
) -> list[tuple[str, str]]:
    """Every (source, line) `make <target>` would execute, one hop past make included.

    Prerequisites, recursive `$(MAKE) other` invocations, and the text of any `.sh` script a
    reachable recipe runs. A script is reported under its own path, because that is where
    the offending line has to be fixed.
    """
    targets = make_targets(makefile)
    seen: set[str] = set()
    collected: list[tuple[str, str]] = []

    def walk_script(path: str) -> None:
        resolved = root / path.removeprefix("./")
        key = f"script:{resolved}"
        if key in seen or not resolved.is_file():
            return
        seen.add(key)
        for line in resolved.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            collected.append((path, stripped))
            for nested in SHELL_SCRIPT.findall(stripped):
                walk_script(nested)

    def walk(name: str) -> None:
        if name in seen or name not in targets:
            return
        seen.add(name)
        prerequisites, recipe = targets[name]
        for prerequisite in prerequisites:
            walk(prerequisite)
        for line in recipe:
            collected.append((name, line))
            for sub_target in SUB_MAKE.findall(line):
                walk(sub_target)
            for script in SHELL_SCRIPT.findall(line):
                walk_script(script)

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


def test_a_bare_interpreter_hidden_behind_a_sub_make_or_a_shell_script_is_still_found(
    tmp_path: Path,
) -> None:
    """CODEX's counterexample from the PR #4 review, made executable.

    `check -> wrapper`, where `wrapper` runs `$(MAKE) hidden` and `hidden` runs a shell
    script that reaches the interpreter. The first walker followed prerequisites only, so it
    stopped at `wrapper` and reported the tree clean. Both hops are red here.
    """
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "check.sh").write_text("#!/bin/sh\npython3 scripts/thing.py\n")
    makefile = tmp_path / "Makefile"
    makefile.write_text(
        "check: wrapper\n"
        "\t@echo done\n"
        "\n"
        "wrapper:\n"
        "\t$(MAKE) hidden\n"
        "\n"
        "hidden:\n"
        "\tbash scripts/check.sh\n"
    )
    found = [line for _, line in recipes_reachable_from("check", makefile, tmp_path)]
    assert "$(MAKE) hidden" in found, "a recipe that re-enters make is an edge in the graph"
    assert "python3 scripts/thing.py" in found, (
        "the interpreter was one hop past where the walk stopped, which is exactly how F-8 "
        "survived being looked at"
    )


def test_the_makefile_stays_inside_the_subset_this_parser_understands() -> None:
    """The guard above is only as true as the parser under it, so pin the parser's premise.

    `include`, conditionals, pattern rules and multi-target rules are all things GNU Make
    does and this parser does not. Rather than claim to handle them, fail loudly the day one
    appears, so the next person fixes the walker instead of trusting a walk that skipped a
    third of the file.
    """
    unmodelled: list[str] = []
    for number, line in enumerate(MAKEFILE.read_text(encoding="utf-8").splitlines(), start=1):
        if line.startswith("\t") or not line.strip() or line.lstrip().startswith("#"):
            continue
        # A directive we do not read, or a rule head we do not parse -- a pattern rule, a
        # multi-target rule, a variable-expanded prerequisite list.
        if UNMODELLED.match(line) or (
            ":" in line.split("=")[0] and not TARGET.match(line)
        ):
            unmodelled.append(f"{number}: {line}")
    assert unmodelled == [], (
        "the Makefile now uses constructs this parser walks past in silence, so "
        f"test_no_make_check_recipe_runs_python_outside_the_locked_environment is no longer "
        f"the guarantee its name claims: {unmodelled}"
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
