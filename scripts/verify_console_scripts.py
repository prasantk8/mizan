#!/usr/bin/env python3
"""Every declared console script must start from an installation, not from the source tree.

`mizan-mcp-gateway` was declared in `[project.scripts]` from the day the MCP gateway landed and
never once started outside pytest, because two packaging defects hid behind
`tool.pytest.ini_options.pythonpath`:

  1. `packages` listed `integrations/mcp/mizan_mcp_gateway`, which derives one source-strip prefix
     per entry -- and hatchling sorts those prefixes, so `integrations/` was always tried before
     `integrations/mcp/` and always matched first. The gateway shipped as a top-level `mcp/`
     package: unimportable as `mizan_mcp_gateway`, and shadowing the `mcp` distribution this
     project itself depends on.
  2. `mizan_mcp_gateway.governance` imports `mizan` (the separate `mizan-sdk` distribution) at
     module import. Nothing declared that dependency, so no installation ever had it.

Both are invisible to every test in this repository, because pytest puts `sdk/python` and
`integrations/mcp` on `sys.path` before anything runs. A test cannot catch this. Only an
installation can, which is what this script is.

Checks, in order:

  A. Every `[project.scripts]` entry in every distribution runs `--help` with exit 0, from a
     virtualenv that has the wheels installed and no source directory on `sys.path`. The list is
     read from `pyproject.toml`, never hardcoded, so a newly declared script is gated the day it
     is declared.
  B. No top-level module our wheels ship collides with a distribution we depend on. This is the
     general form of defect 1: the failure was not "one path was wrong", it was "a build config
     can silently claim a name that belongs to someone else", and the next nested package would
     reintroduce it.

Run from the repository root. Requires `uv` on PATH.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path

# Distributions built and installed together. Each is a directory holding a pyproject.toml.
DISTRIBUTIONS = (Path("."), Path("sdk/python"))

# Extras that must be installed for the declared scripts to resolve. `mizan-mcp-gateway` is
# declared unconditionally but its imports live behind the `mcp` extra, so a bare install is a
# legitimately incomplete environment and this gate installs the extras rather than pretending
# the script is unconditional.
ROOT_EXTRAS = ("mcp",)


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def read_manifest(directory: Path) -> dict:
    path = directory / "pyproject.toml"
    if not path.is_file():
        fail(f"{path} does not exist")
    return tomllib.loads(path.read_text())


def declared_scripts(directory: Path) -> dict[str, str]:
    return read_manifest(directory).get("project", {}).get("scripts", {})


def declared_dependency_names(directory: Path) -> set[str]:
    """Distribution names this project depends on, normalized per PEP 503."""
    project = read_manifest(directory).get("project", {})
    requirements = list(project.get("dependencies", []))
    for extra in project.get("optional-dependencies", {}).values():
        requirements.extend(extra)
    names = set()
    for requirement in requirements:
        # Strip extras, markers, and version specifiers: `pyjwt[crypto]>=2.10,<3` -> `pyjwt`.
        name = re.split(r"[\[<>=!~;\s]", requirement.strip(), maxsplit=1)[0]
        if name:
            names.add(re.sub(r"[-_.]+", "-", name).lower())
    return names


def build_wheels(out_dir: Path) -> list[Path]:
    for directory in DISTRIBUTIONS:
        result = subprocess.run(
            ["uv", "build", "--wheel", "--out-dir", str(out_dir), str(directory)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            fail(f"building a wheel for {directory} failed:\n{result.stderr}")
    wheels = sorted(out_dir.glob("*.whl"))
    if len(wheels) != len(DISTRIBUTIONS):
        fail(f"expected {len(DISTRIBUTIONS)} wheels, built {len(wheels)}: {wheels}")
    return wheels


def top_level_modules(wheel: Path) -> set[str]:
    """Top-level importable names a wheel installs, excluding its own metadata."""
    modules = set()
    with zipfile.ZipFile(wheel) as archive:
        for name in archive.namelist():
            head = name.split("/", 1)[0]
            if head.endswith((".dist-info", ".data")):
                continue
            if head.endswith(".py"):
                modules.add(head[:-3])
            elif "/" in name:
                modules.add(head)
    return modules


def check_no_shadowed_dependency(wheels: list[Path]) -> None:
    """Check B -- no module we ship may claim a name a dependency owns."""
    depended_on = set()
    for directory in DISTRIBUTIONS:
        depended_on |= declared_dependency_names(directory)

    for wheel in wheels:
        for module in sorted(top_level_modules(wheel)):
            normalized = re.sub(r"[-_.]+", "-", module).lower()
            if normalized in depended_on:
                fail(
                    f"{wheel.name} ships a top-level `{module}`, which is also the name of a "
                    f"distribution this project depends on. Installing Mizan would shadow it. "
                    f"See `[tool.hatch.build.targets.wheel]` in pyproject.toml."
                )
    print(f"  no shipped module collides with any of {len(depended_on)} declared dependencies")


def check_scripts_start(wheels: list[Path], venv: Path) -> None:
    """Check A -- every declared script runs `--help` from an installation."""
    subprocess.run(
        ["uv", "venv", str(venv), "--python", "3.12"],
        check=True,
        capture_output=True,
        text=True,
    )
    # `uv` must stay reachable, so the ambient PATH is kept and the venv is only prepended.
    environment = {**os.environ, "VIRTUAL_ENV": str(venv)}
    environment["PATH"] = f"{venv / 'bin'}{os.pathsep}{environment.get('PATH', '')}"
    # A source directory on PYTHONPATH would defeat the entire point of this gate.
    environment.pop("PYTHONPATH", None)

    # The SDK first: the root distribution's `mcp` extra requires it by name, and a path source
    # in pyproject.toml is a development convenience that an installed environment must not need.
    for wheel in sorted(wheels, key=lambda w: "control_plane" in w.name):
        target = str(wheel)
        if "control_plane" in wheel.name and ROOT_EXTRAS:
            target = f"{wheel}[{','.join(ROOT_EXTRAS)}]"
        result = subprocess.run(
            ["uv", "pip", "install", "--quiet", target],
            capture_output=True,
            text=True,
            env=environment,
        )
        if result.returncode != 0:
            fail(f"installing {wheel.name} into a clean environment failed:\n{result.stderr}")

    scripts: dict[str, str] = {}
    for directory in DISTRIBUTIONS:
        scripts.update(declared_scripts(directory))
    if not scripts:
        fail("no console scripts are declared; this gate would pass vacuously")

    broken = []
    for name, target in sorted(scripts.items()):
        executable = venv / "bin" / name
        if not executable.is_file():
            broken.append(f"{name} ({target}): not installed as an executable")
            continue
        result = subprocess.run(
            [str(executable), "--help"], capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            last = (result.stderr or result.stdout).strip().splitlines()
            detail = last[-1] if last else f"exit {result.returncode}"
            broken.append(f"{name} ({target}): {detail}")
        else:
            print(f"  {name:24} OK")

    if broken:
        print(file=sys.stderr)
        for entry in broken:
            print(f"  {entry}", file=sys.stderr)
        fail(
            f"{len(broken)} of {len(scripts)} declared console scripts do not start from an "
            f"installation. They run under pytest only because "
            f"`tool.pytest.ini_options.pythonpath` puts the source tree on `sys.path`."
        )
    print(f"  all {len(scripts)} declared console scripts start from an installation")


def main() -> int:
    if not Path("pyproject.toml").is_file():
        fail("run this from the repository root")
    if shutil.which("uv") is None:
        fail("uv is not on PATH")

    work = Path(".console-script-gate")
    if work.exists():
        shutil.rmtree(work)
    work.mkdir()
    try:
        print("Building wheels for every distribution...")
        wheels = build_wheels(work / "dist")
        for wheel in wheels:
            print(f"  {wheel.name}")

        print("Checking no shipped module shadows a dependency...")
        check_no_shadowed_dependency(wheels)

        print("Installing into a clean environment and starting every console script...")
        check_scripts_start(wheels, work / "venv")
    finally:
        shutil.rmtree(work, ignore_errors=True)

    print("\nPASS: every declared console script starts from an installation.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
