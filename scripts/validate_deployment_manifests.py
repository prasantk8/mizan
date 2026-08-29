#!/usr/bin/env python3
"""The deployment manifests are checked as rendered objects, not as text.

`test_packaging.py::test_production_packaging_contract_is_complete` read Dockerfile, compose,
`values.yaml`, the migration job and `ci.yml` as **strings** and asserted substrings. It passed
throughout the entire period in which `helm install` and `docker compose --profile production up`
could not start Mizan at all, and one of its assertions --

    assert 'profiles: ["drainer"]' in compose

-- asserted the *presence* of a service pointing at `mizan-drain-outbox`, a binary that did not
exist, behind an opt-in profile. The gate named "the production packaging contract is complete"
was the reason nobody noticed the production packaging contract was broken. No `helm lint` or
`helm template` ran anywhere in this repository.

Two properties of a substring gate make that inevitable, and both are why this script exists:

  * **It cannot tell a directive from a comment.** While fixing T-099 I wrote a comment that
    explained the removal of `profiles: [drainer]` and quoted the string; the assertion matched
    the comment describing the fix.
  * **It cannot tell whether a template renders**, let alone what it renders to. `values.yaml`
    containing `enabled: false` says nothing about which key that belongs to, and a chart that
    fails to render fails no assertion at all.

Check A is the one that matters most, because it is the general form of T-099. Every command any
manifest launches must resolve to something this project actually ships. Had it existed,
`mizan-drain-outbox` would have been caught the hour the manifests were written rather than after
they had shipped as the documented way to deploy.

Requires `docker` (for the pinned Helm image) and PyYAML. It fails rather than skips when either
is missing: a packaging gate that quietly does nothing is the failure it exists to prevent
(T-035, skipped-is-not-passed).
"""

from __future__ import annotations

import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

import yaml

# Pinned by digest for the same reason the chart refuses an unpinned application image: a gate
# whose own toolchain floats can change its verdict without anything in this repository changing.
HELM_IMAGE = (
    "alpine/helm@sha256:ed9dfc49d43d034df3f9880eb777caf0183e5156508672478b80412c63f3db4f"
)

# Rendering requires a digest by design (T-075). The value is irrelevant to every property
# asserted here, so a placeholder keeps the gate from needing a published image to run.
RENDER_DIGEST = "sha256:" + "0" * 64

# Commands that are legitimately not console scripts. Each is an interpreter invocation, and each
# is verified further below rather than merely tolerated: `python <file>` must name a file that
# exists in the image, `python -c` is an inline probe with no file to resolve.
INTERPRETERS = {"python", "python3", "/usr/bin/env"}

FAILURES: list[str] = []


def fail(message: str) -> None:
    FAILURES.append(message)


def declared_console_scripts() -> set[str]:
    scripts: set[str] = set()
    for manifest in (Path("pyproject.toml"), Path("sdk/python/pyproject.toml")):
        if manifest.is_file():
            data = tomllib.loads(manifest.read_text(encoding="utf-8"))
            scripts.update(data.get("project", {}).get("scripts", {}))
    return scripts


def resolve_command(where: str, command: list[Any], scripts: set[str]) -> None:
    """Check A -- whatever this container launches must be something the project ships."""
    if not command:
        return
    head = str(command[0])
    name = head.rsplit("/", 1)[-1]

    if name in scripts:
        return

    if name in INTERPRETERS:
        arguments = [str(item) for item in command[1:]]
        # An inline program has no file to resolve; `-m module` is resolved by the interpreter.
        if any(flag in arguments[:1] for flag in ("-c", "-m")):
            return
        target = next((item for item in arguments if not item.startswith("-")), None)
        if target is None:
            return
        # Image paths are absolute under /app; map them back to the repository.
        local = Path(target[len("/app/") :]) if target.startswith("/app/") else Path(target)
        if not local.is_file():
            fail(
                f"{where}: launches `{' '.join(str(item) for item in command)}`, and "
                f"`{target}` does not exist in this repository"
            )
        return

    fail(
        f"{where}: launches `{name}`, which is not one of this project's declared console "
        f"scripts ({', '.join(sorted(scripts)) or 'none'}) and is not an interpreter. "
        f"A manifest that names a binary nothing installs is how T-099 shipped."
    )


def helm(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{Path.cwd() / 'charts'}:/charts:ro",
            HELM_IMAGE,
            *arguments,
        ],
        capture_output=True,
        text=True,
    )


def rendered_chart_objects() -> list[dict[str, Any]]:
    """Check B and the input to check C -- the chart lints and renders."""
    lint = helm("lint", "/charts/mizan", "--set", f"image.digest={RENDER_DIGEST}")
    if lint.returncode != 0:
        fail(f"helm lint failed:\n{lint.stdout}{lint.stderr}")

    render = helm(
        "template", "mizan", "/charts/mizan", "--set", f"image.digest={RENDER_DIGEST}"
    )
    if render.returncode != 0:
        fail(f"helm template failed to render the chart:\n{render.stderr}")
        return []
    documents = [item for item in yaml.safe_load_all(render.stdout) if item]
    if not documents:
        fail("helm template rendered no objects at all")
    return documents


def containers_of(document: dict[str, Any]) -> list[dict[str, Any]]:
    spec = document.get("spec", {})
    pod = spec.get("template", {}).get("spec", {}) if "template" in spec else {}
    return list(pod.get("containers", [])) + list(pod.get("initContainers", []))


def check_chart(documents: list[dict[str, Any]], scripts: set[str]) -> None:
    """Check C -- production properties asserted against rendered objects."""
    kinds = {(item.get("kind"), item.get("metadata", {}).get("name")) for item in documents}

    drainers = [
        item
        for item in documents
        if item.get("kind") == "Deployment"
        and "drainer" in item.get("metadata", {}).get("name", "")
    ]
    if not drainers:
        fail(
            "the chart renders no drainer workload. Without one nothing writes "
            "mizan.evidence_receipts and execution.py refuses every financial_write with 403 "
            "immutable_receipt_missing -- it is not an optional component (T-099)"
        )

    if not any(kind == "Job" for kind, _ in kinds):
        fail("the chart renders no migration Job")
    for document in documents:
        if document.get("kind") != "Job":
            continue
        hooks = document.get("metadata", {}).get("annotations", {}).get("helm.sh/hook", "")
        if "pre-install" not in hooks or "pre-upgrade" not in hooks:
            fail(
                f"migration Job carries helm.sh/hook={hooks!r}; it must run on both "
                f"pre-install and pre-upgrade or an upgrade starts against an old schema"
            )

    for document in documents:
        name = document.get("metadata", {}).get("name", "?")
        for container in containers_of(document):
            where = f"chart {document.get('kind')}/{name} container {container.get('name')}"
            image = str(container.get("image", ""))
            if "@sha256:" not in image:
                fail(f"{where}: image {image!r} is not digest-pinned")
            security = container.get("securityContext", {})
            if security.get("allowPrivilegeEscalation") is not False:
                fail(f"{where}: allowPrivilegeEscalation is not false")
            if security.get("readOnlyRootFilesystem") is not True:
                fail(f"{where}: readOnlyRootFilesystem is not true")
            if security.get("capabilities", {}).get("drop") != ["ALL"]:
                fail(f"{where}: capabilities.drop is not [ALL]")
            resolve_command(where, list(container.get("command", [])), scripts)
            for probe in ("livenessProbe", "readinessProbe", "startupProbe"):
                execution = container.get(probe, {}).get("exec", {})
                if execution:
                    resolve_command(f"{where} {probe}", list(execution.get("command", [])), scripts)


def check_compose(scripts: set[str]) -> None:
    """Check D -- every production service launches something real, and is not opt-in."""
    path = Path("compose.production.yaml")
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    services = document.get("services", {})
    if not services:
        fail(f"{path} declares no services")

    for name, service in services.items():
        where = f"{path}:{name}"
        profiles = service.get("profiles")
        if profiles is not None and "production" not in profiles:
            fail(
                f"{where}: profiles={profiles!r} keeps this service out of the production "
                f"profile. Shipping a required component as opt-in is how the drain worker "
                f"stayed invisible (T-099)"
            )
        command = service.get("entrypoint") or service.get("command") or []
        if isinstance(command, str):
            command = command.split()
        resolve_command(where, list(command), scripts)

    if not any("drain" in name for name in services):
        fail(f"{path} declares no drain worker service")


def check_image_pins() -> None:
    """The Dockerfile's base pins genuinely are a text property; assert them as one, narrowly."""
    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")
    if dockerfile.count("python:3.12-slim-trixie@sha256:") != 2:
        fail("Dockerfile no longer pins both stages to a digest of python:3.12-slim-trixie")
    if "USER 65532:65532" not in dockerfile:
        fail("Dockerfile does not drop to UID/GID 65532")


def main() -> int:
    if not Path("charts/mizan/Chart.yaml").is_file():
        print("FAIL: run this from the repository root", file=sys.stderr)
        return 1
    if subprocess.run(["docker", "version"], capture_output=True).returncode != 0:
        # Not a skip. A packaging gate that quietly does nothing is precisely the defect this
        # script replaces, and T-035 makes skipped-is-not-passed a standing rule.
        print("FAIL: docker is required to render the chart with the pinned Helm image", file=sys.stderr)
        return 1

    scripts = declared_console_scripts()
    if not scripts:
        print("FAIL: no console scripts declared; check A would pass vacuously", file=sys.stderr)
        return 1

    print(f"Resolving manifest entrypoints against {len(scripts)} declared console scripts...")
    check_compose(scripts)
    print("Linting and rendering the chart with the pinned Helm image...")
    documents = rendered_chart_objects()
    if documents:
        print(f"  rendered {len(documents)} object(s)")
        check_chart(documents, scripts)
    check_image_pins()

    if FAILURES:
        print(file=sys.stderr)
        for failure in FAILURES:
            print(f"FAIL: {failure}", file=sys.stderr)
        print(f"\n{len(FAILURES)} deployment manifest failure(s).", file=sys.stderr)
        return 1
    print("\nPASS: every manifest entrypoint resolves and the chart renders as required.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
