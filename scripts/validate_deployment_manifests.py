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
(T-035, skipped-is-not-passed). It also launches the production Compose profile against real
PostgreSQL, TLS Vault Transit, and an S3-compatible Object Lock bucket, then reaches `/readyz`
over mutual TLS. Rendering a manifest is necessary; this boot is the assertion that it works.
"""

from __future__ import annotations

import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import tomllib
import urllib.error
import urllib.request
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

PRODUCTION_COMPOSE = Path("compose.production.yaml")
PRODUCTION_VALIDATION_OVERRIDE = Path(
    "tests/fixtures/deployment/compose.production.validation.yaml"
)
VAULT_IMAGE = (
    "hashicorp/vault:1.18@"
    "sha256:750bb37c1638fa194ab37053a81618c61bb0491ddec6fccac87c07a8e6cd8166"
)
OBJECT_STORE_IMAGE = (
    "minio/minio@"
    "sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e"
)
PRODUCTION_COMPOSE_SERVICES = {
    "control-plane-production",
    "drain-worker",
    "attestation-worker",
}
PRODUCTION_REQUIRED_ENVIRONMENT = {
    "MIZAN_EVIDENCE_OBJECT_STORE": "s3",
    "MIZAN_AUDIT_ANCHOR_BUCKET": None,
    "MIZAN_S3_ENDPOINT_URL": None,
    "MIZAN_VAULT_ADDR": None,
    "MIZAN_VAULT_TOKEN_FILE": None,
    "MIZAN_ANCHOR_TSA_ENDPOINTS": None,
    "MIZAN_EXECUTION_TOKEN_ISSUER": None,
    "MIZAN_EVALUATOR_BUILD": None,
    "MIZAN_EVALUATOR_CONFIGURATION_HASH": None,
}

# Commands that are legitimately not console scripts. Each is an interpreter invocation, and each
# is verified further below rather than merely tolerated: `python <file>` must name a file that
# exists in the image, `python -c` is an inline probe with no file to resolve.
INTERPRETERS = {"python", "python3", "/usr/bin/env"}

# Background workloads a Mizan install cannot honestly do without. Both were shipped as optional
# or as nothing at all, and in both cases the deployment ran, looked healthy, and silently failed
# to do the thing the product exists to do -- which is why their absence is a gate failure rather
# than a chart preference.
REQUIRED_WORKLOADS = {
    "drainer": (
        "Without one nothing writes mizan.evidence_receipts and execution.py refuses every "
        "financial_write with 403 immutable_receipt_missing (T-099)."
    ),
    "attestation": (
        "Without one every anchor stays pending forever, so no stream may be described as "
        "externally anchored (ADR-004 G.11 / B-12) and the product never produces the RFC 3161 "
        "timestamp that is its central claim (T-106)."
    ),
}

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

    for component, consequence in REQUIRED_WORKLOADS.items():
        if not any(
            item.get("kind") == "Deployment"
            and component in item.get("metadata", {}).get("name", "")
            for item in documents
        ):
            fail(f"the chart renders no {component} workload. {consequence}")

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


def check_compose(scripts: set[str], path: Path = PRODUCTION_COMPOSE) -> None:
    """Check D -- every production service launches something real, and is not opt-in."""
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

    for name in sorted(PRODUCTION_COMPOSE_SERVICES):
        service = services.get(name)
        if service is None:
            fail(f"{path} declares no required production service {name!r}")
            continue
        environment = service.get("environment", {})
        for setting, required_value in PRODUCTION_REQUIRED_ENVIRONMENT.items():
            value = environment.get(setting)
            if value is None or value == "":
                fail(f"{path}:{name} does not set production-required {setting}")
            elif required_value is not None and value != required_value:
                fail(
                    f"{path}:{name} sets {setting}={value!r}; production requires "
                    f"{required_value!r}"
                )
        targets: set[str | None] = set()
        for volume in service.get("volumes", []):
            if isinstance(volume, dict):
                targets.add(volume.get("target"))
            elif isinstance(volume, str):
                fields = volume.split(":")
                if len(fields) >= 2:
                    targets.add(fields[-2] if fields[-1] == "ro" else fields[-1])
        if "/run/mizan/secrets" not in targets:
            fail(
                f"{path}:{name} does not mount /run/mizan/secrets for its Vault token file"
            )
        if "/app/var/evidence" in targets:
            fail(
                f"{path}:{name} still mounts local evidence storage although production "
                "requires S3 Object Lock"
            )


def free_tcp_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def run_checked(
    command: list[str],
    *,
    environment: dict[str, str],
    timeout: int = 300,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        env=environment,
        timeout=timeout,
    )
    if completed.returncode != 0:
        rendered = " ".join(command)
        raise RuntimeError(
            f"command failed ({completed.returncode}): {rendered}\n"
            f"{completed.stdout}{completed.stderr}"
        )
    return completed


def wait_until(description: str, probe: Any, timeout_seconds: int = 60) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            if probe():
                return
        except Exception as error:  # the dependency is expected to refuse while it starts
            last_error = error
        time.sleep(1)
    detail = f": {last_error}" if last_error else ""
    raise RuntimeError(f"timed out waiting for {description}{detail}")


def prepare_validation_credentials(root: Path) -> tuple[Path, Path]:
    """Create short-lived mTLS material solely for the boot assertion."""
    from dev_pki import workload_pki

    tls = root / "tls"
    secrets = root / "runtime"
    paths = workload_pki(tls, "spiffe://mizan-validation/health-probe")
    shutil.copyfile(paths["server_key"], tls / "server-key.pem")
    shutil.copyfile(paths["ca"], tls / "client-ca.pem")
    shutil.copyfile(paths["ca"], tls / "server-ca.pem")
    shutil.copyfile(paths["ca"], tls / "tsa-root.pem")
    shutil.copyfile(paths["client_certificate"], tls / "health-client.pem")
    shutil.copyfile(paths["client_key"], tls / "health-client-key.pem")
    secrets.mkdir()
    (secrets / "vault-token").write_text("validation-only-root\n", encoding="utf-8")

    # Bind-mounted validation files must be readable by the image's non-root UID 65532. They are
    # short-lived under a private temporary directory and removed in the finally block below.
    for path in (*tls.iterdir(), *secrets.iterdir()):
        path.chmod(0o644)
    return tls, secrets


def validate_production_compose_boot() -> None:
    """Launch the shipped production profile and require a real mTLS readiness response."""
    if not PRODUCTION_VALIDATION_OVERRIDE.is_file():
        fail(f"{PRODUCTION_VALIDATION_OVERRIDE} is missing")
        return
    validation_services = yaml.safe_load(
        PRODUCTION_VALIDATION_OVERRIDE.read_text(encoding="utf-8")
    ).get("services", {})
    expected_images = {
        "vault-validation": VAULT_IMAGE,
        "object-store-validation": OBJECT_STORE_IMAGE,
    }
    for service, expected in expected_images.items():
        actual = validation_services.get(service, {}).get("image")
        if actual != expected:
            fail(
                f"{PRODUCTION_VALIDATION_OVERRIDE}:{service} image is {actual!r}; expected the "
                f"reviewed digest {expected!r}"
            )
    if FAILURES:
        return

    project = f"mizan-manifest-{os.getpid()}"
    https_port = free_tcp_port()
    s3_port = free_tcp_port()
    bucket = f"mizan-manifest-{os.getpid()}"
    environment = os.environ.copy()
    compose = [
        "docker",
        "compose",
        "--project-name",
        project,
        "--profile",
        "production",
        "--profile",
        "production-validation",
        "--file",
        str(PRODUCTION_COMPOSE),
        "--file",
        str(PRODUCTION_VALIDATION_OVERRIDE),
    ]

    with tempfile.TemporaryDirectory(prefix=".mizan-compose-validation-", dir=Path.cwd()) as raw:
        root = Path(raw).resolve()
        tls, secrets = prepare_validation_credentials(root)
        environment.update(
            {
                "MIZAN_IMAGE": f"mizan-control-plane:manifest-{os.getpid()}",
                "MIZAN_POSTGRES_OWNER_PASSWORD": "validation-owner-password",
                "MIZAN_APP_PASSWORD": "validation-app-password",
                "MIZAN_JWT_ISSUER": "https://issuer.validation.invalid",
                "MIZAN_JWT_PUBLIC_KEY": "unused-by-readiness",
                "MIZAN_VAULT_ADDR": "https://vault-validation:8200",
                "MIZAN_VAULT_CA_CERT": "/run/mizan/tls/vault-ca.pem",
                "MIZAN_ANCHOR_TSA_ENDPOINTS": "https://tsa.validation.invalid",
                "MIZAN_EXECUTION_TOKEN_ISSUER": "https://execution.validation.invalid",
                "MIZAN_EVALUATOR_BUILD": "deployment-manifest-validation",
                "MIZAN_EVALUATOR_CONFIGURATION_HASH": "b" * 64,
                "MIZAN_DRAIN_TENANTS": "tnt_validation",
                "MIZAN_ATTEST_TENANTS": "tnt_validation",
                "MIZAN_AUDIT_ANCHOR_BUCKET": bucket,
                "MIZAN_S3_ENDPOINT_URL": "http://object-store-validation:9000",
                "MIZAN_S3_REGION": "us-east-1",
                "MIZAN_S3_ACCESS_KEY_ID": "validation-access",
                "MIZAN_S3_SECRET_ACCESS_KEY": "validation-secret-key",
                "MIZAN_TLS_DIRECTORY": str(tls),
                "MIZAN_SECRET_DIRECTORY": str(secrets),
                "MIZAN_HTTPS_PORT": str(https_port),
                "MIZAN_VALIDATION_S3_PORT": str(s3_port),
            }
        )

        try:
            run_checked(
                compose + ["up", "--detach", "vault-validation", "object-store-validation"],
                environment=environment,
            )

            def vault_has_ca() -> bool:
                return (
                    subprocess.run(
                        compose
                        + [
                            "exec",
                            "--no-TTY",
                            "vault-validation",
                            "test",
                            "-f",
                            "/vault-tls/vault-ca.pem",
                        ],
                        env=environment,
                        capture_output=True,
                    ).returncode
                    == 0
                )

            wait_until("Vault's TLS certificate", vault_has_ca)
            vault_id = run_checked(
                compose + ["ps", "--quiet", "vault-validation"], environment=environment
            ).stdout.strip()
            if not vault_id:
                raise RuntimeError("Compose returned no container ID for vault-validation")
            run_checked(
                ["docker", "cp", f"{vault_id}:/vault-tls/vault-ca.pem", str(tls / "vault-ca.pem")],
                environment=environment,
            )
            (tls / "vault-ca.pem").chmod(0o644)

            vault = compose + [
                "exec",
                "--no-TTY",
                "--env",
                "VAULT_ADDR=https://127.0.0.1:8200",
                "--env",
                "VAULT_CACERT=/vault-tls/vault-ca.pem",
                "--env",
                "VAULT_TOKEN=validation-only-root",
                "vault-validation",
                "vault",
            ]
            run_checked(vault + ["secrets", "enable", "transit"], environment=environment)
            for role in (
                "evidence-receipt",
                "evidence-anchor",
                "execution-token",
                "degraded-grant",
            ):
                run_checked(
                    vault
                    + [
                        "write",
                        f"transit/keys/mizan-{role}",
                        "type=ed25519",
                        "exportable=false",
                        "allow_plaintext_backup=false",
                    ],
                    environment=environment,
                )

            s3_health = f"http://127.0.0.1:{s3_port}/minio/health/live"

            def object_store_is_ready() -> bool:
                with urllib.request.urlopen(s3_health, timeout=2) as response:
                    return response.status == 200

            wait_until("the S3-compatible Object Lock store", object_store_is_ready)
            from mizan_control_plane.object_store import build_s3_client

            s3 = build_s3_client(
                f"http://127.0.0.1:{s3_port}",
                "us-east-1",
                "validation-access",
                "validation-secret-key",
            )
            s3.create_bucket(Bucket=bucket, ObjectLockEnabledForBucket=True)

            run_checked(
                compose
                + [
                    "up",
                    "--detach",
                    "--build",
                    "--wait",
                    "control-plane-production",
                    "drain-worker",
                    "attestation-worker",
                ],
                environment=environment,
                timeout=600,
            )

            context = ssl.create_default_context(cafile=str(tls / "server-ca.pem"))
            context.load_cert_chain(
                str(tls / "health-client.pem"), str(tls / "health-client-key.pem")
            )
            readiness = f"https://127.0.0.1:{https_port}/readyz"

            def control_plane_is_ready() -> bool:
                with urllib.request.urlopen(readiness, context=context, timeout=4) as response:
                    return response.status == 200 and b'"status":"ready"' in response.read()

            wait_until("production Compose /readyz", control_plane_is_ready)
        except (OSError, RuntimeError, subprocess.TimeoutExpired, urllib.error.URLError) as error:
            time.sleep(1)
            state = subprocess.run(
                compose + ["ps", "--all", "--format", "json"],
                capture_output=True,
                text=True,
                env=environment,
            )
            logs = subprocess.run(
                compose + ["logs", "--no-color"],
                capture_output=True,
                text=True,
                env=environment,
            )
            fail(
                f"production Compose did not reach /readyz: {error}\n"
                f"COMPOSE STATE:\n{state.stdout}{state.stderr}\n"
                f"COMPOSE LOGS:\n{logs.stdout}{logs.stderr}"
            )
        finally:
            subprocess.run(
                compose + ["down", "--volumes", "--remove-orphans"],
                capture_output=True,
                text=True,
                env=environment,
                timeout=120,
            )


def check_image_pins() -> None:
    """The Dockerfile's base pins genuinely are a text property; assert them as one, narrowly."""
    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")
    if dockerfile.count("python:3.12-slim-trixie@sha256:") != 2:
        fail("Dockerfile no longer pins both stages to a digest of python:3.12-slim-trixie")
    if "uv sync --frozen --no-dev --extra s3" not in dockerfile:
        fail("Dockerfile does not install the S3 backend required by production Compose")
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
    if not FAILURES:
        print("Launching the production Compose profile with real Vault and Object Lock...")
        validate_production_compose_boot()

    if FAILURES:
        print(file=sys.stderr)
        for failure in FAILURES:
            print(f"FAIL: {failure}", file=sys.stderr)
        print(f"\n{len(FAILURES)} deployment manifest failure(s).", file=sys.stderr)
        return 1
    print(
        "\nPASS: every manifest entrypoint resolves, the chart renders, and production Compose "
        "reaches /readyz."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
