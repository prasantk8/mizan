"""Production packaging contracts that must reject the unpackaged tree."""

from __future__ import annotations

import hashlib
import json
from datetime import date
from pathlib import Path

import pytest


def test_migration_runner_refuses_a_recorded_migration_mutated_on_disk(tmp_path) -> None:
    from scripts.migrate import MigrationError, require_recorded_checksum

    source = Path("infra/postgres/migrations/0002_anchor_chain.sql")
    original = source.read_bytes()
    recorded = hashlib.sha256(original).hexdigest()
    migration = tmp_path / source.name
    migration.write_bytes(original + b"\n-- post-application mutation\n")
    current = hashlib.sha256(migration.read_bytes()).hexdigest()

    with pytest.raises(MigrationError, match="recorded migration changed on disk"):
        require_recorded_checksum(migration.name, recorded, current)


def test_migration_set_is_ordered_and_every_file_is_atomic() -> None:
    from scripts.migrate import load_migrations

    migrations = load_migrations(Path("infra/postgres/migrations"))
    assert [migration.filename for migration in migrations] == [
        "0001_domain_schema.sql",
        "0002_anchor_chain.sql",
        "0003_anchor_attestations.sql",
        "0004_outbox_quarantine.sql",
        "0005_evidence_immutability.sql",
        "0006_workforce_sessions.sql",
    ]
    assert all("BEGIN;" not in migration.body.splitlines()[:1] for migration in migrations)


def test_vulnerability_allowlist_rejects_permanent_or_unjustified_exceptions(tmp_path) -> None:
    from scripts.validate_vulnerability_allowlist import validate

    allowlist = tmp_path / ".trivyignore.yaml"
    allowlist.write_text(
        json.dumps(
            {
                "vulnerabilities": [{"id": "CVE-2099-0001"}],
                "misconfigurations": [],
                "secrets": [],
                "licenses": [],
            }
        ),
        encoding="utf-8",
    )
    failures, warnings = validate(allowlist, today=date(2026, 8, 27))
    assert failures == [
        "vulnerabilities[0] has no justification statement",
        "vulnerabilities[0] has no RFC 3339 expired_at",
    ]
    assert warnings == []

    document = json.loads(allowlist.read_text(encoding="utf-8"))
    document["vulnerabilities"][0].update(
        {
            "statement": "Reviewed 2026-08-27: temporary exception",
            "expired_at": "2026-09-03",
        }
    )
    allowlist.write_text(json.dumps(document), encoding="utf-8")
    assert validate(allowlist, today=date(2026, 8, 27)) == (
        ["vulnerabilities[0] has no RFC 3339 expired_at"],
        [],
    )


def test_vulnerability_allowlist_expiry_blast_radius_is_the_image_scan_job(tmp_path) -> None:
    # R-008 F-5: an expired suppression must not fail make check for a branch
    # that never touched the allowlist. It fails only where a live CVE database
    # is actually consulted, gated behind --enforce-expiry.
    from scripts.validate_vulnerability_allowlist import validate

    allowlist = tmp_path / ".trivyignore.yaml"
    allowlist.write_text(
        json.dumps(
            {
                "vulnerabilities": [
                    {
                        "id": "CVE-2020-0001",
                        "statement": "Reviewed 2026-08-20: temporary exception",
                        "expired_at": "2026-08-20T00:00:00Z",
                    }
                ],
                "misconfigurations": [],
                "secrets": [],
                "licenses": [],
            }
        ),
        encoding="utf-8",
    )

    # make check's invocation: report-only. A lapsed suppression is a warning
    # a developer can act on, not a build failure they cannot fix.
    failures, warnings = validate(allowlist, today=date(2026, 8, 27), enforce_expiry=False)
    assert failures == []
    assert warnings == ["vulnerabilities[0] expired on 2026-08-20 (7 days ago)"]

    # the image-scan job's invocation: the same lapse is a real failure.
    failures, warnings = validate(allowlist, today=date(2026, 8, 27), enforce_expiry=True)
    assert failures == ["vulnerabilities[0] expired on 2026-08-20 (7 days ago)"]
    assert warnings == []


def test_vulnerability_allowlist_warns_inside_the_final_week(tmp_path) -> None:
    from scripts.validate_vulnerability_allowlist import validate

    allowlist = tmp_path / ".trivyignore.yaml"
    allowlist.write_text(
        json.dumps(
            {
                "vulnerabilities": [
                    {
                        "id": "CVE-2020-0002",
                        "statement": "Reviewed 2026-08-27: temporary exception",
                        "expired_at": "2026-09-01T00:00:00Z",
                    }
                ],
                "misconfigurations": [],
                "secrets": [],
                "licenses": [],
            }
        ),
        encoding="utf-8",
    )
    failures, warnings = validate(allowlist, today=date(2026, 8, 27), enforce_expiry=True)
    assert failures == []
    assert warnings == ["vulnerabilities[0] expires 2026-09-01 (5 days remaining)"]


def test_vulnerability_allowlist_requires_a_dated_justification(tmp_path) -> None:
    from scripts.validate_vulnerability_allowlist import validate

    allowlist = tmp_path / ".trivyignore.yaml"
    allowlist.write_text(
        json.dumps(
            {
                "vulnerabilities": [
                    {
                        "id": "CVE-2020-0003",
                        "statement": "temporary exception with no review date",
                        "expired_at": "2026-09-10T00:00:00Z",
                    }
                ],
                "misconfigurations": [],
                "secrets": [],
                "licenses": [],
            }
        ),
        encoding="utf-8",
    )

    failures, warnings = validate(allowlist, today=date(2026, 8, 31))
    assert failures == [
        "vulnerabilities[0] statement does not begin with Reviewed YYYY-MM-DD:"
    ]
    assert warnings == []


def test_the_supply_chain_scan_is_wired_and_its_artifacts_are_named() -> None:
    """What is left of the old contract test once the manifest claims move to T-100's gate.

    `test_production_packaging_contract_is_complete` used to assert substrings across the
    Dockerfile, compose, `values.yaml`, the migration job and this workflow. It passed
    throughout the entire period in which `helm install` and
    `docker compose --profile production up` could not start Mizan, and one of its assertions
    -- `assert 'profiles: ["drainer"]' in compose` -- asserted the *presence* of a service
    pointing at a binary that did not exist. Everything it claimed about what the manifests
    launch is now `scripts/validate_deployment_manifests.py`, which resolves entrypoints against
    the declared console scripts and asserts against `helm template` output rather than text.

    These four are genuinely text properties of a workflow file -- there is no rendered object
    to interrogate -- so they stay here, narrowly and under an honest name.
    """
    workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "mizan-sbom.cdx.json" in workflow
    assert "mizan-trivy.json" in workflow
    assert "--scanners vuln --skip-version-check --severity HIGH,CRITICAL --exit-code 1" in workflow
    # The gate that replaced this function must itself be wired, or T-100 buys nothing.
    assert "scripts/validate_deployment_manifests.py" in workflow


def test_production_e2e_job_runs_the_full_journey_test() -> None:
    """The production guarantee belongs to a named required job, not an opt-in local command."""
    workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "\n  production-e2e:\n" in workflow
    assert (
        "tests/integration/test_production_boot.py "
        "tests/integration/test_production_e2e.py" in workflow
    )
    assert "actions/setup-node@" in workflow


def test_the_dockerfile_still_builds_the_runtime_rather_than_the_toolchain() -> None:
    """Text assertions that remain text assertions, because a Dockerfile has no rendered form.

    Narrowed to what only the Dockerfile can say. The digest pin and the non-root UID are also
    asserted by the T-100 gate, deliberately: they are the two properties whose regression is
    least recoverable, and a claim worth making twice is worth checking twice.
    """
    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")
    assert dockerfile.count("python:3.12-slim-trixie@sha256:") == 2
    assert "uv sync --frozen --no-dev" in dockerfile
    assert "apt-get install --no-install-recommends --yes ca-certificates openssl" in dockerfile
    assert "USER 65532:65532" in dockerfile
    assert "HEALTHCHECK" in dockerfile and "/readyz" in dockerfile
    assert "MIZAN_HEALTH_SERVER_CA_FILE" in dockerfile
    assert "COPY --chown=65532:65532 SPEC_v1.md ./SPEC_v1.md" in dockerfile
