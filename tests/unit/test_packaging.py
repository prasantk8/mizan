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
        {"statement": "temporary exception", "expired_at": "2026-09-03"}
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
                        "statement": "temporary exception",
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
                        "statement": "temporary exception",
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


def test_production_packaging_contract_is_complete() -> None:
    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")
    assert dockerfile.count("python:3.12-slim-trixie@sha256:") == 2
    assert "uv sync --frozen --no-dev" in dockerfile
    assert "apt-get install --no-install-recommends --yes ca-certificates openssl" in dockerfile
    assert "USER 65532:65532" in dockerfile
    assert "HEALTHCHECK" in dockerfile and "/health/ready" in dockerfile
    assert "MIZAN_HEALTH_SERVER_CA_FILE" in dockerfile
    assert "COPY --chown=65532:65532 SPEC_v1.md ./SPEC_v1.md" in dockerfile

    compose = Path("compose.production.yaml").read_text(encoding="utf-8")
    assert "postgresql://mizan_app:" in compose
    assert "python /app/scripts/migrate.py" not in compose
    assert 'entrypoint: ["python", "/app/scripts/migrate.py"]' in compose
    # Was `assert 'profiles: ["drainer"]' in compose`, and was passing: it asserted the presence
    # of a service pointing at `mizan-drain-outbox`, a binary that did not exist, behind an
    # opt-in profile. Without that service `execution.py::_require_receipts` refuses every
    # `financial_write` with 403 `immutable_receipt_missing`, so the assertion was pinning the
    # defect in place under the name "the production packaging contract is complete" (T-099).
    assert 'profiles: ["drainer"]' not in compose
    assert 'entrypoint: ["mizan-drain-outbox"]' in compose
    assert "MIZAN_HEALTH_SERVER_CA_FILE: /run/mizan/tls/server-ca.pem" in compose

    chart_values = Path("charts/mizan/values.yaml").read_text(encoding="utf-8")
    # Same defect in the chart: `enabled: false` on the drainer. A substring test cannot tell
    # which key it matched, which is half of why this went unnoticed -- T-100 replaces the whole
    # function with `helm template` and assertions against rendered objects.
    assert "drainer:\n" in chart_values
    assert "enabled: false" not in chart_values
    migration_job = Path("charts/mizan/templates/migration-job.yaml").read_text(
        encoding="utf-8"
    )
    assert "pre-install,pre-upgrade" in migration_job

    workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "mizan-sbom.cdx.json" in workflow
    assert "mizan-trivy.json" in workflow
    assert "--scanners vuln --skip-version-check --severity HIGH,CRITICAL --exit-code 1" in workflow
