#!/usr/bin/env python3
"""Restore PostgreSQL and Object Lock evidence into fresh targets, then run both verifiers."""

from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import quote, urlsplit, urlunsplit

import psycopg
from cryptography.hazmat.primitives import serialization
from mizan_control_plane.canonical import binding_hash
from mizan_control_plane.evidence import (
    Ed25519EvidenceSigner,
    EvidenceRepository,
    LocalImmutableObjectStore,
    OutboxPublisher,
)
from mizan_control_plane.evidence_export import export_evidence_bundle
from mizan_control_plane.models import AuthenticatedIdentity, EvaluationContext
from mizan_control_plane.object_store import (
    S3ObjectLockStore,
    build_s3_client,
    provision_object_lock_bucket,
)
from mizan_control_plane.repository import PostgresAuthorizationRepository
from mizan_control_plane.risk import RegistryFloorRiskProvider
from mizan_control_plane.service import AuthorizationService

TENANT = "tnt_restore-drill"
STREAM = f"{TENANT}:adr:0"
SOURCE_DATABASE = "mizan_restore_drill_source"
RESTORED_DATABASE = "mizan_restore_drill_restored"
APP_PASSWORD = "restore-drill-app-only"


def database_dsn(admin_dsn: str, database: str, *, runtime: bool = False) -> str:
    parsed = urlsplit(admin_dsn)
    if parsed.path not in {"", "/", "/postgres"}:
        raise ValueError("admin URL must connect to the postgres maintenance database")
    netloc = parsed.netloc
    if runtime:
        host = parsed.hostname or "127.0.0.1"
        port = f":{parsed.port}" if parsed.port else ""
        netloc = f"mizan_app:{quote(APP_PASSWORD)}@{host}{port}"
    return urlunsplit((parsed.scheme, netloc, f"/{database}", parsed.query, parsed.fragment))


def recreate_database(admin_dsn: str, database: str) -> None:
    if not database.startswith("mizan_restore_drill_"):
        raise ValueError(f"refusing destructive drill target {database!r}")
    with psycopg.connect(admin_dsn, autocommit=True) as connection:
        connection.execute(f'DROP DATABASE IF EXISTS "{database}" WITH (FORCE)')
        connection.execute(f'CREATE DATABASE "{database}"')


def apply_migrations(repository: Path, database_url: str) -> None:
    with psycopg.connect(database_url, autocommit=True) as connection:
        for migration in sorted((repository / "infra/postgres/migrations").glob("*.sql")):
            connection.execute(migration.read_text(encoding="utf-8"))
        connection.execute(f"ALTER ROLE mizan_app LOGIN PASSWORD '{APP_PASSWORD}'")
        connection.execute(
            "INSERT INTO mizan.tenants(tenant_id,region,status) VALUES (%s,'drill','ACTIVE')",
            (TENANT,),
        )


def seed_authorization(database_url: str) -> tuple[EvidenceRepository, Ed25519EvidenceSigner, Ed25519EvidenceSigner]:
    repository = PostgresAuthorizationRepository(database_url)
    tool = {
        "tenant_id": TENANT,
        "tool_id": "tool_restore-check",
        "risk_tier": "HIGH",
        "owner": "continuity-team",
        "resource_owner": "core-banking",
        "data_classification": "financial",
        "binding_profile": {
            "profile_id": "bp_restore-check-v1",
            "profile_version": 1,
            "canonicalization": "RFC8785",
            "bound_pointers": ["/amount"],
            "volatile_pointers": ["/request_time"],
            "unknown_pointer_policy": "reject",
        },
        "execution": {
            "executor_spiffe_ids": ["spiffe://mizan/drill/executor"],
            "token_ttl_seconds": 300,
            "lease_ttl_seconds": 900,
            "heartbeat_interval_seconds": 60,
            "max_lease_extensions": 24,
        },
    }
    policy = {
        "schema_version": "1.2",
        "policy_id": "pol_restore-allow",
        "tenant_id": TENANT,
        "name": "Continuity drill fixture",
        "version": 1,
        "status": "ACTIVE",
        "author": "continuity-team",
        "applies_to": {"tool_ids": ["tool_restore-check"]},
        "conditions": {"field": "action.type", "op": "eq", "value": "financial_write"},
        "decision": "ALLOW",
        "priority": 100,
        "content_hash": "4" * 64,
        "created_at": "2026-09-01T00:00:00Z",
    }
    with repository.pool.connection() as connection, connection.transaction():
        repository._scope(connection, TENANT)
        connection.execute(
            "INSERT INTO mizan.binding_profiles(tenant_id,profile_id,profile_version,canonicalization,bound_pointers,volatile_pointers,content_hash) VALUES (%s,'bp_restore-check-v1',1,'RFC8785','[\"/amount\"]','[\"/request_time\"]',%s)",
            (TENANT, "1" * 64),
        )
        connection.execute(
            "INSERT INTO mizan.tools(tenant_id,tool_id,profile_id,profile_version,document) VALUES (%s,'tool_restore-check','bp_restore-check-v1',1,%s)",
            (TENANT, json.dumps(tool)),
        )
        connection.execute(
            "INSERT INTO mizan.agents(tenant_id,agent_id,version,lifecycle_state,document,created_at,updated_at) VALUES (%s,'agt_restore-agent','1.0.0','ACTIVE',%s,now(),now())",
            (TENANT, json.dumps({"tenant_id": TENANT, "agent_id": "agt_restore-agent"})),
        )
        connection.execute(
            "INSERT INTO mizan.agent_tools(tenant_id,agent_id,tool_id) VALUES (%s,'agt_restore-agent','tool_restore-check')",
            (TENANT,),
        )
        connection.execute(
            "INSERT INTO mizan.policies(tenant_id,policy_id,version,status,effective_from,decision,content_hash,document,created_at) VALUES (%s,'pol_restore-allow',1,'ACTIVE',now()-interval '1 minute','ALLOW',%s,%s,now()-interval '1 minute')",
            (TENANT, "4" * 64, json.dumps(policy)),
        )
        connection.execute(
            "INSERT INTO mizan.evidence_chain_heads(tenant_id,stream_id) VALUES (%s,%s)",
            (TENANT, STREAM),
        )
    principal = AuthenticatedIdentity(
        tenant_id=TENANT,
        agent_id="agt_restore-agent",
        subject="continuity-drill",
        delegation_chain=["agt_restore-agent"],
    )
    service = AuthorizationService(
        repository, RegistryFloorRiskProvider(), "continuity-drill", "f" * 64
    )
    for suffix in ("1", "2"):
        arguments = {"amount": 12500, "request_time": f"drill-{suffix}"}
        service.authorize(
            principal,
            EvaluationContext.model_validate(
                {
                    "schema_version": "1.2",
                    "request_id": f"018f47a6-7b42-7c00-8000-00000000030{suffix}",
                    "tenant_id": TENANT,
                    "principal": {
                        "id": "prn_restore-operator",
                        "type": "employee",
                        "role": "operator",
                        "auth_strength": "mfa",
                    },
                    "agent": {
                        "id": "agt_restore-agent",
                        "version": "1.0.0",
                        "delegation_chain": ["agt_restore-agent"],
                    },
                    "intent": "prove restored evidence",
                    "tool": {
                        "id": "tool_restore-check",
                        "arguments": arguments,
                        "parameters_hash": binding_hash(arguments, ["/amount"]),
                        "binding_profile": {
                            "profile_id": "bp_restore-check-v1",
                            "profile_version": 1,
                        },
                    },
                    "action": {"type": "financial_write"},
                    "resource": {
                        "id": "continuity/fixture",
                        "type": "evidence",
                        "resource_owner": "core-banking",
                        "data_classification": "financial",
                    },
                    "business": {"transaction_value": {"amount": 12500, "currency": "AED"}},
                    "security": {"anomaly_score": 0.0},
                    "environment": "production",
                    "timestamp": "2026-09-01T00:00:00Z",
                }
            ),
        )
    receipt = Ed25519EvidenceSigner.development("evidence-receipt")
    anchor = Ed25519EvidenceSigner.development("evidence-anchor")
    return EvidenceRepository(database_url), receipt, anchor


def key_documents(*signers: tuple[str, Ed25519EvidenceSigner]) -> list[dict[str, object]]:
    return [
        {
            "key_id": signer.key_id,
            "algorithm": "Ed25519",
            "role": role,
            "custody": "development-derived",
            "public_key": base64.urlsafe_b64encode(
                signer.public_key.public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw
                )
            ).decode(),
            "not_before": "2026-09-01T00:00:00Z",
            "not_after": None,
            "revoked_at": None,
        }
        for role, signer in signers
    ]


def backup_bucket(client, bucket: str, target: Path) -> list[str]:
    keys: list[str] = []
    continuation = None
    while True:
        request = {"Bucket": bucket}
        if continuation:
            request["ContinuationToken"] = continuation
        page = client.list_objects_v2(**request)
        for item in page.get("Contents", []):
            key = item["Key"]
            payload = client.get_object(Bucket=bucket, Key=key)["Body"].read()
            path = target / key
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            keys.append(key)
        if not page.get("IsTruncated"):
            break
        continuation = page["NextContinuationToken"]
    if not keys:
        raise RuntimeError("source Object Lock bucket contained no evidence")
    return sorted(keys)


def verify(command: list[str], label: str, repository: Path) -> str:
    result = subprocess.run(command, cwd=repository, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"{label} failed ({result.returncode}):\n{result.stdout}{result.stderr}")
    print(f"PASS: {label}")
    return result.stdout


def verify_bundle(command: list[str], label: str, repository: Path) -> dict[str, object]:
    output = verify([*command, "--json"], label, repository)
    try:
        document = json.loads(output)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"{label} emitted no JSON verdict document") from error
    if document.get("verdict") != "VALID" or document.get("exit_status") != 0:
        raise RuntimeError(f"{label} did not return VALID: {document}")
    return document


def backup_database(admin_dsn: str, database_dsn_value: str, target: Path, container: str) -> None:
    if container:
        parsed = urlsplit(admin_dsn)
        command = [
            "docker",
            "exec",
            "-e",
            f"PGPASSWORD={parsed.password or ''}",
            container,
            "pg_dump",
            "--username",
            parsed.username or "postgres",
            "--dbname",
            SOURCE_DATABASE,
            "--format=custom",
        ]
        completed = subprocess.run(command, capture_output=True)
        if completed.returncode != 0:
            raise RuntimeError(
                "PostgreSQL backup in tools container failed: "
                + completed.stderr.decode(errors="replace")
            )
        target.write_bytes(completed.stdout)
        print("PASS: PostgreSQL backup")
        return
    verify(
        ["pg_dump", "--format=custom", "--file", str(target), database_dsn_value],
        "PostgreSQL backup",
        Path.cwd(),
    )


def restore_database(admin_dsn: str, database_dsn_value: str, source: Path, container: str) -> None:
    if container:
        parsed = urlsplit(admin_dsn)
        command = [
            "docker",
            "exec",
            "-i",
            "-e",
            f"PGPASSWORD={parsed.password or ''}",
            container,
            "pg_restore",
            "--username",
            parsed.username or "postgres",
            "--dbname",
            RESTORED_DATABASE,
            "--no-owner",
        ]
        completed = subprocess.run(command, input=source.read_bytes(), capture_output=True)
        if completed.returncode != 0:
            raise RuntimeError(
                "PostgreSQL restore in tools container failed: "
                + completed.stderr.decode(errors="replace")
            )
        print("PASS: PostgreSQL restore into a fresh database")
        return
    verify(
        ["pg_restore", "--no-owner", "--dbname", database_dsn_value, str(source)],
        "PostgreSQL restore into a fresh database",
        Path.cwd(),
    )


def run_drill(arguments: argparse.Namespace) -> dict[str, object]:
    if os.getenv("MIZAN_CONTINUITY_DRILL_EPHEMERAL") != "true":
        raise RuntimeError(
            "set MIZAN_CONTINUITY_DRILL_EPHEMERAL=true only on an isolated drill database/store"
        )
    repository = Path(__file__).resolve().parents[1]
    source_admin = database_dsn(arguments.admin_database_url, SOURCE_DATABASE)
    restored_admin = database_dsn(arguments.admin_database_url, RESTORED_DATABASE)
    source_runtime = database_dsn(arguments.admin_database_url, SOURCE_DATABASE, runtime=True)
    restored_runtime = database_dsn(arguments.admin_database_url, RESTORED_DATABASE, runtime=True)
    source_bucket = arguments.bucket_prefix + "-source"
    restored_bucket = arguments.bucket_prefix + "-restored"
    client = build_s3_client(
        arguments.s3_endpoint_url,
        arguments.s3_region,
        os.getenv("MIZAN_S3_ACCESS_KEY_ID", ""),
        os.getenv("MIZAN_S3_SECRET_ACCESS_KEY", ""),
    )

    with tempfile.TemporaryDirectory(prefix="mizan-continuity-") as raw:
        work = Path(raw)
        recreate_database(arguments.admin_database_url, SOURCE_DATABASE)
        apply_migrations(repository, source_admin)
        evidence, receipt_signer, anchor_signer = seed_authorization(source_runtime)
        provision_object_lock_bucket(client, source_bucket, arguments.s3_region, 365)
        source_store = S3ObjectLockStore(source_bucket, client=client, retention_years=1)
        source_store.assert_object_lock_enabled()
        publisher = OutboxPublisher(evidence, source_store, receipt_signer, anchor_signer)
        if publisher.drain(TENANT) != 2:
            raise RuntimeError("source drain did not publish both records")
        anchor = publisher.anchor(TENANT, STREAM)
        if anchor["covered_record_count"] != 2:
            raise RuntimeError("source anchor did not cover both records")
        print("PASS: source database and Object Lock evidence created")

        dump = work / "postgres.dump"
        backup_database(
            arguments.admin_database_url,
            source_admin,
            dump,
            arguments.postgres_tools_container,
        )
        object_backup = work / "object-backup"
        keys = backup_bucket(client, source_bucket, object_backup)
        print(f"PASS: Object Lock backup captured {len(keys)} object(s)")

        recreate_database(arguments.admin_database_url, RESTORED_DATABASE)
        restore_database(
            arguments.admin_database_url,
            restored_admin,
            dump,
            arguments.postgres_tools_container,
        )
        provision_object_lock_bucket(client, restored_bucket, arguments.s3_region, 365)
        restored_store = S3ObjectLockStore(restored_bucket, client=client, retention_years=1)
        restored_store.assert_object_lock_enabled()
        for key in keys:
            restored_store.put_once(key, (object_backup / key).read_bytes())
        print("PASS: evidence restored into a fresh Object Lock bucket")

        local_restore = work / "restored-objects"
        for key in keys:
            path = local_restore / key
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(restored_store.get(key))
        documents = key_documents(
            ("evidence-receipt", receipt_signer), ("evidence-anchor", anchor_signer)
        )
        public_keys = {
            signer.key_id: signer.public_key for signer in (receipt_signer, anchor_signer)
        }
        bundle = work / "restored-bundle"
        restored_repository = EvidenceRepository(restored_runtime)
        export_evidence_bundle(
            restored_repository,
            LocalImmutableObjectStore(local_restore),
            public_keys,
            TENANT,
            STREAM,
            bundle,
            key_documents=documents,
            development_custody_reason=(
                "continuity CI fixture uses deterministic development keys; production recovery "
                "uses the restored Vault key versions"
            ),
        )
        verify_bundle(
            [sys.executable, "scripts/verify_evidence_export.py", str(bundle)],
            "restored bundle with the Python verifier",
            repository,
        )
        verify_bundle(
            ["node", "verifier-two/bin/mizan-verify-two.js", str(bundle)],
            "restored bundle with the independent JavaScript verifier",
            repository,
        )
        report = {
            "status": "PASS",
            "source_database": SOURCE_DATABASE,
            "restored_database": RESTORED_DATABASE,
            "source_bucket": source_bucket,
            "restored_bucket": restored_bucket,
            "object_count": len(keys),
            "record_count": 2,
            "anchor_count": 1,
            "python_verifier": "VALID",
            "javascript_verifier": "VALID",
        }
        output = Path(arguments.report)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--admin-database-url", required=True)
    parser.add_argument("--s3-endpoint-url", required=True)
    parser.add_argument("--s3-region", default="us-east-1")
    parser.add_argument("--bucket-prefix", default="mizan-continuity-drill")
    parser.add_argument(
        "--postgres-tools-container",
        default="",
        help="optional isolated PostgreSQL container whose pg_dump/pg_restore binaries are used",
    )
    parser.add_argument("--report", default="var/continuity/backup-restore-report.json")
    arguments = parser.parse_args(argv)
    try:
        report = run_drill(arguments)
    except Exception as error:
        print(f"BACKUP/RESTORE DRILL FAILED: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
