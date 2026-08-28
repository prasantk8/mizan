#!/usr/bin/env python3
"""Apply immutable SQL migrations under one PostgreSQL advisory lock."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

import psycopg

LOCK_ID = 0x4D495A414E  # "MIZAN"
MIGRATION_NAME = re.compile(r"^\d{4}_[a-z0-9_]+\.sql$")


class MigrationError(RuntimeError):
    """A migration history cannot be advanced safely."""


@dataclass(frozen=True, slots=True)
class Migration:
    path: Path
    filename: str
    sha256: str
    body: str


def load_migrations(directory: Path) -> list[Migration]:
    migrations: list[Migration] = []
    for path in sorted(directory.glob("*.sql")):
        if not MIGRATION_NAME.fullmatch(path.name):
            raise MigrationError(f"migration filename is not ordered: {path.name}")
        raw = path.read_bytes()
        text = raw.decode("utf-8")
        lines = text.strip().splitlines()
        if len(lines) < 3 or lines[0].strip() != "BEGIN;" or lines[-1].strip() != "COMMIT;":
            raise MigrationError(f"migration must have one outer BEGIN/COMMIT: {path.name}")
        migrations.append(
            Migration(
                path=path,
                filename=path.name,
                sha256=hashlib.sha256(raw).hexdigest(),
                body="\n".join(lines[1:-1]),
            )
        )
    if not migrations or migrations[0].filename != "0001_domain_schema.sql":
        raise MigrationError("migration set must begin with 0001_domain_schema.sql")
    return migrations


def require_recorded_checksum(filename: str, recorded: str, current: str) -> None:
    if recorded != current:
        raise MigrationError(
            f"recorded migration changed on disk: {filename} "
            f"(recorded {recorded}, current {current})"
        )


def ensure_history_table(connection: psycopg.Connection) -> None:
    connection.execute(
        """CREATE TABLE IF NOT EXISTS mizan.schema_migrations (
             filename text PRIMARY KEY,
             sha256 char(64) NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
             applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
           )"""
    )
    connection.execute("REVOKE ALL ON mizan.schema_migrations FROM PUBLIC")
    role_exists = connection.execute(
        "SELECT 1 FROM pg_roles WHERE rolname='mizan_app'"
    ).fetchone()
    if role_exists:
        connection.execute("REVOKE ALL ON mizan.schema_migrations FROM mizan_app")


def apply(database_url: str, directory: Path) -> list[str]:
    migrations = load_migrations(directory)
    applied: list[str] = []
    with psycopg.connect(database_url, autocommit=True) as connection:
        connection.execute("SELECT pg_advisory_lock(%s)", (LOCK_ID,))
        try:
            schema_exists = connection.execute(
                "SELECT to_regclass('mizan.tenants') IS NOT NULL"
            ).fetchone()[0]
            if not schema_exists:
                first = migrations[0]
                with connection.transaction():
                    connection.execute(first.body)
                    ensure_history_table(connection)
                    connection.execute(
                        "INSERT INTO mizan.schema_migrations(filename,sha256) VALUES (%s,%s)",
                        (first.filename, first.sha256),
                    )
                applied.append(first.filename)
            else:
                with connection.transaction():
                    ensure_history_table(connection)
                    recorded = connection.execute(
                        "SELECT filename,sha256 FROM mizan.schema_migrations ORDER BY filename"
                    ).fetchall()
                    if not recorded:
                        first = migrations[0]
                        connection.execute(
                            "INSERT INTO mizan.schema_migrations(filename,sha256) VALUES (%s,%s)",
                            (first.filename, first.sha256),
                        )

            recorded_by_name = dict(
                connection.execute(
                    "SELECT filename,sha256 FROM mizan.schema_migrations ORDER BY filename"
                ).fetchall()
            )
            known_names = {migration.filename for migration in migrations}
            unknown = sorted(set(recorded_by_name) - known_names)
            if unknown:
                raise MigrationError(
                    "database records migrations absent from disk: " + ", ".join(unknown)
                )

            for migration in migrations:
                recorded_checksum = recorded_by_name.get(migration.filename)
                if recorded_checksum is not None:
                    require_recorded_checksum(
                        migration.filename, recorded_checksum.strip(), migration.sha256
                    )
                    continue
                with connection.transaction():
                    connection.execute(migration.body)
                    connection.execute(
                        "INSERT INTO mizan.schema_migrations(filename,sha256) VALUES (%s,%s)",
                        (migration.filename, migration.sha256),
                    )
                applied.append(migration.filename)
        finally:
            connection.execute("SELECT pg_advisory_unlock(%s)", (LOCK_ID,))
    return applied


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--database-url",
        default=os.getenv("MIZAN_MIGRATION_DATABASE_URL"),
        help="Owner DSN; defaults to MIZAN_MIGRATION_DATABASE_URL",
    )
    parser.add_argument(
        "--migrations",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "infra" / "postgres" / "migrations",
    )
    arguments = parser.parse_args()
    if not arguments.database_url:
        print("migration refused: database URL is required", file=sys.stderr)
        return 78
    try:
        applied = apply(arguments.database_url, arguments.migrations)
    except (MigrationError, psycopg.Error, UnicodeDecodeError) as exc:
        print(f"migration refused: {exc}", file=sys.stderr)
        return 1
    if applied:
        print("applied migrations: " + ", ".join(applied))
    else:
        print("schema already current; no migration re-applied")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
