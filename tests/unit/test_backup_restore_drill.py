from __future__ import annotations

import pytest

from scripts.backup_restore_drill import database_dsn, recreate_database


def test_drill_database_urls_are_explicit_and_runtime_scoped() -> None:
    admin = "postgresql://owner:secret@db.internal:5432/postgres?sslmode=require"
    assert database_dsn(admin, "mizan_restore_drill_source") == (
        "postgresql://owner:secret@db.internal:5432/mizan_restore_drill_source?sslmode=require"
    )
    assert database_dsn(admin, "mizan_restore_drill_restored", runtime=True) == (
        "postgresql://mizan_app:restore-drill-app-only@db.internal:5432/"
        "mizan_restore_drill_restored?sslmode=require"
    )


def test_drill_refuses_a_non_reserved_destructive_target() -> None:
    with pytest.raises(ValueError, match="refusing destructive drill target"):
        recreate_database("postgresql://owner:secret@localhost/postgres", "customer_production")

