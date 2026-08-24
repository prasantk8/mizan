from __future__ import annotations

from scripts.validate_claim_ledger import validate_snapshot

LIVE = """\
| task_id | claimed_by | claim_token | claim_version | claimed_at |
|---|---|---|---|---|
| T-014 | codex | token | 1 | now |
"""
CLOSED = """\
| T-014 | task | CODEX | T-002 | REVIEW |
- 2026-08-25 · CODEX · T-014 · completed · next: T-008
"""


def test_scoped_change_requires_worklog_in_same_commit() -> None:
    assert validate_snapshot(["control-plane/app.py"], False, LIVE)


def test_live_claim_authorizes_scoped_change() -> None:
    assert validate_snapshot(["security/redaction/service.py", "WORK_LOG.md"], True, LIVE) == []


def test_completion_handoff_authorizes_release_commit() -> None:
    assert validate_snapshot(["ui/package.json", "WORK_LOG.md"], True, CLOSED) == []


def test_docs_only_change_needs_no_claim() -> None:
    assert validate_snapshot(["docs/guide.md"], False, "") == []

