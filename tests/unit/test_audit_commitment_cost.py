"""The premise B-30 was ruled on, made into a gate instead of a sentence (T-054).

The founder accepted N+1 backend round trips per audit write, and a Vault outage failing audit
writes closed, **on the stated condition** that `AuditTrail` is off the authorization hot path. A
condition recorded only in prose expires silently: the day someone wires an audit write into
`/v1/authorize` — which is a reasonable-looking thing to do, since authorization is exactly the
event an audit trail wants — the ruling's premise becomes false and nothing anywhere says so.

So the premise is asserted here. If T-146's wiring, or anything after it, puts an audit write on the
authorization path, this fails and B-30 has to be re-ruled rather than quietly outgrown.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
from pathlib import Path

import pytest
from mizan_security.redaction import RedactionPolicy, Redactor, RuleBasedDlpScanner

CONTROL_PLANE = Path(__file__).resolve().parents[2] / "control-plane" / "mizan_control_plane"

POLICY = RedactionPolicy(
    policy_id="dlp_cost-v1",
    version=1,
    content_hash="c" * 64,
    transformations={"pii": "mask", "secret": "drop", "financial": "tokenize"},
)


class CountingMacKey:
    key_id = "test://audit-commitment#v1"

    def __init__(self) -> None:
        self.calls = 0

    def mac(self, payload: bytes) -> bytes:
        self.calls += 1
        return hmac.new(b"k" * 32, payload, hashlib.sha256).digest()


def _names_called_in(path: Path) -> set[str]:
    """Every attribute and function name invoked anywhere in a module."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    called: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            function = node.func
            if isinstance(function, ast.Attribute):
                called.add(function.attr)
            elif isinstance(function, ast.Name):
                called.add(function.id)
    return called


def test_the_authorization_path_never_writes_an_audit_record() -> None:
    """B-30's accepted cost is conditional on this, so this is checked rather than believed."""
    for module in ("service.py", "policy_engine.py", "risk.py"):
        assert "append_audit" not in _names_called_in(CONTROL_PLANE / module), (
            f"{module} calls append_audit. B-30 accepted N+1 Vault round trips and audit writes "
            "failing closed *because* AuditTrail is off the authorization hot path. It no longer "
            "is, so the ruling needs re-taking before this ships."
        )


def test_the_authorize_route_reaches_no_audit_write() -> None:
    """The route as well as the service, because a route can call a repository directly."""
    source = (CONTROL_PLANE / "app.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    authorize = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "authorize"
    )
    called = {
        node.func.attr
        for node in ast.walk(authorize)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert "append_audit" not in called


@pytest.mark.parametrize("findings", [0, 1, 8])
def test_an_audit_write_costs_exactly_one_mac_per_finding_plus_one(findings: int) -> None:
    """N+1, measured against the real redactor rather than restated.

    The `+1` is the commitment over the whole pre-redaction payload, and it is there even when the
    scanner finds nothing — which is the case worth pinning, because a reader assuming "no findings,
    no cost" would price a clean payload at zero and be wrong by exactly one round trip.
    """
    key = CountingMacKey()
    payload = {
        f"holder_{index}": {"email": f"person-{index}@example.test"} for index in range(findings)
    }
    result = Redactor(RuleBasedDlpScanner(), key, lambda _event: None).redact(payload, POLICY)

    assert len(result.redaction["manifest"]) == findings
    assert key.calls == findings + 1


def test_the_commitment_cites_the_key_that_computed_it() -> None:
    """It used to be possible to MAC under one key and label the record with another reference.

    The label is what a stored record cites forever; an operator resolving it later has no way to
    discover that it names a key which never touched the payload.
    """
    key = CountingMacKey()
    result = Redactor(RuleBasedDlpScanner(), key, lambda _event: None).redact(
        {"email": "someone@example.test"}, POLICY
    )
    assert result.source_commitment["key_ref"] == key.key_id
    assert result.source_commitment["alg"] == "HMAC-SHA256"
