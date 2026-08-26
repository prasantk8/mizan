"""`@govern` — the smallest change that makes an existing tool function governed."""

from __future__ import annotations

import functools
import hashlib
from collections.abc import Callable
from typing import Any

import rfc8785

from .client import Decision, MizanClient, Principal, Resource


def result_hash(value: Any) -> str:
    """What the evidence commits to: the canonical hash of the result, never the result."""
    try:
        return hashlib.sha256(rfc8785.dumps(value)).hexdigest()
    except (ValueError, TypeError):
        return hashlib.sha256(repr(value).encode()).hexdigest()


def govern(
    *,
    tool_id: str,
    action_type: str,
    resource: Resource,
    intent: str | None = None,
    client: MizanClient | None = None,
    client_factory: Callable[[], MizanClient] | None = None,
    principal_factory: Callable[..., Principal] | None = None,
    executor_spiffe_id: str | None = None,
    redeem: bool = False,
    approval_timeout_seconds: float = 900.0,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Authorize before the call, and record the outcome after it.

    The decorated function keeps its own signature; its keyword arguments are the tool arguments
    the binding profile is computed over. `redeem=False` (the default) authorizes and records but
    does not take an execution lease — a lease requires a workload identity Mizan has verified
    over mTLS, which an in-process decorator does not have. Set it to True only where the calling
    workload is itself the registered executor.
    """

    def decorate(function: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(function)
        def wrapper(*positional: Any, **arguments: Any) -> Any:
            active = client or (client_factory() if client_factory else None)
            if active is None:
                raise ValueError("govern() needs a client or a client_factory")
            principal = (
                principal_factory(**arguments)
                if principal_factory
                else Principal(id="prn_unattributed", type="application", auth_strength="federated")
            )
            decision: Decision = active.decide(
                tool_id=tool_id,
                arguments=dict(arguments),
                action_type=action_type,
                intent=intent or function.__name__.replace("_", " "),
                principal=principal,
                resource=resource,
                approval_timeout_seconds=approval_timeout_seconds,
            )
            if not redeem:
                return function(*positional, **arguments)
            granted = active.execution_token(decision.decision_id, executor_spiffe_id)
            lease = active.execute(
                decision.decision_id, granted["execution_token"], dict(arguments)
            )
            try:
                value = function(*positional, **arguments)
            except Exception as failure:
                active.complete(
                    decision.decision_id,
                    lease["lease_id"],
                    result_hash({"error": type(failure).__name__}),
                    failure_code="tool_error",
                )
                raise
            active.complete(decision.decision_id, lease["lease_id"], result_hash(value))
            return value

        wrapper.mizan_tool_id = tool_id  # type: ignore[attr-defined]
        return wrapper

    return decorate
